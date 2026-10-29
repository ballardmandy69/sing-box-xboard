package shadowaead_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func testServerConn(conn net.Conn) *serverConn {
	return &serverConn{
		Service: &Service{keySaltLength: 16, constructor: aeadCipher(aes.NewCipher, cipher.NewGCM)},
		Conn:    conn, uPSK: bytes.Repeat([]byte{1}, 16), requestSalt: bytes.Repeat([]byte{2}, 16),
	}
}

type delayedResponseConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *delayedResponseConn) Write(p []byte) (int, error) {
	close(c.entered)
	<-c.release
	return len(p), nil
}

func (c *delayedResponseConn) Close() error {
	c.once.Do(func() { close(c.release) })
	return nil
}

func TestServerConnCloseDuringInitialWrite(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		underlying := &delayedResponseConn{entered: make(chan struct{}), release: make(chan struct{})}
		conn := testServerConn(underlying)
		written := make(chan error, 1)
		go func() { _, err := conn.Write([]byte("payload")); written <- err }()
		<-underlying.entered
		closed := make(chan error, 1)
		go func() { closed <- conn.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close waited for a blocked initial write")
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
}

type observedWriteConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *observedWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}

func TestServerConnCloseInterruptsBlockedWrite(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	underlying := &observedWriteConn{Conn: server, entered: make(chan struct{})}
	conn := testServerConn(underlying)
	written := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("payload")); written <- err }()
	<-underlying.entered
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt the underlying blocked connection")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked pipe write unexpectedly succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("write remained blocked after close")
	}
}

type captureResponseConn struct {
	net.Conn
	access sync.Mutex
	data   bytes.Buffer
}

func (c *captureResponseConn) Write(p []byte) (int, error) {
	runtime.Gosched()
	c.access.Lock()
	defer c.access.Unlock()
	return c.data.Write(p)
}

func TestServerConnConcurrentWriteAndVectorised(t *testing.T) {
	underlying := &captureResponseConn{}
	conn := testServerConn(underlying)
	if err := conn.WriteVectorised(nil); err != nil {
		t.Fatal(err)
	}
	const count = 64
	start := make(chan struct{})
	errors := make(chan error, count)
	var workers sync.WaitGroup
	for index := 0; index < count; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			payload := []byte{byte(index), byte(index)}
			if index%2 == 0 {
				_, err := conn.Write(payload)
				errors <- err
			} else {
				errors <- conn.WriteVectorised([]*buf.Buffer{buf.As(payload[:1]), buf.As(payload[1:])})
			}
		}(index)
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	payload := decryptServerResponse(t, underlying.data.Bytes(), conn.uPSK)
	counts := make(map[byte]int)
	for _, value := range payload {
		counts[value]++
	}
	if len(counts) != count {
		t.Fatalf("received %d identities, expected %d", len(counts), count)
	}
	for index := 0; index < count; index++ {
		if counts[byte(index)] != 2 {
			t.Fatalf("payload %d count=%d, expected 2", index, counts[byte(index)])
		}
	}
}

func decryptServerResponse(t *testing.T, wire, key []byte) []byte {
	t.Helper()
	reader := bytes.NewReader(wire)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(reader, salt); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(SessionKey(key, salt, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	var sequence uint64
	readChunk := func(length int) []byte {
		t.Helper()
		ciphertext := make([]byte, length+aead.Overhead())
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, aead.NonceSize())
		binary.LittleEndian.PutUint64(nonce, sequence)
		sequence++
		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			t.Fatalf("concurrent writes corrupted AEAD sequence %d: %v", sequence-1, err)
		}
		return plaintext
	}
	header := readChunk(1 + 8 + 16 + 2)
	if header[0] != HeaderTypeServer || !bytes.Equal(header[9:25], bytes.Repeat([]byte{2}, 16)) {
		t.Fatal("initial response header changed")
	}
	payload := readChunk(int(binary.BigEndian.Uint16(header[25:])))
	for reader.Len() > 0 {
		length := binary.BigEndian.Uint16(readChunk(2))
		payload = append(payload, readChunk(int(length))...)
	}
	return payload
}
