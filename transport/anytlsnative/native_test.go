// Author: lyt. Date: 2026-10-29.
package anytlsnative

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func testStates(t testing.TB) (recordState, recordState) {
	t.Helper()
	client, server, err := derive(bytes.Repeat([]byte{0x42}, 32), []byte("public-test-salt"), "traffic")
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

// Independent HKDF expansion and record assembly protect the domain, key order,
// endian choices, AD binding and ciphertext layout from accidental wire drift.
func TestRecordVector(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	salt := []byte("public-test-salt")
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	var material, previous []byte
	for counter := byte(1); len(material) < 128; counter++ {
		expand := hmac.New(sha256.New, extract.Sum(nil))
		expand.Write(previous)
		expand.Write([]byte("anytls-native-v1\x00traffic"))
		expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		material = append(material, previous...)
	}
	length, err := chacha20poly1305.NewX(material[:32])
	if err != nil {
		t.Fatal(err)
	}
	body, err := chacha20poly1305.NewX(material[32:64])
	if err != nil {
		t.Fatal(err)
	}
	var nonce [24]byte
	nonce[23] = 7
	payload := []byte("vector")
	plain := append([]byte{0, 6}, payload...)
	ad := []byte("transcript")
	header := length.Seal(nil, nonce[:], []byte{0, 24}, ad)
	want := body.Seal(append([]byte(nil), header...), nonce[:], plain, append(ad, header...))
	writer, _ := testStates(t)
	writer.sequence = 7
	got, err := writer.seal(payload, []byte("transcript"), 0)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("record vector mismatch: error=%v", err)
	}
	reader, _ := testStates(t)
	reader.sequence = 7
	decoded, _, err := reader.read(bytes.NewReader(want), []byte("transcript"))
	if err != nil || !bytes.Equal(decoded, payload) || reader.sequence != 8 {
		t.Fatalf("record vector decode failed: %v", err)
	}
}

func TestRecordBoundsTamperingAndSequence(t *testing.T) {
	for _, size := range []int{0, 1, 256, MaxPayload - 256, MaxPayload} {
		for _, padding := range []int{0, 256} {
			writer, _ := testStates(t)
			reader, _ := testStates(t)
			payload := bytes.Repeat([]byte{0x13}, size)
			wire, err := writer.seal(payload, nil, padding)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := reader.read(bytes.NewReader(wire), nil)
			if err != nil || !bytes.Equal(got, payload) || len(wire) != size+padding+36 {
				t.Fatalf("size=%d padding=%d error=%v", size, padding, err)
			}
		}
	}
	writer, _ := testStates(t)
	wire, err := writer.seal([]byte("authenticated"), []byte("ad"), 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range wire {
		mutated := bytes.Clone(wire)
		mutated[i] ^= 1
		reader, _ := testStates(t)
		if _, _, err = reader.read(bytes.NewReader(mutated), []byte("ad")); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("tampered byte %d accepted: %v", i, err)
		}
	}
	reader, _ := testStates(t)
	if _, _, err = reader.read(bytes.NewReader(wire), []byte("wrong")); err == nil {
		t.Fatal("wrong AD accepted")
	}
	reader, _ = testStates(t)
	if _, _, err = reader.read(bytes.NewReader(wire), []byte("ad")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = reader.read(bytes.NewReader(wire), []byte("ad")); err == nil {
		t.Fatal("replayed sequence accepted")
	}
	writer, _ = testStates(t)
	writer.sequence = math.MaxUint64
	if _, err = writer.seal(nil, nil, 0); err == nil {
		t.Fatal("write nonce wrapped")
	}
	if _, _, err = writer.read(bytes.NewReader(nil), nil); err == nil {
		t.Fatal("read nonce wrapped")
	}
	for _, padding := range []int{-1, 257} {
		writer, _ = testStates(t)
		if _, err = writer.seal(nil, nil, padding); err == nil {
			t.Fatal("invalid padding accepted")
		}
	}
	writer, _ = testStates(t)
	if _, err = writer.seal(make([]byte, MaxPayload+1), nil, 0); err == nil {
		t.Fatal("oversized payload accepted")
	}
	for _, size := range []uint16{0, 17, MaxPayload + maxPadding + 19, math.MaxUint16} {
		reader, _ = testStates(t)
		nonce := recordNonce(0)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], size)
		header := reader.length.Seal(nil, nonce[:], length[:], nil)
		if _, _, err = reader.read(bytes.NewReader(header), nil); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("authenticated invalid length %d: %v", size, err)
		}
	}
}

func TestRecordTruncation(t *testing.T) {
	writer, _ := testStates(t)
	wire, err := writer.seal([]byte("truncation"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for size := 0; size < len(wire); size++ {
		reader, _ := testStates(t)
		_, _, err = reader.read(bytes.NewReader(wire[:size]), nil)
		want := io.ErrUnexpectedEOF
		if size == 0 {
			want = io.EOF
		}
		if !errors.Is(err, want) {
			t.Fatalf("truncation at %d: got %v, want %v", size, err, want)
		}
	}
}

func TestPaddingBudget(t *testing.T) {
	for _, options := range []PaddingOptions{{}, DefaultPaddingOptions(), {256, 100, 1024}} {
		budget := paddingBudget{options: options}
		for i := 0; i < 2000; i++ {
			size := []int{1, 19, 20, 1024, MaxPayload}[i%5]
			padding, err := budget.next(size)
			if err != nil || padding < 0 || padding > 256 {
				t.Fatalf("padding=%d error=%v", padding, err)
			}
			if options.MaxTotal == 0 && padding != 0 {
				t.Fatal("disabled padding emitted bytes")
			}
			allowed := budget.payload / 100 * uint64(options.MaxPercent)
			allowed += budget.payload % 100 * uint64(options.MaxPercent) / 100
			if budget.used > allowed || budget.used > uint64(options.MaxTotal) {
				t.Fatal("padding exceeded cumulative budget")
			}
		}
	}
	budget := paddingBudget{options: DefaultPaddingOptions(), payload: math.MaxUint64 - 1}
	if _, err := budget.next(20); err != nil || budget.payload != math.MaxUint64 {
		t.Fatal("payload counter overflow")
	}
	budget.used = uint64(budget.options.MaxTotal)
	if padding, err := budget.next(1024); err != nil || padding != 0 {
		t.Fatal("exhausted lifetime budget emitted padding")
	}
	for _, options := range []PaddingOptions{{-1, 5, 1}, {257, 5, 1}, {1, 101, 1}, {1, 1, -1}} {
		if options.Validate() == nil {
			t.Fatal("invalid padding accepted")
		}
	}
}

type fragmentConn struct {
	net.Conn
	limit int
}

func (c fragmentConn) Read(data []byte) (int, error) {
	return c.Conn.Read(data[:min(len(data), c.limit)])
}

func (c fragmentConn) Write(data []byte) (int, error) {
	return c.Conn.Write(data[:min(len(data), c.limit)])
}

func handshakePair(t testing.TB, fragmented bool) (net.Conn, net.Conn) {
	t.Helper()
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	var clientRaw, serverRaw net.Conn = a, b
	if fragmented {
		clientRaw = fragmentConn{a, 7}
		serverRaw = fragmentConn{b, 11}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 1)
	go func() {
		conn, err := ServerHandshake(ctx, serverRaw, ServerConfig{PrivateKey: private,
			Padding: DefaultPaddingOptions()})
		results <- result{conn, err}
	}()
	client, err := ClientHandshake(ctx, clientRaw, ClientConfig{ServerPublicKey: public,
		Padding: DefaultPaddingOptions()})
	if err != nil {
		a.Close()
		b.Close()
		t.Fatal(err)
	}
	serverResult := <-results
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	t.Cleanup(func() { client.Close(); serverResult.conn.Close() })
	return client, serverResult.conn
}

func TestHandshakeFragmentationFullDuplex(t *testing.T) {
	client, server := handshakePair(t, true)
	payload := bytes.Repeat([]byte("bidirectional"), 6000)
	var group sync.WaitGroup
	for _, direction := range [][2]net.Conn{{client, server}, {server, client}} {
		group.Add(2)
		go func(writer net.Conn) {
			defer group.Done()
			if n, err := writer.Write(payload); err != nil || n != len(payload) {
				t.Errorf("write %d: %v", n, err)
			}
		}(direction[0])
		go func(reader net.Conn) {
			defer group.Done()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, payload) {
				t.Errorf("duplex read: %v", err)
			}
		}(direction[1])
	}
	group.Wait()
	client.Close()
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("clean underlying EOF: %v", err)
	}
}

func TestHandshakeCancellationAndWrongKey(t *testing.T) {
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, serverSide := range []bool{false, true} {
		a, b := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		results := make(chan error, 1)
		go func() {
			var err error
			if serverSide {
				_, err = ServerHandshake(ctx, a, ServerConfig{PrivateKey: private})
			} else {
				_, err = ClientHandshake(ctx, a, ClientConfig{ServerPublicKey: public})
			}
			results <- err
		}()
		cancel()
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancellation failed to unblock handshake")
		}
		a.Close()
		b.Close()
	}
	a, b := net.Pipe()
	defer b.Close()
	_, err = ServerHandshake(context.Background(), a, ServerConfig{PrivateKey: private,
		HandshakeTimeout: 10 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handshake timeout: %v", err)
	}
	wrongPrivate, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	a, b = net.Pipe()
	results := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(context.Background(), b, ServerConfig{PrivateKey: wrongPrivate})
		results <- err
	}()
	if _, err = ClientHandshake(context.Background(), a, ClientConfig{ServerPublicKey: public}); err == nil {
		t.Fatal("wrong server private key accepted")
	}
	if err = <-results; err == nil {
		t.Fatal("wrong key server accepted hello")
	}
}

func TestTrafficTamperingIsTerminal(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	writer, _ := testStates(t)
	reader, _ := testStates(t)
	conn := newConn(a, reader, writer, PaddingOptions{})
	defer conn.Close()
	wire, err := writer.seal([]byte("payload"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire[len(wire)-1] ^= 1
	go func() { _, _ = b.Write(wire) }()
	if _, err = conn.Read(make([]byte, 10)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("tampered traffic: %v", err)
	}
	if _, err = conn.Write([]byte("later")); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("terminal write: %v", err)
	}
}

func TestConnDeadlineAndConcurrentClose(t *testing.T) {
	client, _ := handshakePair(t, false)
	if err := client.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("read deadline ignored")
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() { _ = client.Close() })
	}
	group.Wait()
}

func BenchmarkRecord16KiB(b *testing.B) {
	writer, _ := testStates(b)
	payload := make([]byte, MaxPayload)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := writer.seal(payload, nil, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshake(b *testing.B) {
	private, public, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		a, c := net.Pipe()
		result := make(chan error, 1)
		go func() {
			conn, err := ServerHandshake(context.Background(), c, ServerConfig{PrivateKey: private})
			if conn != nil {
				conn.Close()
			}
			result <- err
		}()
		conn, err := ClientHandshake(context.Background(), a, ClientConfig{ServerPublicKey: public})
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
		if err := <-result; err != nil {
			b.Fatal(err)
		}
	}
}
