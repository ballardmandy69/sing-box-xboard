// Author: lyt. Date: 2026-10-29.
package anytlsnative

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"testing"
	"time"
)

type enteredConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *enteredConn) Read(data []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(data)
}

func (c *enteredConn) Write(data []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(data)
}

func TestCancelBlockedHandshake(t *testing.T) {
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, serverSide := range []bool{true, false} {
		a, b := net.Pipe()
		conn := &enteredConn{Conn: a, entered: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			if serverSide {
				_, err := ServerHandshake(ctx, conn, ServerConfig{PrivateKey: private})
				result <- err
			} else {
				_, err := ClientHandshake(ctx, conn, ClientConfig{ServerPublicKey: public})
				result <- err
			}
		}()
		<-conn.entered
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("blocked cancellation: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("blocked handshake was not interrupted")
		}
		b.Close()
	}
}

func TestInvalidHandshakeConfigClosesConnection(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 32)} {
		a, b := net.Pipe()
		_, err := ClientHandshake(context.Background(), a, ClientConfig{ServerPublicKey: key})
		if err == nil {
			t.Fatal("malformed or low-order public key accepted")
		}
		if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("failed handshake left connection open: %v", err)
		}
		b.Close()
	}
	a, b := net.Pipe()
	if _, err := ServerHandshake(context.Background(), a, ServerConfig{}); err == nil {
		t.Fatal("empty private key accepted")
	}
	b.Close()
	if _, err := ClientHandshake(context.Background(), nil, ClientConfig{}); err == nil {
		t.Fatal("nil connection accepted")
	}
	a, b = net.Pipe()
	if _, err := ServerHandshake(context.Background(), a, ServerConfig{
		HandshakeTimeout: -time.Second,
	}); err == nil {
		t.Fatal("negative timeout accepted")
	}
	b.Close()
	a, b = net.Pipe()
	if _, err := ClientHandshake(context.Background(), a, ClientConfig{
		Padding: PaddingOptions{MaxPadding: -1},
	}); err == nil {
		t.Fatal("invalid padding config accepted")
	}
	b.Close()
}

func TestServerRejectsVersionBeforeReturningStream(t *testing.T) {
	privateBytes, publicBytes, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := clientPrivate.ECDH(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	var prefix [64]byte
	copy(prefix[:32], clientPrivate.PublicKey().Bytes())
	client, _, err := derive(shared, prefix[32:], "handshake")
	if err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, 33)
	hello[0] = 2
	wire, err := client.seal(hello, prefix[:], 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	result := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(context.Background(), a, ServerConfig{PrivateKey: privateBytes})
		result <- err
	}()
	if err := writeAll(b, append(prefix[:], wire...)); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrInvalidHandshake) {
		t.Fatalf("invalid version: %v", err)
	}
}

func TestAuthenticatedMalformedBodyAndKeySeparation(t *testing.T) {
	for _, plain := range [][]byte{{0, 3, 1}, append([]byte{0, 0}, make([]byte, 257)...)} {
		writer, _ := testStates(t)
		reader, _ := testStates(t)
		nonce := recordNonce(0)
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(plain)+16))
		header := writer.length.Seal(nil, nonce[:], size[:], nil)
		wire := writer.body.Seal(append([]byte(nil), header...), nonce[:], plain, header)
		if _, _, err := reader.read(bytes.NewReader(wire), nil); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("authenticated invalid inner length/padding: %v", err)
		}
	}
	client, server := testStates(t)
	clientWire, err := client.seal([]byte("same data"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverWire, err := server.seal([]byte("same data"), nil, 0)
	if err != nil || bytes.Equal(clientWire, serverWire) {
		t.Fatal("directional keys were not separated")
	}
	client, server, err = derive(bytes.Repeat([]byte{0x42}, 32), []byte("public-test-salt"), "handshake")
	if err != nil {
		t.Fatal(err)
	}
	handshakeWire, err := client.seal([]byte("same data"), nil, 0)
	if err != nil || bytes.Equal(clientWire, handshakeWire) {
		t.Fatal("handshake and traffic keys were not separated")
	}
	if _, _, err := server.read(bytes.NewReader(clientWire), nil); err == nil {
		t.Fatal("wrong direction/stage record accepted")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(data []byte) (int, error) { return f(data) }

func TestWriteAllRejectsInvalidProgress(t *testing.T) {
	for _, result := range []int{-1, 0, 10} {
		err := writeAll(writerFunc(func([]byte) (int, error) { return result, nil }), []byte("a"))
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("invalid progress %d: %v", result, err)
		}
	}
	err := writeAll(writerFunc(func([]byte) (int, error) { return 1, io.ErrClosedPipe }), []byte("a"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error lost: %v", err)
	}
}

func TestNonceExhaustionClosesStream(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	reader, writer := testStates(t)
	writer.sequence = math.MaxUint64
	conn := newConn(a, reader, writer, PaddingOptions{})
	defer conn.Close()
	if _, err := conn.Write([]byte("a")); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("nonce exhaustion: %v", err)
	}
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("nonce exhaustion did not close raw stream: %v", err)
	}
}

func TestReplayedClientFlightHasFreshResponseKeys(t *testing.T) {
	privateBytes, publicBytes, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := clientPrivate.ECDH(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	var prefix [64]byte
	copy(prefix[:32], clientPrivate.PublicKey().Bytes())
	client, _, err := derive(shared, prefix[32:], "handshake")
	if err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, 33)
	hello[0] = handshakeVersion
	firstWire, err := client.seal(hello, prefix[:], 0)
	if err != nil {
		t.Fatal(err)
	}
	firstHash := transcript(prefix[:], firstWire)
	var salts, wires, keyChecks [2][]byte
	for i := range salts {
		a, b := net.Pipe()
		result := make(chan error, 1)
		go func() {
			conn, err := ServerHandshake(context.Background(), a, ServerConfig{PrivateKey: privateBytes})
			if conn != nil {
				conn.Close()
			}
			result <- err
		}()
		if err := writeAll(b, append(prefix[:], firstWire...)); err != nil {
			t.Fatal(err)
		}
		salts[i] = make([]byte, 32)
		if _, err := io.ReadFull(b, salts[i]); err != nil {
			t.Fatal(err)
		}
		ad, hash := responseContext(firstHash, salts[i])
		_, reader, err := derive(shared, hash[:], "response")
		if err != nil {
			t.Fatal(err)
		}
		nonce := recordNonce(0)
		keyChecks[i] = reader.length.Seal(nil, nonce[:], []byte{0, 0}, nil)
		reply, wire, err := reader.read(b, ad)
		if err != nil || len(reply) != 65 || reply[0] != handshakeVersion {
			t.Fatalf("replayed flight response %d: %v", i, err)
		}
		wires[i] = wire
		b.Close()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Equal(salts[0], salts[1]) || bytes.Equal(keyChecks[0], keyChecks[1]) {
		t.Fatal("replayed first flight reused response key/nonce")
	}
	for i := range salts {
		ad, hash := responseContext(firstHash, salts[i])
		_, reader, err := derive(shared, hash[:], "response")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = reader.read(bytes.NewReader(wires[1-i]), ad); err == nil {
			t.Fatal("cross-response salt/ciphertext substitution accepted")
		}
		_, reader, err = derive(shared, hash[:], "response")
		if err != nil {
			t.Fatal(err)
		}
		wrongAD, _ := responseContext(firstHash, salts[1-i])
		if _, _, err = reader.read(bytes.NewReader(wires[i]), wrongAD); err == nil {
			t.Fatal("response associated data substitution accepted")
		}
	}
}

func TestTruncatedResponseSaltClosesHandshake(t *testing.T) {
	_, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, 31} {
		a, b := net.Pipe()
		peerDone := make(chan error, 1)
		go func() {
			defer b.Close()
			// Prefix64 plus version/random33 and record overhead36.
			_, err := io.ReadFull(b, make([]byte, 133))
			if err == nil {
				err = writeAll(b, make([]byte, size))
			}
			peerDone <- err
		}()
		conn, err := ClientHandshake(context.Background(), a, ClientConfig{ServerPublicKey: public})
		if err == nil || conn != nil {
			t.Fatal("truncated response salt accepted")
		}
		if err := <-peerDone; err != nil {
			t.Fatal(err)
		}
		if _, err := a.Write([]byte("later")); err == nil {
			t.Fatal("failed handshake did not close underlying connection")
		}
	}
}
