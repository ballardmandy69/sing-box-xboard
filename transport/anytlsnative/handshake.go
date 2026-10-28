// Author: lyt. Date: 2026-10-29.
package anytlsnative

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"time"
)

const handshakeVersion = 1

// handshake closes the raw connection on every failure. Cancellation uses Close
// to unblock I/O without overwriting caller-installed connection deadlines.
func handshake(ctx context.Context, raw net.Conn, timeout time.Duration,
	perform func() (net.Conn, error),
) (net.Conn, error) {
	if raw == nil {
		return nil, errors.New("anytls-native: nil connection")
	}
	if timeout < 0 || ctx == nil {
		raw.Close()
		return nil, errors.New("anytls-native: invalid handshake context or timeout")
	}
	if timeout == 0 {
		timeout = defaultHandshakeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		raw.Close()
		return nil, err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			raw.Close()
		case <-stop:
		}
	}()
	conn, err := perform()
	close(stop)
	<-done
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func transcript(prefix, firstRecord []byte) [32]byte {
	hash := sha256.New()
	hash.Write(prefix)
	hash.Write(firstRecord)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

// responseContext adds server freshness before encrypting its changing ephemeral
// key. Replaying a client flight must never reuse a response key/nonce pair.
func responseContext(firstHash [32]byte, serverSalt []byte) ([]byte, [32]byte) {
	ad := make([]byte, 0, len(firstHash)+len(serverSalt))
	ad = append(ad, firstHash[:]...)
	ad = append(ad, serverSalt...)
	return ad, sha256.Sum256(ad)
}

func trafficStates(first, second []byte, transcriptHash [32]byte, reply []byte) (
	client, server recordState, err error,
) {
	secret := make([]byte, 0, len(first)+len(second))
	secret = append(secret, first...)
	secret = append(secret, second...)
	defer clear(secret)
	salt := transcript(transcriptHash[:], reply)
	return derive(secret, salt[:], "traffic")
}

// ClientHandshake authenticates the server's pinned static key. No identity,
// authentication credential or application payload is sent in the first flight.
func ClientHandshake(ctx context.Context, raw net.Conn, config ClientConfig) (net.Conn, error) {
	return handshake(ctx, raw, config.HandshakeTimeout, func() (net.Conn, error) {
		if err := config.Padding.Validate(); err != nil {
			return nil, err
		}
		serverPublic, err := ecdh.X25519().NewPublicKey(config.ServerPublicKey)
		if err != nil {
			return nil, err
		}
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		first, err := private.ECDH(serverPublic)
		if err != nil {
			return nil, err
		}
		defer clear(first)
		var prefix [64]byte
		copy(prefix[:32], private.PublicKey().Bytes())
		if _, err = rand.Read(prefix[32:]); err != nil {
			return nil, err
		}
		client, _, err := derive(first, prefix[32:], "handshake")
		if err != nil {
			return nil, err
		}
		var hello [33]byte
		hello[0] = handshakeVersion
		if _, err = rand.Read(hello[1:]); err != nil {
			return nil, err
		}
		wire, err := client.seal(hello[:], prefix[:], 0)
		if err != nil {
			return nil, err
		}
		if err = writeAll(raw, prefix[:]); err != nil {
			return nil, err
		}
		if err = writeAll(raw, wire); err != nil {
			return nil, err
		}
		firstHash := transcript(prefix[:], wire)
		var serverSalt [32]byte
		if _, err = io.ReadFull(raw, serverSalt[:]); err != nil {
			return nil, err
		}
		responseAD, responseHash := responseContext(firstHash, serverSalt[:])
		_, server, err := derive(first, responseHash[:], "response")
		if err != nil {
			return nil, err
		}
		reply, _, err := server.read(raw, responseAD)
		if err != nil {
			return nil, err
		}
		if len(reply) != 65 || reply[0] != handshakeVersion {
			return nil, ErrInvalidHandshake
		}
		ephemeral, err := ecdh.X25519().NewPublicKey(reply[1:33])
		if err != nil {
			return nil, err
		}
		second, err := private.ECDH(ephemeral)
		if err != nil {
			return nil, err
		}
		defer clear(second)
		client, server, err = trafficStates(first, second, responseHash, reply)
		if err != nil {
			return nil, err
		}
		return newConn(raw, server, client, config.Padding), nil
	})
}

// ServerHandshake creates a fresh server ephemeral key for every connection.
// Client/user authentication remains the responsibility of the upper protocol.
func ServerHandshake(ctx context.Context, raw net.Conn, config ServerConfig) (net.Conn, error) {
	return handshake(ctx, raw, config.HandshakeTimeout, func() (net.Conn, error) {
		if err := config.Padding.Validate(); err != nil {
			return nil, err
		}
		private, err := ecdh.X25519().NewPrivateKey(config.PrivateKey)
		if err != nil {
			return nil, err
		}
		var prefix [64]byte
		if _, err = io.ReadFull(raw, prefix[:]); err != nil {
			return nil, err
		}
		clientPublic, err := ecdh.X25519().NewPublicKey(prefix[:32])
		if err != nil {
			return nil, err
		}
		first, err := private.ECDH(clientPublic)
		if err != nil {
			return nil, err
		}
		defer clear(first)
		client, _, err := derive(first, prefix[32:], "handshake")
		if err != nil {
			return nil, err
		}
		hello, firstWire, err := client.read(raw, prefix[:])
		if err != nil {
			return nil, err
		}
		if len(hello) != 33 || hello[0] != handshakeVersion {
			return nil, ErrInvalidHandshake
		}
		firstHash := transcript(prefix[:], firstWire)
		var serverSalt [32]byte
		if _, err = rand.Read(serverSalt[:]); err != nil {
			return nil, err
		}
		responseAD, responseHash := responseContext(firstHash, serverSalt[:])
		_, server, err := derive(first, responseHash[:], "response")
		if err != nil {
			return nil, err
		}
		ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		second, err := ephemeral.ECDH(clientPublic)
		if err != nil {
			return nil, err
		}
		defer clear(second)
		var reply [65]byte
		reply[0] = handshakeVersion
		copy(reply[1:33], ephemeral.PublicKey().Bytes())
		if _, err = rand.Read(reply[33:]); err != nil {
			return nil, err
		}
		wire, err := server.seal(reply[:], responseAD, 0)
		if err != nil {
			return nil, err
		}
		if err = writeAll(raw, serverSalt[:]); err != nil {
			return nil, err
		}
		if err = writeAll(raw, wire); err != nil {
			return nil, err
		}
		client, server, err = trafficStates(first, second, responseHash, reply[:])
		if err != nil {
			return nil, err
		}
		return newConn(raw, client, server, config.Padding), nil
	})
}
