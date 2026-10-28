// Package anytlsnative provides the anytls-native-v1 encrypted stream transport.
// Author: lyt. Date: 2026-10-29.
package anytlsnative

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

const (
	// MaxPayload bounds the plaintext carried by one record.
	MaxPayload              = 16*1024 - 2
	maxPadding              = 256
	defaultHandshakeTimeout = 10 * time.Second
)

var (
	ErrInvalidRecord    = errors.New("anytls-native: invalid record")
	ErrInvalidHandshake = errors.New("anytls-native: invalid handshake")
)

// PaddingOptions limits random padding per sending direction. Any zero field
// disables padding. Fixed record overhead is excluded from MaxPercent.
type PaddingOptions struct {
	MaxPadding int
	MaxPercent int
	MaxTotal   int
}

// DefaultPaddingOptions returns explicit opt-in padding limits.
func DefaultPaddingOptions() PaddingOptions {
	return PaddingOptions{MaxPadding: 256, MaxPercent: 5, MaxTotal: 64 * 1024}
}

// Validate rejects unsupported limits before a connection is opened.
func (p PaddingOptions) Validate() error {
	if p.MaxPadding < 0 || p.MaxPadding > maxPadding || p.MaxPercent < 0 ||
		p.MaxPercent > 100 || p.MaxTotal < 0 {
		return fmt.Errorf("anytls-native: invalid padding limits")
	}
	return nil
}

// ClientConfig pins the server's X25519 public key. Authentication and application
// data must be sent through the returned stream, after the handshake.
type ClientConfig struct {
	ServerPublicKey  []byte
	HandshakeTimeout time.Duration
	Padding          PaddingOptions
}

// ServerConfig supplies the server's X25519 static private key.
type ServerConfig struct {
	PrivateKey       []byte
	HandshakeTimeout time.Duration
	Padding          PaddingOptions
}

// GenerateKeyPair generates a fresh X25519 static key pair as two 32-byte slices.
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key.Bytes(), key.PublicKey().Bytes(), nil
}
