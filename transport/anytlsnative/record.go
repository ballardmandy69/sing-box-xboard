// Author: lyt. Date: 2026-10-29.
package anytlsnative

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const protocolDomain = "anytls-native-v1"

// recordState is confined to a single reader or writer lock.
type recordState struct {
	length   cipher.AEAD
	body     cipher.AEAD
	sequence uint64
}

func derive(secret, salt []byte, purpose string) (client, server recordState, err error) {
	var material [128]byte
	defer clear(material[:])
	kdf := hkdf.New(sha256.New, secret, salt, []byte(protocolDomain+"\x00"+purpose))
	if _, err = io.ReadFull(kdf, material[:]); err != nil {
		return
	}
	var states [4]cipher.AEAD
	for i := range states {
		states[i], err = chacha20poly1305.NewX(material[i*32 : (i+1)*32])
		if err != nil {
			return
		}
	}
	client = recordState{length: states[0], body: states[1]}
	server = recordState{length: states[2], body: states[3]}
	return
}

func recordNonce(sequence uint64) [chacha20poly1305.NonceSizeX]byte {
	var nonce [chacha20poly1305.NonceSizeX]byte
	binary.BigEndian.PutUint64(nonce[16:], sequence)
	return nonce
}

func bodyAD(ad, encryptedLength []byte) []byte {
	result := make([]byte, 0, len(ad)+len(encryptedLength))
	result = append(result, ad...)
	return append(result, encryptedLength...)
}

func (r *recordState) seal(payload, ad []byte, padding int) ([]byte, error) {
	if r.sequence == math.MaxUint64 || len(payload) > MaxPayload || padding < 0 || padding > maxPadding {
		return nil, ErrInvalidRecord
	}
	plain := make([]byte, 2+len(payload)+padding)
	binary.BigEndian.PutUint16(plain, uint16(len(payload)))
	copy(plain[2:], payload)
	if _, err := rand.Read(plain[2+len(payload):]); err != nil {
		return nil, err
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(plain)+r.body.Overhead()))
	nonce := recordNonce(r.sequence)
	header := r.length.Seal(nil, nonce[:], size[:], ad)
	authenticated := bodyAD(ad, header)
	wire := make([]byte, len(header), len(header)+len(plain)+r.body.Overhead())
	copy(wire, header)
	wire = r.body.Seal(wire, nonce[:], plain, authenticated)
	r.sequence++
	return wire, nil
}

// read retains ciphertext separately so handshake transcript hashing never hashes
// an in-place decrypted buffer. All allocations follow authenticated size checks.
func (r *recordState) read(reader io.Reader, ad []byte) (payload, wire []byte, err error) {
	if r.sequence == math.MaxUint64 {
		return nil, nil, ErrInvalidRecord
	}
	var header [18]byte
	if _, err = io.ReadFull(reader, header[:]); err != nil {
		return nil, nil, err
	}
	nonce := recordNonce(r.sequence)
	size, err := r.length.Open(nil, nonce[:], header[:], ad)
	if err != nil || len(size) != 2 {
		return nil, nil, ErrInvalidRecord
	}
	bodySize := int(binary.BigEndian.Uint16(size))
	if bodySize < 18 || bodySize > MaxPayload+maxPadding+18 {
		return nil, nil, ErrInvalidRecord
	}
	wire = make([]byte, len(header)+bodySize)
	copy(wire, header[:])
	if _, err = io.ReadFull(reader, wire[len(header):]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, nil, err
	}
	plain, err := r.body.Open(nil, nonce[:], wire[len(header):], bodyAD(ad, header[:]))
	if err != nil || len(plain) < 2 {
		return nil, nil, ErrInvalidRecord
	}
	sizeValue := int(binary.BigEndian.Uint16(plain))
	if sizeValue > MaxPayload || sizeValue > len(plain)-2 || len(plain)-2-sizeValue > maxPadding {
		return nil, nil, ErrInvalidRecord
	}
	r.sequence++
	return plain[2 : 2+sizeValue], wire, nil
}

type paddingBudget struct {
	options PaddingOptions
	payload uint64
	used    uint64
}

func (p *paddingBudget) next(size int) (int, error) {
	if uint64(size) > math.MaxUint64-p.payload {
		p.payload = math.MaxUint64
	} else {
		p.payload += uint64(size)
	}
	o := p.options
	if o.MaxPadding == 0 || o.MaxPercent == 0 || o.MaxTotal == 0 {
		return 0, nil
	}
	percent := uint64(o.MaxPercent)
	allowed := p.payload/100*percent + p.payload%100*percent/100
	if p.used >= allowed || p.used >= uint64(o.MaxTotal) {
		return 0, nil
	}
	limit := min(uint64(o.MaxPadding), allowed-p.used, uint64(o.MaxTotal)-p.used)
	if limit == 0 {
		return 0, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(limit+1)))
	if err != nil {
		return 0, err
	}
	padding := n.Uint64()
	p.used += padding
	return int(padding), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
