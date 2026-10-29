package sniff

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// legacyJA3Fingerprint follows the legacy first-record ClientHello fingerprint parser.
// Invalid or fragmented input leaves the fingerprint empty without rejecting TLS sniffing.
func legacyJA3Fingerprint(record []byte) string {
	value, ok := legacyJA3(record)
	if !ok {
		return ""
	}
	// MD5 is the JA3 identifier format, never an authentication or encryption primitive.
	digest := md5.Sum(value)
	return hex.EncodeToString(digest[:])
}

func legacyJA3(record []byte) ([]byte, bool) {
	if len(record) < 5 || record[0] != 22 || !legacyTLSVersion(binary.BigEndian.Uint16(record[1:3])) {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(record[3:5]))
	if length > len(record)-5 {
		return nil, false
	}
	hello := record[5 : 5+length]
	if len(hello) < 39 || hello[0] != 1 ||
		int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 {
		return nil, false
	}
	version := binary.BigEndian.Uint16(hello[4:6])
	if !legacyTLSVersion(version) {
		return nil, false
	}
	position := 39 + int(hello[38])
	if position > len(hello)-2 {
		return nil, false
	}
	cipherLength := int(binary.BigEndian.Uint16(hello[position : position+2]))
	position += 2
	if cipherLength+1 > len(hello)-position {
		return nil, false
	}
	ciphers := legacyJA3Words(hello[position : position+cipherLength])
	position += cipherLength
	compressionLength := int(hello[position])
	position++
	if compressionLength > len(hello)-position {
		return nil, false
	}
	position += compressionLength
	extensions, groups, points, ok := legacyJA3Extensions(hello[position:])
	if !ok {
		return nil, false
	}
	value := strconv.AppendUint(nil, uint64(version), 10)
	for _, part := range [][]byte{ciphers, extensions, groups, points} {
		value = append(value, ',')
		value = append(value, part...)
	}
	return value, true
}

func legacyTLSVersion(version uint16) bool { return version >= 0x0300 && version <= 0x0304 }

func legacyJA3Words(data []byte) []byte {
	var result []byte
	for len(data) >= 2 {
		value := binary.BigEndian.Uint16(data[:2])
		data = data[2:]
		if value&0x0f0f != 0x0a0a {
			result = appendJA3Number(result, uint64(value))
		}
	}
	return result
}

func appendJA3Number(values []byte, value uint64) []byte {
	if len(values) != 0 {
		values = append(values, '-')
	}
	return strconv.AppendUint(values, value, 10)
}

func legacyJA3Extensions(data []byte) (extensions, groups, points []byte, ok bool) {
	if len(data) == 0 {
		return nil, nil, nil, true
	}
	if len(data) < 2 || int(binary.BigEndian.Uint16(data[:2])) > len(data)-2 {
		return nil, nil, nil, false
	}
	// The original parser checks the declared length but consumes all remaining bytes.
	data = data[2:]
	for len(data) != 0 {
		if len(data) < 4 {
			return nil, nil, nil, false
		}
		kind := binary.BigEndian.Uint16(data[:2])
		length := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if length > len(data) {
			return nil, nil, nil, false
		}
		body := data[:length]
		data = data[length:]
		if kind&0x0f0f != 0x0a0a {
			extensions = appendJA3Number(extensions, uint64(kind))
		}
		switch kind {
		case 0:
			if len(body) < 5 || body[2] != 0 || int(binary.BigEndian.Uint16(body[3:5])) != len(body)-5 {
				return nil, nil, nil, false
			}
		case 10:
			if len(body) < 2 || int(binary.BigEndian.Uint16(body[:2])) != len(body)-2 {
				return nil, nil, nil, false
			}
			groups = legacyJA3Words(body[2:])
		case 11:
			if len(body) == 0 || int(body[0]) != len(body)-1 {
				return nil, nil, nil, false
			}
			points = nil
			for _, value := range body[1:] {
				points = appendJA3Number(points, uint64(value))
			}
		}
	}
	return extensions, groups, points, true
}
