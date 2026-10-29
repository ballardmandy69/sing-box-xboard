package sniff

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func ja3Extension(kind uint16, data []byte) []byte {
	result := binary.BigEndian.AppendUint16(nil, kind)
	result = binary.BigEndian.AppendUint16(result, uint16(len(data)))
	return append(result, data...)
}

func ja3Record(extensions []byte) []byte {
	hello := make([]byte, 39)
	hello[0], hello[4], hello[5] = 1, 3, 3
	hello = append(hello, 0, 6, 0x0a, 0x0a, 0x13, 1, 0x13, 2, 1, 0)
	if extensions != nil {
		hello = binary.BigEndian.AppendUint16(hello, uint16(len(extensions)))
		hello = append(hello, extensions...)
	}
	length := len(hello) - 4
	hello[1], hello[2], hello[3] = byte(length>>16), byte(length>>8), byte(length)
	record := binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(hello)))
	return append(record, hello...)
}

func TestLegacyJA3OrderGreaseAndFirstRecord(t *testing.T) {
	var extensions []byte
	for _, entry := range [][]byte{
		ja3Extension(0x2a2a, nil), ja3Extension(43, []byte{2, 3, 4}),
		ja3Extension(0, []byte{0, 6, 0, 0, 3, 'a', '.', 'b'}),
		ja3Extension(10, []byte{0, 6, 0x1a, 0x1a, 0, 29, 0, 23}),
		ja3Extension(11, []byte{2, 0, 1}),
	} {
		extensions = append(extensions, entry...)
	}
	record := ja3Record(extensions)
	expected := "771,4865-4866,43-0-10-11,29-23,0-1"
	value, ok := legacyJA3(record)
	require.True(t, ok)
	require.Equal(t, expected, string(value))
	digest := md5.Sum([]byte(expected))
	require.Equal(t, hex.EncodeToString(digest[:]), legacyJA3Fingerprint(record))
	require.Equal(t, legacyJA3Fingerprint(record), legacyJA3Fingerprint(append(record, 22, 3, 3, 0, 0)))
	// The legacy total extension length is a minimum-size check, not a slice boundary.
	record[54], record[55] = 0, 0
	require.Equal(t, hex.EncodeToString(digest[:]), legacyJA3Fingerprint(record))
}

func TestLegacyJA3AbsentRepeatedAndMalformedVectors(t *testing.T) {
	value, ok := legacyJA3(ja3Record(nil))
	require.True(t, ok)
	require.Equal(t, "771,4865-4866,,,", string(value))
	extensions := append(ja3Extension(10, []byte{0, 2, 0, 23}), ja3Extension(10, []byte{0, 2, 0, 29})...)
	value, ok = legacyJA3(ja3Record(extensions))
	require.True(t, ok)
	require.Equal(t, "771,4865-4866,10-10,29,", string(value))
	for _, extension := range [][]byte{
		{0}, {0, 1, 0, 3, 1}, ja3Extension(0, []byte{0, 0, 1, 0, 0}),
		ja3Extension(0, []byte{0, 0, 0, 0, 1}), ja3Extension(10, []byte{0}),
		ja3Extension(10, []byte{0, 4, 0, 29}), ja3Extension(11, nil), ja3Extension(11, []byte{2, 0}),
	} {
		require.Empty(t, legacyJA3Fingerprint(ja3Record(extension)), "%x", extension)
	}
	valid := ja3Record(ja3Extension(11, []byte{1, 0}))
	for length := 0; length < len(valid); length++ {
		require.Empty(t, legacyJA3Fingerprint(valid[:length]), "length %d", length)
	}
	for _, change := range []struct {
		offset int
		value  byte
	}{{0, 23}, {1, 2}, {5, 2}, {8, 0}, {9, 2}, {43, 255}, {45, 255}, {52, 255}} {
		malformed := bytes.Clone(valid)
		malformed[change.offset] = change.value
		require.Empty(t, legacyJA3Fingerprint(malformed), "offset %d", change.offset)
	}
}

func tlsClientRecord(t *testing.T) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer client.Close()
		_ = tls.Client(client, &tls.Config{ServerName: "fingerprint.example", InsecureSkipVerify: true}).Handshake()
	}()
	t.Cleanup(func() { _ = server.Close(); <-done })
	require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
	header := make([]byte, 5)
	_, err := io.ReadFull(server, header)
	require.NoError(t, err)
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	_, err = io.ReadFull(server, body)
	require.NoError(t, err)
	return append(header, body...)
}

func TestTLSFingerprintOnlyWhenScannerEnabled(t *testing.T) {
	record := tlsClientRecord(t)
	expected := legacyJA3Fingerprint(record)
	require.Len(t, expected, 32)
	for _, expression := range []string{"", "''"} {
		registry, err := nodepolicy.NewRegistry(expression, nil)
		require.NoError(t, err)
		ctx := service.ContextWith[adapter.ManagedNodePolicy](context.Background(), registry)
		var metadata adapter.InboundContext
		require.NoError(t, TLSClientHello(ctx, &metadata, bytes.NewReader(record)))
		require.Equal(t, "fingerprint.example", metadata.Domain)
		if expression == "" {
			require.Empty(t, metadata.TLSFingerprint)
		} else {
			require.Equal(t, expected, metadata.TLSFingerprint)
		}
	}
}

func TestFragmentedTLSHelloSniffsWithoutLegacyFingerprint(t *testing.T) {
	record := tlsClientRecord(t)
	first := append([]byte{22, 3, 1, 0, 10}, record[5:15]...)
	second := binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(record)-15))
	fragmented := append(first, append(second, record[15:]...)...)
	registry, err := nodepolicy.NewRegistry(`''`, nil)
	require.NoError(t, err)
	ctx := service.ContextWith[adapter.ManagedNodePolicy](context.Background(), registry)
	var metadata adapter.InboundContext
	require.NoError(t, TLSClientHello(ctx, &metadata, bytes.NewReader(fragmented)))
	require.Equal(t, "fingerprint.example", metadata.Domain)
	require.Equal(t, "tls", metadata.Protocol)
	require.Empty(t, metadata.TLSFingerprint)
}
