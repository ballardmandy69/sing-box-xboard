package anytlsnative_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/anytlsnative"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type nativeRevokingTracker struct {
	managed adapter.ManagedSSMServer
	count   atomic.Int32
	once    sync.Once
	updated chan error
}

func (r *nativeRevokingTracker) TrackConnection(conn net.Conn, _ adapter.InboundContext) net.Conn {
	r.count.Add(1)
	r.once.Do(func() {
		r.updated <- r.managed.UpdateUsers([]string{"bravo"}, []string{"bravo-secret"})
	})
	return conn
}

func (r *nativeRevokingTracker) TrackPacketConnection(conn N.PacketConn, _ adapter.InboundContext) N.PacketConn {
	return conn
}

func TestNativeRevocationRejectsBufferedSYN(t *testing.T) {
	privateKey, publicKey := nativeTestKeys(t)
	serverInbound := nativeServerConfig(nativeFreePort(t), privateKey)
	server := nativeStartBox(t, map[string]any{
		"inbounds": []any{serverInbound}, "outbounds": []any{map[string]any{"type": "direct"}},
	}, nil)
	inbound, _ := server.Inbound().Get("native-in")
	tracker := &nativeRevokingTracker{
		managed: inbound.(adapter.ManagedSSMServer), updated: make(chan error, 1),
	}
	tracker.managed.SetTracker(tracker)
	raw, accepted := nativeTCPPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		inbound.(adapter.TCPInjectableInbound).NewConnection(context.Background(), accepted,
			adapter.InboundContext{Source: M.SocksaddrFromNet(accepted.RemoteAddr())}, nil)
	}()
	key, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	secured, err := anytlsnative.ClientHandshake(ctx, raw, anytlsnative.ClientConfig{ServerPublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer secured.Close()
	var address bytes.Buffer
	if err = M.SocksaddrSerializer.WriteAddrPort(&address, nativeEchoServer(t)); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("alpha-secret"))
	batch := append([]byte{}, digest[:]...)
	batch = append(batch, 0, 0) // Native AnyTLS authentication has no padding.
	batch = nativeAppendFrame(batch, 4, 0, []byte("v=1"))
	for _, streamID := range []uint32{1, 3} {
		batch = nativeAppendFrame(batch, 1, streamID, nil)
		// The extra business byte blocks the synchronous stream pipe after
		// ReadAddrPort. The first tracker revokes alpha before recvLoop can
		// advance to the second SYN, already inside this same decrypted record.
		payload := append(append([]byte{}, address.Bytes()...), 1)
		batch = nativeAppendFrame(batch, 2, streamID, payload)
	}
	if len(batch) > anytlsnative.MaxPayload {
		t.Fatal("test requires both SYN frames in one native record")
	}
	secured.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err = secured.Write(batch); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-tracker.updated:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("first buffered stream did not reach the revocation barrier")
	}
	nativeWaitSignal(t, done, "revoked session consuming or rejecting its buffered frames")
	if count := tracker.count.Load(); count != 1 {
		t.Fatalf("revoked session dispatched %d streams, want only the first authorized stream", count)
	}
}

func nativeAppendFrame(buffer []byte, command byte, streamID uint32, payload []byte) []byte {
	var header [7]byte
	header[0] = command
	binary.BigEndian.PutUint32(header[1:], streamID)
	binary.BigEndian.PutUint16(header[5:], uint16(len(payload)))
	buffer = append(buffer, header[:]...)
	return append(buffer, payload...)
}
