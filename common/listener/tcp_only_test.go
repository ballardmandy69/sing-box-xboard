package listener

import (
	"context"
	"errors"
	"net"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
)

func TestTCPOnlyListenerDoesNotOpenUDP(t *testing.T) {
	l := New(Options{Context: context.Background(), Logger: log.NewNOPFactory().Logger(),
		Network: []string{N.NetworkTCP, N.NetworkUDP}})
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.TCPListener() == nil || l.UDPConn() != nil {
		t.Fatal("dual-network proxy must start only its TCP listener")
	}
	address := l.TCPListener().Addr().(*net.TCPAddr)
	udp, err := net.ListenUDP(N.NetworkUDP, &net.UDPAddr{IP: address.IP, Port: address.Port})
	if err != nil {
		t.Fatalf("proxy unexpectedly occupied the UDP port: %v", err)
	}
	udp.Close()
}

func TestUDPListenerRequestsFailBeforeBinding(t *testing.T) {
	l := New(Options{Network: []string{N.NetworkUDP}})
	if err := l.Start(); !errors.Is(err, C.ErrUDPDisabled) {
		t.Fatalf("UDP-only listener started: %v", err)
	}
	if conn, err := l.ListenUDP(); conn != nil || !errors.Is(err, C.ErrUDPDisabled) {
		t.Fatalf("direct UDP listener bypassed policy: %v", err)
	}
	if conn, err := l.ListenPacket(net.ListenConfig{}, context.Background(), "udp4", "127.0.0.1:0"); conn != nil || !errors.Is(err, C.ErrUDPDisabled) {
		t.Fatalf("packet listener bypassed policy: %v", err)
	}
}
