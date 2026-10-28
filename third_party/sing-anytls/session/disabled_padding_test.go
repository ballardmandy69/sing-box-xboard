package session

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/logger"
)

func TestDisablePaddingOverridesAllPolicies(t *testing.T) {
	conn := &fixtureConn{}
	state := fixturePadding(t)
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, state)
	s := NewClientSession(conn, state, logger.NOP(), true, true)
	if s.sendPadding || s.enhancedPadding || !s.disablePadding {
		t.Fatal("disabled configuration not propagated")
	}
	for _, mode := range []string{"1", "2"} {
		if s.acceptPaddingVersion(mode) != "" {
			t.Fatal("extension accepted")
		}
		s.enableEnhancedPadding(mode)
	}
	if s.enhancedReady.Load() {
		t.Fatal("enhanced negotiation enabled")
	}
	payload := bytes.Repeat([]byte("padding-free"), 2048)
	n, err := s.writeDataFrame(7, payload)
	if err != nil || n != len(payload) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	wire := conn.written.Bytes()
	if len(wire) != 7+len(payload) || wire[0] != cmdPSH || binary.BigEndian.Uint32(wire[1:5]) != 7 || !bytes.Equal(wire[7:], payload) {
		t.Fatal("padding or shaping changed ordinary frame")
	}
	if s.enhancedPaddingBytes != 0 || s.shaper.initialized {
		t.Fatal("shaper ran in disabled mode")
	}
}

func TestDisablePaddingIgnoresPeerPolicyUpdates(t *testing.T) {
	conn := &fixtureConn{}
	state := fixturePadding(t)
	before := state.Load().Md5
	input := fixtureFrame(cmdUpdatePaddingScheme, padding.DefaultPaddingScheme)
	input = append(input, fixtureFrame(cmdServerSettings, util.StringMap{"v": "2", enhancedPaddingSetting: "2"}.ToBytes())...)
	conn.input.Reset(input)
	s := NewClientSession(conn, state, logger.NOP(), true, true)
	_ = s.recvLoop()
	if state.Load().Md5 != before || s.enhancedReady.Load() {
		t.Fatal("remote policy affected disabled client")
	}
	serverConn := &fixtureConn{}
	serverConn.input.Reset(fixtureFrame(cmdSettings, util.StringMap{"v": "2", "padding-md5": "different", enhancedPaddingSetting: "2"}.ToBytes()))
	server := NewServerSession(serverConn, nil, state, logger.NOP(), true, true)
	_ = server.recvLoop()
	wire := serverConn.written.Bytes()
	if len(wire) < 7 || wire[0] != cmdServerSettings {
		t.Fatal("padding update preceded server settings")
	}
	if int(binary.BigEndian.Uint16(wire[5:7])) != len(wire)-7 {
		t.Fatal("unexpected extra frames")
	}
	settings := util.StringMapFromBytes(wire[7:])
	if _, ok := settings[enhancedPaddingSetting]; ok {
		t.Fatal("disabled server advertised enhancement")
	}
}
