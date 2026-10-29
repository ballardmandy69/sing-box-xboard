package shadowsocks

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type obfsTestConn struct {
	input       *bytes.Reader
	output      bytes.Buffer
	reads       int
	readErr     error
	writeErr    error
	deadlineErr error
	shortWrite  bool
	deadlines   []time.Time
}

func (c *obfsTestConn) Read(p []byte) (int, error) {
	c.reads++
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.input.Read(p)
}

func (c *obfsTestConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.shortWrite {
		return len(p) - 1, nil
	}
	return c.output.Write(p)
}

func (c *obfsTestConn) Close() error                     { return nil }
func (c *obfsTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *obfsTestConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *obfsTestConn) SetDeadline(time.Time) error      { return nil }
func (c *obfsTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *obfsTestConn) SetReadDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return c.deadlineErr
}

func TestObfsPreamblePreservesCiphertext(t *testing.T) {
	processor := &obfsProcessor{}
	identity := multiUserIdentity{Name: "7@test@uniproxy", Index: 3}
	processor.update([]multiUserIdentity{identity}, []string{"uuid-text"})
	for _, target := range []string{"/", "http://different.invalid/"} {
		request := "GET " + target + " HTTP/1.1\r\nHost: " + obfsHost("uuid-text") + ":443\r\n\r\n"
		conn := &obfsTestConn{input: bytes.NewReader([]byte(request + "ciphertext"))}
		wrapped, user, err := processor.process(conn)
		if err != nil || user.identity != identity || user.uuid != "uuid-text" {
			t.Fatalf("user=%+v, err=%v", user, err)
		}
		if conn.reads != 1 || conn.output.String() != obfsResponse || len(conn.deadlines) != 2 ||
			!conn.deadlines[1].IsZero() || time.Until(conn.deadlines[0]) < 4*time.Second {
			t.Fatalf("unexpected response/deadlines/read count: %+v", conn)
		}
		payload, err := io.ReadAll(wrapped)
		if err != nil || string(payload) != "ciphertext" {
			t.Fatalf("preserved payload=%q, err=%v", payload, err)
		}
		wrapped.Close()
	}
}

func TestObfsRejectsUnknownAndMalformedPreambles(t *testing.T) {
	processor := &obfsProcessor{}
	processor.update([]multiUserIdentity{{Name: "known"}}, []string{"uuid-text"})
	host := obfsHost("uuid-text")
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: " + host + "\r\n",
		"GET / HTTP/1.1\r\nHost: unknown.invalid\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + strings.ToUpper(host) + "\r\n\r\n",
		"GET / HTTP/1.0\r\n\r\n",
		"invalid\r\n\r\n",
		strings.Repeat("x", 8192) + "\r\n\r\n",
	} {
		conn := &obfsTestConn{input: bytes.NewReader([]byte(request))}
		if _, _, err := processor.process(conn); err == nil || conn.output.Len() != 0 {
			t.Fatalf("accepted invalid preamble or sent success response, err=%v", err)
		}
		if conn.reads != 1 {
			t.Fatalf("fragmented preamble should match original single-read behavior, reads=%d", conn.reads)
		}
	}
}

func TestObfsFailurePropagationAndUserRemoval(t *testing.T) {
	processor := &obfsProcessor{}
	processor.update([]multiUserIdentity{{Name: "known"}}, []string{"uuid-text"})
	request := "GET / HTTP/1.1\r\nHost: " + obfsHost("uuid-text") + "\r\n\r\n"
	failure := errors.New("test I/O failure")
	for _, conn := range []*obfsTestConn{
		{input: bytes.NewReader([]byte(request)), deadlineErr: failure},
		{input: bytes.NewReader([]byte(request)), readErr: failure},
		{input: bytes.NewReader([]byte(request)), writeErr: failure},
		{input: bytes.NewReader([]byte(request)), shortWrite: true},
	} {
		_, _, err := processor.process(conn)
		if !errors.Is(err, failure) && !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("I/O failure lost: %v", err)
		}
	}
	processor.update(nil, nil)
	conn := &obfsTestConn{input: bytes.NewReader([]byte(request))}
	if _, _, err := processor.process(conn); err == nil {
		t.Fatal("removed user was accepted")
	}
}

func TestObfsUserSnapshotsConcurrent(t *testing.T) {
	processor := &obfsProcessor{}
	processor.update([]multiUserIdentity{{Name: "first"}}, []string{"uuid-text"})
	request := "GET / HTTP/1.1\r\nHost: " + obfsHost("uuid-text") + "\r\n\r\n"
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for index := 0; index < 100; index++ {
			processor.update([]multiUserIdentity{{Name: "second", Index: index}}, []string{"uuid-text"})
		}
	}()
	for index := 0; index < 100; index++ {
		conn := &obfsTestConn{input: bytes.NewReader([]byte(request))}
		if _, _, err := processor.process(conn); err != nil {
			t.Fatalf("coherent snapshot rejected: %v", err)
		}
	}
	workers.Wait()
}
