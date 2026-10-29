package route

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

func TestCachedConnReplaysBytesExactlyOnce(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := newCachedConn(server, buf.As([]byte("cached-prefix")).ToOwned())
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	first := make([]byte, 3)
	_, err := io.ReadFull(conn, first)
	require.NoError(t, err)
	require.Equal(t, "cac", string(first))
	written := make(chan error, 1)
	go func() {
		_, writeErr := client.Write([]byte("network-tail"))
		client.Close()
		written <- writeErr
	}()
	var remaining bytes.Buffer
	_, err = bufio.Copy(&remaining, conn)
	require.NoError(t, err)
	require.NoError(t, <-written)
	require.Equal(t, "hed-prefixnetwork-tail", remaining.String())
	require.Nil(t, conn.ReadCached())
	require.True(t, conn.ReaderReplaceable())
}

func TestCachedConnClosePreservesTransferredBuffer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := newCachedConn(server, buf.As([]byte("caller-owned")).ToOwned())
	transferred := conn.ReadCached()
	require.NotNil(t, transferred)
	defer transferred.Release()
	require.NoError(t, conn.Close())
	require.Equal(t, "caller-owned", string(transferred.Bytes()))
	require.Nil(t, conn.ReadCached())
	_, err := conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)
	require.NoError(t, conn.Close())
}

func TestCachedConnCloseInterruptsBlockedRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	reading := make(chan struct{})
	conn := newCachedConn(&cachedReadSignalConn{Conn: server, reading: reading},
		buf.As([]byte("prefix")).ToOwned())
	defer func() {
		server.Close()
		conn.Close()
	}()
	first := make([]byte, len("prefix"))
	_, err := io.ReadFull(conn, first)
	require.NoError(t, err)
	readDone := make(chan error, 1)
	go func() {
		_, readErr := conn.Read(make([]byte, 1))
		readDone <- readErr
	}()
	select {
	case <-reading:
	case <-time.After(5 * time.Second):
		t.Fatal("read did not reach the underlying connection")
	}
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case closeErr := <-closed:
		require.NoError(t, closeErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited on the blocked network read")
	}
	select {
	case readErr := <-readDone:
		require.Error(t, readErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not interrupt the blocked network read")
	}
}

func TestCachedConnConcurrentReadTakeAndClose(t *testing.T) {
	for range 128 {
		client, server := net.Pipe()
		conn := newCachedConn(server, buf.As(bytes.Repeat([]byte("x"), 8192)).ToOwned())
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(3)
		go func() {
			defer workers.Done()
			<-start
			buffer := make([]byte, 31)
			for {
				if _, err := conn.Read(buffer); err != nil {
					return
				}
			}
		}()
		go func() {
			defer workers.Done()
			<-start
			if cached := conn.ReadCached(); cached != nil {
				// The cache consumer owns this buffer even while Close runs.
				for _, value := range cached.Bytes() {
					if value != 'x' {
						t.Error("transferred cache was released or mutated concurrently")
						break
					}
				}
				cached.Release()
			}
		}()
		go func() {
			defer workers.Done()
			<-start
			conn.Close()
		}()
		close(start)
		workers.Wait()
		client.Close()
	}
}

// cachedReadSignalConn identifies when the wrapper has left its cache critical section.
// @author lyt
// @date 2026-10-30
type cachedReadSignalConn struct {
	net.Conn
	reading chan struct{}
	once    sync.Once
}

func (c *cachedReadSignalConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}
