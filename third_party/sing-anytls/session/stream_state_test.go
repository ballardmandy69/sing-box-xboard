package session

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func stateFixture(t *testing.T) (*Session, *Stream) {
	t.Helper()
	session := shapingSession(t, "stop=0", new(shapingConn), false)
	stream := newStream(1, session)
	session.streams[1] = stream
	return session, stream
}

func TestStreamLateHookRunsExactlyOnce(t *testing.T) {
	_, stream := stateFixture(t)
	stream.closeLocally()
	var calls atomic.Int32
	stream.setDieHook(func() {
		calls.Add(1)
		if stream.closeError() == nil {
			t.Error("late hook observed an open stream")
		}
		// Reentrant state access must not execute while stateMu is held.
		stream.setDieHook(func() { calls.Add(100) })
		_ = stream.Close()
	})
	stream.setDieHook(func() { calls.Add(1000) })
	stream.closeLocally()
	_ = stream.Close()
	if calls.Load() != 1 {
		t.Fatalf("hook calls=%d", calls.Load())
	}
}

func TestStreamCloseAndHookRegistrationRace(t *testing.T) {
	for round := 0; round < 100; round++ {
		session, stream := stateFixture(t)
		var calls atomic.Int32
		var workers sync.WaitGroup
		start := make(chan struct{})
		for index := 0; index < 12; index++ {
			workers.Add(1)
			go func(index int) {
				defer workers.Done()
				<-start
				switch index % 4 {
				case 0:
					stream.setDieHook(func() {
						calls.Add(1)
						_ = stream.closeError()
					})
				case 1:
					stream.closeLocally()
				case 2:
					_ = stream.Close()
				case 3:
					_ = session.Close()
				}
			}(index)
		}
		close(start)
		workers.Wait()
		if calls.Load() != 1 {
			t.Fatalf("round=%d hook calls=%d", round, calls.Load())
		}
		if stream.closeError() == nil {
			t.Fatal("stream not closed")
		}
	}
}

func TestStreamReadWriteConcurrentSessionClose(t *testing.T) {
	for round := 0; round < 50; round++ {
		session, stream := stateFixture(t)
		var workers sync.WaitGroup
		start := make(chan struct{})
		workers.Add(4)
		go func() {
			defer workers.Done()
			<-start
			buffer := make([]byte, 64)
			for {
				if _, err := stream.Read(buffer); err != nil {
					return
				}
			}
		}()
		go func() {
			defer workers.Done()
			<-start
			for index := 0; index < 100; index++ {
				if _, err := stream.Write([]byte("outgoing")); err != nil {
					return
				}
			}
		}()
		go func() {
			defer workers.Done()
			<-start
			_, _ = stream.pipeW.Write([]byte("incoming"))
		}()
		go func() { defer workers.Done(); <-start; _ = session.Close() }()
		close(start)
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("close failed to unblock concurrent stream operations")
		}
		if _, err := stream.Write([]byte("after close")); err == nil {
			t.Fatal("closed stream accepted a write")
		}
	}
}

func TestStreamPreservesFirstCloseError(t *testing.T) {
	_, stream := stateFixture(t)
	want := errors.New("first stream failure")
	_ = stream.closeWithError(want)
	_ = stream.closeWithError(io.EOF)
	stream.closeLocally()
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, want) {
		t.Fatalf("read error=%v", err)
	}
	if _, err := stream.Write([]byte("x")); !errors.Is(err, want) {
		t.Fatalf("write error=%v", err)
	}
}
