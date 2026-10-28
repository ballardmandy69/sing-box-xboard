package session

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/pipe"
)

// Stream implements net.Conn
type Stream struct {
	id uint32

	sess *Session

	pipeR         *pipe.PipeReader
	pipeW         *pipe.PipeWriter
	writeDeadline pipe.PipeDeadline

	dieOnce sync.Once
	dieHook func()
	dieErr  error

	reportOnce sync.Once
	stateMu    sync.Mutex
	hookCalled bool
}

// newStream initiates a Stream struct
func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.writeDeadline = pipe.MakePipeDeadline()
	return s
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if n == 0 {
		if closeErr := s.closeError(); closeErr != nil {
			err = closeErr
		}
	}
	return
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if closeErr := s.closeError(); closeErr != nil {
		return 0, closeErr
	}
	n, err = s.sess.writeDataFrame(s.id, b)
	return
}

// Close implements net.Conn
func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// closeLocally only closes Stream and don't notify remote peer
func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		s.stateMu.Lock()
		s.dieErr = net.ErrClosed
		s.pipeR.Close()
		s.stateMu.Unlock()
		once = true
	})
	if once {
		s.runDieHook()
	}
}

func (s *Stream) closeWithError(err error) error {
	if err == nil {
		err = net.ErrClosed
	}
	var once bool
	s.dieOnce.Do(func() {
		s.stateMu.Lock()
		s.dieErr = err
		s.pipeR.Close()
		s.stateMu.Unlock()
		once = true
	})
	if once {
		s.runDieHook()
		return s.sess.streamClosed(s.id)
	} else {
		return s.closeError()
	}
}

func (s *Stream) closeError() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.dieErr
}

// setDieHook registers the pool callback, including when a remote close raced
// with OpenStream returning. Callbacks run outside all Stream state locks.
func (s *Stream) setDieHook(hook func()) {
	s.stateMu.Lock()
	if s.hookCalled || s.dieHook != nil {
		s.stateMu.Unlock()
		return
	}
	if s.dieErr != nil && hook != nil {
		s.hookCalled = true
		s.stateMu.Unlock()
		hook()
		return
	}
	s.dieHook = hook
	s.stateMu.Unlock()
}

func (s *Stream) runDieHook() {
	s.stateMu.Lock()
	hook := s.dieHook
	if s.hookCalled || hook == nil {
		s.stateMu.Unlock()
		return
	}
	s.hookCalled = true
	s.dieHook = nil
	s.stateMu.Unlock()
	hook()
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.healthPeerVersion() >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.healthPeerVersion() >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}
