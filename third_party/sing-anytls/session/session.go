package session

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	stdatomic "sync/atomic"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamId   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	synDone     func()
	synDoneLock sync.Mutex

	// pool
	seq       uint64
	idleSince time.Time
	padding   *atomic.TypedValue[*padding.PaddingFactory]
	logger    logger.Logger

	peerVersion byte

	// client
	isClient    bool
	sendPadding bool
	buffering   bool
	buffer      []byte
	pktCounter  atomic.Uint32

	// server
	onNewStream func(stream *Stream)

	// Enhanced padding is enabled only after both peers opt in through Settings.
	enhancedPadding      bool
	enhancedReady        stdatomic.Bool
	enhancedDataBytes    uint64
	enhancedPaddingBytes uint64
	enhancedMode         stdatomic.Uint32
	shaper               shapingState
	health               sessionHealth
	controlPending       stdatomic.Int32
	controlCond          *sync.Cond
	disablePadding       bool
}

func NewClientSession(conn net.Conn, _padding *atomic.TypedValue[*padding.PaddingFactory], logger logger.Logger, enhancedPadding ...bool) *Session {
	s := &Session{
		conn:            conn,
		isClient:        true,
		sendPadding:     !(len(enhancedPadding) > 1 && enhancedPadding[1]),
		padding:         _padding,
		logger:          logger,
		enhancedPadding: len(enhancedPadding) > 0 && enhancedPadding[0] && !(len(enhancedPadding) > 1 && enhancedPadding[1]),
		disablePadding:  len(enhancedPadding) > 1 && enhancedPadding[1],
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.TypedValue[*padding.PaddingFactory], logger logger.Logger, enhancedPadding ...bool) *Session {
	s := &Session{
		conn:            conn,
		onNewStream:     onNewStream,
		padding:         _padding,
		logger:          logger,
		enhancedPadding: len(enhancedPadding) > 0 && enhancedPadding[0] && !(len(enhancedPadding) > 1 && enhancedPadding[1]),
		disablePadding:  len(enhancedPadding) > 1 && enhancedPadding[1],
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func (s *Session) Run() {
	if !s.isClient {
		s.recvLoop()
		return
	}

	settings := util.StringMap{
		"v":           "2",
		"client":      util.Verison,
		"padding-md5": s.padding.Load().Md5,
	}
	if s.enhancedPadding {
		settings[enhancedPaddingSetting] = enhancedShapingVersion
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	s.buffering = true
	s.writeControlFrame(f)

	go s.recvLoop()
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close is used to close the session and all streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		s.streamLock.Lock()
		for _, stream := range s.streams {
			stream.closeLocally()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		return s.conn.Close()
	} else {
		return io.ErrClosedPipe
	}
}

// OpenStream is used to create a new stream for CLIENT
func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamId.Add(1)
	stream := newStream(sid, s)
	s.streamLock.Lock()
	select {
	case <-s.die:
		s.streamLock.Unlock()
		stream.closeLocally()
		return nil, io.ErrClosedPipe
	default:
		s.streams[sid] = stream
	}
	s.streamLock.Unlock()

	if sid >= 2 && s.healthPeerVersion() >= 2 {
		s.synDoneLock.Lock()
		if s.synDone != nil {
			s.synDone()
		}
		s.synDone = util.NewDeadlineWatcher(time.Second*3, func() {
			s.Close()
		})
		s.synDoneLock.Unlock()
	}

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		return nil, err
	}

	s.connLock.Lock()
	s.buffering = false // proxy Write it's SocksAddr to flush the buffer
	s.connLock.Unlock()

	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}
	if closeErr := stream.closeError(); closeErr != nil {
		s.streamLock.Lock()
		delete(s.streams, sid)
		s.streamLock.Unlock()
		return nil, closeErr
	}
	return stream, nil
}

func (s *Session) recvLoop() error {
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		logrus.Errorln("[BUG]", r, string(debug.Stack()))
	// 	}
	// }()
	defer s.Close()

	var receivedSettingsFromClient bool
	var hdr rawHeader

	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}
		// read header first
		if _, err := io.ReadFull(s.conn, hdr[:]); err == nil {
			sid := hdr.StreamID()
			switch hdr.Cmd() {
			case cmdPSH:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err == nil {
						s.streamLock.RLock()
						stream, ok := s.streams[sid]
						s.streamLock.RUnlock()
						if ok {
							stream.pipeW.Write(buffer)
						}
						buf.Put(buffer)
					} else {
						buf.Put(buffer)
						return err
					}
				}
			case cmdSYN: // should be server only
				if !s.isClient && !receivedSettingsFromClient {
					f := newFrame(cmdAlert, 0)
					f.data = []byte("client did not send its settings")
					s.writeControlFrame(f)
					return nil
				}
				s.streamLock.Lock()
				if _, ok := s.streams[sid]; !ok {
					stream := newStream(sid, s)
					s.streams[sid] = stream
					go func() {
						if s.onNewStream != nil {
							s.onNewStream(stream)
						} else {
							stream.Close()
						}
					}()
				}
				s.streamLock.Unlock()
			case cmdSYNACK: // should be client only
				s.synDoneLock.Lock()
				if s.synDone != nil {
					s.synDone()
					s.synDone = nil
				}
				s.synDoneLock.Unlock()
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					// report error
					s.streamLock.RLock()
					stream, ok := s.streams[sid]
					s.streamLock.RUnlock()
					if ok {
						stream.closeWithError(fmt.Errorf("remote: %s", string(buffer)))
					}
					buf.Put(buffer)
				}
			case cmdFIN:
				s.streamLock.Lock()
				stream, ok := s.streams[sid]
				delete(s.streams, sid)
				s.streamLock.Unlock()
				if ok {
					stream.closeLocally()
				}
			case cmdWaste:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					buf.Put(buffer)
				}
			case cmdSettings:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if !s.isClient {
						receivedSettingsFromClient = true
						m := util.StringMapFromBytes(buffer)
						paddingF := s.padding.Load()
						if !s.disablePadding && m["padding-md5"] != paddingF.Md5 {
							f := newFrame(cmdUpdatePaddingScheme, 0)
							f.data = paddingF.RawScheme
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
						}
						// check client's version
						if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
							s.peerVersion = byte(v)
							s.markHealthPeerVersion(s.peerVersion)
							// send cmdServerSettings
							f := newFrame(cmdServerSettings, 0)
							serverSettings := util.StringMap{
								"v": "2",
							}
							mode := s.acceptPaddingVersion(m[enhancedPaddingSetting])
							if mode != "" {
								serverSettings[enhancedPaddingSetting] = mode
							}
							f.data = serverSettings.ToBytes()
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
							if mode != "" {
								s.enableEnhancedPadding(mode)
							}
						}
					}
					buf.Put(buffer)
				}
			case cmdAlert:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient {
						s.logger.Error("[Alert from server]", string(buffer))
					}
					buf.Put(buffer)
					return nil
				}
			case cmdUpdatePaddingScheme:
				if hdr.Length() > 0 {
					// `rawScheme` Do not use buffer to prevent subsequent misuse
					rawScheme := make([]byte, int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, rawScheme); err != nil {
						return err
					}
					if s.isClient && !s.disablePadding {
						if padding.UpdatePaddingScheme(rawScheme, s.padding) {
							s.logger.Debug(fmt.Sprintf("[Update padding succeed] %x\n", md5.Sum(rawScheme)))
						} else {
							s.logger.Warn(fmt.Sprintf("[Update padding failed] %x\n", md5.Sum(rawScheme)))
						}
					}
				}
			case cmdHeartRequest:
				if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
					return err
				}
			case cmdHeartResponse:
				s.handleHealthResponse(sid)
			case cmdServerSettings:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient {
						// check server's version
						m := util.StringMapFromBytes(buffer)
						if v, err := strconv.Atoi(m["v"]); err == nil {
							s.peerVersion = byte(v)
							s.markHealthPeerVersion(s.peerVersion)
							if mode := s.acceptPaddingVersion(m[enhancedPaddingSetting]); v >= 2 && mode != "" {
								s.enableEnhancedPadding(mode)
							}
						}
					}
					buf.Put(buffer)
				}
			default:
				// I don't know what command it is (can't have data)
			}
		} else {
			return err
		}
	}
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	limit := 65535
	// A complete frame fits the existing uint16 payload length. Control frames
	// can take priority between frames without adding enhancement-only headers.
	if len(data) <= limit {
		return s.writeOneDataFrame(sid, data)
	}
	var written int
	for len(data) > 0 {
		size := min(len(data), limit)
		n, err := s.writeOneDataFrame(sid, data[:size])
		written += n
		if err != nil {
			return written, err
		}
		data = data[size:]
	}
	return written, nil
}

func (s *Session) writeOneDataFrame(sid uint32, data []byte) (int, error) {
	dataLen := len(data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(cmdPSH)
	binary.BigEndian.PutUint32(buffer.Extend(4), sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(data)
	_, err := s.writeConn(buffer.Bytes(), dataLen)
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	return dataLen, nil
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	return dataLen, nil
}

func (s *Session) writeConn(b []byte, payloadSize ...int) (n int, err error) {
	isControl := len(payloadSize) == 0
	if isControl {
		s.controlPending.Add(1)
	}
	s.connLock.Lock()
	if s.controlCond == nil {
		s.controlCond = sync.NewCond(&s.connLock)
	}
	defer func() {
		if isControl && s.controlPending.Add(-1) == 0 {
			s.controlCond.Broadcast()
		}
		s.connLock.Unlock()
	}()
	for !isControl && s.controlPending.Load() > 0 {
		s.controlCond.Wait()
	}

	if s.buffering {
		s.buffer = slices.Concat(s.buffer, b)
		return len(b), nil
	} else if len(s.buffer) > 0 {
		b = slices.Concat(s.buffer, b)
		s.buffer = nil
	}
	if len(payloadSize) == 0 {
		s.conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
		defer s.conn.SetWriteDeadline(time.Time{})
	}

	// calulate & send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.padding.Load()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == padding.CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				if remainPayloadLen > l { // this packet is all payload
					_, err = s.writeWire(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := make([]byte, headerOverHeadSize+paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = slices.Concat(b, padding)
					}
					_, err = s.writeWire(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else { // this packet is all padding
					padding := make([]byte, headerOverHeadSize+l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.writeWire(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			} else {
				n2, err := s.writeWire(b)
				return n + n2, err
			}
		} else {
			s.sendPadding = false
		}
	}

	return s.writeShaped(b, payloadSize...)
}
