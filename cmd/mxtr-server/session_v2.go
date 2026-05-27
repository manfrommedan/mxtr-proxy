// mxtr-server v2: stream multiplexing over a single mxtr session.
//
// Wire format inside the existing AEAD frame plaintext:
//   [4 byte stream_id BE][1 byte type][2 byte payload_len BE][payload]
//
// Frame types:
//   0x01 OPEN     - client: payload = target_spec
//   0x02 DATA     - bidir: payload = bytes
//   0x03 CLOSE    - either side: close stream
//   0x04 PING     - keepalive
//   0x05 PONG     - response to PING
//   0x06 OPEN_OK  - server: stream opened
//   0x07 OPEN_ERR - server: dial failed (payload = error byte/text)
//
// stream_id 0 reserved for control. Client allocates 1, 3, 5, ...

package main

import (
	crand "crypto/rand"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	v2FrameHeader = 7 // 4 + 1 + 2

	v2TypeOpen    = 0x01
	v2TypeData    = 0x02
	v2TypeClose   = 0x03
	v2TypePing    = 0x04
	v2TypePong    = 0x05
	v2TypeOpenOK  = 0x06
	v2TypeOpenErr = 0x07

	v2StreamInBuf = 64
)

type v2Stream struct {
	id      uint32
	conn    net.Conn
	in      chan []byte
	closing chan struct{}
	closed  atomic.Bool
}

// v2MaxConcurrentOpens caps in-flight OPEN dispatches per session so one
// authenticated peer can't exhaust the fd table or memory by spamming opens
// (H2-04). 64 is comfortably above legitimate matrix-rust-sdk parallelism
// (~8-16 concurrent HTTP requests per session) but small enough to bound an
// attacker.
const v2MaxConcurrentOpens = 64

type v2Session struct {
	id           int64
	conn         net.Conn
	aeadC2S      cipher.AEAD
	aeadS2C      cipher.AEAD
	seqRead      uint64
	seqWrite     uint64
	writeMu      sync.Mutex
	streams      sync.Map      // uint32 -> *v2Stream
	openSem      chan struct{} // bounded semaphore for in-flight handleOpen
	done         chan struct{} // closed by closeAll, lets heartbeat/loops exit promptly
	closeOnce    sync.Once
	closed       atomic.Bool  // set true by closeAll; checked by handleOpen to avoid leaks
	lastActivity atomic.Int64 // last frame in either direction (used by reaper)
	lastWriteAt  atomic.Int64 // last server-to-client frame (used by heartbeat)
}

// v2Sessions tracks live v2 sessions so a single reaper goroutine can close
// those silent for too long. sync.Map gives lock-free reads in the reap loop.
var v2Sessions sync.Map // int64 -> *v2Session

const v2SessionIdleTimeout = 5 * time.Minute

// reapV2Sessions runs in its own goroutine, started once by main(). It walks
// active sessions every 30 s and force-closes any whose lastActivity is older
// than v2SessionIdleTimeout. Closing the underlying conn unblocks the read
// loop which then exits and removes the session from the map.
func reapV2Sessions() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for now := range t.C {
		cutoff := now.Add(-v2SessionIdleTimeout).UnixNano()
		v2Sessions.Range(func(k, v any) bool {
			s, ok := v.(*v2Session)
			if !ok {
				return true
			}
			if s.lastActivity.Load() < cutoff {
				logInfof("[v2-%d] reaping idle session (>%s)", s.id, v2SessionIdleTimeout)
				_ = s.conn.Close()
			}
			return true
		})
	}
}

func (s *v2Session) touch() { s.lastActivity.Store(time.Now().UnixNano()) }

// writeStreamFrame is the ONLY valid post-handshake writer on a v2Session's
// underlying conn. All paths that need to put bytes on the wire after the mxtr
// handshake completes (DATA, OPEN_OK, OPEN_ERR, CLOSE, PING, PONG) MUST go
// through here. The handshake itself (writeServerHandshake) writes earlier in
// handleTCPv2 BEFORE the session is constructed, so no contention exists at
// that point; do not introduce a parallel writer or AEAD ciphertext will
// interleave with raw handshake bytes.
func (s *v2Session) writeStreamFrame(streamID uint32, frameType byte, payload []byte) error {
	if len(payload) > maxPlaintextSize-v2FrameHeader {
		return errors.New("payload too large for single frame")
	}
	inner := make([]byte, v2FrameHeader+len(payload))
	binary.BigEndian.PutUint32(inner[0:4], streamID)
	inner[4] = frameType
	binary.BigEndian.PutUint16(inner[5:7], uint16(len(payload)))
	copy(inner[7:], payload)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	seq := s.seqWrite
	s.seqWrite++
	if err := writeFrame(s.conn, s.aeadS2C, seq, inner); err != nil {
		return err
	}
	now := time.Now().UnixNano()
	s.lastWriteAt.Store(now)
	// HI3-01: the idle reaper key off lastActivity, not lastWriteAt. Without
	// this update a long server→client stream (large download) looks idle to
	// the reaper for v2SessionIdleTimeout and gets killed mid-flight.
	s.lastActivity.Store(now)
	return nil
}

// heartbeatLoop emits a PING with random padding when the session has been
// quiet long enough. Interval, padding size, and idle threshold are all
// derived from the PSK (see pskDerivedConfig), so two deployments with
// different PSKs trickle on different cadences. Symmetric with the Kotlin
// client's heartbeatLoop so DPI sees bidirectional padding bursts rather
// than one-way trickle (which would itself be a fingerprint).
func (s *v2Session) heartbeatLoop() {
	defer func() {
		if r := recover(); r != nil {
			logErrorf("[v2-%d] heartbeat panic: %v", s.id, r)
		}
	}()
	minMs := pskCfg.heartbeatMinMs
	rangeMs := pskCfg.heartbeatMaxMs - minMs
	if rangeMs < 0 {
		rangeMs = 0
	}
	padMin := pskCfg.heartbeatPadMin
	padRange := pskCfg.heartbeatPadMax - padMin
	if padRange < 0 {
		padRange = 0
	}
	// H2-01: hard cap so a future config drift past maxPlaintextSize doesn't
	// silently kill the heartbeat goroutine via "payload too large".
	padCap := maxPlaintextSize - v2FrameHeader
	if padMin > padCap {
		padMin = padCap
	}
	if padMin+padRange > padCap {
		padRange = padCap - padMin
	}
	idleThresholdNs := int64(pskCfg.idleThresholdMs) * int64(time.Millisecond)
	for {
		jitterMs := minMs + mrand.IntN(rangeMs+1)
		// H2-02: select on done so closeAll unblocks us within one timer tick
		// instead of up to heartbeatMaxMs (~70s) of held session reference.
		select {
		case <-time.After(time.Duration(jitterMs) * time.Millisecond):
		case <-s.done:
			return
		}
		idleNs := time.Now().UnixNano() - s.lastWriteAt.Load()
		if idleNs < idleThresholdNs {
			continue
		}
		pad := make([]byte, padMin+mrand.IntN(padRange+1))
		_, _ = crand.Read(pad)
		if err := s.writeStreamFrame(0, v2TypePing, pad); err != nil {
			logWarnf("[v2-%d] heartbeat write failed; exiting loop: %v", s.id, err)
			return
		}
	}
}

func (s *v2Session) closeAll() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
		s.streams.Range(func(k, v any) bool {
			st := v.(*v2Stream)
			if st.closed.CompareAndSwap(false, true) {
				close(st.closing)
				if st.conn != nil {
					_ = st.conn.Close()
				}
			}
			s.streams.Delete(k)
			return true
		})
	})
}

func (s *v2Session) closeStream(streamID uint32) {
	v, ok := s.streams.LoadAndDelete(streamID)
	if !ok {
		return
	}
	st := v.(*v2Stream)
	if st.closed.CompareAndSwap(false, true) {
		close(st.closing)
		// CR2-01: close the upstream socket too. Without this, the
		// upstream→client reader goroutine sits in a blocking upstream.Read
		// and only checks closing AFTER the read returns — which for an idle
		// peer (HTTP keep-alive, IMAP IDLE, websocket) can be hours. Closing
		// the conn here unblocks the read with ErrClosedConn immediately.
		if st.conn != nil {
			_ = st.conn.Close()
		}
	}
}

func (s *v2Session) handleOpen(streamID uint32, targetSpec []byte) {
	dialAddr, err := parseTarget(targetSpec)
	if err != nil {
		logInfof("[v2-%d] stream %d bad target: %v", s.id, streamID, err)
		_ = s.writeStreamFrame(streamID, v2TypeOpenErr, []byte("bad target"))
		return
	}
	if !isTargetAllowed(dialAddr) {
		logInfof("[v2-%d] stream %d target %s not in allowlist; refusing", s.id, streamID, dialAddr)
		_ = s.writeStreamFrame(streamID, v2TypeOpenErr, []byte("target not allowed"))
		return
	}

	upstream, err := net.DialTimeout("tcp", dialAddr, dialTimeout)
	if err != nil {
		logInfof("[v2-%d] stream %d dial %s: %v", s.id, streamID, dialAddr, err)
		_ = s.writeStreamFrame(streamID, v2TypeOpenErr, []byte("dial failed"))
		return
	}

	st := &v2Stream{
		id:      streamID,
		conn:    upstream,
		in:      make(chan []byte, v2StreamInBuf),
		closing: make(chan struct{}),
	}
	if _, loaded := s.streams.LoadOrStore(streamID, st); loaded {
		upstream.Close()
		logInfof("[v2-%d] stream %d already exists; refusing", s.id, streamID)
		return
	}
	// Defend against closeAll racing this goroutine: if the session was torn
	// down between our dial and our store, the stream sits in the map forever
	// because closeAll already finished its Range. Detect and clean up.
	if s.closed.Load() {
		s.streams.Delete(streamID)
		upstream.Close()
		return
	}
	if err := s.writeStreamFrame(streamID, v2TypeOpenOK, nil); err != nil {
		s.closeStream(streamID)
		upstream.Close()
		return
	}
	logInfof("[v2-%d] stream %d -> %s", s.id, streamID, dialAddr)

	// upstream → client (read target, send DATA frames)
	go func() {
		defer upstream.Close()
		buf := make([]byte, maxPlaintextSize-v2FrameHeader)
		for {
			// M2-01: check closing before blocking on Read so an immediate
			// closeStream (e.g. from CR-01 fast-close path) tears us down.
			select {
			case <-st.closing:
				return
			default:
			}
			n, err := upstream.Read(buf)
			if n > 0 {
				if werr := s.writeStreamFrame(streamID, v2TypeData, buf[:n]); werr != nil {
					s.closeStream(streamID)
					return
				}
			}
			if err != nil {
				_ = s.writeStreamFrame(streamID, v2TypeClose, nil)
				s.closeStream(streamID)
				return
			}
		}
	}()

	// client → upstream (drain st.in, write to target)
	go func() {
		for {
			select {
			case data := <-st.in:
				if _, err := upstream.Write(data); err != nil {
					upstream.Close()
					s.closeStream(streamID)
					return
				}
			case <-st.closing:
				upstream.Close()
				return
			}
		}
	}()
}

func handleTCPv2(conn net.Conn) {
	id := atomic.AddInt64(&connCounter, 1)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}

	nonceC, raw, err := readClientHandshake(conn)
	if err != nil {
		if looksLikeHTTP(raw) {
			logInfof("[v2-%d] http probe from %s; serving 500", id, conn.RemoteAddr())
			drainHTTPRequest(conn, raw)
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write(pickCamouflage())
			return
		}
		logInfof("[v2-%d] bad PSK from %s; hanging", id, conn.RemoteAddr())
		time.Sleep(probeHangDuration)
		return
	}

	jitterMs := jitterMinMS + mrand.IntN(jitterMaxMS-jitterMinMS+1)
	time.Sleep(time.Duration(jitterMs) * time.Millisecond)

	nonceS, err := writeServerHandshake(conn)
	if err != nil {
		return
	}

	keyC2S := deriveKey(nonceC, nonceS, "c2s-key")
	keyS2C := deriveKey(nonceC, nonceS, "s2c-key")
	aeadC2S, _ := chacha20poly1305.New(keyC2S)
	aeadS2C, _ := chacha20poly1305.New(keyS2C)

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	sess := &v2Session{
		id:       id,
		conn:     conn,
		aeadC2S:  aeadC2S,
		aeadS2C:  aeadS2C,
		seqRead:  1,
		seqWrite: 1,
		openSem:  make(chan struct{}, v2MaxConcurrentOpens),
		done:     make(chan struct{}),
	}
	sess.touch()
	sess.lastWriteAt.Store(time.Now().UnixNano())
	v2Sessions.Store(id, sess)
	defer func() {
		sess.closeAll()
		v2Sessions.Delete(id)
	}()
	logInfof("[v2-%d] session established from %s", id, conn.RemoteAddr())
	go sess.heartbeatLoop()

	for {
		pt, err := readFrame(conn, aeadC2S, sess.seqRead)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logInfof("[v2-%d] read frame: %v", id, err)
			}
			return
		}
		sess.seqRead++
		sess.touch()

		if len(pt) < v2FrameHeader {
			logInfof("[v2-%d] short frame %d", id, len(pt))
			return
		}
		streamID := binary.BigEndian.Uint32(pt[0:4])
		frameType := pt[4]
		payloadLen := int(binary.BigEndian.Uint16(pt[5:7]))
		if payloadLen > len(pt)-v2FrameHeader {
			logInfof("[v2-%d] payload len %d exceeds frame", id, payloadLen)
			return
		}
		payload := pt[v2FrameHeader : v2FrameHeader+payloadLen]

		switch frameType {
		case v2TypeOpen:
			// Per-session semaphore caps in-flight dials at v2MaxConcurrentOpens
			// (H2-04). Non-blocking acquire so a flood of OPEN frames is
			// rejected with OPEN_ERR rather than queued / blocking the read loop.
			payloadCopy := append([]byte(nil), payload...)
			select {
			case sess.openSem <- struct{}{}:
				go func(sid uint32, spec []byte) {
					defer func() { <-sess.openSem }()
					sess.handleOpen(sid, spec)
				}(streamID, payloadCopy)
			default:
				logInfof("[v2-%d] OPEN dispatch saturated (%d in flight); refusing stream %d",
					id, v2MaxConcurrentOpens, streamID)
				_ = sess.writeStreamFrame(streamID, v2TypeOpenErr, []byte("server busy"))
			}
		case v2TypeData:
			v, ok := sess.streams.Load(streamID)
			if !ok {
				continue
			}
			st := v.(*v2Stream)
			payloadCopy := append([]byte(nil), payload...)
			// Non-blocking send: when a single upstream is wedged its in-queue
			// fills up; rather than backpressure into the session read loop
			// (which would HoL-block every other live stream on the session
			// including PING/CLOSE/OPEN_OK), drop the slow stream. The peer
			// gets a CLOSE and can reopen if it wants to retry.
			select {
			case st.in <- payloadCopy:
			case <-st.closing:
			default:
				logInfof("[v2-%d] stream %d in-queue full, closing to unblock session", id, streamID)
				_ = sess.writeStreamFrame(streamID, v2TypeClose, nil)
				sess.closeStream(streamID)
			}
		case v2TypeClose:
			sess.closeStream(streamID)
		case v2TypePing:
			_ = sess.writeStreamFrame(0, v2TypePong, payload)
		case v2TypePong:
			// ignore
		default:
			logInfof("[v2-%d] unknown frame type 0x%02x stream %d", id, frameType, streamID)
		}
	}
}
