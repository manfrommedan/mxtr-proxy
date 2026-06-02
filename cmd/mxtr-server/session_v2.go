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
//   0x06 OPEN_OK  - server: stream opened (payload = 4-byte BE initial send window)
//   0x07 OPEN_ERR - server: dial failed (payload = error byte/text)
//   0x08 WINDOW_UPDATE - server: credit N more client->upstream bytes (4-byte BE)
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

	v2TypeOpen         = 0x01
	v2TypeData         = 0x02
	v2TypeClose        = 0x03
	v2TypePing         = 0x04
	v2TypePong         = 0x05
	v2TypeOpenOK       = 0x06
	v2TypeOpenErr      = 0x07
	v2TypeWindowUpdate = 0x08

	// v2InitialWindow is the per-stream client→upstream send window the server
	// advertises in OPEN_OK. A flow-control-aware client keeps at most this many
	// bytes in flight (sent but not yet credited); the server credits more via
	// WINDOW_UPDATE as it drains to the upstream. This is what lets the proxy
	// stay TRANSPARENT for arbitrarily large uploads: the client paces itself to
	// the homeserver's real drain rate, so we hold ~window bytes in memory
	// instead of the whole 100-500 MB file, and we NEVER drop a byte. 4 MiB sits
	// well above a mobile-uplink bandwidth-delay product so the pipe stays full.
	v2InitialWindow = 4 << 20
	// v2WindowUpdateThreshold batches credits: the pump emits one WINDOW_UPDATE
	// per this many drained bytes (or when its queue empties), instead of one per
	// ~16 KB data frame, trading a little window slack for far fewer control
	// frames.
	v2WindowUpdateThreshold = v2InitialWindow / 2

	// v2SessionBufferCap / v2GlobalBufferCap are SAFETY BACKSTOPS, not the normal
	// path. With flow control a well-behaved client self-limits to v2InitialWindow
	// per stream, so a session holds at most (active uploads)x4 MiB - a few MB in
	// practice, far below these caps, and is never shed. The caps only bound a
	// client that ignores WINDOW_UPDATE (older build) or an authenticated peer
	// deliberately flooding: such a stream is shed once the budget is hit, which
	// reclaims memory without HoL-stalling the session's other streams. The
	// session cap is sized above any realistic concurrent-upload count so flow-
	// controlled clients never trip it; the global cap is the hard host-memory
	// ceiling across all sessions. Both are tunable for the deployment's RAM.
	v2SessionBufferCap = 128 << 20
	v2GlobalBufferCap  = 256 << 20
)

type v2Stream struct {
	id      uint32
	conn    net.Conn
	closing chan struct{}
	closed  atomic.Bool

	// client→upstream pending chunks held as a byte-bounded queue (not a
	// fixed-count channel) so the shared session read loop NEVER blocks on one
	// slow stream (CR-01: blocking the loop HoL-stalls every other stream
	// including PING/PONG/CLOSE) and NEVER silently drops a progressing upload
	// (the old 64-frame channel overflowed at ~1 MB and closed the stream
	// mid-upload, truncating any larger media so the recipient saw 0 bytes / no
	// MIME). The pump goroutine drains it; the read loop only sheds this stream
	// when the session/global byte budget is exceeded. cond is signalled on
	// enqueue and on close. queue/qbytes are guarded by mu.
	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte
	qbytes int64 // sum of len(queue[i]); reclaimed from the byte budgets on close
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
	buffered     atomic.Int64 // client→upstream bytes queued across all streams (vs v2SessionBufferCap)
}

// v2Sessions tracks live v2 sessions so a single reaper goroutine can close
// those silent for too long. sync.Map gives lock-free reads in the reap loop.
var v2Sessions sync.Map // int64 -> *v2Session

// v2GlobalBuffered counts client→upstream bytes queued across ALL sessions, the
// hard backstop behind each session's v2SessionBufferCap so a fleet of
// simultaneously-wedged upstreams can't exhaust host memory (v2GlobalBufferCap).
var v2GlobalBuffered atomic.Int64

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
				// The session's own buffered counter dies with the session, but
				// the process-global one must be reclaimed or it leaks upward.
				// Wake the pump so it exits instead of parking forever in Wait.
				st.mu.Lock()
				if st.qbytes > 0 {
					v2GlobalBuffered.Add(-st.qbytes)
					st.qbytes = 0
				}
				st.queue = nil
				st.cond.Broadcast()
				st.mu.Unlock()
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
		// Reclaim this stream's queued client→upstream bytes from the session
		// and global budgets, drop the buffer, and wake the pump (which may be
		// parked in cond.Wait on an empty queue) so it exits promptly.
		st.mu.Lock()
		if st.qbytes > 0 {
			s.buffered.Add(-st.qbytes)
			v2GlobalBuffered.Add(-st.qbytes)
			st.qbytes = 0
		}
		st.queue = nil
		st.cond.Broadcast()
		st.mu.Unlock()
		// CR2-01: close the upstream socket too. Without this, the
		// upstream→client reader goroutine sits in a blocking upstream.Read
		// and only checks closing AFTER the read returns — which for an idle
		// peer (HTTP keep-alive, IMAP IDLE, websocket) can be hours. Closing
		// the conn here unblocks the read with ErrClosedConn immediately, and
		// also unblocks the pump if it is parked in upstream.Write.
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
		closing: make(chan struct{}),
	}
	st.cond = sync.NewCond(&st.mu)
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
	// OPEN_OK carries the initial per-stream send window. A flow-control-aware
	// client paces its client→upstream writes to this and to the WINDOW_UPDATE
	// credits below, so the proxy never has to drop a byte of a large upload.
	// Older clients ignore the payload and rely on the buffer-cap backstop.
	var initWin [4]byte
	binary.BigEndian.PutUint32(initWin[:], uint32(v2InitialWindow))
	if err := s.writeStreamFrame(streamID, v2TypeOpenOK, initWin[:]); err != nil {
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

	// client → upstream pump: drain the byte-bounded queue and write to the
	// target. Parks in st.cond.Wait while the queue is empty (signalled by the
	// read loop's enqueue and by close), so the session read loop hands off
	// without ever blocking. On a write error we also send the peer a CLOSE so
	// the sender learns its upload failed instead of seeing bytes silently
	// vanish — the old drop path notified nothing, which is exactly how a
	// truncated upload surfaced as "0 bytes / no MIME" on the receiver.
	go func() {
		var credited int64 // bytes drained since the last WINDOW_UPDATE (batched)
		for {
			st.mu.Lock()
			for len(st.queue) == 0 && !st.closed.Load() {
				st.cond.Wait()
			}
			if st.closed.Load() {
				st.mu.Unlock()
				return
			}
			chunk := st.queue[0]
			st.queue[0] = nil // let the consumed chunk be GC'd before realloc
			st.queue = st.queue[1:]
			emptyNow := len(st.queue) == 0
			if emptyNow {
				st.queue = nil // release the backing array once fully drained
			}
			n := int64(len(chunk))
			st.qbytes -= n
			s.buffered.Add(-n)
			v2GlobalBuffered.Add(-n)
			st.mu.Unlock()
			if _, err := upstream.Write(chunk); err != nil {
				_ = s.writeStreamFrame(streamID, v2TypeClose, nil)
				upstream.Close()
				s.closeStream(streamID)
				return
			}
			// Flow control: credit the client for the bytes we just delivered so
			// it may send that much more without ever overrunning our buffer.
			// Batch to v2WindowUpdateThreshold, but always flush once the queue is
			// empty so the tail of an upload can't stall waiting on a credit the
			// threshold never reaches.
			credited += n
			if credited >= v2WindowUpdateThreshold || (emptyNow && credited > 0) {
				var wu [4]byte
				binary.BigEndian.PutUint32(wu[:], uint32(credited))
				if err := s.writeStreamFrame(streamID, v2TypeWindowUpdate, wu[:]); err != nil {
					upstream.Close()
					s.closeStream(streamID)
					return
				}
				credited = 0
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
			path := drainHTTPRequest(conn, raw)
			logInfof("[v2-%d] http probe from %s (%q); serving camouflage", id, conn.RemoteAddr(), path)
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write(camouflageForPath(path))
			return
		}
		// Non-mxtr bytes after TLS: either random garbage or a wrong-PSK
		// handshake whose MAC failed. A real nginx/Apache answers malformed
		// input with 400 Bad Request and closes -- it does NOT hang silently,
		// so the previous 60s silent hang was itself a fingerprint a prober
		// could use to tell mxtr from the CDN it claims to be. Mirror the
		// pinned family's 400 page and close. This trades the mass-scan cost
		// amplification of the old hang for camouflage consistency.
		logInfof("[v2-%d] non-mxtr bytes from %s; serving 400", id, conn.RemoteAddr())
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(renderCamouflage(pickCamouflageTemplate(), 400))
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
			plen := int64(payloadLen)
			// Hand the chunk to the per-stream pump without ever blocking the
			// shared read loop (CR-01) and without silently dropping a
			// progressing upload (the old fixed channel overflowed at ~1 MB and
			// truncated larger media). We only shed THIS stream when the
			// session-wide or global pending-byte budget would be exceeded —
			// i.e. its upstream is wedged or sustained-slower than the peer
			// sends — which reclaims memory without HoL-stalling the session's
			// other streams. The peer gets a CLOSE so the upload fails loudly.
			if sess.buffered.Load()+plen > v2SessionBufferCap || v2GlobalBuffered.Load()+plen > v2GlobalBufferCap {
				logInfof("[v2-%d] stream %d: client→upstream buffer budget reached (sess=%d global=%d); shedding stream",
					id, streamID, sess.buffered.Load(), v2GlobalBuffered.Load())
				_ = sess.writeStreamFrame(streamID, v2TypeClose, nil)
				sess.closeStream(streamID)
				continue
			}
			payloadCopy := append([]byte(nil), payload...)
			st.mu.Lock()
			if st.closed.Load() {
				st.mu.Unlock()
				continue
			}
			st.queue = append(st.queue, payloadCopy)
			st.qbytes += plen
			sess.buffered.Add(plen)
			v2GlobalBuffered.Add(plen)
			st.cond.Signal()
			st.mu.Unlock()
		case v2TypeClose:
			sess.closeStream(streamID)
		case v2TypePing:
			// Decouple PONG timing from PING arrival by 0-15ms so the
			// "every PING is matched by PONG within <1ms" tell — a strong
			// signal a flow-shape ML classifier learns to use — is broken.
			// Copy payload because the read buffer is reused on next loop.
			// Select on sess.done so a closing session unblocks the timer
			// instead of leaving an orphan goroutine sleeping its way to a
			// guaranteed-failed write.
			payloadCopy := append([]byte(nil), payload...)
			go func() {
				if d := mrand.IntN(16); d > 0 {
					select {
					case <-time.After(time.Duration(d) * time.Millisecond):
					case <-sess.done:
						return
					}
				}
				_ = sess.writeStreamFrame(0, v2TypePong, payloadCopy)
			}()
		case v2TypePong:
			// ignore
		default:
			logInfof("[v2-%d] unknown frame type 0x%02x stream %d", id, frameType, streamID)
		}
	}
}
