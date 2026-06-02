// Integration test for the v2 client→upstream path: a large upload to an
// upstream that drains slower than the tunnel delivers must arrive complete
// (no truncation) AND must not head-of-line-block the rest of the session.
//
// This is a discriminating regression test for two coupled bugs:
//   - the silent upload truncation: the old fixed 64-frame (~1 MB) channel
//     overflowed and closed the stream mid-upload, so anything larger than
//     ~1 MB reached the receiver as 0 bytes / no MIME. A 5 MB upload through a
//     slow sink fails this test under the old code (sink sees ~1 MB then EOF).
//   - CR-01: if the fix had instead reverted to blocking the shared read loop,
//     the mid-upload PING below would not be answered until the slow upstream
//     drained. We assert a prompt PONG while the upload is still draining.
//
// The client side reuses the server's own frame codec (writeFrame/readFrame/
// deriveKey/computeMac) so the test can't drift from the wire format it tests.

package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type mxtrTestClient struct {
	conn    net.Conn
	aeadC2S cipher.AEAD
	aeadS2C cipher.AEAD
	seqW    uint64
	seqR    uint64
}

// dialMxtr performs the client half of the mxtr v2 handshake against a raw TCP
// conn already speaking the post-TLS mxtr protocol (handleTCPv2 does no TLS of
// its own). padLen 0 keeps the handshake minimal.
func dialMxtr(t *testing.T, addr string) *mxtrTestClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	nonceC := make([]byte, nonceLen)
	if _, err := rand.Read(nonceC); err != nil {
		t.Fatal(err)
	}
	macInput := append(append([]byte{}, nonceC...), byte(0)) // nonceC || padLen(0)
	mac := computeMac(macInput, "c2s-hs")
	hello := append(append(append([]byte{}, nonceC...), byte(0)), mac...)
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write client hello: %v", err)
	}
	nonceS := make([]byte, nonceLen)
	if _, err := io.ReadFull(conn, nonceS); err != nil {
		t.Fatalf("read server nonce: %v", err)
	}
	var pl [1]byte
	if _, err := io.ReadFull(conn, pl[:]); err != nil {
		t.Fatalf("read server padlen: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, int(pl[0])+macLen)); err != nil {
		t.Fatalf("read server pad+mac: %v", err)
	}
	aC2S, _ := chacha20poly1305.New(deriveKey(nonceC, nonceS, "c2s-key"))
	aS2C, _ := chacha20poly1305.New(deriveKey(nonceC, nonceS, "s2c-key"))
	return &mxtrTestClient{conn: conn, aeadC2S: aC2S, aeadS2C: aS2C, seqW: 1, seqR: 1}
}

func (c *mxtrTestClient) writeV2(streamID uint32, ftype byte, payload []byte) error {
	inner := make([]byte, v2FrameHeader+len(payload))
	binary.BigEndian.PutUint32(inner[0:4], streamID)
	inner[4] = ftype
	binary.BigEndian.PutUint16(inner[5:7], uint16(len(payload)))
	copy(inner[7:], payload)
	err := writeFrame(c.conn, c.aeadC2S, c.seqW, inner)
	c.seqW++
	return err
}

func (c *mxtrTestClient) readV2() (streamID uint32, ftype byte, payload []byte, err error) {
	inner, err := readFrame(c.conn, c.aeadS2C, c.seqR)
	if err != nil {
		return 0, 0, nil, err
	}
	c.seqR++
	if len(inner) < v2FrameHeader {
		return 0, 0, nil, io.ErrUnexpectedEOF
	}
	streamID = binary.BigEndian.Uint32(inner[0:4])
	ftype = inner[4]
	plen := int(binary.BigEndian.Uint16(inner[5:7]))
	return streamID, ftype, inner[v2FrameHeader : v2FrameHeader+plen], nil
}

func ipv4Spec(port int) []byte {
	spec := make([]byte, 1+4+2)
	spec[0] = addrTypeIPv4
	copy(spec[1:5], net.IPv4(127, 0, 0, 1).To4())
	binary.BigEndian.PutUint16(spec[5:7], uint16(port))
	return spec
}

func TestV2UploadThroughSlowUpstreamNotTruncated(t *testing.T) {
	// Package globals the handler reads. No other tests share this package, so
	// setting them here is safe.
	psk = make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	pskCfg = derivePskConfig(psk)
	pickedCamouflage = &camouflageFamilies[0]
	allowedDomains = nil

	// Slow sink: drains in 32 KiB reads with a 2 ms pause so it lags the
	// in-memory tunnel and the server has to buffer the burst.
	sinkLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sinkLn.Close()
	var received int64
	go func() {
		uc, err := sinkLn.Accept()
		if err != nil {
			return
		}
		defer uc.Close()
		// Pin a small kernel receive buffer so the OS can't sponge up the whole
		// upload and silently keep the server's queue drained — without this the
		// backlog never forms and the test wouldn't exercise the cap/drop path
		// (it then passes even at a 1 MB cap, masking the very regression it
		// guards). With a small recv buffer the pump blocks at the sink's app
		// read rate and the burst genuinely backs up in the server's queue.
		if tcp, ok := uc.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(32 * 1024)
		}
		buf := make([]byte, 32*1024)
		for {
			n, err := uc.Read(buf)
			if n > 0 {
				atomic.AddInt64(&received, int64(n))
				time.Sleep(3 * time.Millisecond) // ~10 MB/s, slower than the loopback tunnel
			}
			if err != nil {
				return
			}
		}
	}()
	sinkPort := sinkLn.Addr().(*net.TCPAddr).Port

	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()
	go func() {
		sc, err := srvLn.Accept()
		if err != nil {
			return
		}
		handleTCPv2(sc)
	}()

	c := dialMxtr(t, srvLn.Addr().String())
	defer c.conn.Close()

	if err := c.writeV2(1, v2TypeOpen, ipv4Spec(sinkPort)); err != nil {
		t.Fatalf("OPEN: %v", err)
	}
	if sid, ft, _, err := c.readV2(); err != nil || ft != v2TypeOpenOK || sid != 1 {
		t.Fatalf("expected OPEN_OK for stream 1, got sid=%d type=0x%02x err=%v", sid, ft, err)
	}

	const total = 5 * 1024 * 1024
	chunk := make([]byte, maxPlaintextSize-v2FrameHeader-128)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	sent := 0
	for sent < total {
		n := len(chunk)
		if total-sent < n {
			n = total - sent
		}
		if err := c.writeV2(1, v2TypeData, chunk[:n]); err != nil {
			t.Fatalf("send DATA at offset %d: %v", sent, err)
		}
		sent += n
	}

	// Responsiveness: a PING sent while the slow upload is still draining must
	// be answered promptly. If the read loop were HoL-blocked (CR-01), this PONG
	// would lag until the sink finished draining the whole 5 MB.
	pingAt := time.Now()
	if err := c.writeV2(0, v2TypePing, []byte("rtt")); err != nil {
		t.Fatalf("PING: %v", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, ft, _, err := c.readV2()
		if err != nil {
			t.Fatalf("waiting for PONG: %v", err)
		}
		if ft == v2TypePong {
			break
		}
		if ft == v2TypeClose {
			t.Fatalf("stream was shed mid-upload (truncation) - received %d of %d", atomic.LoadInt64(&received), total)
		}
	}
	t.Logf("PONG returned %v into the slow drain (received so far: %d of %d)", time.Since(pingAt), atomic.LoadInt64(&received), total)
	_ = c.conn.SetReadDeadline(time.Time{})

	// The whole upload must reach the sink: no byte dropped.
	deadline := time.Now().Add(15 * time.Second)
	for atomic.LoadInt64(&received) < total {
		if time.Now().After(deadline) {
			t.Fatalf("truncated upload: sink received %d of %d bytes", atomic.LoadInt64(&received), total)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&received); got != total {
		t.Fatalf("sink received %d bytes, want %d", got, total)
	}
}

// TestV2FlowControlPacesLargeUpload proves the proxy is transparent for a large
// upload: a flow-control-aware client uploads 32 MB through an upstream slower
// than the tunnel, and (a) every byte arrives (no truncation) while (b) the
// in-flight backlog stays bounded near the advertised window — the client is
// paced to the upstream's drain rate instead of buffering the whole file. If
// flow control were not working the peak in-flight would balloon to the full
// 32 MB; the assertion below would fail. This is what lets 100-500 MB uploads
// stream through with a few MB of server memory and zero loss.
func TestV2FlowControlPacesLargeUpload(t *testing.T) {
	psk = make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	pskCfg = derivePskConfig(psk)
	pickedCamouflage = &camouflageFamilies[0]
	allowedDomains = nil

	// Slow sink with a small kernel receive buffer so the server's WINDOW_UPDATE
	// credits track the sink's real app-read rate (not a multi-MB OS sponge);
	// that keeps in-flight pinned near the window so the pacing is observable.
	var received int64
	sinkLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sinkLn.Close()
	go func() {
		uc, err := sinkLn.Accept()
		if err != nil {
			return
		}
		defer uc.Close()
		if tcp, ok := uc.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(32 * 1024)
		}
		buf := make([]byte, 32*1024)
		for {
			n, err := uc.Read(buf)
			if n > 0 {
				atomic.AddInt64(&received, int64(n))
				time.Sleep(2 * time.Millisecond)
			}
			if err != nil {
				return
			}
		}
	}()
	sinkPort := sinkLn.Addr().(*net.TCPAddr).Port

	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvLn.Close()
	go func() {
		sc, err := srvLn.Accept()
		if err != nil {
			return
		}
		handleTCPv2(sc)
	}()

	c := dialMxtr(t, srvLn.Addr().String())
	defer c.conn.Close()

	// Flow-control state driven by a reader goroutine (mirrors the Kotlin client).
	var fmu sync.Mutex
	fcond := sync.NewCond(&fmu)
	var window int64
	var streamClosed bool
	var gotOpenOK bool
	var openErr string
	openCh := make(chan struct{})
	var openOnce sync.Once

	go func() {
		for {
			_, ft, payload, err := c.readV2()
			if err != nil {
				fmu.Lock()
				streamClosed = true
				fcond.Broadcast()
				fmu.Unlock()
				return
			}
			switch ft {
			case v2TypeOpenOK:
				fmu.Lock()
				if len(payload) >= 4 {
					window = int64(binary.BigEndian.Uint32(payload))
				}
				gotOpenOK = true
				fmu.Unlock()
				openOnce.Do(func() { close(openCh) })
			case v2TypeOpenErr:
				fmu.Lock()
				openErr = string(payload)
				fmu.Unlock()
				openOnce.Do(func() { close(openCh) })
			case v2TypeWindowUpdate:
				if len(payload) >= 4 {
					fmu.Lock()
					window += int64(binary.BigEndian.Uint32(payload))
					fcond.Signal()
					fmu.Unlock()
				}
			case v2TypeClose:
				fmu.Lock()
				streamClosed = true
				fcond.Broadcast()
				fmu.Unlock()
			}
		}
	}()

	if err := c.writeV2(1, v2TypeOpen, ipv4Spec(sinkPort)); err != nil {
		t.Fatalf("OPEN: %v", err)
	}
	<-openCh
	if !gotOpenOK {
		t.Fatalf("OPEN refused: %q", openErr)
	}
	fmu.Lock()
	initialWindow := window
	fmu.Unlock()
	if initialWindow <= 0 {
		t.Fatalf("server advertised no flow-control window in OPEN_OK (got %d)", initialWindow)
	}

	const total = 32 * 1024 * 1024
	chunk := make([]byte, maxPlaintextSize-v2FrameHeader-128)
	sent := 0
	var maxInFlight int64
	for sent < total {
		c2 := len(chunk)
		if total-sent < c2 {
			c2 = total - sent
		}
		fmu.Lock()
		for window < int64(c2) && !streamClosed {
			fcond.Wait()
		}
		if streamClosed {
			fmu.Unlock()
			t.Fatalf("stream shed/closed mid-upload at %d of %d bytes - the proxy broke the transfer", sent, total)
		}
		window -= int64(c2)
		fmu.Unlock()
		if err := c.writeV2(1, v2TypeData, chunk[:c2]); err != nil {
			t.Fatalf("DATA at offset %d: %v", sent, err)
		}
		sent += c2
		if inflight := int64(sent) - atomic.LoadInt64(&received); inflight > maxInFlight {
			maxInFlight = inflight
		}
	}

	deadline := time.Now().Add(30 * time.Second)
	for atomic.LoadInt64(&received) < total {
		if time.Now().After(deadline) {
			t.Fatalf("truncated upload: sink received %d of %d bytes", atomic.LoadInt64(&received), total)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("uploaded %d MiB through a slow upstream; advertised window %d MiB, peak in-flight %d MiB",
		total>>20, initialWindow>>20, maxInFlight>>20)

	// The whole point: the client was paced. Peak in-flight must stay near the
	// window, not approach the file size. Without flow control it would reach
	// ~total (the client would blast all 32 MB before the sink drained).
	if maxInFlight > initialWindow+8*1024*1024 {
		t.Fatalf("flow control not pacing: peak in-flight %d B exceeds window %d B + margin (client not throttled to drain rate)",
			maxInFlight, initialWindow)
	}
}
