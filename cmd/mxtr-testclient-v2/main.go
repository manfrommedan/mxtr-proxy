// mxtr-testclient-v2: command-line client that speaks mxtr v2 (stream
// multiplexed) protocol. Useful for local e2e testing without an Android
// device, and as a stand-alone SOCKS5 relay for power users.
//
// Modes:
//
//	-method socks5     local SOCKS5 server (RFC 1928, no auth, CONNECT only)
//	-method https      one-shot HTTPS GET against -target host:port
//	-method http       one-shot HTTP  GET against -target host:port
//
// Examples:
//
//	./mxtr-testclient-v2 -server 127.0.0.1:9290 -psk <hex> -socks-addr :1984 -method socks5
//	curl --socks5-hostname 127.0.0.1:1984 https://matrix.org/_matrix/client/versions
//
//	./mxtr-testclient-v2 -server 127.0.0.1:9290 -psk <hex> -target matrix.org:443 -method https
//
// All cryptography matches mxtr-server v2 (ChaCha20-Poly1305 inside outer
// TLS, variable handshake padding, power-of-2 frame padding, HMAC-SHA256
// auth, HKDF-SHA256 key derivation).

package main

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	nonceLen           = 16
	macLen             = 16
	maxHandshakePad    = 255
	maxPlaintext       = 16384 - 2
	maxPadded          = 16384
	maxCiphertext      = maxPadded + 16
	frameHeader        = 7
	maxStreamPayloadV2 = maxPlaintext - frameHeader

	typeOpen         byte = 0x01
	typeData         byte = 0x02
	typeClose        byte = 0x03
	typePing         byte = 0x04
	typePong         byte = 0x05
	typeOpenOK       byte = 0x06
	typeOpenErr      byte = 0x07
	typeWindowUpdate byte = 0x08
)

// padSizes mirrors mxtr-server's PADME-style 13-rung ladder. Both ends pad
// independently — wire only carries encrypted ct length — but matching the
// ladder keeps the testclient's send fingerprint in line with the Kotlin
// client. Old 7-rung ladder is intentionally NOT kept; the server-side
// reader accepts any padded inner length up to maxCiphertext, so wire-compat
// is unaffected, only fingerprint posture changes.
var padSizes = []int{256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384}

func nextPadSize(n int) int {
	for _, s := range padSizes {
		if s >= n {
			return s
		}
	}
	return padSizes[len(padSizes)-1]
}

// bumpProbability + pickPadRung mirror mxtr-server's size-scaled distribution
// smoother. Small signaling frames blend bucket counts where it matters
// most; large frames don't pay extra bandwidth for marginal diversity.
func bumpProbability(minSize int) int {
	switch {
	case minSize < 1024:
		return 30
	case minSize < 4096:
		return 18
	default:
		return 8
	}
}

func pickPadRung(minSize int) int {
	base := nextPadSize(minSize)
	if mrand.IntN(100) >= bumpProbability(minSize) {
		return base
	}
	for i, s := range padSizes {
		if s == base && i+1 < len(padSizes) {
			return padSizes[i+1]
		}
	}
	return base
}

// isIPLiteral mirrors mxtr-server: refuses hostnames so the testclient never
// triggers DNS for the mxtr endpoint. SNI carries no real hostname either
// (cert is self-signed CDN-style CN), so no DNS leak in any path.
func isIPLiteral(s string) bool {
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	return net.ParseIP(s) != nil
}

// --- share-string parser, mirrors Kotlin MxtrShareString.parse ---

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base58")
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == b58Alphabet[0] {
		zeros++
	}
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(b58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("bad base58 char %q", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	out := n.Bytes()
	return append(make([]byte, zeros), out...), nil
}

type shareData struct {
	host   string
	port   int
	pskHex string
	// sni is the optional hostname clients should present in the outer TLS
	// ClientHello so SNI matches the cert Subject the server emits. Empty
	// means "use the host string as SNI" — fine for IP-literal hosts when
	// no real cert is in play. Comes from ?sni= query in the share-string.
	sni string
}

func parseShareString(s string) (*shareData, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "mxtr://") {
		return nil, errors.New("share-string must start with mxtr://")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "mxtr" {
		return nil, errors.New("scheme not mxtr")
	}
	if u.User == nil {
		return nil, errors.New("share-string missing PSK (mxtr://<psk>@<ip>:<port>)")
	}
	pskB58 := u.User.Username()
	if pskB58 == "" {
		return nil, errors.New("empty PSK")
	}
	if _, password := u.User.Password(); password {
		return nil, errors.New("share-string userInfo must not contain ':'")
	}
	pskBytes, err := base58Decode(pskB58)
	if err != nil {
		return nil, fmt.Errorf("decode PSK: %w", err)
	}
	if len(pskBytes) != 32 {
		return nil, fmt.Errorf("PSK must be 32 bytes; got %d", len(pskBytes))
	}
	host := u.Hostname()
	if !isIPLiteral(host) {
		return nil, fmt.Errorf("share-string host must be IP literal (no DNS); got %q", host)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", u.Port())
	}
	sni := u.Query().Get("sni")
	if sni != "" && net.ParseIP(sni) != nil {
		return nil, errors.New("?sni= must be a hostname, not an IP")
	}
	return &shareData{
		host:   host,
		port:   port,
		pskHex: hex.EncodeToString(pskBytes),
		sni:    sni,
	}, nil
}

// --- crypto helpers (mirror server) ---

func computeMac(psk, input []byte, label string) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(input)
	m.Write([]byte(label))
	return m.Sum(nil)[:macLen]
}

func deriveKey(psk, nonceC, nonceS []byte, info string) []byte {
	salt := append(append([]byte{}, nonceC...), nonceS...)
	r := hkdf.New(sha256.New, psk, salt, []byte(info))
	out := make([]byte, chacha20poly1305.KeySize)
	// hkdf.New never returns a short read in current x/crypto; on impl
	// drift we'd silently use a zero-padded key here. Panic instead — the
	// only path leading here is a programmer error.
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf read: " + err.Error())
	}
	return out
}

func frameNonce(seq uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

func writeAEADFrame(w io.Writer, aead cipher.AEAD, seq uint64, pt []byte) error {
	if len(pt) > maxPlaintext {
		return fmt.Errorf("plaintext too large %d", len(pt))
	}
	innerSize := pickPadRung(len(pt) + 2)
	inner := make([]byte, innerSize)
	binary.BigEndian.PutUint16(inner[:2], uint16(len(pt)))
	copy(inner[2:], pt)
	rand.Read(inner[2+len(pt):])
	nonce := frameNonce(seq)
	ct := aead.Seal(nil, nonce[:], inner, nil)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(ct)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(ct)
	return err
}

func readAEADFrame(r io.Reader, aead cipher.AEAD, seq uint64) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	clen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if clen == 0 || clen > maxCiphertext {
		return nil, fmt.Errorf("bad ciphertext len %d", clen)
	}
	ct := make([]byte, clen)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, err
	}
	nonce := frameNonce(seq)
	inner, err := aead.Open(nil, nonce[:], ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt seq %d: %w", seq, err)
	}
	if len(inner) < 2 {
		return nil, errors.New("inner too small")
	}
	real := int(binary.BigEndian.Uint16(inner[:2]))
	if real > len(inner)-2 {
		return nil, fmt.Errorf("real %d > inner %d", real, len(inner)-2)
	}
	return inner[2 : 2+real], nil
}

// --- session & stream ---

type stream struct {
	id           uint32
	incoming     chan []byte
	openOK       chan struct{}
	openErr      chan string
	closed       atomic.Bool
	closeMu      sync.Mutex // serialises closed-set + channel-close, gates deliver
	pendingChunk []byte
	pendingPos   int

	// client->upstream send window (flow control), mirrors the Kotlin client:
	// the server advertises the initial value in OPEN_OK and tops it up with
	// WINDOW_UPDATE frames as it drains to the upstream. acquireWindow blocks
	// sends once it is exhausted, so a large upload paces to the upstream's
	// rate and never overruns the proxy. flowControlled stays false against an
	// older server (empty OPEN_OK), preserving the prior unbounded-send path.
	winMu          sync.Mutex
	winCond        *sync.Cond
	sendWindow     int64
	flowControlled bool
}

// deliver hands a frame payload to the reader side under closeMu so a racing
// session.close() can't `close(incoming)` between our `closed` check and our
// send (CR-04). Returns false if the stream is already closed.
func (st *stream) deliver(payload []byte) bool {
	st.closeMu.Lock()
	defer st.closeMu.Unlock()
	if st.closed.Load() {
		return false
	}
	st.incoming <- payload
	return true
}

// markClosed flips the closed flag and closes the incoming channel atomically
// w.r.t. deliver(). Returns false if already closed.
func (st *stream) markClosed() bool {
	st.closeMu.Lock()
	defer st.closeMu.Unlock()
	if !st.closed.CompareAndSwap(false, true) {
		return false
	}
	close(st.incoming)
	// Wake any writer blocked on the send window so it errors out instead of
	// hanging when the stream/session goes away.
	if st.winCond != nil {
		st.winMu.Lock()
		st.winCond.Broadcast()
		st.winMu.Unlock()
	}
	return true
}

// acquireWindow blocks until the send window has room for n bytes, the server
// credits it (WINDOW_UPDATE), or the stream closes. No-op when the server
// advertised no window (older build), so behaviour there is unchanged.
func (st *stream) acquireWindow(n int) error {
	st.winMu.Lock()
	defer st.winMu.Unlock()
	if !st.flowControlled {
		return nil
	}
	for st.sendWindow < int64(n) {
		if st.closed.Load() {
			return errors.New("stream closed while awaiting send window")
		}
		st.winCond.Wait()
	}
	st.sendWindow -= int64(n)
	return nil
}

type session struct {
	conn     net.Conn
	aeadC2S  cipher.AEAD
	aeadS2C  cipher.AEAD
	seqRead  uint64
	seqWrite uint64
	writeMu  sync.Mutex
	streams  sync.Map // uint32 -> *stream
	nextID   uint32
	closed   atomic.Bool
}

func dialSession(serverHost string, serverPort int, psk []byte, sni string) (*session, error) {
	if !isIPLiteral(serverHost) {
		return nil, fmt.Errorf("mxtr server must be IP literal (no DNS); got %q", serverHost)
	}
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(serverHost, strconv.Itoa(serverPort)), 10*time.Second)
	if err != nil {
		return nil, err
	}
	// ServerName in tls.Config drives the SNI value sent in ClientHello.
	// When the share-string carries ?sni=<hostname>, present that name so a
	// passive observer sees an HTTPS handshake to a normal hostname — even
	// though our TCP connect is by IP literal and skipped DNS. ServerName=""
	// (no sni in share-string) makes tls.Client send SNI=IP-literal/empty
	// per RFC, which is a tell — set explicitly to the host IP only as a
	// fallback so we never accidentally emit a hostname we didn't intend.
	serverName := sni
	if serverName == "" {
		serverName = serverHost
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		// Pin TLS 1.3 to match the real Kotlin client's fingerprint posture
		// (WR-03). Server (main.go) already enforces 1.3 only so MinVersion=1.2
		// was dead config that misleads readers.
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		raw.Close()
		return nil, fmt.Errorf("outer tls: %w", err)
	}
	conn := net.Conn(tlsConn)

	nonceC := make([]byte, nonceLen)
	rand.Read(nonceC)
	padLen := mrand.IntN(maxHandshakePad + 1)
	pad := make([]byte, padLen)
	rand.Read(pad)
	macIn := make([]byte, 0, nonceLen+1+padLen)
	macIn = append(macIn, nonceC...)
	macIn = append(macIn, byte(padLen))
	macIn = append(macIn, pad...)
	mac := computeMac(psk, macIn, "c2s-hs")
	hello := append(append(append([]byte{}, nonceC...), byte(padLen)), pad...)
	hello = append(hello, mac...)
	if _, err := conn.Write(hello); err != nil {
		conn.Close()
		return nil, err
	}

	first := make([]byte, nonceLen+1)
	if _, err := io.ReadFull(conn, first); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read server hello head: %w", err)
	}
	nonceS := first[:nonceLen]
	srvPadLen := int(first[nonceLen])
	rest := make([]byte, srvPadLen+macLen)
	if _, err := io.ReadFull(conn, rest); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read server hello body: %w", err)
	}
	srvPad := rest[:srvPadLen]
	srvMacGot := rest[srvPadLen:]
	srvMacIn := make([]byte, 0, nonceLen+1+srvPadLen)
	srvMacIn = append(srvMacIn, nonceS...)
	srvMacIn = append(srvMacIn, byte(srvPadLen))
	srvMacIn = append(srvMacIn, srvPad...)
	srvMacWant := computeMac(psk, srvMacIn, "s2c-hs")
	if !hmac.Equal(srvMacGot, srvMacWant) {
		conn.Close()
		return nil, errors.New("server hello mac mismatch")
	}

	keyC2S := deriveKey(psk, nonceC, nonceS, "c2s-key")
	keyS2C := deriveKey(psk, nonceC, nonceS, "s2c-key")
	aeadC2S, _ := chacha20poly1305.New(keyC2S)
	aeadS2C, _ := chacha20poly1305.New(keyS2C)

	s := &session{
		conn:     conn,
		aeadC2S:  aeadC2S,
		aeadS2C:  aeadS2C,
		seqRead:  1,
		seqWrite: 1,
		nextID:   1,
	}
	go s.readLoop()
	return s, nil
}

func (s *session) writeStreamFrame(sid uint32, t byte, payload []byte) error {
	if len(payload) > maxStreamPayloadV2 {
		return fmt.Errorf("payload too large: %d", len(payload))
	}
	inner := make([]byte, frameHeader+len(payload))
	binary.BigEndian.PutUint32(inner[0:4], sid)
	inner[4] = t
	binary.BigEndian.PutUint16(inner[5:7], uint16(len(payload)))
	copy(inner[7:], payload)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return errors.New("session closed")
	}
	if err := writeAEADFrame(s.conn, s.aeadC2S, s.seqWrite, inner); err != nil {
		return err
	}
	s.seqWrite++
	return nil
}

func (s *session) readLoop() {
	defer s.close()
	for {
		pt, err := readAEADFrame(s.conn, s.aeadS2C, s.seqRead)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("session reader: %v", err)
			}
			return
		}
		s.seqRead++
		if len(pt) < frameHeader {
			return
		}
		sid := binary.BigEndian.Uint32(pt[0:4])
		t := pt[4]
		pln := int(binary.BigEndian.Uint16(pt[5:7]))
		if pln > len(pt)-frameHeader {
			return
		}
		payload := pt[frameHeader : frameHeader+pln]
		v, ok := s.streams.Load(sid)
		var st *stream
		if ok {
			st = v.(*stream)
		}
		switch t {
		case typeOpenOK:
			if st != nil {
				// OPEN_OK from a flow-control-aware server carries the 4-byte
				// initial send window; older servers send an empty payload.
				if len(payload) >= 4 {
					st.winMu.Lock()
					st.sendWindow = int64(binary.BigEndian.Uint32(payload))
					st.flowControlled = true
					st.winMu.Unlock()
				}
				select {
				case st.openOK <- struct{}{}:
				default:
				}
			}
		case typeOpenErr:
			if st != nil {
				select {
				case st.openErr <- string(payload):
				default:
				}
			}
		case typeData:
			if st != nil {
				cp := append([]byte(nil), payload...)
				st.deliver(cp)
			}
		case typeWindowUpdate:
			if st != nil && len(payload) >= 4 {
				st.winMu.Lock()
				st.sendWindow += int64(binary.BigEndian.Uint32(payload))
				st.winCond.Broadcast()
				st.winMu.Unlock()
			}
		case typeClose:
			if st != nil {
				st.markClosed()
				s.streams.Delete(sid)
			}
		case typePing:
			_ = s.writeStreamFrame(0, typePong, payload)
		case typePong:
		default:
		}
	}
}

func (s *session) open(targetHost string, targetPort int) (*stream, error) {
	sid := atomic.AddUint32(&s.nextID, 2) - 2
	st := &stream{
		id:       sid,
		incoming: make(chan []byte, 32),
		openOK:   make(chan struct{}, 1),
		openErr:  make(chan string, 1),
	}
	st.winCond = sync.NewCond(&st.winMu)
	s.streams.Store(sid, st)

	hb := []byte(targetHost)
	if len(hb) > 255 {
		return nil, errors.New("target host too long")
	}
	target := make([]byte, 0, 1+1+len(hb)+2)
	target = append(target, 2) // domain
	target = append(target, byte(len(hb)))
	target = append(target, hb...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(targetPort))
	target = append(target, pb[:]...)

	if err := s.writeStreamFrame(sid, typeOpen, target); err != nil {
		s.streams.Delete(sid)
		return nil, err
	}

	select {
	case <-st.openOK:
		return st, nil
	case msg := <-st.openErr:
		s.streams.Delete(sid)
		return nil, fmt.Errorf("server refused stream open: %s", msg)
	case <-time.After(15 * time.Second):
		s.streams.Delete(sid)
		return nil, errors.New("open stream timeout")
	}
}

func (s *session) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.streams.Range(func(k, v any) bool {
		v.(*stream).markClosed()
		return true
	})
	s.conn.Close()
}

// stream io.ReadWriteCloser
func (st *stream) Read(p []byte) (int, error) {
	if st.pendingChunk == nil {
		chunk, ok := <-st.incoming
		if !ok {
			return 0, io.EOF
		}
		st.pendingChunk = chunk
		st.pendingPos = 0
	}
	n := copy(p, st.pendingChunk[st.pendingPos:])
	st.pendingPos += n
	if st.pendingPos >= len(st.pendingChunk) {
		st.pendingChunk = nil
		st.pendingPos = 0
	}
	return n, nil
}

// --- SOCKS5 server ---

func runSocks5(sess *session, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 listening on %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleSocks5(sess, c)
	}
}

func handleSocks5(sess *session, c net.Conn) {
	defer c.Close()

	// Greeting: [ver=5][nmethods][methods...]
	buf := make([]byte, 257)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	if buf[0] != 5 {
		return
	}
	n := int(buf[1])
	if _, err := io.ReadFull(c, buf[:n]); err != nil {
		return
	}
	// Reply: [ver=5][method=0 (no auth)]
	c.Write([]byte{5, 0})

	// Request: [ver=5][cmd][rsv=0][atyp][addr][port]
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	if buf[0] != 5 || buf[1] != 1 { // CONNECT only
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch buf[3] {
	case 1: // IPv4
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3: // domain
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	case 4: // IPv6
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(buf[:2]))

	st, err := sess.open(host, port)
	if err != nil {
		log.Printf("socks open %s:%d: %v", host, port, err)
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	// Bridge bidirectional. Stream writes go via sess.writeStreamFrame in chunks.
	go func() {
		bbuf := make([]byte, 16*1024)
		for {
			n, err := c.Read(bbuf)
			if n > 0 {
				offset := 0
				for offset < n {
					chunk := n - offset
					if chunk > maxStreamPayloadV2 {
						chunk = maxStreamPayloadV2
					}
					if werr := st.acquireWindow(chunk); werr != nil {
						break
					}
					if werr := sess.writeStreamFrame(st.id, typeData, bbuf[offset:offset+chunk]); werr != nil {
						break
					}
					offset += chunk
				}
			}
			if err != nil {
				sess.writeStreamFrame(st.id, typeClose, nil)
				return
			}
		}
	}()
	io.Copy(c, st)
}

// --- one-shot HTTP/HTTPS modes ---

func runHTTPOnce(sess *session, target string, useTLS bool) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	st, err := sess.open(host, port)
	if err != nil {
		return err
	}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: mxtr-testclient-v2\r\n\r\n", host)
	var w io.Writer
	var r io.Reader = st
	if useTLS {
		tc := tls.Client(&streamConn{st: st, sess: sess}, &tls.Config{ServerName: host, InsecureSkipVerify: false})
		if err := tc.Handshake(); err != nil {
			return fmt.Errorf("inner tls: %w", err)
		}
		w = tc
		r = tc
	} else {
		w = &streamWriter{st: st, sess: sess}
	}
	if _, err := w.Write([]byte(req)); err != nil {
		return err
	}
	io.Copy(os.Stdout, r)
	return nil
}

type streamWriter struct {
	st   *stream
	sess *session
}

func (w *streamWriter) Write(p []byte) (int, error) {
	off := 0
	for off < len(p) {
		chunk := len(p) - off
		if chunk > maxStreamPayloadV2 {
			chunk = maxStreamPayloadV2
		}
		if err := w.st.acquireWindow(chunk); err != nil {
			return off, err
		}
		if err := w.sess.writeStreamFrame(w.st.id, typeData, p[off:off+chunk]); err != nil {
			return off, err
		}
		off += chunk
	}
	return off, nil
}

type streamConn struct {
	st   *stream
	sess *session
}

func (c *streamConn) Read(p []byte) (int, error) { return c.st.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) {
	return (&streamWriter{st: c.st, sess: c.sess}).Write(p)
}
func (c *streamConn) Close() error                       { c.sess.writeStreamFrame(c.st.id, typeClose, nil); return nil }
func (c *streamConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *streamConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *streamConn) SetDeadline(t time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }

// --- main ---

func main() {
	share := flag.String("share", "", "mxtr share-string (mxtr://<base58-psk>@<ip>:<port>); preferred input — overrides -server/-psk")
	server := flag.String("server", "", "mxtr v2 server IP:port (only used when -share is empty)")
	pskHex := flag.String("psk", "", "PSK as hex (or env MXTR_PSK); only used when -share is empty")
	pskFile := flag.String("psk-file", "", "path to PSK file written by mxtr-server (e.g. ./mxtr-psk.hex); used when -psk and MXTR_PSK are unset")
	method := flag.String("method", "socks5", "socks5 | http | https")
	target := flag.String("target", "matrix.org:443", "target for http/https mode")
	socksAddr := flag.String("socks-addr", "127.0.0.1:1984", "local SOCKS5 listen for socks5 mode (override with any free port)")
	flag.Parse()

	var (
		host string
		port int
		psk  []byte
		sni  string
	)
	if *share != "" {
		sd, err := parseShareString(*share)
		if err != nil {
			log.Fatalf("bad share-string: %v", err)
		}
		host = sd.host
		port = sd.port
		sni = sd.sni
		psk, _ = hex.DecodeString(sd.pskHex)
	} else {
		if *server == "" {
			log.Fatal("need -share <mxtr://...> OR -server <ip:port> + (-psk|-psk-file|env MXTR_PSK)")
		}
		h, portStr, err := net.SplitHostPort(*server)
		if err != nil {
			log.Fatalf("bad -server: %v", err)
		}
		host = h
		port, err = strconv.Atoi(portStr)
		if err != nil {
			log.Fatalf("bad port in -server: %v", err)
		}
		if *pskHex == "" {
			*pskHex = os.Getenv("MXTR_PSK")
		}
		if *pskHex == "" && *pskFile != "" {
			data, err := os.ReadFile(*pskFile)
			if err != nil {
				log.Fatalf("read -psk-file %s: %v", *pskFile, err)
			}
			*pskHex = strings.TrimSpace(string(data))
		}
		if *pskHex == "" {
			log.Fatal("PSK required: -psk, env MXTR_PSK, or -psk-file")
		}
		psk, err = hex.DecodeString(*pskHex)
		if err != nil {
			log.Fatalf("bad PSK hex: %v", err)
		}
		if len(psk) < 16 {
			log.Fatalf("PSK must be at least 16 bytes; got %d", len(psk))
		}
	}

	sess, err := dialSession(host, port, psk, sni)
	if err != nil {
		log.Fatalf("session: %v", err)
	}
	if sni != "" {
		log.Printf("session established to %s:%d (SNI=%s)", host, port, sni)
	} else {
		log.Printf("session established to %s:%d (no SNI)", host, port)
	}

	switch *method {
	case "socks5":
		if err := runSocks5(sess, *socksAddr); err != nil {
			log.Fatal(err)
		}
	case "http":
		if err := runHTTPOnce(sess, *target, false); err != nil {
			log.Fatal(err)
		}
	case "https":
		if err := runHTTPOnce(sess, *target, true); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown method %s", *method)
	}
}
