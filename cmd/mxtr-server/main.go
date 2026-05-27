// mxtr-server: obfuscated TCP relay with PSK-based handshake and TLS fronting.
//
// Design goals (v1.1):
//   - Indistinguishable from random noise at the byte level
//   - Variable-size handshake (no fixed-length fingerprint)
//   - Power-of-2 padded frames (hide payload sizes)
//   - Timing jitter on handshake response (no instant-reply fingerprint)
//   - Self-signed TLS wrapper with rotating plausible CN (passive DPI sees
//     "boring HTTPS server with some self-signed cert" rather than raw bytes)
//   - Probe deflection: HTTP-shape probes get a real-looking 500 page from
//     a randomly chosen webserver family, anything else hangs for ~1 minute

package main

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/http2"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	nonceLen = 16
	macLen   = 16

	addrTypeIPv4   = 1
	addrTypeDomain = 2
	addrTypeIPv6   = 3

	// Max plaintext payload per frame (before 2-byte real-len prefix and
	// padding). Capped a bit below 16K so the padded ciphertext + tag fits
	// inside the 16-bit length field on the wire.
	maxPlaintextSize = 16384 - 2
	maxPaddedSize    = 16384
	maxCiphertextLen = maxPaddedSize + 16 // poly1305 tag

	maxHandshakePad = 255 // padlen field is 1 byte
	maxTotalHandshake = nonceLen + 1 + maxHandshakePad + macLen

	// 10s is well above what a legitimate mxtr client needs (TLS + one
	// padded handshake write in a single round trip) and bounds the per-conn
	// goroutine when a probe completes TLS but sends no mxtr bytes (M2-03).
	handshakeTimeout = 10 * time.Second
	// Hard cap on concurrent TLS-accepted connections per listener. Above
	// this we refuse new accepts at the OS level (TCP backlog absorbs the
	// rest, eventually they time out). Stops trivial fd-exhaustion DoS
	// against the handshake path (M2-03).
	maxConcurrentConns = 1024
	probeHangDuration = 60 * time.Second
	dialTimeout       = 10 * time.Second
	maxHTTPHeaderRead = 8192

	jitterMinMS = 5
	jitterMaxMS = 50
)

var psk []byte

func computeMac(input []byte, label string) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(input)
	m.Write([]byte(label))
	return m.Sum(nil)[:macLen]
}

func deriveKey(nonceC, nonceS []byte, info string) []byte {
	salt := append(append([]byte{}, nonceC...), nonceS...)
	r := hkdf.New(sha256.New, psk, salt, []byte(info))
	out := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

func frameNonce(seq uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// padSizes is the ladder of allowed inner-frame sizes after padding. Inner
// frame format is [2-byte real-len BE][plaintext][random padding] sized to
// the next ladder rung that fits.
var padSizes = []int{256, 512, 1024, 2048, 4096, 8192, 16384}

func nextPadSize(n int) int {
	for _, s := range padSizes {
		if s >= n {
			return s
		}
	}
	return padSizes[len(padSizes)-1]
}

func writeFrame(w io.Writer, aead cipher.AEAD, seq uint64, pt []byte) error {
	if len(pt) > maxPlaintextSize {
		return fmt.Errorf("plaintext too large: %d", len(pt))
	}
	innerSize := nextPadSize(len(pt) + 2)
	inner := make([]byte, innerSize)
	binary.BigEndian.PutUint16(inner[:2], uint16(len(pt)))
	copy(inner[2:], pt)
	// Fill the padding region with random bytes so observed ciphertexts of
	// the same plaintext look different and the padding has no structure.
	if _, err := rand.Read(inner[2+len(pt):]); err != nil {
		return err
	}
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

func readFrame(r io.Reader, aead cipher.AEAD, seq uint64) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	clen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if clen == 0 || clen > maxCiphertextLen {
		return nil, fmt.Errorf("invalid ciphertext length %d", clen)
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
		return nil, errors.New("inner frame missing length prefix")
	}
	realLen := int(binary.BigEndian.Uint16(inner[:2]))
	if realLen > len(inner)-2 {
		return nil, fmt.Errorf("real_len %d exceeds inner %d", realLen, len(inner)-2)
	}
	return inner[2 : 2+realLen], nil
}

func parseTarget(p []byte) (string, error) {
	if len(p) < 1 {
		return "", errors.New("empty target spec")
	}
	switch p[0] {
	case addrTypeIPv4:
		if len(p) != 1+4+2 {
			return "", fmt.Errorf("ipv4 target wrong length %d", len(p))
		}
		ip := net.IP(p[1:5])
		port := binary.BigEndian.Uint16(p[5:7])
		return fmt.Sprintf("%s:%d", ip, port), nil
	case addrTypeDomain:
		if len(p) < 2 {
			return "", errors.New("domain target too short")
		}
		dlen := int(p[1])
		if len(p) != 2+dlen+2 {
			return "", fmt.Errorf("domain target wrong length")
		}
		return fmt.Sprintf("%s:%d", string(p[2:2+dlen]),
			binary.BigEndian.Uint16(p[2+dlen:2+dlen+2])), nil
	case addrTypeIPv6:
		if len(p) != 1+16+2 {
			return "", fmt.Errorf("ipv6 target wrong length %d", len(p))
		}
		ip := net.IP(p[1:17])
		port := binary.BigEndian.Uint16(p[17:19])
		return fmt.Sprintf("[%s]:%d", ip, port), nil
	default:
		return "", fmt.Errorf("unknown addr type %d", p[0])
	}
}

// Camouflage 500 templates, each mimicking a different real-world web server.
// camouflageTemplate is a structured 500 page so the same Server identity and
// body can be served over either raw HTTP/1.1 (dispatchTLSConn fallback when
// readClientHandshake doesn't see mxtr bytes) or HTTP/2 (h2 ALPN path via
// http2.Server). The Server header MUST stay consistent across both code
// paths for the run lifetime, otherwise it's a fingerprint.
type camouflageTemplate struct {
	server      string
	contentType string
	body        []byte
}

var camouflage500s = []camouflageTemplate{
	{
		server:      "nginx/1.27.4",
		contentType: "text/html",
		body: []byte("<html>\r\n<head><title>500 Internal Server Error</title></head>\r\n" +
			"<body>\r\n<center><h1>500 Internal Server Error</h1></center>\r\n" +
			"<hr><center>nginx/1.27.4</center>\r\n</body>\r\n</html>\r\n"),
	},
	{
		server:      "Apache/2.4.62 (Ubuntu)",
		contentType: "text/html; charset=iso-8859-1",
		body: []byte("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n" +
			"<html><head>\n<title>500 Internal Server Error</title>\n</head><body>\n" +
			"<h1>Internal Server Error</h1>\n<p>The server encountered an internal error or\n" +
			"misconfiguration and was unable to complete\nyour request.</p>\n" +
			"<p>Please contact the server administrator at \n" +
			" webmaster@localhost to inform them of the time this error occurred,\n" +
			" and the actions you performed just before this error.</p>\n" +
			"<p>More information about this error may be available\nin the server error log.</p>\n" +
			"<hr>\n<address>Apache/2.4.62 (Ubuntu) Server at localhost Port 443</address>\n" +
			"</body></html>\n"),
	},
	{
		server:      "LiteSpeed",
		contentType: "text/html",
		body: []byte("<html><head><title>500 Internal Server Error</title></head>\n" +
			"<body><h1>Internal Server Error</h1>\n<p>Server error.</p>\n</body></html>\n"),
	},
}

// pickedCamouflage is chosen once at startup so a real server's behaviour is
// mimicked: the Server: header must stay consistent across requests, otherwise
// it's a give-away that the 500 page is faked. Set by main() before serving.
var pickedCamouflage *camouflageTemplate

func pickCamouflageTemplate() *camouflageTemplate {
	if pickedCamouflage == nil {
		pickedCamouflage = &camouflage500s[0]
	}
	return pickedCamouflage
}

// pickCamouflage returns the full HTTP/1.1 response bytes (status line + headers
// + body) using the pinned template. Used when readClientHandshake detects
// an HTTP/1.1 probe and writes raw bytes back to the TLS conn.
func pickCamouflage() []byte {
	t := pickCamouflageTemplate()
	// Date header for fingerprint parity with the h2 path (M2-05): net/http's
	// http2.Server auto-adds Date on every response. Real nginx/Apache/LiteSpeed
	// also always include it. Missing Date in just the h1 path is a DPI tell.
	date := time.Now().UTC().Format(time.RFC1123)
	resp := []byte("HTTP/1.1 500 Internal Server Error\r\n" +
		"Server: " + t.server + "\r\n" +
		"Date: " + date + "\r\n" +
		"Content-Type: " + t.contentType + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(t.body)) + "\r\n" +
		"Connection: close\r\n" +
		"\r\n")
	return append(resp, t.body...)
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST"), []byte("HEAD"),
	[]byte("PUT "), []byte("DELE"), []byte("OPTI"),
	[]byte("CONN"), []byte("PATC"), []byte("TRAC"),
}

func looksLikeHTTP(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	for _, m := range httpMethods {
		if len(buf) >= len(m) && string(buf[:len(m)]) == string(m) {
			return true
		}
	}
	return false
}

func drainHTTPRequest(conn net.Conn, prefix []byte) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var s int
	for _, b := range prefix {
		switch b {
		case '\r':
			if s == 0 || s == 2 {
				s++
			} else {
				s = 1
			}
		case '\n':
			if s == 1 || s == 3 {
				s++
				if s == 4 {
					return
				}
			} else {
				s = 0
			}
		default:
			s = 0
		}
	}
	one := make([]byte, 1)
	read := len(prefix)
	for read < maxHTTPHeaderRead {
		n, err := conn.Read(one)
		if err != nil || n == 0 {
			return
		}
		read++
		switch one[0] {
		case '\r':
			if s == 0 || s == 2 {
				s++
			} else {
				s = 1
			}
		case '\n':
			if s == 1 || s == 3 {
				s++
				if s == 4 {
					return
				}
			} else {
				s = 0
			}
		default:
			s = 0
		}
	}
}

// readClientHandshake reads the variable-length client handshake from conn:
//   [nonceLen nonce_c][1 padlen][padlen padding][macLen HMAC]
// HMAC is computed over (nonce_c || padlen || padding) with label "c2s-hs".
// Returns the nonce on success, plus the bytes already consumed for fallback
// probe-deflection logic.
func readClientHandshake(conn net.Conn) (nonceC []byte, raw []byte, err error) {
	// Short-circuit HTTP/1.1 probes after just 4 bytes so the 500 fallback
	// path doesn't block on a 30s ReadFull waiting for the rest of a padded
	// mxtr handshake that's never coming. Real mxtr clients send `nonceLen+1`
	// bytes in one write so the second ReadFull below sees them immediately.
	prefix := make([]byte, 4)
	if _, err = io.ReadFull(conn, prefix); err != nil {
		return nil, prefix, err
	}
	if looksLikeHTTP(prefix) {
		return nil, prefix, errors.New("http probe")
	}
	rest1 := make([]byte, nonceLen+1-4)
	if _, err = io.ReadFull(conn, rest1); err != nil {
		return nil, append(prefix, rest1...), err
	}
	first := append(prefix, rest1...)
	padLen := int(first[nonceLen])
	rest := make([]byte, padLen+macLen)
	if _, err = io.ReadFull(conn, rest); err != nil {
		return nil, append(first, rest...), err
	}
	pad := rest[:padLen]
	gotMac := rest[padLen:]
	macInput := make([]byte, 0, nonceLen+1+padLen)
	macInput = append(macInput, first[:nonceLen]...)
	macInput = append(macInput, first[nonceLen])
	macInput = append(macInput, pad...)
	wantMac := computeMac(macInput, "c2s-hs")
	if !hmac.Equal(gotMac, wantMac) {
		return nil, append(first, rest...), errors.New("hmac mismatch")
	}
	return first[:nonceLen], nil, nil
}

func writeServerHandshake(conn net.Conn) (nonceS []byte, err error) {
	nonceS = make([]byte, nonceLen)
	if _, err = rand.Read(nonceS); err != nil {
		return nil, err
	}
	padLen := mrand.IntN(maxHandshakePad + 1)
	pad := make([]byte, padLen)
	if _, err = rand.Read(pad); err != nil {
		return nil, err
	}
	macInput := make([]byte, 0, nonceLen+1+padLen)
	macInput = append(macInput, nonceS...)
	macInput = append(macInput, byte(padLen))
	macInput = append(macInput, pad...)
	mac := computeMac(macInput, "s2c-hs")
	hello := make([]byte, 0, nonceLen+1+padLen+macLen)
	hello = append(hello, nonceS...)
	hello = append(hello, byte(padLen))
	hello = append(hello, pad...)
	hello = append(hello, mac...)
	if _, err = conn.Write(hello); err != nil {
		return nil, err
	}
	return nonceS, nil
}

var connCounter int64


// generateSelfSignedCert builds a fresh ECDSA P-256 cert at startup with a
// plausible-looking Subject from a pool of CDN-style hostnames. A passive
// observer sees an HTTPS server presenting some self-signed cert for a CDN
// edge - common enough on the open internet that it doesn't scream "proxy".
func generateSelfSignedCert() (tls.Certificate, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cnPool := []string{
		"edge-fra-04.cdn-cf.net",
		"node-sg2.bunnycdn.com",
		"front-1.lb.cloudfront.net",
		"cdn02.akamaiedge.net",
		"edge-london.fastly.net",
		"lb-tokyo-3.cdn77.org",
		"node07.gcdn.net",
		"pop-nyc-1.stackpath.cdn",
		"edge-pa1.kxcdn.com",
		"front-amsterdam.cdnetworks.com",
	}
	orgPool := []string{
		"Edge Networks, Ltd.", "BunnyCDN s.r.o.", "Internet Services Inc.",
		"Cloud Distribution AG", "Hyperion CDN GmbH", "CDN Solutions LLC",
	}
	cn := cnPool[mrand.IntN(len(cnPool))]
	org := orgPool[mrand.IntN(len(orgPool))]

	serial, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	// rand.Int returns [0, max); RFC 5280 forbids serial=0. Shift to [1, max].
	serial.Add(serial, big.NewInt(1))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:    time.Now().Add(-7 * 24 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, cn, nil
}

// loadedCert is non-nil when the operator provides -cert/-key flags. When set,
// every runTCP listener reuses the loaded certificate (real LE/CA-signed) and
// skips self-signed generation. Otherwise each listener generates a fresh
// self-signed cert at startup with a rotating CDN-style CN.
var loadedCert *tls.Certificate
var loadedCertName string

func runTCP(addr string, handler func(net.Conn), label string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen tcp %s: %v", addr, err)
	}
	var cert tls.Certificate
	var cn string
	if loadedCert != nil {
		cert = *loadedCert
		cn = loadedCertName
	} else {
		var err error
		cert, cn, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("generate self-signed cert: %v", err)
		}
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.3 only: this is what modern CloudFront/Cloudflare/Fastly edges
		// negotiate by default in 2025+. Drops the entire TLS-1.2 cipher
		// configuration surface (Go ignores CipherSuites/PreferServerCipherSuites
		// on 1.3 anyway) and produces a minimal, clean ServerHello with no
		// legacy extensions. Smaller fingerprint surface for DPI to match.
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		// Per-PSK ALPN ordering — see pskDerivedConfig.alpnOrder. Both "h2"
		// and "http/1.1" are always offered; the order is shuffled per PSK so
		// different deployments don't share an identical ServerHello ALPN
		// extension payload. Kotlin mxtr client sends no ALPN extension so
		// server falls through to "" for those conns; dispatchTLSConn routes.
		NextProtos: pskCfg.alpnOrder,
		// Modern CDN posture: Cloudflare disables session tickets by default
		// since 2018 to provide forward secrecy. Matching that here both
		// shrinks our SH and adds a tiny bit of PFS for free.
		SessionTicketsDisabled: true,
	}
	tlsLn := tls.NewListener(ln, tlsConfig)
	logInfof("%s TCP+TLS listening on %s (self-signed cert for %q)", label, addr, cn)
	// Bounded semaphore (M2-03): caps concurrent in-flight TLS handshakes /
	// mxtr handshakes so a probe storm can't exhaust goroutines/fds.
	gate := make(chan struct{}, maxConcurrentConns)
	for {
		c, err := tlsLn.Accept()
		if err != nil {
			logInfof("%s accept: %v", label, err)
			continue
		}
		select {
		case gate <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-gate }()
				dispatchTLSConn(c, handler, label)
			}(c)
		default:
			// At capacity; reject newcomers fast rather than queuing.
			_ = c.Close()
			logWarnf("%s accept saturated (%d in flight); dropping", label, maxConcurrentConns)
		}
	}
}

// dispatchTLSConn forces the TLS handshake so we can inspect the negotiated
// ALPN before deciding what to do with the bytes that follow. mxtr clients do
// not advertise ALPN, so the server-side selection ends up empty for them and
// we hand the raw byte stream to the mxtr handler. Browsers will pick "h2" out
// of our offered list and we feed those conns into a real http2.Server that
// answers with the pinned 500 camouflage — no protocol error, just a normal
// "this server is having a bad day" page.
func dispatchTLSConn(c net.Conn, mxtrHandler func(net.Conn), label string) {
	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		mxtrHandler(c)
		return
	}
	if err := tlsConn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		tlsConn.Close()
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		// Bad TLS / scanner / port probe -- silently drop.
		tlsConn.Close()
		return
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return
	}
	switch tlsConn.ConnectionState().NegotiatedProtocol {
	case "h2":
		serveH2Camouflage(tlsConn, label)
	default:
		mxtrHandler(tlsConn)
	}
}

// camouflageHTTPHandler answers every request with the pinned 500 template.
// Used by both the per-connection http2.Server and any future http.Server use.
var camouflageHTTPHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	t := pickCamouflageTemplate()
	w.Header().Set("Server", t.server)
	w.Header().Set("Content-Type", t.contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(t.body)))
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(t.body)
})

// h2Server is reused across all conns so we don't allocate one per request.
// MaxConcurrentStreams=10 mimics a small backend; IdleTimeout cleans up
// browsers that hold the connection open after seeing the 500.
var h2Server = &http2.Server{
	MaxConcurrentStreams: 10,
	// IdleTimeout bounds gap between requests; the conn-wide deadline below
	// bounds total time. Real CDNs cut probes that don't ask for anything
	// useful well below 30s.
	IdleTimeout: 15 * time.Second,
}

// h2CamouflageHardDeadline bounds total time spent serving any single
// camouflage probe (L2-02). h2Server.ServeConn would otherwise honour MaxConcurrentStreams=10
// indefinitely if the attacker keeps pipelining requests.
const h2CamouflageHardDeadline = 30 * time.Second

func serveH2Camouflage(tlsConn *tls.Conn, label string) {
	logInfof("%s h2 probe from %s; serving 500", label, tlsConn.RemoteAddr())
	_ = tlsConn.SetDeadline(time.Now().Add(h2CamouflageHardDeadline))
	h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: camouflageHTTPHandler,
	})
	_ = tlsConn.Close()
}


func main() {
	var (
		tcpAddr    = flag.String("tcp", ":9290", "TCP listen address (empty to disable)")
		pskHex     = flag.String("psk", "", "PSK as hex string (16+ bytes = 32+ hex chars)")
		certPath   = flag.String("cert", "", "path to TLS cert (PEM); if empty, fresh self-signed cert with rotating CN is generated per-startup")
		keyPath    = flag.String("key", "", "path to TLS private key (PEM); required if -cert is set")
		genPSK     = flag.Bool("gen-psk", false, "generate a random 32-byte PSK and exit")
		logLevel   = flag.String("log-level", "info", "log verbosity: off|error|warn|info|debug")
		quiet      = flag.Bool("quiet", false, "shorthand for -log-level=off")
		publicHost = flag.String("public-host", "", "public hostname or IP printed in share-strings at startup")
		allowList  = flag.String("allow", "", "comma-separated allowlist of target domains (subdomains auto-included; empty = allow all)")
	)
	flag.Parse()
	allowedDomains = parseAllowList(*allowList)
	if len(allowedDomains) > 0 {
		logInfof("target allowlist: %v", allowedDomains)
	}

	chosen, err := parseLogLevel(*logLevel)
	if err != nil {
		log.Fatal(err)
	}
	if *quiet {
		chosen = LogOff
	}
	configureLogger(chosen)

	if *genPSK {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(key))
		return
	}

	if *pskHex == "" {
		*pskHex = os.Getenv("MXTR_PSK")
	}
	if *pskHex == "" {
		log.Fatal("PSK required: -psk <hex> or env MXTR_PSK; use -gen-psk to generate")
	}

	p, err := hex.DecodeString(*pskHex)
	if err != nil {
		log.Fatalf("bad PSK hex: %v", err)
	}
	if len(p) < 16 {
		log.Fatal("PSK must be at least 16 bytes (32 hex chars)")
	}
	psk = p

	// Derive per-PSK fingerprint knobs (camouflage family, ALPN order,
	// heartbeat cadence). This pins the same fingerprint for the lifetime of
	// this PSK, while different PSKs produce different fingerprints so a DPI
	// vendor cannot match all mxtr deployments with one regex.
	pskCfg = derivePskConfig(psk)
	pickedCamouflage = &camouflage500s[pskCfg.camouflageIdx]
	logInfof("PSK-derived: camouflage=%s alpn=%v heartbeat=%d-%dms idle=%dms",
		pickedCamouflage.server, pskCfg.alpnOrder,
		pskCfg.heartbeatMinMs, pskCfg.heartbeatMaxMs, pskCfg.idleThresholdMs)

	// Optional: load a real CA-signed cert (e.g. Let's Encrypt). When absent
	// each listener generates a self-signed cert with a plausible CDN CN.
	if *certPath != "" {
		if *keyPath == "" {
			log.Fatal("-cert provided but -key missing")
		}
		c, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			log.Fatalf("load cert: %v", err)
		}
		loadedCert = &c
		// Surface the actual CN from the leaf for logging.
		if len(c.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
				loadedCertName = leaf.Subject.CommonName
				logInfof("loaded real TLS cert for %q (NotAfter=%s)", loadedCertName, leaf.NotAfter.Format(time.RFC3339))
			}
		}
		if loadedCertName == "" {
			loadedCertName = "real-cert"
		}
	}

	host := *publicHost
	if host == "" {
		host = "<YOUR-PUBLIC-HOST>"
	}
	if *tcpAddr != "" {
		// Route through logInfof so -quiet (=LogOff) suppresses the PSK
		// from stderr (L2-03). Anyone who needs the share-string can set
		// -log-level=info or higher when generating it the first time.
		logInfof("share-string: %s", buildShareString(host, *tcpAddr))
		go runTCP(*tcpAddr, handleTCPv2, "tcp")
		go reapV2Sessions()
	}

	select {}
}
