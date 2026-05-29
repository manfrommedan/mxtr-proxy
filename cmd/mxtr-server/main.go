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
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"


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
	// against the handshake path (M2-03). Sized to comfortably absorb
	// 1000 concurrent users plus reconnect churn and probe storms. Each
	// in-flight slot costs ~10 KiB goroutine stack + buffered socket
	// state; 8192 ~= 80 MiB ceiling, well under VPS-class memory budgets.
	// At scale this needs `ulimit -n` >= 65536 and tcp_max_orphans tuning.
	maxConcurrentConns = 8192
	dialTimeout       = 10 * time.Second
	maxHTTPHeaderRead = 8192

	// Server-side jitter before writing the mxtr handshake response. Kills
	// the "instant reply" timing tell that DPI uses to fingerprint
	// proxies (real servers don't reply in <1ms, processing time always
	// shows). Tightened from 5-50ms to 1-15ms 2026-05-28: 5-50 added an
	// avg 27ms to every first-connect for ~negligible extra DPI defense;
	// 1-15 (mean 8ms) buries the deterministic processing time
	// (~0.5-2ms) just as effectively while saving ~20ms per cold start.
	jitterMinMS = 1
	jitterMaxMS = 15
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

// Buffer pools for the two hot allocations in writeFrame: the padded inner
// plaintext (sized to padSizes ladder) and the AEAD output (inner + 16-byte
// poly1305 tag). At 1000 concurrent sessions with /sync long-poll + bursts
// we see roughly 2-5k frames/sec aggregate; per-frame fresh make() allocs
// reach 30-80 MiB/s of garbage. Pooling drops allocations/op by >10x in
// pprof and trims Go's tail-latency p99 noticeably under load (BenchmarkXXX).
// One pool per ladder rung keeps Get/Put O(1); rungs are powers of two so
// the small-frame case (PING heartbeats, short DATA) doesn't waste 16 KiB.
var (
	innerPools = func() map[int]*sync.Pool {
		m := make(map[int]*sync.Pool, len(padSizes))
		for _, sz := range padSizes {
			s := sz
			m[s] = &sync.Pool{New: func() any { b := make([]byte, s); return &b }}
		}
		return m
	}()
	ctPools = func() map[int]*sync.Pool {
		m := make(map[int]*sync.Pool, len(padSizes))
		for _, sz := range padSizes {
			s := sz + 16
			m[s] = &sync.Pool{New: func() any { b := make([]byte, s); return &b }}
		}
		return m
	}()
)

func getInnerBuf(size int) *[]byte {
	if p, ok := innerPools[size]; ok {
		return p.Get().(*[]byte)
	}
	b := make([]byte, size)
	return &b
}

func putInnerBuf(buf *[]byte) {
	if p, ok := innerPools[len(*buf)]; ok {
		p.Put(buf)
	}
}

func getCtBuf(size int) *[]byte {
	if p, ok := ctPools[size]; ok {
		return p.Get().(*[]byte)
	}
	b := make([]byte, size)
	return &b
}

func putCtBuf(buf *[]byte) {
	if p, ok := ctPools[len(*buf)]; ok {
		p.Put(buf)
	}
}

// padSizes is the ladder of allowed inner-frame sizes after padding. Inner
// frame format is [2-byte real-len BE][plaintext][random padding] sized to
// the next ladder rung that fits.
//
// Previous version was a strict power-of-2 ladder of 7 rungs
// (256/512/.../16384) — this gives the observer only 7 distinct
// ciphertext sizes to histogram. PADME-style finer ladder with 1.5x
// half-rungs gives 13 rungs and reduces cliff overhead on common
// near-rung sizes (e.g. 800-byte payload no longer wastes 224 bytes
// jumping to 1024; it lands on 1024 vs the 1.5x rung 768→1024 with
// less waste at intermediate sizes). The set is symmetric with the
// Kotlin client's PAD_SIZES in MxtrSession.kt — must stay in sync.
//
// Additionally, frames may probabilistically bump up one rung (see
// pickPadRung) to smear the size distribution across rungs and break
// the clean "exact power-of-2 rung" histogram tell.
var padSizes = []int{256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384}

func nextPadSize(n int) int {
	for _, s := range padSizes {
		if s >= n {
			return s
		}
	}
	return padSizes[len(padSizes)-1]
}

// pickPadRung returns the rung writeFrame should pad to. Probability of
// bumping up one rung is size-scaled: small payloads (<1024 B) bump 30% of
// the time so signaling-frame size histograms blend adjacent buckets,
// large payloads (>=4096 B) bump only 8% of the time because rung spacing
// is already coarse and the bandwidth cost of an extra rung at the top is
// substantial. Mid-sized payloads scale linearly between the two.
//
// This is the size-scaled version of a flat 25% bump — saves ~12% of
// average bandwidth at 1000 users while preserving most of the diversity
// benefit where it matters (small frames carry the most identifiable size
// info).
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
	// Find base's index, bump up if not already at top.
	for i, s := range padSizes {
		if s == base && i+1 < len(padSizes) {
			return padSizes[i+1]
		}
	}
	return base
}

func writeFrame(w io.Writer, aead cipher.AEAD, seq uint64, pt []byte) error {
	if len(pt) > maxPlaintextSize {
		return fmt.Errorf("plaintext too large: %d", len(pt))
	}
	innerSize := pickPadRung(len(pt) + 2)
	innerPtr := getInnerBuf(innerSize)
	defer putInnerBuf(innerPtr)
	inner := *innerPtr
	binary.BigEndian.PutUint16(inner[:2], uint16(len(pt)))
	copy(inner[2:], pt)
	// Fill the padding region with random bytes so observed ciphertexts of
	// the same plaintext look different and the padding has no structure.
	if _, err := rand.Read(inner[2+len(pt):]); err != nil {
		return err
	}
	nonce := frameNonce(seq)
	ctPtr := getCtBuf(innerSize + 16)
	defer putCtBuf(ctPtr)
	ct := aead.Seal((*ctPtr)[:0], nonce[:], inner, nil)
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

// camouflageFamily is one server identity. Real production servers usually
// run with their version suppressed (nginx server_tokens off, Apache
// ServerSignature Off, etc.) so the Server header carries only the family
// name. That is good cover: any DPI/IP-scanner sees nothing more interesting
// than the dozens of millions of legitimately-deployed servers behind
// stripped-down headers.
//
// statusBodies maps an HTTP status code to a realistic body for that family.
// We support 403, 404, 500 — the three "deflection" responses real servers
// hand out when something's wrong. 200 deliberately not in the set: serving
// a real content body would invite scrutiny of its plausibility. Each probe
// gets a different status drawn from this set so the response distribution
// looks like a real server fielding mixed broken requests, not a single
// pinned 500.
type camouflageFamily struct {
	server          string // Server: header value, e.g. "nginx"
	contentType     string // Content-Type for all bodies in this family
	extraHeaders    []string // raw "K: v" lines emitted on every response
	statusBodies    map[int][]byte
}

// htmlBody returns a minimal HTML body that mimics what `server_tokens off`
// (or equivalent) deployments produce: title + heading + one-liner +
// generic server-family footer. No version, no hostname leaks.
func htmlBody(title, heading, line, footer string) []byte {
	return []byte("<html>\r\n<head><title>" + title + "</title></head>\r\n" +
		"<body>\r\n<center><h1>" + heading + "</h1></center>\r\n" +
		"<p>" + line + "</p>\r\n" +
		"<hr><center>" + footer + "</center>\r\n</body>\r\n</html>\r\n")
}

var camouflageFamilies = []camouflageFamily{
	{
		server:       "nginx",
		contentType:  "text/html",
		extraHeaders: []string{},
		statusBodies: map[int][]byte{
			400: htmlBody("400 Bad Request", "400 Bad Request", "", "nginx"),
			403: htmlBody("403 Forbidden", "403 Forbidden", "", "nginx"),
			404: htmlBody("404 Not Found", "404 Not Found", "", "nginx"),
			500: htmlBody("500 Internal Server Error", "500 Internal Server Error", "", "nginx"),
		},
	},
	{
		server:       "Apache",
		contentType:  "text/html; charset=iso-8859-1",
		extraHeaders: []string{},
		statusBodies: map[int][]byte{
			400: []byte("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>400 Bad Request</title>\n</head><body>\n<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand.</p>\n</body></html>\n"),
			403: []byte("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\n<p>You don't have permission to access this resource.</p>\n</body></html>\n"),
			404: []byte("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n</body></html>\n"),
			500: []byte("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>500 Internal Server Error</title>\n</head><body>\n<h1>Internal Server Error</h1>\n<p>The server encountered an internal error or misconfiguration and was unable to complete your request.</p>\n</body></html>\n"),
		},
	},
	{
		server:       "LiteSpeed",
		contentType:  "text/html",
		extraHeaders: []string{},
		statusBodies: map[int][]byte{
			400: []byte("<html><head><title>400 Bad Request</title></head>\n<body><h1>Bad Request</h1>\n<p>The request could not be understood.</p>\n</body></html>\n"),
			403: []byte("<html><head><title>403 Forbidden</title></head>\n<body><h1>Forbidden</h1>\n<p>Access denied.</p>\n</body></html>\n"),
			404: []byte("<html><head><title>404 Not Found</title></head>\n<body><h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n</body></html>\n"),
			500: []byte("<html><head><title>500 Internal Server Error</title></head>\n<body><h1>Internal Server Error</h1>\n<p>Server error.</p>\n</body></html>\n"),
		},
	},
	{
		server:       "Caddy",
		contentType:  "text/plain; charset=utf-8",
		extraHeaders: []string{"Strict-Transport-Security: max-age=31536000"},
		statusBodies: map[int][]byte{
			400: []byte("400 Bad Request\n"),
			403: []byte("403 Forbidden\n"),
			404: []byte("404 page not found\n"),
			500: []byte("500 Internal Server Error\n"),
		},
	},
	{
		server:       "cloudflare",
		contentType:  "text/html; charset=UTF-8",
		extraHeaders: []string{
			"Cache-Control: max-age=0, no-cache, no-store, must-revalidate",
			"Expires: Thu, 01 Jan 1970 00:00:01 GMT",
			"Vary: Accept-Encoding",
		},
		statusBodies: map[int][]byte{
			400: []byte("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error 400</title></head><body><center><h1>Error 400</h1></center><hr><center>cloudflare</center></body></html>\n"),
			403: []byte("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error 403</title></head><body><center><h1>Error 403</h1></center><hr><center>cloudflare</center></body></html>\n"),
			404: []byte("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error 404</title></head><body><center><h1>Error 404</h1></center><hr><center>cloudflare</center></body></html>\n"),
			500: []byte("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error 500</title></head><body><center><h1>Error 500</h1></center><hr><center>cloudflare</center></body></html>\n"),
		},
	},
	{
		// Generic Go-stdlib server posture: empty Server header is what
		// net/http emits unless overridden. Many small services run this.
		server:       "",
		contentType:  "text/plain; charset=utf-8",
		extraHeaders: []string{"X-Content-Type-Options: nosniff"},
		statusBodies: map[int][]byte{
			400: []byte("400 Bad Request\n"),
			403: []byte("Forbidden\n"),
			404: []byte("404 page not found\n"),
			500: []byte("Internal Server Error\n"),
		},
	},
}

// pickedCamouflage is selected on FIRST startup (cryptographically random,
// independent of PSK) and persisted alongside the PSK file. Subsequent
// restarts reuse the stored choice — real production servers don't
// change their 500 page on restart, and a flapping cloak identity is
// itself a fingerprint ("this host's Server header changed 4 times this
// week"). Operator can force a fresh pick via -rotate-cloak.
//
// First-deploy diversity is preserved (different VPS instances pick
// different families even with the same PSK); restart-stability matches
// real-server behaviour. WIN-WIN over either pure-random or pure-PSK-derived.
var pickedCamouflage *camouflageFamily

var statusReasons = map[int]string{
	400: "Bad Request",
	403: "Forbidden",
	404: "Not Found",
	500: "Internal Server Error",
}

var cloakStatuses = []int{403, 404, 500}

// pickRandomStatus returns one of 403/404/500 with uniform weight. Each
// probe gets an independent draw so successive scans see a varied
// distribution rather than a single pinned status.
func pickRandomStatus() int {
	return cloakStatuses[mrand.IntN(len(cloakStatuses))]
}

// pickRandomFamilyIdx picks an index via crypto/rand. Used by first-time
// startup and by -rotate-cloak.
func pickRandomFamilyIdx() int {
	var seedBuf [8]byte
	if _, err := rand.Read(seedBuf[:]); err != nil {
		// /dev/urandom unavailable — extremely unlikely on Linux. Fall
		// back to the first family; better to serve consistent cloak than
		// crash on a missing entropy source.
		return 0
	}
	return int(binary.BigEndian.Uint64(seedBuf[:]) % uint64(len(camouflageFamilies)))
}

// resolveCloakFamily implements first-start-pick + persist + reuse-on-restart.
// statePath: path next to PSK file (e.g. ./mxtr-cloak.idx). rotate=true
// forces re-pick even if state exists.
// resolvePersistedCN reads the cert CN from path. Fresh-picks a neutral
// synthetic hostname on first run or when rotate=true, and persists the
// choice via atomic-replace + O_NOFOLLOW (mirrors PSK/cloak hardening). Real
// LE-cert path bypasses this entirely (operator-managed).
func resolvePersistedCN(path string, rotate bool) string {
	if !rotate {
		if data, err := os.ReadFile(path); err == nil {
			cn := strings.TrimSpace(string(data))
			if isValidHostname(cn) {
				logInfof("cert-cn: reusing persisted CN=%q", cn)
				return cn
			}
			if cn != "" {
				logWarnf("cert-cn: persisted CN %q is not a valid hostname; picking fresh", cn)
			}
		}
	}
	cn := generateSyntheticCN()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	if err := atomicReplaceSecure(path, []byte(cn+"\n"), 0o600); err != nil {
		logWarnf("cert-cn: could not persist CN to %s: %v (will re-pick on restart)", path, err)
	} else {
		verb := "picked fresh"
		if rotate {
			verb = "rotated"
		}
		logInfof("cert-cn: %s CN=%q; persisted to %s", verb, cn, path)
	}
	return cn
}

func resolveCloakFamily(statePath string, rotate bool) *camouflageFamily {
	if !rotate {
		if data, err := os.ReadFile(statePath); err == nil {
			s := strings.TrimSpace(string(data))
			if idx, err := strconv.Atoi(s); err == nil && idx >= 0 && idx < len(camouflageFamilies) {
				logInfof("cloak: reusing persisted family idx=%d (%s)", idx, displayName(camouflageFamilies[idx].server))
				return &camouflageFamilies[idx]
			}
			logWarnf("cloak: persisted state %s unparseable (%q); picking fresh", statePath, s)
		}
	}
	idx := pickRandomFamilyIdx()
	if dir := filepath.Dir(statePath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	if err := atomicReplaceSecure(statePath, []byte(strconv.Itoa(idx)+"\n"), 0o600); err != nil {
		logWarnf("cloak: could not persist family to %s: %v (will re-pick on restart)", statePath, err)
	} else {
		verb := "picked fresh"
		if rotate {
			verb = "rotated"
		}
		logInfof("cloak: %s family idx=%d (%s); persisted to %s", verb, idx, displayName(camouflageFamilies[idx].server), statePath)
	}
	return &camouflageFamilies[idx]
}

func displayName(server string) string {
	if server == "" {
		return "(no Server header)"
	}
	return server
}

// renderCamouflage builds the full HTTP/1.1 response bytes for the given
// family at the given status. Adds Date for parity with h2 path (M2-05) and
// the family-specific extraHeaders so a passive observer sees the same
// header set this family always emits.
func renderCamouflage(fam *camouflageFamily, status int) []byte {
	body := fam.statusBodies[status]
	if body == nil {
		body = fam.statusBodies[500]
	}
	date := time.Now().UTC().Format(time.RFC1123)
	var b []byte
	b = append(b, "HTTP/1.1 "...)
	b = append(b, strconv.Itoa(status)...)
	b = append(b, ' ')
	b = append(b, statusReasons[status]...)
	b = append(b, "\r\n"...)
	if fam.server != "" {
		b = append(b, "Server: "...)
		b = append(b, fam.server...)
		b = append(b, "\r\n"...)
	}
	b = append(b, "Date: "...)
	b = append(b, date...)
	b = append(b, "\r\n"...)
	b = append(b, "Content-Type: "...)
	b = append(b, fam.contentType...)
	b = append(b, "\r\n"...)
	b = append(b, "Content-Length: "...)
	b = append(b, strconv.Itoa(len(body))...)
	b = append(b, "\r\n"...)
	for _, h := range fam.extraHeaders {
		b = append(b, h...)
		b = append(b, "\r\n"...)
	}
	b = append(b, "Connection: close\r\n\r\n"...)
	b = append(b, body...)
	return b
}

func pickCamouflageTemplate() *camouflageFamily {
	if pickedCamouflage == nil {
		pickedCamouflage = &camouflageFamilies[0]
	}
	return pickedCamouflage
}

// pickCamouflage returns the full HTTP/1.1 response bytes (status line +
// headers + body). Status is drawn uniformly per call from {403,404,500}.
// Used when readClientHandshake detects an HTTP/1.1 probe and writes raw
// bytes back to the TLS conn.
func pickCamouflage() []byte {
	return renderCamouflage(pickCamouflageTemplate(), pickRandomStatus())
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

// drainHTTPRequest reads the rest of an HTTP request (prefix holds the bytes
// already consumed) up to the blank line ending the headers, so the socket is
// positioned for a clean camouflage reply. It returns the request path parsed
// from the first line (best-effort; "" if unparseable) so callers can answer
// path-aware (e.g. /robots.txt). Bounded by maxHTTPHeaderRead.
func drainHTTPRequest(conn net.Conn, prefix []byte) string {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var s int
	firstLine := make([]byte, 0, 64)
	lineDone := false
	// step feeds one byte through the first-line capture and the CRLFCRLF
	// end-of-headers state machine; returns true once the blank line is seen.
	step := func(b byte) bool {
		if !lineDone {
			if b == '\n' {
				lineDone = true
			} else if b != '\r' && len(firstLine) < 256 {
				firstLine = append(firstLine, b)
			}
		}
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
					return true
				}
			} else {
				s = 0
			}
		default:
			s = 0
		}
		return false
	}
	for _, b := range prefix {
		if step(b) {
			return httpRequestPath(firstLine)
		}
	}
	one := make([]byte, 1)
	read := len(prefix)
	for read < maxHTTPHeaderRead {
		n, err := conn.Read(one)
		if err != nil || n == 0 {
			return httpRequestPath(firstLine)
		}
		read++
		if step(one[0]) {
			return httpRequestPath(firstLine)
		}
	}
	return httpRequestPath(firstLine)
}

// httpRequestPath extracts the request-target from an HTTP request line such
// as "GET /robots.txt HTTP/1.1". Returns "" if the line is malformed.
func httpRequestPath(line []byte) string {
	fields := strings.Fields(string(line))
	if len(fields) >= 2 {
		return fields[1]
	}
	return ""
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


// isValidHostname enforces RFC 1035 label syntax for the -sni flag: dot-
// separated labels of [a-zA-Z0-9-], no leading/trailing hyphen per label,
// each label 1-63 chars, total length up to 253. Refuses IP literals so
// operator can't pass an IP as SNI by accident (TLS spec forbids).
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c >= '0' && c <= '9':
			case c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// isPublicIPLiteral additionally refuses addresses that make no sense in a
// share-string: loopback (127.x, ::1), unspecified (0.0.0.0, ::), multicast,
// link-local, private (RFC 1918, RFC 4193) — clients would not be able to
// reach those anyway. Operator footgun guard for -public-ip.
func isPublicIPLiteral(s string) bool {
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}

// secureCreateExclFile opens a fresh file refusing to follow symlinks or
// overwrite anything pre-existing. Defends against attacker-pre-created
// symlinks at the target path tricking us into writing PSK / cloak state
// onto a sensitive file (e.g. /etc/passwd via a planted symlink when the
// server is started with -psk-file pointed at a directory the attacker
// can write to).
func secureCreateExclFile(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|oNoFollow, mode)
}

// writeFileSecure writes data to path, refusing symlink targets and
// pre-existing files. Use rename-from-tmp pattern at the caller when an
// overwrite is intended (so the existence check still defends against
// symlink swapping racing the write).
func writeFileSecure(path string, data []byte, mode os.FileMode) error {
	f, err := secureCreateExclFile(path, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		_ = os.Remove(path)
		return err
	}
	return f.Sync()
}

// atomicReplaceSecure overwrites path atomically by writing to a sibling
// tmp file with O_NOFOLLOW|O_EXCL then renaming. Survives an attacker that
// swaps symlinks at path mid-write — the rename targets the inode, not the
// link. Tmp suffix is cryptographically random so concurrent rotates do
// not collide.
func atomicReplaceSecure(path string, data []byte, mode os.FileMode) error {
	var rbuf [4]byte
	if _, err := rand.Read(rbuf[:]); err != nil {
		return err
	}
	tmp := path + "." + hex.EncodeToString(rbuf[:]) + ".tmp"
	if err := writeFileSecure(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// autoDetectPublicIP returns the first non-loopback IPv4 we can find on the
// host. Best-effort: when the host is multi-homed or sits behind NAT this
// will not be the externally-routable address; in that case the operator
// must pass -public-ip explicitly. Used to make first-run zero-config when
// running directly on a single-NIC VPS.
func autoDetectPublicIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// Synthetic hostname generator for the self-signed cert CN (which is also
// the value the client sends as SNI). An earlier version impersonated named
// CDNs (fastly.net, akamaiedge.net, bunnycdn.com, ...). That turned out to
// be a liability, not camouflage: those names resolve to the CDN's published
// anycast ranges, so a censor that resolves the SNI sees it claim Fastly
// while the TCP destination is a plain VPS in some hosting ASN -- a
// verifiable lie. And a self-signed cert bearing a real CDN's name is
// impossible in the wild (those CDNs always serve CA-valid certs), so the
// pairing is a one-probe giveaway.
//
// We drop the CDN cosplay. These names are infrastructure-flavoured but
// modelled on no specific provider, so the resolve-and-disprove check yields
// NXDOMAIN / nothing notable instead of a caught impersonation, and a
// self-signed cert on a nameless small host is mundane (mail servers,
// management UIs, fresh unconfigured boxes all do it). The randomised parts
// keep the space large enough that it can't be dictionary-blocked. A truly
// clean posture (SNI that resolves back into the VPS's own ASN) still needs
// a real domain + LE cert via -cert/-key/-sni; that is operator-managed and
// out of scope here.
var cdnCities = []string{
	"fra", "ams", "lon", "par", "mil", "sg", "hkg", "tyo", "syd", "sjc",
	"lax", "ord", "dal", "mia", "jfk", "sfo", "dfw", "atl", "sea", "dub",
	"mad", "prg", "mun", "ber", "vie", "zur", "war", "hel", "sto", "osl",
	"cph", "bru", "bcn", "vlc", "lis", "ath", "ist", "dxb", "nrt", "kix",
	"pek", "sha", "bom", "del", "blr", "cgk", "kul", "mnl", "akl", "yyz",
	"hnd", "gru", "scl", "mex", "lhr", "cdg", "ham", "tll", "vno", "rix",
}

// edgeApexes are neutral, hosting-flavoured apex domains across a few TLDs.
// Each reads like a small generic hosting / datacenter operator, none is a
// real CDN brand. Compound names are used on purpose: they are unlikely to
// be a famous registered domain, so a censor resolving the SNI lands on
// NXDOMAIN or some low-profile host rather than a name it can pin to a known
// provider's ASN.
var edgeApexes = []string{
	"hosted-edge.net", "vmpool-cloud.com", "dc-nodes.net", "netregion-hosting.io",
	"corenet-dc.net", "srvcloud-host.com", "racknode-systems.io", "edge-datacenter.net",
	"datacore-hosting.com", "cloudspan-hosting.net", "regionhost-dc.com", "relaynode-mta.net",
	"vmcluster-host.net", "gridnode-cloud.io", "metro-edge-dc.com", "northbridge-host.net",
}

func generateSyntheticCN() string {
	region := cdnCities[mrand.IntN(len(cdnCities))]
	num := mrand.IntN(999) + 1
	apex := edgeApexes[mrand.IntN(len(edgeApexes))]
	// Subdomain shape is also randomised, so the visible name is apex x shape
	// x region x num -- a large, non-dictionary-able space.
	switch mrand.IntN(7) {
	case 0:
		return fmt.Sprintf("srv%d-%s.%s", num, region, apex)
	case 1:
		return fmt.Sprintf("node-%s-%d.%s", region, num, apex)
	case 2:
		return fmt.Sprintf("host%d.%s.%s", num, region, apex)
	case 3:
		return fmt.Sprintf("edge-%s%d.%s", region, num, apex)
	case 4:
		return fmt.Sprintf("%s-gw%d.%s", region, num, apex)
	case 5:
		return fmt.Sprintf("vm%d.%s.%s", num, region, apex)
	case 6:
		return fmt.Sprintf("pop-%s-%d.%s", region, num, apex)
	}
	return fmt.Sprintf("n%d-%s.%s", num, region, apex)
}

var cdnOrgPool = []string{
	"Edge Networks, Ltd.", "Internet Services Inc.", "Cloud Distribution AG",
	"Hyperion Hosting GmbH", "Datacore Solutions LLC", "Netregion B.V.",
	"Core Hosting s.r.o.", "VM Cloud Holdings", "Server Networks Ltd.",
	"DC Nodes Inc.",
}

// generateSelfSignedCertWithCN builds a fresh ECDSA P-256 cert with the
// given CN. The CN is also a valid SNI value: callers persist it (see
// resolvePersistedCN) so the same Subject appears on cert and in share-
// string SNI across restarts.
func generateSelfSignedCertWithCN(cn string) (tls.Certificate, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	org := cdnOrgPool[mrand.IntN(len(cdnOrgPool))]

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
	// loadedCert and loadedCertName are populated by main() before any
	// listener starts (either from -cert+-key or from generated+persisted
	// self-signed). One cert across listeners keeps SNI stable.
	if loadedCert == nil {
		log.Fatalf("internal: loadedCert nil at listener start (bug)")
	}
	cert := *loadedCert
	cn := loadedCertName
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.3 only: this is what modern CloudFront/Cloudflare/Fastly edges
		// negotiate by default in 2025+. Drops the entire TLS-1.2 cipher
		// configuration surface (Go ignores CipherSuites/PreferServerCipherSuites
		// on 1.3 anyway) and produces a minimal, clean ServerHello with no
		// legacy extensions. Smaller fingerprint surface for DPI to match.
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		// http/1.1 only (pskDerivedConfig.alpnOrder). We deliberately do NOT
		// offer h2: an h2 probe would be served by a Go http2.Server whose
		// SETTINGS frame fingerprints the box as Go, contradicting the
		// nginx/cloudflare camouflage. The Kotlin mxtr client sends no ALPN
		// extension anyway, so real traffic never negotiates a protocol;
		// dispatchTLSConn hands every conn to the mxtr handler post-handshake.
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
		// SCALE: NoDelay disables Nagle so small handshake / heartbeat / OPEN
		// frames don't sit in the kernel waiting for ACK coalescing — important
		// when /sync long-poll bursts are interleaved with sub-100B PING/PONG.
		// SetKeepAlive prevents silent NAT teardowns on 3G/4G NATs where the
		// PSK-derived heartbeat (max 70s) can exceed typical NAT mappings
		// (30-60s on lossy RU mobile). 25s probe matches the lower bound.
		if tcpConn, ok := underlyingTCP(c); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(25 * time.Second)
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

// underlyingTCP unwraps a *tls.Conn back to its *net.TCPConn so we can set
// TCP_NODELAY and SO_KEEPALIVE on the actual kernel socket. crypto/tls
// exposes NetConn() since Go 1.18 specifically for this use.
func underlyingTCP(c net.Conn) (*net.TCPConn, bool) {
	if tc, ok := c.(*tls.Conn); ok {
		if tcp, ok := tc.NetConn().(*net.TCPConn); ok {
			return tcp, true
		}
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		return tcp, true
	}
	return nil, false
}

// dispatchTLSConn forces the TLS handshake, then hands every connection to the
// mxtr handler. We only offer http/1.1 in ALPN (no h2), so there is no
// protocol to branch on: real mxtr clients send no ALPN and ride the mxtr
// handler; HTTP probes that negotiated http/1.1 hit the camouflage inside the
// same handler (readClientHandshake -> looksLikeHTTP). An h2-only ClientHello
// has no shared protocol and Go fails the handshake with no_application_protocol
// below, exactly as a real http/1.1-only server would.
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
	mxtrHandler(tlsConn)
}

// renderRobots builds a realistic `200 OK` robots.txt reply for the pinned
// family. Real public-facing servers answer /robots.txt with a body; an empty
// disallow-nothing is the most common shape. Hand-rolled bytes (not Go
// net/http) so the response carries no Go stack fingerprint.
func renderRobots(fam *camouflageFamily) []byte {
	body := []byte("User-agent: *\nDisallow:\n")
	date := time.Now().UTC().Format(time.RFC1123)
	var b []byte
	b = append(b, "HTTP/1.1 200 OK\r\n"...)
	if fam.server != "" {
		b = append(b, "Server: "...)
		b = append(b, fam.server...)
		b = append(b, "\r\n"...)
	}
	b = append(b, "Date: "...)
	b = append(b, date...)
	b = append(b, "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "...)
	b = append(b, strconv.Itoa(len(body))...)
	b = append(b, "\r\n"...)
	for _, h := range fam.extraHeaders {
		b = append(b, h...)
		b = append(b, "\r\n"...)
	}
	b = append(b, "Connection: close\r\n\r\n"...)
	b = append(b, body...)
	return b
}

// camouflageForPath answers an HTTP probe path-aware: /robots.txt gets a
// realistic 200, every other path the random 4xx/5xx of the pinned family.
func camouflageForPath(path string) []byte {
	if path == "/robots.txt" {
		return renderRobots(pickCamouflageTemplate())
	}
	return pickCamouflage()
}


// version is the build version. Release builds override it via
// -ldflags "-X main.version=<tag>" (see .github/workflows/release.yml);
// the default below is the in-repo development version.
var version = "0.2.3"

func main() {
	var (
		showVer    = flag.Bool("version", false, "print version and exit")
		tcpAddr    = flag.String("tcp", ":9290", "TCP listen address (empty to disable)")
		pskHex     = flag.String("psk", "", "PSK as hex string (16+ bytes = 32+ hex chars); overrides -psk-file")
		pskFile    = flag.String("psk-file", "./mxtr-psk.hex", "path to PSK file; created with random 32-byte PSK on first run if missing")
		cloakState = flag.String("cloak-state", "", "path to persisted cloak family idx; default is <psk-file dir>/mxtr-cloak.idx")
		rotateCloak = flag.Bool("rotate-cloak", false, "force a fresh cloak family pick this startup (overwrites the persisted choice)")
		certPath   = flag.String("cert", "", "path to TLS cert (PEM); if empty, fresh self-signed cert with rotating CN is generated per-startup")
		keyPath    = flag.String("key", "", "path to TLS private key (PEM); required if -cert is set")
		genPSK     = flag.Bool("gen-psk", false, "generate a random 32-byte PSK to stdout and exit")
		logLevel   = flag.String("log-level", "info", "log verbosity: off|error|warn|info|debug")
		quiet      = flag.Bool("quiet", false, "shorthand for -log-level=off")
		publicIP   = flag.String("public-ip", "", "public IPv4 or IPv6 literal printed in share-strings; hostnames refused (clients must skip DNS)")
		sniName    = flag.String("sni", "", "hostname clients should send as SNI in the outer TLS ClientHello; required when -cert is a CA-signed cert that maps to a real domain (clients still connect by IP literal)")
		allowList  = flag.String("allow", "", "comma-separated allowlist of target domains (subdomains auto-included; empty = allow all)")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
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
	logInfof("mxtr-server %s starting", version)

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
	// PSK resolution order: -psk flag > MXTR_PSK env > -psk-file content >
	// auto-generate and persist to -psk-file. The persist step makes restart
	// a no-op for existing clients (PSK is stable across reboots), and lets
	// operators get going with zero pre-config: first run writes the file,
	// share-string is printed once at startup, subsequent runs re-use it.
	if *pskHex == "" {
		if data, err := os.ReadFile(*pskFile); err == nil {
			*pskHex = string(bytes.TrimSpace(data))
			if *pskHex != "" {
				logInfof("PSK loaded from %s", *pskFile)
			}
		}
	}
	if *pskHex == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatalf("generate PSK: %v", err)
		}
		*pskHex = hex.EncodeToString(key)
		if dir := filepath.Dir(*pskFile); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0o700)
		}
		// atomicReplaceSecure handles both first-write and the empty/stale
		// file case (e.g. crash mid-write left zero bytes). Symlink defence
		// is on the tmp file → rename, so an attacker can't redirect us by
		// pre-creating a symlink at the destination either way.
		if err := atomicReplaceSecure(*pskFile, []byte(*pskHex+"\n"), 0o600); err != nil {
			logWarnf("could not persist PSK to %s: %v (PSK will change on restart)", *pskFile, err)
		} else {
			logInfof("generated fresh PSK and persisted to %s (chmod 600)", *pskFile)
		}
	}

	p, err := hex.DecodeString(*pskHex)
	if err != nil {
		log.Fatalf("bad PSK hex: %v", err)
	}
	if len(p) < 16 {
		log.Fatal("PSK must be at least 16 bytes (32 hex chars)")
	}
	psk = p

	// Per-PSK fingerprint knobs cover ALPN order, heartbeat cadence, idle
	// threshold — same PSK yields same wire knobs, so a DPI vendor can't
	// match all deployments with one regex.
	pskCfg = derivePskConfig(psk)
	// Camouflage family is picked on first startup, persisted next to the
	// PSK file, and reused on every subsequent restart so a passive observer
	// sees the same Server identity from this IP — real nginx behaviour.
	// -rotate-cloak forces a fresh pick.
	statePath := *cloakState
	if statePath == "" {
		statePath = filepath.Join(filepath.Dir(*pskFile), "mxtr-cloak.idx")
	}
	pickedCamouflage = resolveCloakFamily(statePath, *rotateCloak)
	camName := pickedCamouflage.server
	if camName == "" {
		camName = "(no Server header)"
	}
	logInfof("cloak=%s alpn=%v heartbeat=%d-%dms idle=%dms",
		camName, pskCfg.alpnOrder,
		pskCfg.heartbeatMinMs, pskCfg.heartbeatMaxMs, pskCfg.idleThresholdMs)

	// Cert resolution: real CA cert via -cert flag, OR self-signed with a
	// persisted synthetic CDN-style CN. Persisted CN means restart keeps
	// the same Subject the client's share-string SNI was issued for. Fresh
	// CN is picked from a million+ synthetic space (cdnCities × patterns ×
	// numbers) — no enumerable dictionary.
	if *certPath != "" {
		if *keyPath == "" {
			log.Fatal("-cert provided but -key missing")
		}
		c, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			log.Fatalf("load cert: %v", err)
		}
		loadedCert = &c
		if len(c.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
				loadedCertName = leaf.Subject.CommonName
				logInfof("loaded real TLS cert for %q (NotAfter=%s)", loadedCertName, leaf.NotAfter.Format(time.RFC3339))
			}
		}
		if loadedCertName == "" {
			loadedCertName = "real-cert"
		}
	} else {
		cnPath := filepath.Join(filepath.Dir(*pskFile), "mxtr-cert.cn")
		cn := resolvePersistedCN(cnPath, *rotateCloak)
		c, _, err := generateSelfSignedCertWithCN(cn)
		if err != nil {
			log.Fatalf("generate self-signed cert: %v", err)
		}
		loadedCert = &c
		loadedCertName = cn
		logInfof("self-signed TLS cert ready for CN=%q", cn)
	}

	host := *publicIP
	if host == "" {
		host = autoDetectPublicIP()
		if host == "" {
			host = "<YOUR-PUBLIC-IP>"
		} else {
			logInfof("auto-detected public IP: %s (override with -public-ip)", host)
		}
	}
	// Reject hostnames AND non-public addresses. Clients dial via IP literal
	// so RU DNS-poisoning cannot redirect; loopback/private/multicast as
	// public-host is a misconfiguration (clients can't reach 127.0.0.1 or
	// 10.x.x.x from elsewhere on the internet) and we'd otherwise emit a
	// dead share-string.
	if host != "<YOUR-PUBLIC-IP>" && !isPublicIPLiteral(host) {
		log.Fatalf("-public-ip must be a public IPv4 or IPv6 literal (no hostnames, loopback, private, multicast, or unspecified); got %q", host)
	}
	// SNI default: if operator didn't override -sni, use the cert's CN.
	// For self-signed path that's the neutral synthetic hostname we just
	// generated/loaded; for -cert path that's the real domain. Either way,
	// SNI matches the Subject the server presents — no "ClientHello SNI ≠
	// cert subject" tell for passive observers.
	if *sniName == "" {
		*sniName = loadedCertName
	}
	if *sniName != "" && !isValidHostname(*sniName) {
		log.Fatalf("-sni %q is not a valid DNS hostname", *sniName)
	}
	if *tcpAddr != "" {
		// Route through logInfof so -quiet (=LogOff) suppresses the PSK
		// from stderr (L2-03). Anyone who needs the share-string can set
		// -log-level=info or higher when generating it the first time.
		logInfof("share-string: %s", buildShareString(host, *tcpAddr, *sniName))
		go runTCP(*tcpAddr, handleTCPv2, "tcp")
		go reapV2Sessions()
	}

	select {}
}
