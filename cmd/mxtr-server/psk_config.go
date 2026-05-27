// PSK-derived runtime configuration.
//
// Server-side fingerprint is identical across all mxtr deployments by default:
// same camouflage template, same ALPN order, same heartbeat cadence. That
// makes life easy for a DPI vendor who wants to write a single signature.
//
// Deriving these knobs from HKDF(PSK) makes every PSK its own deployment
// signature. Multiple deployments => N signatures to maintain, with no shared
// regex. Same PSK => deterministic; safe to re-derive on both client and
// server, no out-of-band coordination.

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

type pskDerivedConfig struct {
	camouflageIdx    int
	alpnOrder        []string
	heartbeatMinMs   int
	heartbeatMaxMs   int
	heartbeatPadMin  int
	heartbeatPadMax  int
	idleThresholdMs  int
}

// derivePskConfig produces the per-PSK runtime knobs. Salt + info are stable
// strings so any client with the same PSK derives identical values. Length:
// 16 bytes -> plenty of entropy to bias a handful of small integer choices.
func derivePskConfig(psk []byte) pskDerivedConfig {
	r := hkdf.New(sha256.New, psk, []byte("mxtr-config-v1-salt"), []byte("mxtr-config-v1"))
	out := make([]byte, 16)
	// io.ReadFull guarantees full fill; hkdf.Reader.Read may legally return
	// short reads per Reader contract, even though the current impl doesn't.
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf read: " + err.Error())
	}

	alpn := []string{"h2", "http/1.1"}
	if out[1]&1 == 1 {
		alpn = []string{"http/1.1", "h2"}
	}

	return pskDerivedConfig{
		camouflageIdx:    int(out[0]) % len(camouflage500s),
		alpnOrder:        alpn,
		heartbeatMinMs:   20_000 + int(out[2])*100,                                 // 20-45.5s
		heartbeatMaxMs:   45_000 + int(out[3])*100,                                 // 45-70.5s
		heartbeatPadMin:  32 + int(out[4]),                                         // 32-287
		heartbeatPadMax:  512 + int(binary.BigEndian.Uint16(out[5:7]))%3584,        // 512-4095
		idleThresholdMs:  10_000 + int(out[8])*50,                                  // 10-22.75s
	}
}

var pskCfg pskDerivedConfig
