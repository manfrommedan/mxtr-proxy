// Package main — share_string.go
//
// Emits the canonical `mxtr://<psk-base58>@<host>:<port>` string at server
// startup so the operator can paste it directly into a client without manual
// base58 encoding. Host is taken from the listener address; if it's wildcard
// (":9290") we resolve via -public-host flag, else fall back to <YOUR-HOST>.

package main

import (
	"math/big"
)

// base58 alphabet identical to MxtrShareString on the Kotlin client.
const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	rest := input[zeros:]
	n := new(big.Int).SetBytes(rest)
	base := big.NewInt(58)
	mod := new(big.Int)
	var rev []byte
	for n.Sign() > 0 {
		n.QuoRem(n, base, mod)
		rev = append(rev, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		rev = append(rev, b58Alphabet[0])
	}
	// reverse
	out := make([]byte, len(rev))
	for i, b := range rev {
		out[len(rev)-1-i] = b
	}
	return string(out)
}

// buildShareString assembles a single share URL.
//   - host is the IP literal clients connect to (no DNS).
//   - portAddr is the listen address ":N" or "ip:N"; leading colon is stripped.
//   - sni is the optional hostname clients should send as TLS SNI; appended
//     as ?sni=<hostname> when non-empty. Lets us live in 443 HTTPS haystack
//     while still skipping DNS for the TCP connect.
func buildShareString(host string, portAddr string, sni string) string {
	port := portAddr
	if len(port) > 0 && port[0] == ':' {
		port = port[1:]
	}
	if host == "" {
		host = "<YOUR-PUBLIC-HOST>"
	}
	s := "mxtr://" + base58Encode(psk) + "@" + host + ":" + port
	if sni != "" {
		s += "?sni=" + sni
	}
	return s
}
