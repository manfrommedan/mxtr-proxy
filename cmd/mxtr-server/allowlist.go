// Server-side target-domain allowlist.
//
// When `-allow` is set, the server only relays CONNECTs to listed entries and
// their subdomains. A PSK leak then can't turn the server into a generic open
// proxy — the worst an attacker can do is talk to the same endpoints the
// operator already exposes to themselves.
//
// Syntax: comma-separated. Each entry is either a domain (subdomains
// auto-included) or an IP literal (exact match only). `matrix.org` matches
// `matrix.org` and any `*.matrix.org`. `1.2.3.4` matches `1.2.3.4` only.
// Single-label entries (`com`, `org`) are refused at parse time to prevent
// accidental "the whole TLD is open" misconfigurations.

package main

import (
	"net"
	"strings"
)

type allowEntry struct {
	value string // for domain: lowercased; for ip: net.IP.String()
	isIP  bool
}

var allowedDomains []allowEntry

func parseAllowList(spec string) []allowEntry {
	if spec == "" {
		return nil
	}
	out := make([]allowEntry, 0, 4)
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(strings.ToLower(raw))
		entry = strings.TrimPrefix(entry, "*.")
		entry = strings.TrimSuffix(entry, ".") // tolerate FQDN form
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			out = append(out, allowEntry{value: ip.String(), isIP: true})
			continue
		}
		// Reject single-label entries — `-allow=com` would otherwise open
		// the entire TLD to anyone with the PSK (M2-04). Anything containing
		// non-LDH characters or consecutive dots is also rejected as it
		// can't be a real hostname.
		if !strings.Contains(entry, ".") {
			logWarnf("ignoring allowlist entry %q: needs at least one dot (single-label entries open whole TLDs)", entry)
			continue
		}
		if strings.Contains(entry, "..") || !isValidHostnameChars(entry) {
			logWarnf("ignoring allowlist entry %q: contains invalid hostname characters", entry)
			continue
		}
		out = append(out, allowEntry{value: entry, isIP: false})
	}
	return out
}

// isValidHostnameChars accepts only LDH (letters, digits, hyphen) plus dots.
// Per RFC 1035 §2.3.1 labels may not start or end with a hyphen — enforce
// that too so attacker-supplied operator flags can't slip in weird forms
// (LO3-09).
func isValidHostnameChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			continue
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// isTargetAllowed checks a `host:port` dial-address against the allowlist.
// Empty allowlist = allow everything (back-compat). Trailing dots on the
// host are stripped so `matrix.org.` resolves the same as `matrix.org`.
// Hosts containing consecutive dots or other bypass attempts are rejected.
func isTargetAllowed(dialAddr string) bool {
	if len(allowedDomains) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(dialAddr)
	if err != nil {
		host = dialAddr
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.Contains(host, "..") {
		return false
	}
	hostIP := net.ParseIP(host)
	for _, e := range allowedDomains {
		if e.isIP {
			if hostIP != nil && hostIP.Equal(net.ParseIP(e.value)) {
				return true
			}
			continue
		}
		// Domain entry: reject if candidate is an IP literal — otherwise
		// `evil.com.1.2.3.4` (treated as a hostname by net.Dial) would
		// suffix-match an IP-suffix entry. Also CR2-03.
		if hostIP != nil {
			continue
		}
		if host == e.value || strings.HasSuffix(host, "."+e.value) {
			return true
		}
	}
	return false
}
