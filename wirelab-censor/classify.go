package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"
)

// Facts is what a classifier knows about a flow's protocol. Rules read it;
// they never parse protocols themselves beyond the TSPU behaviour they model.
type Facts struct {
	// Proto in nDPI's naming: TLS, QUIC, SSH, RDP, WireGuard, OpenVPN, DNS,
	// DTLS, HTTP. Empty while undecided; "Unknown" once the classifier gave up.
	Proto string
	// Host: the SNI of TLS, DTLS or QUIC (decrypted Initial), the HTTP Host,
	// or the name asked in a DNS query.
	Host string
	// JA4 client fingerprint of TLS or DTLS.
	JA4         string
	QUICVersion uint32
	// Done: the classifier wants no more packets of this flow.
	Done bool
}

// Caps says what a classifier can tell, so a rule that needs more than it
// has can be reported as inactive instead of silently never firing.
type Caps struct {
	QUICSNI bool
	JA4     bool
	DNS     bool
}

type Classifier interface {
	Name() string
	Caps() Caps
	// Observe feeds one packet of a flow (p.Raw is the whole IP packet) and
	// returns everything known so far.
	Observe(p Packet, now time.Time) Facts
	Forget(k FlowKey)
}

// classifyPackets bounds how many packets of a flow go to the classifier:
// every protocol the presets care about shows itself well before that.
const classifyPackets = 32

// builtinClassifier recognises protocols from their first bytes, without
// nDPI: what replay on Windows and the tests use. It cannot decrypt QUIC
// Initials or compute JA4.
type builtinClassifier struct {
	flows map[FlowKey]*Facts
}

func newBuiltinClassifier() *builtinClassifier {
	return &builtinClassifier{flows: map[FlowKey]*Facts{}}
}

func (b *builtinClassifier) Name() string { return "built-in (first bytes only)" }
func (b *builtinClassifier) Caps() Caps   { return Caps{DNS: true} }
func (b *builtinClassifier) Forget(k FlowKey) {
	delete(b.flows, k)
}

func (b *builtinClassifier) Observe(p Packet, now time.Time) Facts {
	f := b.flows[p.Key]
	if f == nil {
		f = &Facts{}
		b.flows[p.Key] = f
	}
	if f.Done || len(p.Payload) == 0 {
		return *f
	}
	pl := p.Payload
	switch {
	case p.Proto == 6 && bytes.HasPrefix(pl, []byte("SSH-")):
		f.Proto, f.Done = "SSH", true
	case p.Proto == 6 && p.Dir == dirC2S && len(pl) >= 7 && pl[0] == 3 && pl[1] == 0 && pl[5]&0xf0 == 0xe0:
		// TPKT + X.224 Connection Request: how every RDP session opens.
		f.Proto, f.Done = "RDP", true
	case p.Proto == 6 && p.Dir == dirC2S && pl[0] == 0x16:
		f.Proto, f.Done = "TLS", true
		if sni, ok := clientHelloSNI(pl); ok {
			f.Host = sni
		}
	case p.Proto == 6 && p.Dir == dirC2S && isHTTPRequest(pl):
		f.Proto, f.Done = "HTTP", true
		f.Host = httpHost(pl)
	case p.Proto == 17 && p.Dir == dirC2S && p.Key.ServerPort == 53:
		if name, ok := dnsQueryName(pl); ok {
			f.Proto, f.Host, f.Done = "DNS", name, true
		}
	case p.Proto == 17 && p.Dir == dirC2S && len(pl) >= 5 && pl[0]&0x80 != 0:
		f.Proto, f.QUICVersion, f.Done = "QUIC", binary.BigEndian.Uint32(pl[1:5]), true
	case p.Proto == 17 && len(pl) == 148 && pl[0] == 1 && pl[1] == 0 && pl[2] == 0 && pl[3] == 0:
		f.Proto, f.Done = "WireGuard", true
	default:
		f.Proto, f.Done = "Unknown", true
	}
	return *f
}

func isHTTPRequest(b []byte) bool {
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "CONNECT "} {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

func httpHost(b []byte) string {
	for _, line := range strings.Split(string(b), "\r\n") {
		if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
			h := strings.TrimSpace(line[5:])
			if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
				h = h[:i]
			}
			return strings.ToLower(h)
		}
	}
	return ""
}

// dnsQueryName reads the first question of a DNS query.
func dnsQueryName(b []byte) (string, bool) {
	if len(b) < 12 || b[2]&0x80 != 0 || binary.BigEndian.Uint16(b[4:6]) == 0 {
		return "", false
	}
	var labels []string
	i := 12
	for i < len(b) {
		n := int(b[i])
		if n == 0 {
			return strings.ToLower(strings.Join(labels, ".")), len(labels) > 0
		}
		if n&0xc0 != 0 || i+1+n > len(b) {
			return "", false
		}
		labels = append(labels, string(b[i+1:i+1+n]))
		i += 1 + n
	}
	return "", false
}
