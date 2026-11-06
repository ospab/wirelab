//go:build ndpi && linux && cgo

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// classifyFile runs every IPv4 packet of a capture through a fresh nDPI
// classifier, taking the first sender of each flow as its client, and
// returns the last facts of each flow.
func classifyFile(t *testing.T, path string) map[FlowKey]Facts {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	frames, _, err := readCapture(b)
	if err != nil && len(frames) == 0 {
		t.Fatalf("%s: %v", path, err)
	}
	cls := defaultClassifier()
	if _, ok := cls.(*ndpiClassifier); !ok {
		t.Fatal("nDPI did not initialise")
	}
	clientOf := map[FlowKey][4]byte{}
	out := map[FlowKey]Facts{}
	for _, fr := range frames {
		p, ok := parsePacket(fr.IP, dirC2S)
		if !ok || (p.Proto != 6 && p.Proto != 17) {
			continue
		}
		// Normalise: the same flow seen from the other side has the reversed key.
		rev := FlowKey{p.Proto, p.Key.ServerIP, p.Key.ServerPort, p.Key.ClientIP, p.Key.ClientPort}
		if _, seen := clientOf[rev]; seen {
			p, _ = parsePacket(fr.IP, dirS2C)
		} else if _, seen := clientOf[p.Key]; !seen {
			clientOf[p.Key] = p.Key.ClientIP
		}
		out[p.Key] = cls.Observe(p, fr.T)
	}
	return out
}

func ndpiTests(t *testing.T) string {
	dir := os.Getenv("NDPI_TESTS")
	if dir == "" {
		t.Skip("NDPI_TESTS not set (the build container sets it to nDPI's test captures)")
	}
	return dir
}

func TestNDPIDecryptsQUICInitials(t *testing.T) {
	dir := ndpiTests(t)
	files, _ := filepath.Glob(filepath.Join(dir, "quic*"))
	var v1, v2 int
	for _, f := range files {
		for _, fa := range classifyFile(t, f) {
			if fa.Proto == "QUIC" && fa.Host != "" {
				switch fa.QUICVersion {
				case 1:
					v1++
				case 0x6b3343cf:
					v2++
				}
			}
		}
	}
	if v1 == 0 {
		t.Fatalf("no QUIC v1 flow with a decrypted SNI in %d captures", len(files))
	}
	t.Logf("QUIC flows with SNI: v1 %d, v2 %d", v1, v2)
}

func TestNDPIRecognisesTheTunnels(t *testing.T) {
	dir := ndpiTests(t)
	for file, want := range map[string]string{
		"mullvad_wireguard.pcap": "WireGuard",
		"openvpn.pcap":           "OpenVPN",
		"dns.pcap":               "DNS",
		"dtls.pcap":              "DTLS",
	} {
		found := false
		for _, fa := range classifyFile(t, filepath.Join(dir, file)) {
			if fa.Proto == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no flow classified as %s", file, want)
		}
	}
}

func TestNDPIReadsSNIAndJA4(t *testing.T) {
	cls := defaultClassifier()
	syn := ipPacket(6, dirC2S, 5000, 443, tcpSYN, nil)
	synack := ipPacket(6, dirS2C, 443, 5000, tcpSYN|tcpACK, nil)
	hello := ipPacket(6, dirC2S, 5000, 443, tcpACK, clientHello("www.example.com"))
	var fa Facts
	for _, x := range []struct {
		ip  []byte
		dir Dir
	}{{syn, dirC2S}, {synack, dirS2C}, {hello, dirC2S}} {
		p, _ := parsePacket(x.ip, x.dir)
		fa = cls.Observe(p, nowForTest())
	}
	if fa.Proto != "TLS" || fa.Host != "www.example.com" {
		t.Fatalf("want TLS www.example.com, got %+v", fa)
	}
	if fa.JA4 == "" {
		t.Errorf("no JA4 for the ClientHello: %+v", fa)
	}
}
