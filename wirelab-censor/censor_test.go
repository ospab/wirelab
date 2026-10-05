package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	clientIP = [4]byte{10, 77, 1, 3}
	serverIP = [4]byte{10, 77, 2, 3}
)

// ipPacket builds an IPv4 packet with a TCP (proto 6) or UDP (17) header.
func ipPacket(proto byte, dir Dir, sport, dport uint16, flags byte, payload []byte) []byte {
	l4 := 8
	if proto == 6 {
		l4 = 20
	}
	total := 20 + l4 + len(payload)
	ip := make([]byte, total)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	ip[8] = 64
	ip[9] = proto
	src, dst := clientIP, serverIP
	if dir == dirS2C {
		src, dst = serverIP, clientIP
	}
	copy(ip[12:], src[:])
	copy(ip[16:], dst[:])
	binary.BigEndian.PutUint16(ip[20:], sport)
	binary.BigEndian.PutUint16(ip[22:], dport)
	if proto == 6 {
		ip[32] = 5 << 4
		ip[33] = flags
	} else {
		binary.BigEndian.PutUint16(ip[24:], uint16(8+len(payload)))
	}
	copy(ip[20+l4:], payload)
	return ip
}

func clientHello(sni string) []byte {
	name := []byte(sni)
	sn := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, name...)
	snl := append([]byte{byte(len(sn) >> 8), byte(len(sn))}, sn...)
	ext := append([]byte{0, 0, byte(len(snl) >> 8), byte(len(snl))}, snl...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func testCensor(t *testing.T, preset string) *Censor {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	if err := os.WriteFile(path, []byte(preset), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := loadPreset(path)
	if err != nil {
		t.Fatal(err)
	}
	logf, _ := os.Create(filepath.Join(dir, "log"))
	t.Cleanup(func() { logf.Close() })
	_, cn, _ := net.ParseCIDR("10.77.1.0/24")
	_, sn, _ := net.ParseCIDR("10.77.2.0/24")
	c := newCensor(cn, sn, logf)
	c.setPreset(p)
	return c
}

func judgeRaw(c *Censor, ip []byte, dir Dir) verdictKind {
	p, ok := parsePacket(ip, dir)
	if !ok {
		panic("unparsable test packet")
	}
	return c.judge(p).kind
}

func TestRealPresetLoads(t *testing.T) {
	p, err := loadPreset("../containers/censor/presets/ru-tspu.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Rules {
		if !strings.Contains(r.Source, "http") {
			t.Errorf("rule %s cites no link: %q", r.ID, r.Source)
		}
	}
}

func TestRuleWithoutSourceIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(path, []byte(`{"name":"x","rules":[{"id":"a","kind":"ip","action":"drop_both"}]}`), 0o644)
	if _, err := loadPreset(path); err == nil || !strings.Contains(err.Error(), "source") {
		t.Fatalf("want a missing-source error, got %v", err)
	}
}

func TestSNIRewritesServerReplyToRST(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"sni","kind":"sni","action":"rst_s2c","block_seconds":75,
		"domains":["blocked.example"],"source":"test"}]}`)
	if v := judgeRaw(c, ipPacket(6, dirC2S, 5000, 443, tcpACK, clientHello("www.blocked.example")), dirC2S); v != passPacket {
		t.Fatalf("SNI-I lets the ClientHello through, got %v", v)
	}
	reply := ipPacket(6, dirS2C, 443, 5000, tcpACK, []byte("server hello bytes"))
	if v := judgeRaw(c, reply, dirS2C); v != rewriteRST {
		t.Fatalf("server reply must become RST/ACK, got %v", v)
	}
	p, _ := parsePacket(reply, dirS2C)
	n := toRSTAck(reply, p)
	if n != 40 || reply[33] != tcpRST|tcpACK {
		t.Fatalf("RST/ACK rewrite: len %d flags %#x", n, reply[33])
	}
	// An allowed name in another flow is untouched.
	if v := judgeRaw(c, ipPacket(6, dirC2S, 5001, 443, tcpACK, clientHello("fine.example")), dirC2S); v != passPacket {
		t.Fatal("unlisted SNI must pass")
	}
	if v := judgeRaw(c, ipPacket(6, dirS2C, 443, 5001, tcpACK, []byte("ok")), dirS2C); v != passPacket {
		t.Fatal("reply in an unlisted flow must pass")
	}
}

func TestSNIDropAfterLetsSomePacketsThrough(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"s2","kind":"sni","action":"drop_both","after_packets":5,
		"block_seconds":420,"domains":["nordvpn.com"],"source":"test"}]}`)
	judgeRaw(c, ipPacket(6, dirC2S, 5000, 443, tcpACK, clientHello("nordvpn.com")), dirC2S)
	for i := 0; i < 5; i++ {
		if v := judgeRaw(c, ipPacket(6, dirS2C, 443, 5000, tcpACK, []byte("x")), dirS2C); v != passPacket {
			t.Fatalf("packet %d after the trigger must pass", i+1)
		}
	}
	if v := judgeRaw(c, ipPacket(6, dirC2S, 5000, 443, tcpACK, []byte("x")), dirC2S); v != dropPacket {
		t.Fatal("the 6th packet must be dropped")
	}
}

func TestFreezeAfter25PacketsDropsOnlyServerSide(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"fz","kind":"freeze","action":"drop_s2c","after_packets":25,
		"cidrs":["10.77.2.0/24"],"exempt_ssh":true,"source":"test"}]}`)
	for i := 0; i < 25; i++ {
		dir := Dir(i % 2)
		sp, dp := uint16(5000), uint16(443)
		if dir == dirS2C {
			sp, dp = dp, sp
		}
		if v := judgeRaw(c, ipPacket(6, dir, sp, dp, tcpACK, []byte("data")), dir); v != passPacket {
			t.Fatalf("packet %d is under the limit and must pass", i+1)
		}
	}
	if v := judgeRaw(c, ipPacket(6, dirS2C, 443, 5000, tcpACK, []byte("data")), dirS2C); v != dropPacket {
		t.Fatal("server packet 26 must be dropped")
	}
	if v := judgeRaw(c, ipPacket(6, dirC2S, 5000, 443, tcpACK, []byte("data")), dirC2S); v != passPacket {
		t.Fatal("a freeze leaves the client direction alone")
	}
}

func TestFreezeSparesSSH(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"fz","kind":"freeze","action":"drop_s2c","after_packets":3,
		"cidrs":["10.77.2.0/24"],"exempt_ssh":true,"source":"test"}]}`)
	judgeRaw(c, ipPacket(6, dirS2C, 22, 5000, tcpACK, []byte("SSH-2.0-OpenSSH_9.6\r\n")), dirS2C)
	for i := 0; i < 10; i++ {
		if v := judgeRaw(c, ipPacket(6, dirS2C, 22, 5000, tcpACK, []byte("x")), dirS2C); v != passPacket {
			t.Fatal("SSH must not be frozen")
		}
	}
}

func TestQUICv1Dropped(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"q","kind":"quic_v1","action":"drop_both","port":443,
		"min_payload":1001,"block_seconds":420,"source":"test"}]}`)
	small := append([]byte{0xc0, 0, 0, 0, 1}, make([]byte, 995)...)
	if v := judgeRaw(c, ipPacket(17, dirC2S, 6000, 443, 0, small), dirC2S); v != passPacket {
		t.Fatal("1000 bytes is under the threshold")
	}
	big := append([]byte{0xc0, 0, 0, 0, 1}, make([]byte, 996)...)
	if v := judgeRaw(c, ipPacket(17, dirC2S, 6001, 443, 0, big), dirC2S); v != dropPacket {
		t.Fatal("1001-byte QUIC v1 Initial must be dropped")
	}
	if v := judgeRaw(c, ipPacket(17, dirS2C, 443, 6001, 0, []byte("x")), dirS2C); v != dropPacket {
		t.Fatal("the rest of the flow must be dropped too")
	}
	draft29 := append([]byte{0xc0, 0xff, 0, 0, 0x1d}, make([]byte, 1100)...)
	if v := judgeRaw(c, ipPacket(17, dirC2S, 6002, 443, 0, draft29), dirC2S); v != passPacket {
		t.Fatal("draft-29 is not matched by the v1 fingerprint")
	}
}

func TestWireGuardCutAfterTwoDataPackets(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"wg","kind":"wireguard","action":"drop_both","max_data_packets":2,"source":"test"}]}`)
	init := append([]byte{1, 0, 0, 0}, make([]byte, 144)...)
	resp := append([]byte{2, 0, 0, 0}, make([]byte, 88)...)
	data := append([]byte{4, 0, 0, 0}, make([]byte, 60)...)
	judgeRaw(c, ipPacket(17, dirC2S, 7000, 51820, 0, init), dirC2S)
	judgeRaw(c, ipPacket(17, dirS2C, 51820, 7000, 0, resp), dirS2C)
	for i := 0; i < 2; i++ {
		if v := judgeRaw(c, ipPacket(17, dirC2S, 7000, 51820, 0, data), dirC2S); v != passPacket {
			t.Fatalf("data packet %d must pass", i+1)
		}
	}
	if v := judgeRaw(c, ipPacket(17, dirC2S, 7000, 51820, 0, data), dirC2S); v != dropPacket {
		t.Fatal("the third data packet must be dropped")
	}
}

func TestChecksumsVerifyAfterForward(t *testing.T) {
	ip := ipPacket(6, dirC2S, 5000, 443, tcpACK, []byte("payload!"))
	if !finishForward(ip) {
		t.Fatal("TTL 64 must forward")
	}
	if ip[8] != 63 {
		t.Fatal("TTL must drop by one")
	}
	if checksum(ip[:20], 0) != 0 {
		t.Fatal("IP header checksum must verify")
	}
	var ph [12]byte
	copy(ph[0:8], ip[12:20])
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:], uint16(len(ip)-20))
	if checksum(ip[20:], sumWords(ph[:], 0)) != 0 {
		t.Fatal("TCP checksum must verify")
	}
}

func TestNoPresetPassesEverything(t *testing.T) {
	_, cn, _ := net.ParseCIDR("10.77.1.0/24")
	_, sn, _ := net.ParseCIDR("10.77.2.0/24")
	logf, _ := os.Create(filepath.Join(t.TempDir(), "log"))
	t.Cleanup(func() { logf.Close() })
	c := newCensor(cn, sn, logf)
	if v := judgeRaw(c, ipPacket(6, dirC2S, 1, 443, tcpACK, clientHello("twitter.com")), dirC2S); v != passPacket {
		t.Fatal("with no preset nothing is touched")
	}
}
