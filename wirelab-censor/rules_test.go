package main

import (
	"encoding/binary"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeClassifier answers with fixed facts per server port, standing in for
// nDPI where a test needs what the built-in classifier cannot tell.
type fakeClassifier struct {
	byPort map[uint16]Facts
	caps   Caps
}

func (f *fakeClassifier) Name() string     { return "fake" }
func (f *fakeClassifier) Caps() Caps       { return f.caps }
func (f *fakeClassifier) Forget(k FlowKey) {}
func (f *fakeClassifier) Observe(p Packet, now time.Time) Facts {
	return f.byPort[p.Key.ServerPort]
}

func judgeAt(c *Censor, ip []byte, dir Dir, now time.Time) verdict {
	p, ok := parsePacket(ip, dir)
	if !ok {
		panic("unparsable test packet")
	}
	return c.judge(p, now)
}

func TestHypothesisFieldsAreRuleFields(t *testing.T) {
	presetsOrSkip(t)
	tags := map[string]bool{}
	rt := reflect.TypeOf(Rule{})
	for i := 0; i < rt.NumField(); i++ {
		if tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]; tag != "" {
			tags[tag] = true
		}
	}
	for _, f := range []string{"../containers/censor/presets/ru-tspu.json", "../containers/censor/presets/ru-mobile-whitelist.json"} {
		p, err := loadPreset(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range p.Hypotheses {
			if !tags[h.Field] {
				t.Errorf("%s: hypothesis %s sets %q, which no rule has", f, h.ID, h.Field)
			}
		}
	}
}

func TestQUICSNIBlocksAndRenews(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"q","kind":"quic_sni","action":"drop_both","quic_versions":[1],
		"block_seconds":420,"restart_on_trigger":true,"domains":["blocked.example"],"source":"test"}]}`)
	c.cls = &fakeClassifier{byPort: map[uint16]Facts{
		8443: {Proto: "QUIC", Host: "www.blocked.example", QUICVersion: 1, Done: true},
		8444: {Proto: "QUIC", Host: "www.blocked.example", QUICVersion: 0x6b3343cf, Done: true},
		8445: {Proto: "QUIC", Host: "fine.example", QUICVersion: 1, Done: true},
	}}
	initial := append([]byte{0xc0, 0, 0, 0, 1}, make([]byte, 1200)...)
	t0 := time.Unix(1000, 0)
	// Any UDP port, not just 443.
	if v := judgeAt(c, ipPacket(17, dirC2S, 6000, 8443, 0, initial), dirC2S, t0); v.kind != dropPacket {
		t.Fatal("a v1 Initial with a blocked SNI must be dropped")
	}
	// Another Initial 400 s later renews the 420 s block...
	judgeAt(c, ipPacket(17, dirC2S, 6000, 8443, 0, initial), dirC2S, t0.Add(400*time.Second))
	// ...so at 800 s it still holds.
	if v := judgeAt(c, ipPacket(17, dirS2C, 8443, 6000, 0, []byte("x")), dirS2C, t0.Add(800*time.Second)); v.kind != dropPacket {
		t.Fatal("the renewed residual block must still hold")
	}
	if v := judgeAt(c, ipPacket(17, dirS2C, 8443, 6000, 0, []byte("x")), dirS2C, t0.Add(1300*time.Second)); v.kind != passPacket {
		t.Fatal("the block must lapse 420 s after the last Initial")
	}
	if v := judgeAt(c, ipPacket(17, dirC2S, 6001, 8444, 0, initial), dirC2S, t0); v.kind != passPacket {
		t.Fatal("QUIC v2 is not read by the filter")
	}
	if v := judgeAt(c, ipPacket(17, dirC2S, 6002, 8445, 0, initial), dirC2S, t0); v.kind != passPacket {
		t.Fatal("an unlisted SNI passes")
	}
}

func TestQUICSNINeedsAClassifierThatDecrypts(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"q","kind":"quic_sni","action":"drop_both","domains":["x.example"],"source":"test"}]}`)
	c.cls = newBuiltinClassifier()
	if d := c.describe(c.preset); !strings.Contains(d, "cannot fire") || !strings.Contains(d, "q (") {
		t.Fatalf("the built-in classifier must report q as unable to fire: %s", d)
	}
}

func TestFreezeOnUDPBlocksTheServer(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"fz","kind":"freeze","action":"drop_s2c","after_packets":5,
		"udp_host_seconds":600,"cidrs":["10.77.2.0/24"],"source":"test"}]}`)
	t0 := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		judgeAt(c, ipPacket(17, dirC2S, 7000, 4433, 0, []byte("data")), dirC2S, t0)
	}
	if v := judgeAt(c, ipPacket(17, dirC2S, 7000, 4433, 0, []byte("data")), dirC2S, t0); v.kind != dropPacket {
		t.Fatal("the 6th UDP packet must be dropped")
	}
	// A new UDP flow to the same server, from another port, is blocked too.
	if v := judgeAt(c, ipPacket(17, dirC2S, 7001, 9999, 0, []byte("hi")), dirC2S, t0.Add(time.Minute)); v.kind != dropPacket {
		t.Fatal("all UDP to the server must be blocked for 10 minutes")
	}
	// TCP to it is not.
	if v := judgeAt(c, ipPacket(6, dirC2S, 7002, 443, tcpSYN, nil), dirC2S, t0.Add(time.Minute)); v.kind != passPacket {
		t.Fatal("the UDP host block must leave TCP alone")
	}
	if v := judgeAt(c, ipPacket(17, dirC2S, 7003, 9999, 0, []byte("hi")), dirC2S, t0.Add(601*time.Second)); v.kind != passPacket {
		t.Fatal("the host block lapses after 600 s")
	}
}

func TestFreezeWhitelistedSNIDependsOnTheCIDRTie(t *testing.T) {
	for _, tied := range []bool{true, false} {
		c := testCensor(t, `{"name":"t","rules":[{"id":"fz","kind":"freeze","action":"drop_s2c","after_packets":3,
			"cidrs":["10.77.2.0/24"],"allow_sni":["ozon.ru"],"sni_cidrs":["10.88.0.0/16"],"sni_tied_to_cidr":`+map[bool]string{true: "true", false: "false"}[tied]+`,"source":"test"}]}`)
		judgeAt(c, ipPacket(6, dirC2S, 5000, 443, tcpACK, clientHello("ozon.ru")), dirC2S, time.Now())
		var last verdictKind
		for i := 0; i < 5; i++ {
			last = judgeAt(c, ipPacket(6, dirS2C, 443, 5000, tcpACK, []byte("x")), dirS2C, time.Now()).kind
		}
		want := dropPacket
		if !tied {
			want = passPacket
		}
		if last != want {
			t.Fatalf("tied=%v: a borrowed SNI on a foreign address gave %v, want %v", tied, last, want)
		}
	}
}

func TestFreezeCountingBytes(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"fz","kind":"freeze","action":"drop_s2c","count_bytes":true,
		"max_s2c_bytes":3000,"cidrs":["10.77.2.0/24"],"source":"test"}]}`)
	chunk := make([]byte, 1000)
	for i := 0; i < 3; i++ {
		if v := judgeAt(c, ipPacket(6, dirS2C, 443, 5000, tcpACK, chunk), dirS2C, time.Now()); v.kind != passPacket {
			t.Fatalf("chunk %d is within 3000 bytes", i+1)
		}
	}
	if v := judgeAt(c, ipPacket(6, dirS2C, 443, 5000, tcpACK, chunk), dirS2C, time.Now()); v.kind != dropPacket {
		t.Fatal("past 3000 bytes the server's packets stop")
	}
}

func TestEncapsulatedTLSHeuristic(t *testing.T) {
	preset := `{"name":"t","rules":[{"id":"et","kind":"encapsulated_tls","action":"drop_both","min_client_packets":3,
		"min_client_size":411,"within_packets":30,"only_unknown":true,"ports":[443],"cidrs":["10.77.2.0/24"],"source":"test"}]}`
	big, small := make([]byte, 450), make([]byte, 100)
	for i := range big {
		big[i] = byte(i*7 + 3) // not 0x16, not "SSH-": a fully encrypted protocol
	}
	run := func(c *Censor, sport uint16, first []byte) verdictKind {
		judgeAt(c, ipPacket(6, dirC2S, sport, 443, tcpACK, first), dirC2S, time.Now())
		judgeAt(c, ipPacket(6, dirS2C, 443, sport, tcpACK, small), dirS2C, time.Now())
		judgeAt(c, ipPacket(6, dirC2S, sport, 443, tcpACK, big), dirC2S, time.Now())
		judgeAt(c, ipPacket(6, dirS2C, 443, sport, tcpACK, small), dirS2C, time.Now())
		judgeAt(c, ipPacket(6, dirS2C, 443, sport, tcpACK, small), dirS2C, time.Now())
		judgeAt(c, ipPacket(6, dirS2C, 443, sport, tcpACK, small), dirS2C, time.Now())
		return judgeAt(c, ipPacket(6, dirC2S, sport, 443, tcpACK, big), dirC2S, time.Now()).kind
	}
	if v := run(testCensor(t, preset), 5000, big); v != dropPacket {
		t.Fatalf("three large client packets with a chattier server: got %v, want drop", v)
	}
	// The same shape inside real TLS is not this rule's business.
	hello := append(clientHello("site.example"), make([]byte, 400)...)
	if v := run(testCensor(t, preset), 5001, hello); v != passPacket {
		t.Fatalf("TLS on the wire must pass: got %v", v)
	}
}

func TestTLSRateBlocksTheTwelfthConnection(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"tr","kind":"tls_rate","action":"drop_both","max_conns":11,
		"window_seconds":10,"block_seconds":120,"ports":[443],"source":"test"}]}`)
	t0 := time.Unix(1000, 0)
	for i := 0; i < 11; i++ {
		if v := judgeAt(c, ipPacket(6, dirC2S, uint16(5000+i), 443, tcpACK, clientHello("a.example")), dirC2S, t0.Add(time.Duration(i)*100*time.Millisecond)); v.kind != passPacket {
			t.Fatalf("connection %d must pass", i+1)
		}
	}
	if v := judgeAt(c, ipPacket(6, dirC2S, 5011, 443, tcpACK, clientHello("a.example")), dirC2S, t0.Add(2*time.Second)); v.kind != dropPacket {
		t.Fatal("the 12th ClientHello within 10 s must be dropped")
	}
	if v := judgeAt(c, ipPacket(6, dirC2S, 5012, 443, tcpACK, clientHello("a.example")), dirC2S, t0.Add(60*time.Second)); v.kind != dropPacket {
		t.Fatal("new connections stay blocked for 120 s")
	}
	if v := judgeAt(c, ipPacket(6, dirC2S, 5013, 443, tcpACK, []byte{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0}), dirC2S, t0.Add(60*time.Second)); v.kind != passPacket {
		t.Fatal("a connection without SNI is not affected")
	}
	if v := judgeAt(c, ipPacket(6, dirC2S, 5014, 443, tcpACK, clientHello("a.example")), dirC2S, t0.Add(125*time.Second)); v.kind != passPacket {
		t.Fatal("after 120 s connections go through again")
	}
}

func TestTLSRateByFingerprint(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"tr","kind":"tls_rate","action":"drop_both","max_conns":1,
		"window_seconds":10,"block_seconds":120,"by_fingerprint":true,"source":"test"}]}`)
	c.cls = &fakeClassifier{caps: Caps{JA4: true}, byPort: map[uint16]Facts{
		443: {Proto: "TLS", JA4: "t13d1516h2_aaa", Done: true},
		444: {Proto: "TLS", JA4: "t13d0909h2_bbb", Done: true},
	}}
	now := time.Now()
	judgeAt(c, ipPacket(6, dirC2S, 5000, 443, tcpACK, clientHello("a.example")), dirC2S, now)
	if v := judgeAt(c, ipPacket(6, dirC2S, 5001, 443, tcpACK, clientHello("a.example")), dirC2S, now); v.kind != dropPacket {
		t.Fatal("the second hello with the same fingerprint must be dropped")
	}
	if v := judgeAt(c, ipPacket(6, dirC2S, 5002, 444, tcpACK, clientHello("a.example")), dirC2S, now); v.kind != passPacket {
		t.Fatal("another fingerprint is counted on its own")
	}
}

// dnsQuery builds a query for name with an EDNS OPT record after it.
func dnsQuery(id uint16, name string) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	return append(q, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
}

func TestUDPDNSAnsweredNXDOMAIN(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"dns","kind":"dns_udp","action":"nxdomain","domains":["rutracker.org","ua"],"source":"test"}]}`)
	v := judgeAt(c, ipPacket(17, dirC2S, 40000, 53, 0, dnsQuery(0xbeef, "rutracker.org")), dirC2S, time.Now())
	if v.kind != injectReply {
		t.Fatalf("a blocked name must be answered by the censor, got %v", v.kind)
	}
	r := v.reply
	if r[9] != 17 || string(r[12:16]) != string(serverIP[:]) || string(r[16:20]) != string(clientIP[:]) {
		t.Fatal("the answer comes from the resolver to the client over UDP")
	}
	if binary.BigEndian.Uint16(r[20:22]) != 53 || binary.BigEndian.Uint16(r[22:24]) != 40000 {
		t.Fatal("ports swapped")
	}
	dns := r[28:]
	if binary.BigEndian.Uint16(dns[0:2]) != 0xbeef || dns[2]&0x80 == 0 || dns[3]&0x0f != 3 {
		t.Fatalf("want a response with the query's id and RCODE 3: % x", dns[:4])
	}
	if !finishForward(r) || checksum(r[:20], 0) != 0 {
		t.Fatal("the reply must forward with a valid header checksum")
	}
	if v := judgeAt(c, ipPacket(17, dirC2S, 40001, 53, 0, dnsQuery(1, "news.kyiv.ua")), dirC2S, time.Now()); v.kind != injectReply {
		t.Fatal("a whole TLD can be listed")
	}
	if v := judgeAt(c, ipPacket(17, dirC2S, 40002, 53, 0, dnsQuery(2, "example.org")), dirC2S, time.Now()); v.kind != passPacket {
		t.Fatal("other names pass")
	}
	if v := judgeAt(c, ipPacket(6, dirC2S, 40003, 53, tcpACK, append([]byte{0, 40}, dnsQuery(3, "rutracker.org")...)), dirC2S, time.Now()); v.kind != passPacket {
		t.Fatal("DNS over TCP is untouched")
	}
}

func TestPoliceHoldsSSHToItsRate(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"pol","kind":"police","action":"police","protocols":["SSH"],
		"after_bytes":2000,"rate_kbit":16,"source":"test"}]}`)
	t0 := time.Unix(1000, 0)
	judgeAt(c, ipPacket(6, dirS2C, 22, 5000, tcpACK, []byte("SSH-2.0-OpenSSH_9.6\r\n")), dirS2C, t0)
	chunk := make([]byte, 1000)
	passed := 0
	// 50 packets of 1 KB in one second, against 2 KB/s.
	for i := 0; i < 50; i++ {
		if judgeAt(c, ipPacket(6, dirS2C, 22, 5000, tcpACK, chunk), dirS2C, t0.Add(time.Duration(i)*20*time.Millisecond)).kind == passPacket {
			passed++
		}
	}
	if passed < 2 || passed > 6 {
		t.Fatalf("about 2 KB in the first threshold plus 2 KB/s should pass; %d of 50 did", passed)
	}
}

func TestWhitelistLetsHandshakesThroughButNotData(t *testing.T) {
	c := testCensor(t, `{"name":"t","rules":[{"id":"wl","kind":"whitelist","action":"drop_payload","cidrs":["10.77.9.0/24"],
		"allow_sni":["vk.com"],"sni_cidrs":["10.77.9.0/24"],"sni_tied_to_cidr":true,"source":"test"}]}`)
	now := time.Now()
	if v := judgeAt(c, ipPacket(6, dirC2S, 5000, 443, tcpSYN, nil), dirC2S, now); v.kind != passPacket {
		t.Fatal("the SYN is delivered")
	}
	if v := judgeAt(c, ipPacket(6, dirS2C, 443, 5000, tcpSYN|tcpACK, nil), dirS2C, now); v.kind != passPacket {
		t.Fatal("the SYN-ACK comes back")
	}
	if v := judgeAt(c, ipPacket(6, dirC2S, 5000, 443, tcpACK, clientHello("vk.com")), dirC2S, now); v.kind != dropPacket {
		t.Fatal("an allowed SNI on an address off the list does not help when tied")
	}
	if v := judgeAt(c, ipPacket(17, dirC2S, 6000, 443, 0, []byte("quic?")), dirC2S, now); v.kind != dropPacket {
		t.Fatal("UDP off the list is dropped")
	}
	icmp := ipPacket(17, dirC2S, 0, 0, 0, []byte{8, 0, 0, 0})
	icmp[9] = 1
	if v := judgeAt(c, icmp, dirC2S, now); v.kind != dropPacket {
		t.Fatal("ICMP off the list is dropped")
	}
}

func TestNoUnusedPresetFile(t *testing.T) {
	presetsOrSkip(t)
	// The panel lists every file in the presets folder; a stray file there
	// would show up as a broken preset.
	entries, _ := os.ReadDir("../containers/censor/presets")
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			t.Errorf("unexpected file in presets: %s", e.Name())
		}
	}
}

func nowForTest() time.Time { return time.Unix(1_800_000_000, 0) }

// presetsOrSkip: the presets live outside this module; the container build
// of the censor sees only the module.
func presetsOrSkip(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("../containers/censor/presets/ru-tspu.json"); err != nil {
		t.Skip("presets not here (built outside the checkout)")
	}
}
