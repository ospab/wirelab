package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Preset is a censor model: an ordered list of rules, each tied to the
// observation or paper it reproduces.
type Preset struct {
	Name       string       `json:"name"`
	AsOf       string       `json:"as_of"`
	Notes      string       `json:"notes"`
	Hypotheses []Hypothesis `json:"hypotheses"`
	Rules      []Rule       `json:"rules"`
}

// Hypothesis is a behaviour the sources do not settle. The preset states
// it, the panel lets you pick, and the choice is written into the listed
// rules' Field, so a result can always say which assumption it rests on.
type Hypothesis struct {
	ID      string   `json:"id"`
	Label   string   `json:"label"`
	Field   string   `json:"field"`
	Rules   []string `json:"rules"`
	Default bool     `json:"default"`
	Note    string   `json:"note"`
	// Chosen is set in an active preset: the value written into the rules.
	Chosen *bool `json:"chosen,omitempty"`
}

type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Action   string `json:"action"`
	Source   string `json:"source"`
	Disabled bool   `json:"disabled"`

	// sni, quic_sni, dns_udp: names the rule is about (a name and its subdomains).
	Domains []string `json:"domains"`
	// sni: the ClientHello itself is dropped.
	DropTrigger bool `json:"drop_trigger"`
	// sni: packets let through after the trigger; freeze: packets of the
	// flow, both directions, before it.
	AfterPackets int `json:"after_packets"`
	// How long a block lasts; 0: for the rest of the flow.
	BlockSeconds int `json:"block_seconds"`
	// quic_sni: another blocked Initial on the same flow restarts the timer.
	RestartOnTrigger bool `json:"restart_on_trigger"`
	// quic_v1 (the 2022 wholesale block): server port and smallest payload.
	Port       int `json:"port"`
	MinPayload int `json:"min_payload"`
	// quic_sni: QUIC versions the filter reads (v1 is 0x00000001).
	QUICVersions []uint32 `json:"quic_versions"`
	// Server addresses a rule applies to (ip: the block list; whitelist:
	// the allowed ones).
	CIDRs []string `json:"cidrs"`
	// Server ports a rule applies to; empty: all.
	Ports []int `json:"ports"`
	// freeze, whitelist: names that exempt a flow...
	AllowSNI []string `json:"allow_sni"`
	// ...and, when SNITiedToCIDR, only on servers in these networks.
	SNICIDRs      []string `json:"sni_cidrs"`
	SNITiedToCIDR bool     `json:"sni_tied_to_cidr"`
	// freeze: protocols (Facts.Proto) it leaves alone.
	ExemptProtocols []string `json:"exempt_protocols"`
	ExemptRDP       bool     `json:"exempt_rdp"`
	// freeze: count server-to-client payload bytes instead of packets.
	CountBytes  bool `json:"count_bytes"`
	MaxS2CBytes int  `json:"max_s2c_bytes"`
	// freeze: a frozen UDP flow blocks all UDP from that client to that
	// server for this long.
	UDPHostSeconds int `json:"udp_host_seconds"`
	// wireguard, openvpn: data packets allowed after the handshake.
	MaxData int `json:"max_data_packets"`
	// sni: read the ClientHello from the TCP stream rather than from one
	// segment, so splitting it across segments does not hide the name.
	ReassembleHello bool `json:"reassemble_hello"`
	// encapsulated_tls: within the first WithinPackets packets, at least
	// MinClientPackets client packets of MinClientSize bytes or more, and the
	// server sending more often than the client.
	MinClientPackets int  `json:"min_client_packets"`
	MinClientSize    int  `json:"min_client_size"`
	WithinPackets    int  `json:"within_packets"`
	OnlyUnknown      bool `json:"only_unknown"`
	// tls_rate: more than MaxConns ClientHellos with SNI from one client to
	// one server within WindowSeconds; ByFingerprint keys it by JA4 too.
	MaxConns      int  `json:"max_conns"`
	WindowSeconds int  `json:"window_seconds"`
	ByFingerprint bool `json:"by_fingerprint"`
	// police: flows of these protocols, after AfterBytes, held to RateKbit.
	Protocols  []string `json:"protocols"`
	AfterBytes int      `json:"after_bytes"`
	RateKbit   int      `json:"rate_kbit"`

	nets, sniNets []*net.IPNet
}

type Decision struct {
	T      int64  `json:"t"`
	Rule   string `json:"rule"`
	Action string `json:"action"`
	Flow   string `json:"flow,omitempty"`
	// The packet the decision was made on: its direction and transport
	// payload length, so a capture can show the decision on that packet.
	Dir    string `json:"dir,omitempty"`
	Len    *int   `json:"len,omitempty"`
	Detail string `json:"detail,omitempty"`
	Source string `json:"source,omitempty"`
}

type block struct {
	rule     *Rule
	action   string
	until    time.Time // zero: until the flow goes idle
	passLeft int
	affected int
	// police: token bucket, bytes.
	tokens float64
	last   time.Time
}

type flow struct {
	// ClientHello bytes gathered from the client's first segments, and what
	// this packet made of them (see judge).
	helloBuf     []byte
	helloSettled bool
	segHello     bool
	segSNI       string
	streamHello  bool
	streamSNI    string
	lastSeen     time.Time
	packets      int
	sni          string
	wgInit, wgUp bool
	ovpn         bool
	dataCount    int
	block        *block
	facts        Facts
	// Per direction: packets carrying payload, and payload bytes.
	c2sData, s2cData   int
	c2sBytes, s2cBytes int
	largeClient        int
}

// hostKey is a client and a server address, for blocks that outlive a flow.
type hostKey struct {
	client, server [4]byte
	proto          uint8
}

type hostBlock struct {
	rule     *Rule
	until    time.Time
	affected int
}

// rateKey is what tls_rate counts connections by.
type rateKey struct {
	client, server [4]byte
	fp             string
}

type fragKey struct {
	src, dst [4]byte
	proto    uint8
	id       uint16
}

type fragEntry struct {
	key  FlowKey
	seen time.Time
}

// The TSPU keeps fragments for about 5 s while reassembling (Xue et al.,
// IMC 2022, section 5.3.1); a later fragment older than that is on its own.
const fragHold = 5 * time.Second

// attribute gives a non-first IP fragment the flow of its first fragment, so
// per-flow counts and blocks cover the whole datagram.
func (c *Censor) attribute(p *Packet, now time.Time) {
	if p.FragOff == 0 && !p.MoreFrags {
		return
	}
	k := fragKey{p.Src, p.Dst, p.Proto, p.FragID}
	if p.FragOff == 0 {
		c.frags[k] = fragEntry{p.Key, now}
		return
	}
	if e, ok := c.frags[k]; ok && now.Sub(e.seen) <= fragHold {
		p.Key = e.key
		if !p.MoreFrags {
			delete(c.frags, k)
		}
	}
}

// helloCap bounds how much of a client's opening the censor buffers looking
// for a ClientHello; past it, or past helloSegs segments, it gives up.
const (
	helloCap  = 16 << 10
	helloSegs = 8
)

// readHello sets what this packet reveals of a ClientHello: in the segment
// alone (segHello) and in the stream so far (streamHello). Both are cleared
// for every packet, so a rule only ever reacts to the packet that completed
// the hello.
func (c *Censor) readHello(f *flow, p Packet) {
	f.segHello, f.streamHello = false, false
	if f.helloSettled || p.Dir != dirC2S || p.Proto != 6 || len(p.Payload) == 0 {
		return
	}
	if sni, ok := clientHelloSNI(p.Payload); ok {
		f.segHello, f.segSNI, f.sni = true, sni, sni
	}
	f.helloBuf = append(f.helloBuf, p.Payload...)
	b := f.helloBuf
	if b[0] != 0x16 || len(b) > helloCap || f.packets > helloSegs*2 {
		f.helloSettled, f.helloBuf = true, nil
		return
	}
	if len(b) >= 5 && len(b) >= 5+(int(b[3])<<8|int(b[4])) {
		if sni, ok := clientHelloSNI(b); ok {
			f.streamHello, f.streamSNI, f.sni = true, sni, sni
		}
		f.helloSettled, f.helloBuf = true, nil
	}
}

type verdictKind int

const (
	passPacket verdictKind = iota
	dropPacket
	rewriteRST
	// injectReply: drop the packet and send Reply (a whole IP packet) back
	// to where it came from.
	injectReply
)

type verdict struct {
	kind  verdictKind
	reply []byte
}

type Censor struct {
	mu         sync.Mutex
	preset     *Preset
	cls        Classifier
	flows      map[FlowKey]*flow
	frags      map[fragKey]fragEntry
	hostBlocks map[hostKey]*hostBlock
	helloTimes map[rateKey][]time.Time
	rateBlocks map[rateKey]*hostBlock
	cnet       *net.IPNet
	snet       *net.IPNet
	logMu      sync.Mutex
	log        io.Writer
	// live: decisions are logged from a goroutine so the forwarding path
	// never waits on the disk. A replay logs inline to keep the order.
	live bool
	// onDecision, when set, also receives every decision (replay summary).
	onDecision func(Decision)
}

func newCensor(cnet, snet *net.IPNet, log io.Writer) *Censor {
	return &Censor{
		cls:        defaultClassifier(),
		flows:      map[FlowKey]*flow{},
		frags:      map[fragKey]fragEntry{},
		hostBlocks: map[hostKey]*hostBlock{},
		helloTimes: map[rateKey][]time.Time{},
		rateBlocks: map[rateKey]*hostBlock{},
		cnet:       cnet,
		snet:       snet,
		log:        log,
		live:       true,
	}
}

func (c *Censor) emit(d Decision) {
	if c.live {
		go c.event(d)
	} else {
		c.event(d)
	}
}

func (c *Censor) event(d Decision) {
	if d.T == 0 {
		d.T = time.Now().UnixMilli()
	}
	if c.onDecision != nil {
		c.onDecision(d)
	}
	b, _ := json.Marshal(d)
	c.logMu.Lock()
	_, _ = c.log.Write(append(b, '\n'))
	c.logMu.Unlock()
}

// decide logs a decision about packet p.
func (c *Censor) decide(r *Rule, action string, p Packet, now time.Time, detail string) {
	c.emit(Decision{T: now.UnixMilli(), Rule: r.ID, Action: action, Flow: p.Key.String(), Dir: p.Dir.String(), Len: payloadLen(p), Detail: detail, Source: r.Source})
}

// Statistics derived from timeouts measured on the TSPU: an idle
// ESTABLISHED flow is forgotten after 480 s (Xue et al., IMC 2022, Table 2).
const flowIdle = 480 * time.Second

func (c *Censor) gcLoop() {
	for range time.Tick(10 * time.Second) {
		c.gc(time.Now())
	}
}

func (c *Censor) gc(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, f := range c.flows {
		if now.Sub(f.lastSeen) > flowIdle {
			delete(c.flows, k)
			c.cls.Forget(k)
		}
	}
	for k, e := range c.frags {
		if now.Sub(e.seen) > fragHold {
			delete(c.frags, k)
		}
	}
	for k, b := range c.hostBlocks {
		if now.After(b.until) {
			delete(c.hostBlocks, k)
		}
	}
	for k, b := range c.rateBlocks {
		if now.After(b.until) {
			delete(c.rateBlocks, k)
		}
	}
	for k, ts := range c.helloTimes {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > 10*time.Minute {
			delete(c.helloTimes, k)
		}
	}
}

func (c *Censor) watchPreset(path string) {
	var lastMod time.Time
	var present bool
	for {
		st, err := os.Stat(path)
		switch {
		case err != nil && present:
			present = false
			c.setPreset(nil)
			c.event(Decision{Rule: "-", Action: "preset", Detail: "off (no preset file): traffic passes untouched"})
		case err == nil && (!present || st.ModTime() != lastMod):
			present, lastMod = true, st.ModTime()
			p, perr := loadPreset(path)
			if perr != nil {
				c.event(Decision{Rule: "-", Action: "error", Detail: "preset not loaded, previous one stays: " + perr.Error()})
			} else {
				c.setPreset(p)
				c.event(Decision{Rule: "-", Action: "preset", Detail: c.describe(p)})
			}
		}
		time.Sleep(time.Second)
	}
}

// describe says which rules of p are active, and which this classifier
// cannot serve.
func (c *Censor) describe(p *Preset) string {
	on := 0
	var blind []string
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Disabled {
			continue
		}
		on++
		if why := needs(r, c.cls.Caps()); why != "" {
			blind = append(blind, r.ID+" ("+why+")")
		}
	}
	s := fmt.Sprintf("%s (as of %s), %d rules active, classifier %s", p.Name, p.AsOf, on, c.cls.Name())
	if len(blind) > 0 {
		s += "; cannot fire with this classifier: " + strings.Join(blind, ", ")
	}
	return s
}

// needs names what rule r requires that a classifier with caps lacks.
func needs(r *Rule, caps Caps) string {
	switch {
	case r.Kind == "quic_sni" && !caps.QUICSNI:
		return "QUIC Initial decryption, nDPI"
	case r.Kind == "tls_rate" && r.ByFingerprint && !caps.JA4:
		return "JA4, nDPI; counts all fingerprints together"
	case r.Kind == "dns_udp" && !caps.DNS:
		return "DNS parsing"
	}
	return ""
}

var kinds = map[string][]string{
	"sni":              {"rst_s2c", "drop_both", "drop_s2c"},
	"quic_v1":          {"drop_both"},
	"quic_sni":         {"drop_both"},
	"ip":               {"drop_both"},
	"freeze":           {"drop_s2c", "drop_both"},
	"wireguard":        {"drop_both"},
	"openvpn":          {"drop_both"},
	"encapsulated_tls": {"drop_both", "drop_s2c"},
	"tls_rate":         {"drop_both"},
	"dns_udp":          {"nxdomain"},
	"police":           {"police"},
	"whitelist":        {"drop_payload"},
}

func loadPreset(path string) (*Preset, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Preset
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		actions, ok := kinds[r.Kind]
		if !ok {
			return nil, fmt.Errorf("rule %s: unknown kind %q", r.ID, r.Kind)
		}
		if !contains(actions, r.Action) {
			return nil, fmt.Errorf("rule %s: a %s rule takes action %s, not %q", r.ID, r.Kind, strings.Join(actions, " or "), r.Action)
		}
		if r.Source == "" {
			return nil, fmt.Errorf("rule %s has no source; every rule must cite what it reproduces", r.ID)
		}
		if err := checkParams(r); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		for _, s := range r.CIDRs {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			r.nets = append(r.nets, n)
		}
		for _, s := range r.SNICIDRs {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			r.sniNets = append(r.sniNets, n)
		}
		for j, d := range r.Domains {
			r.Domains[j] = strings.ToLower(strings.TrimPrefix(d, "."))
		}
		for j, d := range r.AllowSNI {
			r.AllowSNI[j] = strings.ToLower(strings.TrimPrefix(d, "."))
		}
	}
	return &p, nil
}

// checkParams refuses a rule missing what its kind cannot work without: a
// rule that silently never fires would read as "the censor let it through".
func checkParams(r *Rule) error {
	switch r.Kind {
	case "sni", "quic_sni", "dns_udp":
		if len(r.Domains) == 0 {
			return fmt.Errorf("needs domains")
		}
	case "freeze":
		if r.CountBytes && r.MaxS2CBytes <= 0 {
			return fmt.Errorf("count_bytes needs max_s2c_bytes")
		}
		if !r.CountBytes && r.AfterPackets <= 0 {
			return fmt.Errorf("needs after_packets (or count_bytes with max_s2c_bytes)")
		}
	case "encapsulated_tls":
		if r.MinClientPackets <= 0 || r.MinClientSize <= 0 || r.WithinPackets <= 0 {
			return fmt.Errorf("needs min_client_packets, min_client_size and within_packets")
		}
	case "tls_rate":
		if r.MaxConns <= 0 || r.WindowSeconds <= 0 || r.BlockSeconds <= 0 {
			return fmt.Errorf("needs max_conns, window_seconds and block_seconds")
		}
	case "police":
		if r.RateKbit <= 0 || len(r.Protocols) == 0 {
			return fmt.Errorf("needs protocols and rate_kbit")
		}
	case "whitelist":
		if len(r.CIDRs) == 0 {
			return fmt.Errorf("needs cidrs: the allowed networks")
		}
	}
	return nil
}

func contains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (c *Censor) setPreset(p *Preset) {
	c.mu.Lock()
	c.preset = p
	// Blocks belong to the rules that made them; a new preset starts clean.
	for k := range c.flows {
		c.cls.Forget(k)
	}
	c.flows = map[FlowKey]*flow{}
	c.hostBlocks = map[hostKey]*hostBlock{}
	c.helloTimes = map[rateKey][]time.Time{}
	c.rateBlocks = map[rateKey]*hostBlock{}
	c.mu.Unlock()
}

func domainMatch(host string, list []string) bool {
	for _, d := range list {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func inNets(ip [4]byte, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(net.IP(ip[:])) {
			return true
		}
	}
	return false
}

// portMatch: an empty list means every port.
func portMatch(port uint16, ports []int) bool {
	return len(ports) == 0 || contains(ports, int(port))
}

// judge decides one packet. Called for every forwarded packet, so it holds
// the lock only for map and flow updates and logs outside the hot path.
// now is the packet's time: the wall clock when routing, the capture
// timestamp when replaying a file, so block expiry follows the traffic.
func (c *Censor) judge(p Packet, now time.Time) verdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.preset == nil {
		return verdict{kind: passPacket}
	}
	if p.Proto != 6 && p.Proto != 17 {
		// Only a whitelist has an opinion about ICMP and the rest.
		for i := range c.preset.Rules {
			r := &c.preset.Rules[i]
			if !r.Disabled && r.Kind == "whitelist" && !inNets(p.Key.ServerIP, r.nets) {
				return verdict{kind: dropPacket}
			}
		}
		return verdict{kind: passPacket}
	}
	c.attribute(&p, now)
	f := c.flows[p.Key]
	if f == nil {
		f = &flow{}
		c.flows[p.Key] = f
	}
	f.lastSeen = now
	f.packets++
	if len(p.Payload) > 0 {
		if p.Dir == dirC2S {
			f.c2sData++
			f.c2sBytes += len(p.Payload)
		} else {
			f.s2cData++
			f.s2cBytes += len(p.Payload)
		}
	}
	if !f.facts.Done && f.packets <= classifyPackets && p.Raw != nil {
		f.facts = c.cls.Observe(p, now)
	}

	hk := hostKey{p.Key.ClientIP, p.Key.ServerIP, p.Proto}
	if hb := c.hostBlocks[hk]; hb != nil {
		if now.After(hb.until) {
			delete(c.hostBlocks, hk)
			c.decide(hb.rule, "expired", p, now, fmt.Sprintf("host block lifted, %d packets affected", hb.affected))
		} else {
			hb.affected++
			return verdict{kind: dropPacket}
		}
	}

	if b := f.block; b != nil {
		if !b.until.IsZero() && now.After(b.until) {
			c.decide(b.rule, "expired", p, now, fmt.Sprintf("block lifted after %d s, %d packets affected", b.rule.BlockSeconds, b.affected))
			f.block = nil
		} else {
			if b.rule.Kind == "quic_sni" && b.rule.RestartOnTrigger && isQUICInitial(p) && b.rule.BlockSeconds > 0 {
				b.until = now.Add(time.Duration(b.rule.BlockSeconds) * time.Second)
			}
			return c.apply(b, p, now)
		}
	}

	c.readHello(f, p)

	for i := range c.preset.Rules {
		r := &c.preset.Rules[i]
		if r.Disabled {
			continue
		}
		if v, hit := c.match(r, f, p, now); hit {
			return v
		}
	}
	return verdict{kind: passPacket}
}

func isQUICInitial(p Packet) bool {
	pl := p.Payload
	return p.Proto == 17 && p.Dir == dirC2S && len(pl) >= 5 && pl[0]&0xb0 == 0x80 // long header, type Initial (v1)
}

func (c *Censor) trigger(r *Rule, f *flow, p Packet, now time.Time, detail string, dropThis bool) verdict {
	b := &block{rule: r, action: r.Action, last: now}
	if r.BlockSeconds > 0 {
		b.until = now.Add(time.Duration(r.BlockSeconds) * time.Second)
	}
	if r.Kind == "sni" {
		b.passLeft = r.AfterPackets
	}
	f.block = b
	c.decide(r, r.Action, p, now, detail)
	if dropThis {
		b.affected++
		return verdict{kind: dropPacket}
	}
	return verdict{kind: passPacket}
}

func (c *Censor) apply(b *block, p Packet, now time.Time) verdict {
	if b.passLeft > 0 {
		b.passLeft--
		return verdict{kind: passPacket}
	}
	switch b.action {
	case "drop_both":
		b.affected++
		return verdict{kind: dropPacket}
	case "drop_s2c":
		if p.Dir == dirS2C {
			b.affected++
			return verdict{kind: dropPacket}
		}
	case "rst_s2c":
		if p.Dir == dirS2C && p.Proto == 6 && p.TCPFlags&tcpRST == 0 {
			b.affected++
			return verdict{kind: rewriteRST}
		}
	case "drop_payload":
		if p.Proto != 6 || len(p.Payload) > 0 {
			b.affected++
			return verdict{kind: dropPacket}
		}
	case "police":
		// Token bucket holding one second of the rate: a policer, which
		// drops what exceeds it (a shaper would queue).
		rate := float64(b.rule.RateKbit) * 1000 / 8
		b.tokens += now.Sub(b.last).Seconds() * rate
		if b.tokens > rate {
			b.tokens = rate
		}
		b.last = now
		size := float64(len(p.Raw))
		if size == 0 {
			size = float64(len(p.Payload) + 40)
		}
		if b.tokens < size {
			b.affected++
			return verdict{kind: dropPacket}
		}
		b.tokens -= size
	}
	return verdict{kind: passPacket}
}

func (c *Censor) match(r *Rule, f *flow, p Packet, now time.Time) (verdict, bool) {
	switch r.Kind {
	case "sni":
		hello, sni, how := f.segHello, f.segSNI, "in one segment"
		if r.ReassembleHello {
			hello, sni, how = f.streamHello, f.streamSNI, "reassembled from the stream"
		}
		if hello && sni != "" && domainMatch(sni, r.Domains) {
			return c.trigger(r, f, p, now, "ClientHello SNI "+sni+", "+how, r.DropTrigger), true
		}
	case "quic_v1":
		pl := p.Payload
		if p.Dir == dirC2S && p.Proto == 17 && int(p.Key.ServerPort) == r.Port && len(pl) >= r.MinPayload &&
			len(pl) >= 5 && pl[0]&0x80 != 0 && bytes.Equal(pl[1:5], []byte{0, 0, 0, 1}) {
			return c.trigger(r, f, p, now, fmt.Sprintf("QUIC v1 long header, %d byte payload", len(pl)), true), true
		}
	case "quic_sni":
		fa := f.facts
		if p.Dir == dirC2S && p.Proto == 17 && fa.Proto == "QUIC" && fa.Host != "" &&
			(len(r.QUICVersions) == 0 || contains(r.QUICVersions, fa.QUICVersion)) && domainMatch(fa.Host, r.Domains) {
			return c.trigger(r, f, p, now, fmt.Sprintf("QUIC Initial (version %#x) SNI %s", fa.QUICVersion, fa.Host), true), true
		}
	case "ip":
		if inNets(p.Key.ServerIP, r.nets) {
			c.decide(r, r.Action, p, now, "address on the block list")
			return verdict{kind: dropPacket}, true
		}
	case "freeze":
		return c.matchFreeze(r, f, p, now)
	case "wireguard":
		pl := p.Payload
		if p.Proto != 17 || len(pl) < 4 || pl[1] != 0 || pl[2] != 0 || pl[3] != 0 {
			return verdict{}, false
		}
		switch {
		case pl[0] == 1 && len(pl) == 148 && p.Dir == dirC2S:
			f.wgInit = true
		case pl[0] == 2 && len(pl) == 92 && p.Dir == dirS2C && f.wgInit:
			f.wgUp = true
		case pl[0] == 4 && f.wgUp:
			f.dataCount++
			if f.dataCount > r.MaxData {
				return c.trigger(r, f, p, now, fmt.Sprintf("WireGuard handshake then %d data packets", f.dataCount), true), true
			}
		}
	case "openvpn":
		pl := p.Payload
		if p.Proto == 6 && len(pl) >= 3 {
			pl = pl[2:] // TCP framing: 2-byte length prefix
		}
		if len(pl) < 1 {
			return verdict{}, false
		}
		op := pl[0] >> 3
		switch {
		case (op == 7 || op == 10) && p.Dir == dirC2S:
			f.ovpn = true
		case (op == 6 || op == 9) && f.ovpn:
			f.dataCount++
			if f.dataCount > r.MaxData {
				return c.trigger(r, f, p, now, fmt.Sprintf("OpenVPN handshake then %d data packets", f.dataCount), true), true
			}
		}
	case "encapsulated_tls":
		return c.matchEncapsulated(r, f, p, now)
	case "tls_rate":
		return c.matchTLSRate(r, f, p, now)
	case "dns_udp":
		fa := f.facts
		if p.Proto == 17 && p.Dir == dirC2S && p.Key.ServerPort == 53 && fa.Proto == "DNS" && domainMatch(fa.Host, r.Domains) {
			reply := nxdomainReply(p)
			if reply == nil {
				return verdict{}, false
			}
			c.decide(r, r.Action, p, now, "UDP DNS query for "+fa.Host+" answered NXDOMAIN in the resolver's name")
			return verdict{kind: injectReply, reply: reply}, true
		}
	case "police":
		if (len(r.nets) > 0 && !inNets(p.Key.ServerIP, r.nets)) || !contains(r.Protocols, f.facts.Proto) {
			return verdict{}, false
		}
		if f.c2sBytes+f.s2cBytes > r.AfterBytes {
			f.block = &block{rule: r, action: "police", last: now, tokens: float64(r.RateKbit) * 1000 / 8}
			c.decide(r, r.Action, p, now, fmt.Sprintf("%s flow past %d bytes, held to %d kbit/s", f.facts.Proto, r.AfterBytes, r.RateKbit))
			return c.apply(f.block, p, now), true
		}
	case "whitelist":
		if inNets(p.Key.ServerIP, r.nets) {
			return verdict{}, false
		}
		if f.sni != "" && domainMatch(f.sni, r.AllowSNI) && (!r.SNITiedToCIDR || inNets(p.Key.ServerIP, r.sniNets)) {
			return verdict{}, false
		}
		if p.Proto == 6 && len(p.Payload) == 0 {
			return verdict{}, false // the handshake goes through; the first data does not
		}
		return c.trigger(r, f, p, now, "server not on the allow list", true), true
	}
	return verdict{}, false
}

func (c *Censor) matchFreeze(r *Rule, f *flow, p Packet, now time.Time) (verdict, bool) {
	if !inNets(p.Key.ServerIP, r.nets) || contains(r.ExemptProtocols, f.facts.Proto) || (r.ExemptRDP && f.facts.Proto == "RDP") {
		return verdict{}, false
	}
	if f.sni != "" && domainMatch(f.sni, r.AllowSNI) && (!r.SNITiedToCIDR || inNets(p.Key.ServerIP, r.sniNets)) {
		return verdict{}, false
	}
	var over bool
	var detail string
	if r.CountBytes {
		over = f.s2cBytes > r.MaxS2CBytes
		detail = fmt.Sprintf("%d bytes from the server in the flow", f.s2cBytes)
	} else {
		over = f.packets > r.AfterPackets
		detail = fmt.Sprintf("%d packets in the flow", f.packets-1)
	}
	if !over {
		return verdict{}, false
	}
	if p.Proto == 17 && r.UDPHostSeconds > 0 {
		hk := hostKey{p.Key.ClientIP, p.Key.ServerIP, 17}
		c.hostBlocks[hk] = &hostBlock{rule: r, until: now.Add(time.Duration(r.UDPHostSeconds) * time.Second), affected: 1}
		c.decide(r, "drop_both", p, now, fmt.Sprintf("%s; all UDP from this client to this server blocked for %d s", detail, r.UDPHostSeconds))
		return verdict{kind: dropPacket}, true
	}
	return c.trigger(r, f, p, now, detail, p.Dir == dirS2C || r.Action == "drop_both"), true
}

func (c *Censor) matchEncapsulated(r *Rule, f *flow, p Packet, now time.Time) (verdict, bool) {
	if p.Proto != 6 || f.packets > r.WithinPackets || (len(r.nets) > 0 && !inNets(p.Key.ServerIP, r.nets)) || !portMatch(p.Key.ServerPort, r.Ports) {
		return verdict{}, false
	}
	if r.OnlyUnknown && f.facts.Proto != "" && f.facts.Proto != "Unknown" {
		return verdict{}, false
	}
	if p.Dir == dirC2S && len(p.Payload) >= r.MinClientSize {
		f.largeClient++
	}
	if f.largeClient >= r.MinClientPackets && f.s2cData > f.c2sData {
		return c.trigger(r, f, p, now, fmt.Sprintf("%d client packets of %d+ bytes, server sent %d data packets to the client's %d",
			f.largeClient, r.MinClientSize, f.s2cData, f.c2sData), true), true
	}
	return verdict{}, false
}

func (c *Censor) matchTLSRate(r *Rule, f *flow, p Packet, now time.Time) (verdict, bool) {
	hello := f.segHello || f.streamHello
	if p.Proto != 6 || p.Dir != dirC2S || !hello || f.sni == "" || !portMatch(p.Key.ServerPort, r.Ports) ||
		(len(r.nets) > 0 && !inNets(p.Key.ServerIP, r.nets)) {
		return verdict{}, false
	}
	k := rateKey{client: p.Key.ClientIP, server: p.Key.ServerIP}
	if r.ByFingerprint {
		k.fp = f.facts.JA4
	}
	if b := c.rateBlocks[k]; b != nil && now.Before(b.until) {
		b.affected++
		return c.trigger(r, f, p, now, fmt.Sprintf("ClientHello while this client's connections to the server are blocked (until %s)", b.until.Format("15:04:05")), true), true
	}
	window := time.Duration(r.WindowSeconds) * time.Second
	ts := append(c.helloTimes[k], now)
	for len(ts) > 0 && now.Sub(ts[0]) > window {
		ts = ts[1:]
	}
	c.helloTimes[k] = ts
	if len(ts) > r.MaxConns {
		c.rateBlocks[k] = &hostBlock{rule: r, until: now.Add(time.Duration(r.BlockSeconds) * time.Second)}
		fp := "all fingerprints"
		if k.fp != "" {
			fp = "JA4 " + k.fp
		}
		return c.trigger(r, f, p, now, fmt.Sprintf("%d TLS connections with SNI to one server within %d s (%s); new ones blocked for %d s",
			len(ts), r.WindowSeconds, fp, r.BlockSeconds), true), true
	}
	return verdict{}, false
}

func payloadLen(p Packet) *int {
	n := len(p.Payload)
	return &n
}
