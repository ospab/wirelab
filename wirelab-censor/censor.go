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
	Name  string `json:"name"`
	AsOf  string `json:"as_of"`
	Notes string `json:"notes"`
	Rules []Rule `json:"rules"`
}

type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`   // sni, quic_v1, ip, freeze, wireguard, openvpn
	Action   string `json:"action"` // rst_s2c, drop_both, drop_s2c
	Source   string `json:"source"`
	Disabled bool   `json:"disabled"`

	Domains      []string `json:"domains"`       // sni
	DropTrigger  bool     `json:"drop_trigger"`  // sni: the ClientHello itself is dropped
	AfterPackets int      `json:"after_packets"` // sni: packets let through after the trigger; freeze: packets before it
	BlockSeconds int      `json:"block_seconds"` // 0: for the rest of the flow
	Port         int      `json:"port"`          // quic_v1
	MinPayload   int      `json:"min_payload"`   // quic_v1
	CIDRs        []string `json:"cidrs"`         // ip; freeze: servers it applies to
	AllowSNI     []string `json:"allow_sni"`     // freeze
	ExemptSSH    bool     `json:"exempt_ssh"`    // freeze
	MaxData      int      `json:"max_data_packets"`

	nets []*net.IPNet
}

type Decision struct {
	T      int64  `json:"t"`
	Rule   string `json:"rule"`
	Action string `json:"action"`
	Flow   string `json:"flow,omitempty"`
	Detail string `json:"detail,omitempty"`
	Source string `json:"source,omitempty"`
}

type block struct {
	rule     *Rule
	action   string
	until    time.Time // zero: until the flow goes idle
	passLeft int
	affected int
}

type flow struct {
	lastSeen     time.Time
	packets      int
	helloDone    bool
	sni          string
	ssh          bool
	payloadSeen  bool
	wgInit, wgUp bool
	ovpn         bool
	dataCount    int
	block        *block
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

type verdictKind int

const (
	passPacket verdictKind = iota
	dropPacket
	rewriteRST
)

type verdict struct{ kind verdictKind }

type Censor struct {
	mu     sync.Mutex
	preset *Preset
	flows  map[FlowKey]*flow
	frags  map[fragKey]fragEntry
	cnet   *net.IPNet
	snet   *net.IPNet
	logMu  sync.Mutex
	log    io.Writer
	// live: decisions are logged from a goroutine so the forwarding path
	// never waits on the disk. A replay logs inline to keep the order.
	live bool
	// onDecision, when set, also receives every decision (replay summary).
	onDecision func(Decision)
}

func newCensor(cnet, snet *net.IPNet, log io.Writer) *Censor {
	return &Censor{flows: map[FlowKey]*flow{}, frags: map[fragKey]fragEntry{}, cnet: cnet, snet: snet, log: log, live: true}
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

// Statistics derived from timeouts measured on the TSPU: an idle
// ESTABLISHED flow is forgotten after 480 s (Xue et al., IMC 2022, Table 2).
const flowIdle = 480 * time.Second

func (c *Censor) gcLoop() {
	for range time.Tick(10 * time.Second) {
		c.mu.Lock()
		for k, f := range c.flows {
			if time.Since(f.lastSeen) > flowIdle {
				delete(c.flows, k)
			}
		}
		for k, e := range c.frags {
			if time.Since(e.seen) > fragHold {
				delete(c.frags, k)
			}
		}
		c.mu.Unlock()
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
				on := 0
				for _, r := range p.Rules {
					if !r.Disabled {
						on++
					}
				}
				c.event(Decision{Rule: "-", Action: "preset", Detail: fmt.Sprintf("%s (as of %s), %d rules active", p.Name, p.AsOf, on)})
			}
		}
		time.Sleep(time.Second)
	}
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
		switch r.Kind {
		case "sni", "quic_v1", "ip", "freeze", "wireguard", "openvpn":
		default:
			return nil, fmt.Errorf("rule %s: unknown kind %q", r.ID, r.Kind)
		}
		switch r.Action {
		case "rst_s2c", "drop_both", "drop_s2c":
		default:
			return nil, fmt.Errorf("rule %s: unknown action %q", r.ID, r.Action)
		}
		if r.Source == "" {
			return nil, fmt.Errorf("rule %s has no source; every rule must cite what it reproduces", r.ID)
		}
		for _, s := range r.CIDRs {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			r.nets = append(r.nets, n)
		}
		for j, d := range r.Domains {
			r.Domains[j] = strings.ToLower(strings.TrimPrefix(d, "."))
		}
	}
	return &p, nil
}

func (c *Censor) setPreset(p *Preset) {
	c.mu.Lock()
	c.preset = p
	// Blocks belong to the rules that made them; a new preset starts clean.
	c.flows = map[FlowKey]*flow{}
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

// judge decides one packet. Called for every forwarded packet, so it holds
// the lock only for map and flow updates and logs outside the hot path.
// now is the packet's time: the wall clock when routing, the capture
// timestamp when replaying a file, so block expiry follows the traffic.
func (c *Censor) judge(p Packet, now time.Time) verdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.preset == nil || (p.Proto != 6 && p.Proto != 17) {
		return verdict{passPacket}
	}
	c.attribute(&p, now)
	f := c.flows[p.Key]
	if f == nil {
		f = &flow{}
		c.flows[p.Key] = f
	}
	f.lastSeen = now
	f.packets++

	if b := f.block; b != nil {
		if !b.until.IsZero() && now.After(b.until) {
			c.emit(Decision{T: now.UnixMilli(), Rule: b.rule.ID, Action: "expired", Flow: p.Key.String(),
				Detail: fmt.Sprintf("block lifted after %d s, %d packets affected", b.rule.BlockSeconds, b.affected)})
			f.block = nil
		} else {
			return c.apply(b, p)
		}
	}

	if len(p.Payload) > 0 && !f.payloadSeen {
		f.payloadSeen = true
		f.ssh = bytes.HasPrefix(p.Payload, []byte("SSH-"))
	}

	for i := range c.preset.Rules {
		r := &c.preset.Rules[i]
		if r.Disabled {
			continue
		}
		if v, hit := c.match(r, f, p, now); hit {
			return v
		}
	}
	return verdict{passPacket}
}

func (c *Censor) trigger(r *Rule, f *flow, p Packet, now time.Time, detail string, dropThis bool) verdict {
	b := &block{rule: r, action: r.Action}
	if r.BlockSeconds > 0 {
		b.until = now.Add(time.Duration(r.BlockSeconds) * time.Second)
	}
	if r.Kind == "sni" {
		b.passLeft = r.AfterPackets
	}
	f.block = b
	c.emit(Decision{T: now.UnixMilli(), Rule: r.ID, Action: r.Action, Flow: p.Key.String(), Detail: detail, Source: r.Source})
	if dropThis {
		b.affected++
		return verdict{dropPacket}
	}
	return verdict{passPacket}
}

func (c *Censor) apply(b *block, p Packet) verdict {
	if b.passLeft > 0 {
		b.passLeft--
		return verdict{passPacket}
	}
	switch b.action {
	case "drop_both":
		b.affected++
		return verdict{dropPacket}
	case "drop_s2c":
		if p.Dir == dirS2C {
			b.affected++
			return verdict{dropPacket}
		}
	case "rst_s2c":
		if p.Dir == dirS2C && p.Proto == 6 && p.TCPFlags&tcpRST == 0 {
			b.affected++
			return verdict{rewriteRST}
		}
	}
	return verdict{passPacket}
}

func (c *Censor) match(r *Rule, f *flow, p Packet, now time.Time) (verdict, bool) {
	switch r.Kind {
	case "sni":
		if p.Dir != dirC2S || p.Proto != 6 || len(p.Payload) == 0 || f.helloDone {
			return verdict{}, false
		}
		sni, isHello := clientHelloSNI(p.Payload)
		if !isHello {
			return verdict{}, false
		}
		f.helloDone, f.sni = true, sni
		if sni != "" && domainMatch(sni, r.Domains) {
			return c.trigger(r, f, p, now, "ClientHello SNI "+sni, r.DropTrigger), true
		}
		// Later sni rules must still see this hello.
		f.helloDone = false
	case "quic_v1":
		pl := p.Payload
		if p.Dir == dirC2S && p.Proto == 17 && int(p.Key.ServerPort) == r.Port && len(pl) >= r.MinPayload &&
			len(pl) >= 5 && pl[0]&0x80 != 0 && bytes.Equal(pl[1:5], []byte{0, 0, 0, 1}) {
			return c.trigger(r, f, p, now, fmt.Sprintf("QUIC v1 long header, %d byte payload", len(pl)), true), true
		}
	case "ip":
		if inNets(p.Key.ServerIP, r.nets) {
			c.emit(Decision{T: now.UnixMilli(), Rule: r.ID, Action: r.Action, Flow: p.Key.String(), Detail: "address on the block list", Source: r.Source})
			return verdict{dropPacket}, true
		}
	case "freeze":
		if !inNets(p.Key.ServerIP, r.nets) || (r.ExemptSSH && f.ssh) || (f.sni != "" && domainMatch(f.sni, r.AllowSNI)) {
			return verdict{}, false
		}
		if f.packets > r.AfterPackets {
			return c.trigger(r, f, p, now, fmt.Sprintf("%d packets in the flow", f.packets-1), p.Dir == dirS2C), true
		}
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
	}
	return verdict{}, false
}
