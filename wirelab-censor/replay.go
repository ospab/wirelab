package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// Lab addresses the presets are written against. A replay of a capture from
// elsewhere maps them onto that capture's networks.
const (
	labClientNet = "10.77.1.0/24"
	labServerNet = "10.77.2.0/24"
)

type replayFlow struct {
	key       FlowKey
	packets   int
	first     time.Time
	hitAt     int // packet number in the flow at the first block, 0 if none
	hitRule   string
	hitAction string
	hitDetail string
	hitT      time.Time
}

func runReplay(capPath, presetPath, logOut string, cnet, snet *net.IPNet, w io.Writer) error {
	raw, err := os.ReadFile(capPath)
	if err != nil {
		return err
	}
	frames, skipped, err := readCapture(raw)
	if err != nil && len(frames) == 0 {
		return fmt.Errorf("%s: %w", capPath, err)
	}
	truncated := err

	preset, err := loadPreset(presetPath)
	if err != nil {
		return fmt.Errorf("%s: %w", presetPath, err)
	}
	mapped := retarget(preset, cnet, snet)

	var sink io.Writer = io.Discard
	if logOut != "" {
		f, err := os.Create(logOut)
		if err != nil {
			return err
		}
		defer f.Close()
		sink = f
	}
	c := newCensor(cnet, snet, sink)
	c.live = false
	c.setPreset(preset)

	flows := map[FlowKey]*replayFlow{}
	var order []*replayFlow
	var current *replayFlow
	c.onDecision = func(d Decision) {
		if current != nil && current.hitAt == 0 && d.Action != "expired" {
			current.hitAt, current.hitRule, current.hitAction, current.hitDetail = current.packets, d.Rule, d.Action, d.Detail
			current.hitT = time.UnixMilli(d.T)
		}
	}

	judged, outside := 0, 0
	var start, end time.Time
	for _, fr := range frames {
		ip := fr.IP
		if len(ip) < 20 {
			outside++
			continue
		}
		src, dst := net.IP(ip[12:16]), net.IP(ip[16:20])
		var dir Dir
		switch {
		case cnet.Contains(src) && snet.Contains(dst):
			dir = dirC2S
		case snet.Contains(src) && cnet.Contains(dst):
			dir = dirS2C
		default:
			outside++
			continue
		}
		p, ok := parsePacket(ip, dir)
		if !ok || (p.Proto != 6 && p.Proto != 17) {
			outside++
			continue
		}
		// Account the fragment to its datagram's flow, as judge will.
		c.mu.Lock()
		c.attribute(&p, fr.T)
		c.mu.Unlock()
		if start.IsZero() {
			start = fr.T
		}
		end = fr.T
		rf := flows[p.Key]
		if rf == nil {
			rf = &replayFlow{key: p.Key, first: fr.T}
			flows[p.Key] = rf
			order = append(order, rf)
		}
		rf.packets++
		current = rf
		v := c.judge(p, fr.T)
		if v.kind != passPacket && rf.hitAt == 0 {
			// A block decided by an earlier packet of the flow (an IP rule
			// logs per packet) still counts from here.
			rf.hitAt, rf.hitT = rf.packets, fr.T
		}
		judged++
	}

	fmt.Fprintf(w, "capture   %s\n", capPath)
	fmt.Fprintf(w, "packets   %d judged (tcp/udp between %s and %s), %d outside those, %d not IPv4\n", judged, cnet, snet, outside, skipped)
	if truncated != nil {
		fmt.Fprintf(w, "warning   %v; judged what was readable\n", truncated)
	}
	if judged > 0 {
		fmt.Fprintf(w, "span      %.1f s\n", end.Sub(start).Seconds())
	}
	active := 0
	for _, r := range preset.Rules {
		if !r.Disabled {
			active++
		}
	}
	fmt.Fprintf(w, "preset    %s (as of %s), %d rules active\n", preset.Name, preset.AsOf, active)
	for _, m := range mapped {
		fmt.Fprintf(w, "mapped    %s\n", m)
	}

	byRule := map[string][]*replayFlow{}
	for _, rf := range order {
		if rf.hitAt > 0 {
			byRule[rf.hitRule] = append(byRule[rf.hitRule], rf)
		}
	}
	fmt.Fprintf(w, "\nflows     %d, blocked %d\n", len(order), countHit(order))
	rules := make([]string, 0, len(byRule))
	for r := range byRule {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	for _, r := range rules {
		list := byRule[r]
		fmt.Fprintf(w, "  %s (%s): %d flow(s)\n", r, list[0].hitAction, len(list))
		for i, rf := range list {
			if i == 5 {
				fmt.Fprintf(w, "    ... %d more\n", len(list)-5)
				break
			}
			fmt.Fprintf(w, "    %s  at packet %d of %d, +%.2f s: %s\n", rf.key, rf.hitAt, rf.packets, rf.hitT.Sub(start).Seconds(), rf.hitDetail)
		}
	}
	passed := len(order) - countHit(order)
	fmt.Fprintf(w, "  untouched: %d flow(s)\n", passed)
	fmt.Fprintln(w, "\nA capture records what really happened next. After the first block in a flow,"+
		"\nthe rest of that flow shows the real network, not this preset.")
	return nil
}

func countHit(fs []*replayFlow) int {
	n := 0
	for _, f := range fs {
		if f.hitAt > 0 {
			n++
		}
	}
	return n
}

// retarget points rule addresses written for the lab at the capture's own
// networks, and says what it changed.
func retarget(p *Preset, cnet, snet *net.IPNet) []string {
	var notes []string
	for i := range p.Rules {
		r := &p.Rules[i]
		changed := false
		for j, s := range r.CIDRs {
			switch {
			case s == labServerNet && snet.String() != labServerNet:
				r.CIDRs[j], changed = snet.String(), true
			case s == labClientNet && cnet.String() != labClientNet:
				r.CIDRs[j], changed = cnet.String(), true
			}
		}
		if changed {
			r.nets = nil
			for _, s := range r.CIDRs {
				if _, n, err := net.ParseCIDR(s); err == nil {
					r.nets = append(r.nets, n)
				}
			}
			notes = append(notes, fmt.Sprintf("rule %s now applies to %s", r.ID, strings.Join(r.CIDRs, ", ")))
		}
	}
	return notes
}
