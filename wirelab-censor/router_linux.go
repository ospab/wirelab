//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// route runs the censor as the lab's router between two interfaces.
func route(ifc, ifs, preset, logPath string, cnet, snet *net.IPNet) error {
	dlog, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	c := newCensor(cnet, snet, dlog)
	cport, err := openPort(ifc, cnet)
	if err != nil {
		return err
	}
	sport, err := openPort(ifs, snet)
	if err != nil {
		return err
	}
	go c.watchPreset(preset)
	go c.gcLoop()

	var wg sync.WaitGroup
	wg.Add(2)
	// Client side: frames for the server network go out the server side.
	go func() { defer wg.Done(); c.pump(cport, sport, snet, dirC2S) }()
	go func() { defer wg.Done(); c.pump(sport, cport, cnet, dirS2C) }()
	c.event(Decision{Rule: "-", Action: "start", Detail: fmt.Sprintf("routing %s <-> %s", ifc, ifs)})
	wg.Wait()
	return nil
}

// pump reads frames arriving on `in`, routes IPv4 packets addressed to `dst`
// through the censor and out of `out`.
func (c *Censor) pump(in, out *Port, dst *net.IPNet, dir Dir) {
	buf := make([]byte, 65536)
	for {
		n, outgoing, err := in.recv(buf)
		if err != nil {
			c.event(Decision{Rule: "-", Action: "error", Detail: "recv on " + in.name + ": " + err.Error()})
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// Our own transmissions are looped back to packet sockets as
		// PACKET_OUTGOING; forwarding them again would loop forever.
		if outgoing || n < 14+20 {
			continue
		}
		frame := buf[:n]
		if frame[12] != 0x08 || frame[13] != 0x00 {
			continue // not IPv4; ARP is the kernel's job
		}
		ip := frame[14:]
		src := net.IP(ip[12:16])
		dstIP := net.IP(ip[16:20])
		in.learn(src, frame[6:12])
		if !dst.Contains(dstIP) {
			continue // addressed to the wire itself or elsewhere
		}

		pkt, ok := parsePacket(ip, dir)
		if !ok {
			continue
		}
		ipLen := int(ip[2])<<8 | int(ip[3])
		verdict := c.judge(pkt, time.Now())
		switch verdict.kind {
		case passPacket:
		case dropPacket:
			continue
		case injectReply:
			// Back where the query came from, to the MAC that sent it.
			reply := verdict.reply
			if !finishForward(reply) {
				continue
			}
			back := append(make([]byte, 14, 14+len(reply)), reply...)
			back[12], back[13] = 0x08, 0x00
			if err := in.send(back, net.HardwareAddr(frame[6:12])); err != nil {
				c.event(Decision{Rule: "-", Action: "error", Detail: "send on " + in.name + ": " + err.Error()})
			}
			continue
		case rewriteRST:
			if ipLen = toRSTAck(ip, pkt); ipLen == 0 {
				continue
			}
		}
		if !finishForward(ip) {
			continue // TTL ran out
		}
		frame = frame[:14+ipLen]
		mac, ok := out.neighbor(dstIP)
		if !ok {
			continue // ARP in flight; the sender's retransmit gets through
		}
		if err := out.send(frame, mac); err != nil && !strings.Contains(err.Error(), "no buffer") {
			c.event(Decision{Rule: "-", Action: "error", Detail: "send on " + out.name + ": " + err.Error()})
		}
	}
}
