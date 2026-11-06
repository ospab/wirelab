package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type Dir int

const (
	dirC2S Dir = iota
	dirS2C
)

func (d Dir) String() string {
	if d == dirC2S {
		return "c2s"
	}
	return "s2c"
}

// FlowKey names a flow from the client's side regardless of direction.
type FlowKey struct {
	Proto      uint8
	ClientIP   [4]byte
	ClientPort uint16
	ServerIP   [4]byte
	ServerPort uint16
}

func (k FlowKey) String() string {
	p := map[uint8]string{1: "icmp", 6: "tcp", 17: "udp"}[k.Proto]
	return fmt.Sprintf("%s %s:%d > %s:%d", p, net.IP(k.ClientIP[:]), k.ClientPort, net.IP(k.ServerIP[:]), k.ServerPort)
}

type Packet struct {
	Dir      Dir
	Proto    uint8
	Key      FlowKey
	IHL      int
	L4       int // offset of the transport header within the IP packet
	Payload  []byte
	TCPFlags byte
	// IP fragmentation: a non-first fragment has no transport header, so its
	// ports come from the first fragment (see Censor.attribute).
	FragID    uint16
	FragOff   uint16
	MoreFrags bool
	Src, Dst  [4]byte
	// Raw is the whole IP packet, for the classifier.
	Raw []byte
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// parsePacket trims ip to its own length (Ethernet pads short frames) and
// reads what the censor needs. Fragments other than the first are passed
// through unexamined, as their transport header is elsewhere.
func parsePacket(ip []byte, dir Dir) (Packet, bool) {
	if ip[0]>>4 != 4 {
		return Packet{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total > len(ip) || total < ihl {
		return Packet{}, false
	}
	ip = ip[:total]
	p := Packet{Dir: dir, Proto: ip[9], IHL: ihl, L4: ihl, Raw: ip}
	var a, b [4]byte
	copy(a[:], ip[12:16])
	copy(b[:], ip[16:20])
	fragOff := binary.BigEndian.Uint16(ip[6:8]) & 0x1fff
	p.FragID, p.FragOff, p.MoreFrags = binary.BigEndian.Uint16(ip[4:6]), fragOff, ip[6]&0x20 != 0
	p.Src, p.Dst = a, b
	var sport, dport uint16
	if fragOff == 0 {
		switch p.Proto {
		case 6:
			if len(ip) < ihl+20 {
				return Packet{}, false
			}
			sport, dport = binary.BigEndian.Uint16(ip[ihl:]), binary.BigEndian.Uint16(ip[ihl+2:])
			doff := int(ip[ihl+12]>>4) * 4
			if len(ip) < ihl+doff {
				return Packet{}, false
			}
			p.TCPFlags = ip[ihl+13]
			p.Payload = ip[ihl+doff:]
		case 17:
			if len(ip) < ihl+8 {
				return Packet{}, false
			}
			sport, dport = binary.BigEndian.Uint16(ip[ihl:]), binary.BigEndian.Uint16(ip[ihl+2:])
			p.Payload = ip[ihl+8:]
		}
	}
	if dir == dirC2S {
		p.Key = FlowKey{p.Proto, a, sport, b, dport}
	} else {
		p.Key = FlowKey{p.Proto, b, dport, a, sport}
	}
	return p, true
}

// finishForward does what a router does to a forwarded packet (TTL) and
// recomputes the checksums. They are recomputed even when nothing changed:
// on a veth the sender often leaves the transport checksum for the NIC to
// fill in, and a packet socket hands it to us unfilled.
func finishForward(ip []byte) bool {
	if ip[8] <= 1 {
		return false
	}
	ip[8]--
	ihl := int(ip[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	ip = ip[:total]
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:ihl], 0))
	fragOff := binary.BigEndian.Uint16(ip[6:8]) & 0x1fff
	moreFrags := ip[6]&0x20 != 0
	if fragOff != 0 || moreFrags {
		return true // a fragment's transport checksum covers bytes we do not have
	}
	seg := ip[ihl:]
	var off int
	switch ip[9] {
	case 6:
		off = 16
	case 17:
		off = 6
	default:
		return true
	}
	if len(seg) < off+2 {
		return true
	}
	seg[off], seg[off+1] = 0, 0
	var ph [12]byte
	copy(ph[0:8], ip[12:20])
	ph[9] = ip[9]
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(seg)))
	sum := checksum(seg, sumWords(ph[:], 0))
	if ip[9] == 17 && sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(seg[off:off+2], sum)
	return true
}

// toRSTAck turns a server-to-client TCP segment into an empty RST/ACK with
// the same sequence numbers: TSPU behaviour SNI-I (Xue et al., IMC 2022,
// §5.2). Returns the new IP packet length, or 0 if the packet is not TCP.
func toRSTAck(ip []byte, p Packet) int {
	if p.Proto != 6 {
		return 0
	}
	doff := int(ip[p.L4+12]>>4) * 4
	newLen := p.IHL + doff
	binary.BigEndian.PutUint16(ip[2:4], uint16(newLen))
	ip[p.L4+13] = tcpRST | tcpACK
	return newLen
}

func sumWords(b []byte, sum uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func checksum(b []byte, initial uint32) uint16 {
	sum := sumWords(b, initial)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// clientHelloSNI returns the server_name of a TLS ClientHello at the start
// of payload, and whether payload is a ClientHello at all.
func clientHelloSNI(b []byte) (string, bool) {
	r := reader{b: b}
	if r.u8() != 0x16 {
		return "", false
	}
	r.skip(2)
	rec := r.take(int(r.u16()))
	h := reader{b: rec}
	if h.u8() != 1 {
		return "", false
	}
	body := reader{b: h.take(int(h.u24()))}
	body.skip(2 + 32)
	body.skip(int(body.u8()))
	body.skip(int(body.u16()))
	body.skip(int(body.u8()))
	exts := reader{b: body.take(int(body.u16()))}
	if body.bad || h.bad || r.bad {
		return "", false
	}
	for len(exts.b) > 0 && !exts.bad {
		ty := exts.u16()
		e := reader{b: exts.take(int(exts.u16()))}
		if ty != 0 {
			continue
		}
		list := reader{b: e.take(int(e.u16()))}
		for len(list.b) > 0 && !list.bad {
			kind := list.u8()
			name := list.take(int(list.u16()))
			if kind == 0 && !list.bad {
				return strings.ToLower(string(name)), true
			}
		}
	}
	return "", true
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) skip(n int) { r.take(n) }
func (r *reader) u8() byte {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}
func (r *reader) u16() uint16 {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}
func (r *reader) u24() uint32 {
	v := r.take(3)
	if v == nil {
		return 0
	}
	return uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
}

// nxdomainReply answers the UDP DNS query in p with NXDOMAIN, from the
// resolver's address: what the client sees when the TSPU sends its UDP DNS
// to the national resolver instead (net4people/bbs #657). Returns the whole
// IP packet, or nil if p is not a query it can answer.
func nxdomainReply(p Packet) []byte {
	q := p.Payload
	if p.Proto != 17 || len(q) < 12 || p.FragOff != 0 || p.MoreFrags {
		return nil
	}
	// Header and the first question; additional records (EDNS) are dropped.
	end := 12
	for end < len(q) && q[end] != 0 {
		if q[end]&0xc0 != 0 {
			return nil
		}
		end += 1 + int(q[end])
	}
	end += 1 + 4 // root label, QTYPE, QCLASS
	if end > len(q) {
		return nil
	}
	dns := append([]byte(nil), q[:end]...)
	dns[2] = 0x80 | dns[2]&0x79 // QR, keep opcode and RD
	dns[3] = 0x80 | 3           // RA, RCODE NXDOMAIN
	binary.BigEndian.PutUint16(dns[4:6], 1)
	binary.BigEndian.PutUint16(dns[6:8], 0)
	binary.BigEndian.PutUint16(dns[8:10], 0)
	binary.BigEndian.PutUint16(dns[10:12], 0)

	total := 20 + 8 + len(dns)
	ip := make([]byte, total)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	ip[6] = 0x40 // DF
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], p.Dst[:])
	copy(ip[16:20], p.Src[:])
	binary.BigEndian.PutUint16(ip[20:22], p.Key.ServerPort)
	binary.BigEndian.PutUint16(ip[22:24], p.Key.ClientPort)
	binary.BigEndian.PutUint16(ip[24:26], uint16(8+len(dns)))
	copy(ip[28:], dns)
	// finishForward decrements the TTL and fills in both checksums.
	ip[8]++
	return ip
}
