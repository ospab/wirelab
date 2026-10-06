package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// Frame is one captured packet, reduced to its IPv4 header onwards.
type Frame struct {
	T  time.Time
	IP []byte
}

const (
	linkEthernet = 1
	linkRaw      = 101
	linkSLL      = 113
	linkIPv4     = 228
	linkSLL2     = 276
)

// readCapture reads classic pcap or pcapng (what tcpdump and Wireshark
// write) and returns the IPv4 packets. Frames of other kinds are counted in
// skipped rather than silently ignored.
func readCapture(b []byte) (frames []Frame, skipped int, err error) {
	if len(b) < 4 {
		return nil, 0, errors.New("file too short to be a capture")
	}
	if binary.LittleEndian.Uint32(b) == 0x0a0d0d0a {
		return readPcapng(b)
	}
	return readPcap(b)
}

func ipFromLink(link uint32, frame []byte) []byte {
	var ethertype uint16
	var off int
	switch link {
	case linkEthernet:
		if len(frame) < 14 {
			return nil
		}
		ethertype, off = binary.BigEndian.Uint16(frame[12:]), 14
		// One 802.1Q tag is common on captures from a trunk port.
		if ethertype == 0x8100 && len(frame) >= 18 {
			ethertype, off = binary.BigEndian.Uint16(frame[16:]), 18
		}
	case linkSLL:
		if len(frame) < 16 {
			return nil
		}
		ethertype, off = binary.BigEndian.Uint16(frame[14:]), 16
	case linkSLL2:
		if len(frame) < 20 {
			return nil
		}
		ethertype, off = binary.BigEndian.Uint16(frame[0:]), 20
	case linkRaw, linkIPv4:
		if len(frame) > 0 && frame[0]>>4 == 4 {
			return frame
		}
		return nil
	default:
		return nil
	}
	if ethertype != 0x0800 {
		return nil
	}
	return frame[off:]
}

func readPcap(b []byte) ([]Frame, int, error) {
	if len(b) < 24 {
		return nil, 0, errors.New("pcap shorter than its header")
	}
	var bo binary.ByteOrder
	nanos := false
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		bo = binary.LittleEndian
	case 0xa1b23c4d:
		bo, nanos = binary.LittleEndian, true
	case 0xd4c3b2a1:
		bo = binary.BigEndian
	case 0x4d3cb2a1:
		bo, nanos = binary.BigEndian, true
	default:
		return nil, 0, fmt.Errorf("not a pcap or pcapng file (magic %#08x)", binary.LittleEndian.Uint32(b))
	}
	link := bo.Uint32(b[20:]) & 0x0fffffff
	var out []Frame
	skipped := 0
	for off := 24; off+16 <= len(b); {
		sec, frac := int64(bo.Uint32(b[off:])), int64(bo.Uint32(b[off+4:]))
		caplen := int(bo.Uint32(b[off+8:]))
		off += 16
		if off+caplen > len(b) {
			return out, skipped, errors.New("capture ends mid-packet")
		}
		ns := frac * 1000
		if nanos {
			ns = frac
		}
		if ip := ipFromLink(link, b[off:off+caplen]); ip != nil {
			out = append(out, Frame{T: time.Unix(sec, ns), IP: ip})
		} else {
			skipped++
		}
		off += caplen
	}
	return out, skipped, nil
}

func readPcapng(b []byte) ([]Frame, int, error) {
	type iface struct {
		link  uint32
		units float64 // timestamp units per second
	}
	var ifaces []iface
	var bo binary.ByteOrder = binary.LittleEndian
	var out []Frame
	skipped := 0
	for off := 0; off+12 <= len(b); {
		ty := bo.Uint32(b[off:])
		if ty == 0x0a0d0d0a && off+12 <= len(b) {
			if binary.LittleEndian.Uint32(b[off+8:]) == 0x1a2b3c4d {
				bo = binary.LittleEndian
			} else {
				bo = binary.BigEndian
			}
			ifaces = nil // interfaces are numbered per section
		}
		blen := int(bo.Uint32(b[off+4:]))
		if blen < 12 || off+blen > len(b) {
			return out, skipped, errors.New("pcapng block runs past the end of the file")
		}
		body := b[off+8 : off+blen-4]
		switch ty {
		case 1: // Interface Description
			if len(body) < 8 {
				return out, skipped, errors.New("short interface block")
			}
			ifc := iface{link: uint32(bo.Uint16(body)), units: 1e6}
			for o := 8; o+4 <= len(body); {
				code, l := bo.Uint16(body[o:]), int(bo.Uint16(body[o+2:]))
				if code == 0 || o+4+l > len(body) {
					break
				}
				if code == 9 && l >= 1 { // if_tsresol
					v := body[o+4]
					if v&0x80 != 0 {
						ifc.units = math.Pow(2, float64(v&0x7f))
					} else {
						ifc.units = math.Pow(10, float64(v))
					}
				}
				o += 4 + (l+3)&^3
			}
			ifaces = append(ifaces, ifc)
		case 6: // Enhanced Packet
			if len(body) < 20 {
				return out, skipped, errors.New("short packet block")
			}
			id := int(bo.Uint32(body))
			if id >= len(ifaces) {
				return out, skipped, errors.New("packet refers to an undeclared interface")
			}
			ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
			caplen := int(bo.Uint32(body[12:]))
			if 20+caplen > len(body) {
				return out, skipped, errors.New("packet block shorter than its data")
			}
			secs := float64(ts) / ifaces[id].units
			t := time.Unix(0, int64(secs*1e9))
			if ip := ipFromLink(ifaces[id].link, body[20:20+caplen]); ip != nil {
				out = append(out, Frame{T: t, IP: ip})
			} else {
				skipped++
			}
		}
		off += blen
	}
	return out, skipped, nil
}
