package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ether(ip []byte) []byte {
	f := make([]byte, 14, 14+len(ip))
	f[12], f[13] = 0x08, 0x00
	return append(f, ip...)
}

func pcapFile(frames [][]byte) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], linkEthernet)
	b.Write(hdr)
	for i, f := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec, 1000)
		binary.LittleEndian.PutUint32(rec[4:], uint32(i*1000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f)))
		b.Write(rec)
		b.Write(f)
	}
	return b.Bytes()
}

func pcapngFile(frames [][]byte) []byte {
	var b bytes.Buffer
	block := func(ty uint32, body []byte) {
		n := 12 + (len(body)+3)&^3
		h := make([]byte, 8)
		binary.LittleEndian.PutUint32(h, ty)
		binary.LittleEndian.PutUint32(h[4:], uint32(n))
		b.Write(h)
		b.Write(body)
		b.Write(make([]byte, (len(body)+3)&^3-len(body)))
		t := make([]byte, 4)
		binary.LittleEndian.PutUint32(t, uint32(n))
		b.Write(t)
	}
	shb := make([]byte, 16)
	binary.LittleEndian.PutUint32(shb, 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(shb[4:], 1)
	binary.LittleEndian.PutUint64(shb[8:], ^uint64(0))
	block(0x0a0d0d0a, shb)
	idb := make([]byte, 8)
	binary.LittleEndian.PutUint16(idb, linkEthernet)
	block(1, idb)
	for i, f := range frames {
		epb := make([]byte, 20, 20+len(f))
		ts := uint64(1_000_000_000 + i*1000)
		binary.LittleEndian.PutUint32(epb[4:], uint32(ts>>32))
		binary.LittleEndian.PutUint32(epb[8:], uint32(ts))
		binary.LittleEndian.PutUint32(epb[12:], uint32(len(f)))
		binary.LittleEndian.PutUint32(epb[16:], uint32(len(f)))
		block(6, append(epb, f...))
	}
	return b.Bytes()
}

func udpExchange(n int) [][]byte {
	var frames [][]byte
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			frames = append(frames, ether(ipPacket(17, dirC2S, 40000, 443, 0, []byte("ping"))))
		} else {
			frames = append(frames, ether(ipPacket(17, dirS2C, 443, 40000, 0, []byte("pong"))))
		}
	}
	return frames
}

func TestBothCaptureFormatsRead(t *testing.T) {
	frames := udpExchange(4)
	for name, file := range map[string][]byte{"pcap": pcapFile(frames), "pcapng": pcapngFile(frames)} {
		got, skipped, err := readCapture(file)
		if err != nil || skipped != 0 || len(got) != 4 {
			t.Fatalf("%s: %d frames, %d skipped, err %v", name, len(got), skipped, err)
		}
		if got[1].T.Sub(got[0].T).Microseconds() != 1000 {
			t.Fatalf("%s: timestamps 1 ms apart, got %v", name, got[1].T.Sub(got[0].T))
		}
	}
}

func TestReplayReportsTheFreeze(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "c.pcap")
	os.WriteFile(capPath, pcapFile(udpExchange(40)), 0o644)
	_, cn, _ := net.ParseCIDR(labClientNet)
	_, sn, _ := net.ParseCIDR(labServerNet)
	var out bytes.Buffer
	if err := runReplay(capPath, "../containers/censor/presets/ru-tspu.json", "", cn, sn, &out); err != nil {
		t.Fatal(err)
	}
	report := out.String()
	for _, want := range []string{"40 judged", "ru-freeze-16k (drop_s2c): 1 flow", "at packet 26 of 40"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
}

func TestReplayMapsLabNetworks(t *testing.T) {
	p, err := loadPreset("../containers/censor/presets/ru-tspu.json")
	if err != nil {
		t.Fatal(err)
	}
	_, cn, _ := net.ParseCIDR("192.168.1.0/24")
	_, sn, _ := net.ParseCIDR("203.0.113.7/32")
	notes := retarget(p, cn, sn)
	if len(notes) == 0 {
		t.Fatal("the freeze rule's lab network must be mapped onto the capture's server")
	}
	for _, r := range p.Rules {
		if r.ID == "ru-freeze-16k" && !inNets([4]byte{203, 0, 113, 7}, r.nets) {
			t.Fatal("freeze rule must now cover 203.0.113.7")
		}
	}
}
