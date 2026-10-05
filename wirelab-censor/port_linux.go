//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const ethPAll = 0x0003

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Port is one interface: a packet socket bound to it, its MAC, and the MACs
// of its neighbours.
type Port struct {
	name  string
	index int
	mac   net.HardwareAddr
	fd    int
	net   *net.IPNet

	mu        sync.Mutex
	neighbors map[string]net.HardwareAddr
	asked     map[string]time.Time
}

func openPort(name string, n *net.IPNet) (*Port, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifi.Index}); err != nil {
		return nil, fmt.Errorf("bind %s: %w", name, err)
	}
	// A burst larger than the default buffer would be dropped before we see
	// it, which would look exactly like censorship.
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8<<20)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8<<20)
	return &Port{name: name, index: ifi.Index, mac: ifi.HardwareAddr, fd: fd, net: n,
		neighbors: map[string]net.HardwareAddr{}, asked: map[string]time.Time{}}, nil
}

func (p *Port) recv(buf []byte) (int, bool, error) {
	n, from, err := syscall.Recvfrom(p.fd, buf, 0)
	if err != nil {
		return 0, false, err
	}
	ll, _ := from.(*syscall.SockaddrLinklayer)
	return n, ll != nil && ll.Pkttype == syscall.PACKET_OUTGOING, nil
}

// learn records the MAC a host on this interface's network sent from.
func (p *Port) learn(ip net.IP, mac []byte) {
	if !p.net.Contains(ip) {
		return
	}
	key := ip.String()
	p.mu.Lock()
	if _, ok := p.neighbors[key]; !ok {
		p.neighbors[key] = append(net.HardwareAddr(nil), mac...)
	}
	p.mu.Unlock()
}

// neighbor returns the MAC for ip. Unknown ones are looked up in the kernel's
// ARP cache, and if absent the kernel is made to ARP for it by sending it a
// datagram; the packet that asked is dropped meanwhile.
func (p *Port) neighbor(ip net.IP) (net.HardwareAddr, bool) {
	key := ip.String()
	p.mu.Lock()
	mac, ok := p.neighbors[key]
	p.mu.Unlock()
	if ok {
		return mac, true
	}
	if mac := arpCache(key); mac != nil {
		p.mu.Lock()
		p.neighbors[key] = mac
		p.mu.Unlock()
		return mac, true
	}
	p.mu.Lock()
	last := p.asked[key]
	if time.Since(last) > 500*time.Millisecond {
		p.asked[key] = time.Now()
		go func() {
			if c, err := net.Dial("udp", net.JoinHostPort(key, "9")); err == nil {
				_, _ = c.Write([]byte{0})
				_ = c.Close()
			}
		}()
	}
	p.mu.Unlock()
	return nil, false
}

func arpCache(ip string) net.HardwareAddr {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 4 && fields[0] == ip && fields[2] != "0x0" {
			if mac, err := net.ParseMAC(fields[3]); err == nil {
				return mac
			}
		}
	}
	return nil
}

func (p *Port) send(frame []byte, dst net.HardwareAddr) error {
	copy(frame[0:6], dst)
	copy(frame[6:12], p.mac)
	var addr [8]byte
	copy(addr[:], dst)
	return syscall.Sendto(p.fd, frame, 0, &syscall.SockaddrLinklayer{Ifindex: p.index, Halen: 6, Addr: addr})
}
