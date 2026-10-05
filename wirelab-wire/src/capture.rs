//! Reading a real capture (libpcap format, as `tcpdump -w` writes it) back
//! into transport-level packets, and the few protocol dissectors the wire
//! zone needs.

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    /// ICMP type and code; the payload is the ICMP body after the 4-byte
    /// header, so for errors it starts with the quoted original packet.
    Icmp(u8, u8),
}

#[derive(Debug, Clone)]
pub struct Packet {
    /// Capture timestamp, µs since the Unix epoch.
    pub t_us: u64,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub transport: Transport,
    pub sport: u16,
    pub dport: u16,
    /// IPv4 total length: what the packet occupied on the link minus framing.
    pub ip_len: usize,
    pub payload: Vec<u8>,
}

const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_IPV4: u32 = 228;

/// Parse a classic pcap file. IPv4 TCP/UDP only; everything else (ARP, IGMP,
/// IPv6) is skipped, and the count of skipped frames is returned so a caller
/// can say how much it did not look at.
pub fn read_pcap(bytes: &[u8]) -> Result<(Vec<Packet>, usize)> {
    if bytes.len() < 24 {
        bail!("pcap shorter than its global header");
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let (le, nanos) = match magic {
        0xa1b2_c3d4 => (true, false),
        0xa1b2_3c4d => (true, true),
        0xd4c3_b2a1 => (false, false),
        0x4d3c_b2a1 => (false, true),
        0x0a0d_0d0a => bail!("pcapng is not supported here; capture with tcpdump -w (classic pcap)"),
        m => bail!("not a pcap file (magic {m:#010x})"),
    };
    let u32_at = |off: usize| -> u32 {
        let b: [u8; 4] = bytes[off..off + 4].try_into().unwrap();
        if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    let linktype = u32_at(20) & 0x0fff_ffff;

    let mut packets = Vec::new();
    let mut skipped = 0;
    let mut off = 24;
    while off + 16 <= bytes.len() {
        let sec = u32_at(off) as u64;
        let frac = u32_at(off + 4) as u64;
        let caplen = u32_at(off + 8) as usize;
        off += 16;
        let frame = bytes.get(off..off + caplen).context("pcap record runs past the end of the file")?;
        off += caplen;
        let t_us = sec * 1_000_000 + if nanos { frac / 1000 } else { frac };
        match parse_frame(linktype, frame, t_us)? {
            Some(p) => packets.push(p),
            None => skipped += 1,
        }
    }
    Ok((packets, skipped))
}

/// Incremental pcap reader for a live capture (`tcpdump -w -`): feed bytes as
/// they arrive, get back whole packets.
#[derive(Default)]
pub struct PcapStream {
    buf: Vec<u8>,
    /// `(little_endian, nanosecond_timestamps, linktype)` once the global
    /// header has been read.
    header: Option<(bool, bool, u32)>,
    pub skipped: usize,
}

impl PcapStream {
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Packet>> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        let mut off = 0;
        if self.header.is_none() {
            if self.buf.len() < 24 {
                return Ok(out);
            }
            let magic = u32::from_le_bytes(self.buf[0..4].try_into().unwrap());
            let (le, nanos) = match magic {
                0xa1b2_c3d4 => (true, false),
                0xa1b2_3c4d => (true, true),
                0xd4c3_b2a1 => (false, false),
                0x4d3c_b2a1 => (false, true),
                m => bail!("live capture is not classic pcap (magic {m:#010x})"),
            };
            let lt: [u8; 4] = self.buf[20..24].try_into().unwrap();
            let linktype = if le { u32::from_le_bytes(lt) } else { u32::from_be_bytes(lt) } & 0x0fff_ffff;
            self.header = Some((le, nanos, linktype));
            off = 24;
        }
        let (le, nanos, linktype) = self.header.unwrap();
        let rd = |b: &[u8]| -> u32 {
            let a: [u8; 4] = b.try_into().unwrap();
            if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
        };
        while self.buf.len() >= off + 16 {
            let caplen = rd(&self.buf[off + 8..off + 12]) as usize;
            if self.buf.len() < off + 16 + caplen {
                break;
            }
            let sec = rd(&self.buf[off..off + 4]) as u64;
            let frac = rd(&self.buf[off + 4..off + 8]) as u64;
            let t_us = sec * 1_000_000 + if nanos { frac / 1000 } else { frac };
            let frame = &self.buf[off + 16..off + 16 + caplen];
            match parse_frame(linktype, frame, t_us)? {
                Some(p) => out.push(p),
                None => self.skipped += 1,
            }
            off += 16 + caplen;
        }
        self.buf.drain(..off);
        Ok(out)
    }
}

fn parse_frame(linktype: u32, frame: &[u8], t_us: u64) -> Result<Option<Packet>> {
    let ip = match linktype {
        LINKTYPE_ETHERNET => match frame.get(12..14) {
            Some([0x08, 0x00]) => &frame[14..],
            _ => return Ok(None),
        },
        LINKTYPE_RAW | LINKTYPE_IPV4 => frame,
        other => bail!("unsupported link type {other}"),
    };
    Ok(parse_ipv4(ip, t_us))
}

fn parse_ipv4(ip: &[u8], t_us: u64) -> Option<Packet> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let ip_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    // Trust the IP length over the frame: Ethernet pads short frames.
    let l4 = ip.get(ihl..ip_len.min(ip.len()))?;
    let (transport, sport, dport, payload) = match ip[9] {
        6 => {
            let doff = (*l4.get(12)? >> 4) as usize * 4;
            (Transport::Tcp, u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]]), l4.get(doff..)?)
        }
        1 => (Transport::Icmp(*l4.first()?, *l4.get(1)?), 0, 0, l4.get(8..)?),
        17 => (Transport::Udp, u16::from_be_bytes([*l4.first()?, *l4.get(1)?]), u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]), l4.get(8..)?),
        _ => return None,
    };
    Some(Packet { t_us, src, dst, transport, sport, dport, ip_len, payload: payload.to_vec() })
}

/// An ICMP destination-unreachable quotes the packet it refers to. Returns
/// `(protocol, destination, destination port)` of that original packet.
pub fn icmp_quoted_target(body: &[u8]) -> Option<(&'static str, Ipv4Addr, u16)> {
    if body.len() < 20 || body[0] >> 4 != 4 {
        return None;
    }
    let ihl = (body[0] & 0x0f) as usize * 4;
    let proto = match body[9] {
        6 => "tcp",
        17 => "udp",
        _ => return None,
    };
    let dst = Ipv4Addr::new(body[16], body[17], body[18], body[19]);
    let l4 = body.get(ihl..ihl + 4)?;
    Some((proto, dst, u16::from_be_bytes([l4[2], l4[3]])))
}

/// What a TLS ClientHello reveals in the clear.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ClientHello {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    /// From supported_versions, e.g. 0x0304 for TLS 1.3.
    pub versions: Vec<u16>,
    pub cipher_suites: usize,
    pub extensions: Vec<u16>,
}

/// Parse a ClientHello from the start of a TCP stream. `None` if the bytes
/// are not a TLS handshake record carrying one (or it is cut short).
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    let mut r = Reader(data);
    if r.u8()? != 0x16 {
        return None;
    }
    r.skip(2)?; // record version
    let rec = { let n = r.u16()? as usize; r.take(n) }?;
    let mut h = Reader(rec);
    if h.u8()? != 1 {
        return None;
    }
    let body = { let n = h.u24()? as usize; h.take(n) }?;
    let mut b = Reader(body);
    b.skip(2 + 32)?; // legacy_version, random
    let sid = b.u8()? as usize;
    b.skip(sid)?;
    let suites = b.u16()? as usize;
    b.skip(suites)?;
    let comp = b.u8()? as usize;
    b.skip(comp)?;

    let mut hello = ClientHello { cipher_suites: suites / 2, ..Default::default() };
    let mut exts = Reader({ let n = b.u16()? as usize; b.take(n) }?);
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let mut e = Reader({ let n = exts.u16()? as usize; exts.take(n) }?);
        hello.extensions.push(ty);
        match ty {
            0 => {
                let mut list = Reader({ let n = e.u16()? as usize; e.take(n) }?);
                while !list.0.is_empty() {
                    let kind = list.u8()?;
                    let name = { let n = list.u16()? as usize; list.take(n) }?;
                    if kind == 0 {
                        hello.sni = Some(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            16 => {
                let mut list = Reader({ let n = e.u16()? as usize; e.take(n) }?);
                while !list.0.is_empty() {
                    let n = list.u8()? as usize;
                    hello.alpn.push(String::from_utf8_lossy(list.take(n)?).into_owned());
                }
            }
            43 => {
                let mut list = Reader({ let n = e.u8()? as usize; e.take(n) }?);
                while !list.0.is_empty() {
                    hello.versions.push(list.u16()?);
                }
            }
            _ => {}
        }
    }
    Some(hello)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<u32> {
        self.take(3).map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}

/// Every place `needle` occurs in `hay`.
pub fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return Vec::new();
    }
    hay.windows(needle.len()).enumerate().filter(|(_, w)| *w == needle).map(|(i, _)| i).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello built by hand, field by field, so the test does not
    /// depend on a captured sample whose provenance would need explaining.
    fn hello_bytes() -> Vec<u8> {
        let mut ext = Vec::new();
        // server_name
        let name = b"www.example.com";
        let mut sn = vec![0u8];
        sn.extend((name.len() as u16).to_be_bytes());
        sn.extend(name);
        let mut snl = (sn.len() as u16).to_be_bytes().to_vec();
        snl.extend(sn);
        ext.extend(0u16.to_be_bytes());
        ext.extend((snl.len() as u16).to_be_bytes());
        ext.extend(snl);
        // ALPN h2
        let alpn = [0u8, 3, 2, b'h', b'2'];
        ext.extend(16u16.to_be_bytes());
        ext.extend((alpn.len() as u16).to_be_bytes());
        ext.extend(alpn);
        // supported_versions: TLS 1.3, 1.2
        let sv = [4u8, 0x03, 0x04, 0x03, 0x03];
        ext.extend(43u16.to_be_bytes());
        ext.extend((sv.len() as u16).to_be_bytes());
        ext.extend(sv);

        let mut body = vec![0x03, 0x03];
        body.extend([0u8; 32]);
        body.push(0); // session id
        body.extend(4u16.to_be_bytes());
        body.extend([0x13, 0x01, 0x13, 0x02]);
        body.extend([1, 0]); // compression
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(ext);

        let mut hs = vec![1];
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn client_hello_fields() {
        let h = parse_client_hello(&hello_bytes()).unwrap();
        assert_eq!(h.sni.as_deref(), Some("www.example.com"));
        assert_eq!(h.alpn, vec!["h2"]);
        assert_eq!(h.versions, vec![0x0304, 0x0303]);
        assert_eq!(h.cipher_suites, 2);
        assert_eq!(h.extensions, vec![0, 16, 43]);
    }

    #[test]
    fn truncated_or_foreign_bytes_are_not_a_hello() {
        let full = hello_bytes();
        assert_eq!(parse_client_hello(&full[..full.len() - 3]), None);
        assert_eq!(parse_client_hello(b"\x00\x01GET / HTTP/1.1"), None);
    }

    #[test]
    fn reads_back_what_the_writer_wrote() {
        // A classic pcap with one raw-IPv4 record, assembled from the synthetic
        // packet our pcapng writer produces.
        let mut ng = crate::PcapngWriter::new(Vec::new(), 0, 443).unwrap();
        ng.write_datagram(wirelab_core::SimTime::from_ms(3), wirelab_core::Dir::C2s, b"hello").unwrap();
        let ng = ng.finish().unwrap();
        let ip = &ng[28 + 20 + 28..][..33];

        let mut pcap = Vec::new();
        pcap.extend(0xa1b2_c3d4u32.to_le_bytes());
        pcap.extend([2, 0, 4, 0]);
        pcap.extend([0u8; 8]);
        pcap.extend(65535u32.to_le_bytes());
        pcap.extend(LINKTYPE_RAW.to_le_bytes());
        pcap.extend(0u32.to_le_bytes());
        pcap.extend(3000u32.to_le_bytes());
        pcap.extend((ip.len() as u32).to_le_bytes());
        pcap.extend((ip.len() as u32).to_le_bytes());
        pcap.extend(ip);

        let (pkts, skipped) = read_pcap(&pcap).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(pkts.len(), 1);
        let p = &pkts[0];
        assert_eq!(p.t_us, 3000);
        assert_eq!(p.transport, Transport::Udp);
        assert_eq!((p.sport, p.dport), (40000, 443));
        assert_eq!(p.payload, b"hello");
    }

    #[test]
    fn stream_reassembles_across_chunks() {
        let mut ng = crate::PcapngWriter::new(Vec::new(), 0, 443).unwrap();
        ng.write_datagram(wirelab_core::SimTime::from_ms(1), wirelab_core::Dir::S2c, b"abc").unwrap();
        let ng = ng.finish().unwrap();
        let ip = &ng[28 + 20 + 28..][..31];
        let mut pcap = Vec::new();
        pcap.extend(0xa1b2_c3d4u32.to_le_bytes());
        pcap.extend([2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        pcap.extend(65535u32.to_le_bytes());
        pcap.extend(LINKTYPE_RAW.to_le_bytes());
        for t in [1000u32, 2000] {
            pcap.extend(0u32.to_le_bytes());
            pcap.extend(t.to_le_bytes());
            pcap.extend((ip.len() as u32).to_le_bytes());
            pcap.extend((ip.len() as u32).to_le_bytes());
            pcap.extend(ip);
        }
        // Byte at a time: the worst split a pipe can produce.
        let mut s = PcapStream::default();
        let mut got = Vec::new();
        for b in &pcap {
            got.extend(s.push(std::slice::from_ref(b)).unwrap());
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].t_us, 2000);
        assert_eq!(got[0].payload, b"abc");
    }

    #[test]
    fn find_all_positions() {
        assert_eq!(find_all(b"abcabc", b"bc"), vec![1, 4]);
        assert!(find_all(b"ab", b"abc").is_empty());
    }
}
