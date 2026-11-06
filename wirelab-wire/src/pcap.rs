//! pcapng export of the wire, so a run opens in Wireshark.
//!
//! The simulator moves bare datagrams, so each one is wrapped in a synthetic
//! IPv4 + UDP header with fixed lab addresses. Link type is LINKTYPE_IPV4:
//! there is no Ethernet on a simulated link and inventing MACs adds nothing.

use std::io::{self, Write};
use wirelab_core::{Dir, SimTime};

const LINKTYPE_IPV4: u16 = 228;
pub const CLIENT_ADDR: [u8; 4] = [10, 77, 0, 1];
pub const SERVER_ADDR: [u8; 4] = [10, 77, 0, 2];
pub const CLIENT_PORT: u16 = 40000;

pub struct PcapngWriter<W: Write> {
    out: W,
    /// Wall-clock time of simulated zero, µs since the Unix epoch.
    base_us: u64,
    server_port: u16,
    ip_id: u16,
}

impl<W: Write> PcapngWriter<W> {
    pub fn new(mut out: W, base_us: u64, server_port: u16) -> io::Result<Self> {
        // Section Header Block.
        let mut shb = Vec::with_capacity(28);
        shb.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
        shb.extend_from_slice(&28u32.to_le_bytes());
        shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        shb.extend_from_slice(&28u32.to_le_bytes());
        out.write_all(&shb)?;

        // Interface Description Block; no options, so the default 1 µs
        // timestamp resolution applies.
        let mut idb = Vec::with_capacity(20);
        idb.extend_from_slice(&1u32.to_le_bytes());
        idb.extend_from_slice(&20u32.to_le_bytes());
        idb.extend_from_slice(&LINKTYPE_IPV4.to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&0u32.to_le_bytes());
        idb.extend_from_slice(&20u32.to_le_bytes());
        out.write_all(&idb)?;

        Ok(Self { out, base_us, server_port, ip_id: 0 })
    }

    pub fn write_datagram(&mut self, at: SimTime, dir: Dir, payload: &[u8]) -> io::Result<()> {
        let total = 20 + 8 + payload.len();
        if total > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram does not fit an IPv4 packet"));
        }
        let (src, dst, sport, dport) = match dir {
            Dir::C2s => (CLIENT_ADDR, SERVER_ADDR, CLIENT_PORT, self.server_port),
            Dir::S2c => (SERVER_ADDR, CLIENT_ADDR, self.server_port, CLIENT_PORT),
        };
        self.ip_id = self.ip_id.wrapping_add(1);

        let mut pkt = Vec::with_capacity(total);
        pkt.extend_from_slice(&[0x45, 0]);
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&self.ip_id.to_be_bytes());
        pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
        pkt.extend_from_slice(&[64, 17, 0, 0]);
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);
        let csum = ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt.extend_from_slice(&sport.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // zero = no UDP checksum, legal over IPv4
        pkt.extend_from_slice(payload);

        let padded = (pkt.len() + 3) & !3;
        let block_len = (32 + padded) as u32;
        let ts = self.base_us + at.as_us();

        let mut epb = Vec::with_capacity(block_len as usize);
        epb.extend_from_slice(&6u32.to_le_bytes());
        epb.extend_from_slice(&block_len.to_le_bytes());
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(ts as u32).to_le_bytes());
        epb.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        epb.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        epb.extend_from_slice(&pkt);
        epb.resize(28 + padded, 0);
        epb.extend_from_slice(&block_len.to_le_bytes());
        self.out.write_all(&epb)
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}

/// pcapng of real captured frames, each with optional comments: how the lab
/// puts the censor's decisions next to the packets they were made on, so
/// Wireshark shows them (Packet comments, `frame.comment`).
pub struct PcapngFrames<W: Write> {
    out: W,
}

/// One pcapng option: code, length, value padded to 4 bytes.
fn option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
    buf.resize((buf.len() + 3) & !3, 0);
}

/// Wrap a block body (everything after type and length) into a block.
fn block(ty: u32, body: &[u8]) -> Vec<u8> {
    let len = (12 + body.len()) as u32;
    let mut b = Vec::with_capacity(len as usize);
    b.extend_from_slice(&ty.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(body);
    b.extend_from_slice(&len.to_le_bytes());
    b
}

/// Longest text one option can hold.
const MAX_OPTION: usize = u16::MAX as usize - 4;

impl<W: Write> PcapngFrames<W> {
    /// `comment` goes on the section: what was captured, where and when.
    pub fn new(mut out: W, linktype: u32, snaplen: u32, comment: &str) -> io::Result<Self> {
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        if !comment.is_empty() {
            option(&mut shb, 1, truncate(comment).as_bytes());
        }
        option(&mut shb, 4, b"wirelab");
        option(&mut shb, 0, &[]);
        out.write_all(&block(0x0A0D_0D0A, &shb))?;

        let mut idb = Vec::new();
        idb.extend_from_slice(&(linktype as u16).to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&snaplen.to_le_bytes());
        option(&mut idb, 2, b"wire, client side");
        option(&mut idb, 0, &[]);
        out.write_all(&block(1, &idb))?;
        Ok(Self { out })
    }

    pub fn write_frame(&mut self, t_us: u64, orig_len: u32, frame: &[u8], comments: &[String]) -> io::Result<()> {
        let mut epb = Vec::with_capacity(20 + frame.len() + 8);
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&((t_us >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(t_us as u32).to_le_bytes());
        epb.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        epb.extend_from_slice(&orig_len.to_le_bytes());
        epb.extend_from_slice(frame);
        epb.resize((epb.len() + 3) & !3, 0);
        if !comments.is_empty() {
            for c in comments {
                option(&mut epb, 1, truncate(c).as_bytes());
            }
            option(&mut epb, 0, &[]);
        }
        self.out.write_all(&block(6, &epb))
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}

fn truncate(s: &str) -> &str {
    if s.len() <= MAX_OPTION {
        return s;
    }
    let mut end = MAX_OPTION;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]]) as u32).sum();
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_are_well_formed() {
        let mut w = PcapngWriter::new(Vec::new(), 1_000_000, 443).unwrap();
        w.write_datagram(SimTime::from_ms(5), Dir::C2s, &[1, 2, 3]).unwrap();
        let buf = w.finish().unwrap();

        // Walk the blocks: each one's leading and trailing lengths must agree
        // and the walk must land exactly on the end of the file.
        let mut off = 0;
        let mut types = Vec::new();
        while off < buf.len() {
            let ty = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let len = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
            let tail = u32::from_le_bytes(buf[off + len - 4..off + len].try_into().unwrap()) as usize;
            assert_eq!(len, tail);
            assert_eq!(len % 4, 0);
            types.push(ty);
            off += len;
        }
        assert_eq!(off, buf.len());
        assert_eq!(types, [0x0A0D_0D0A, 1, 6]);

        // The IPv4 header checksum verifies to zero.
        let ip = &buf[28 + 20 + 28..][..20];
        assert_eq!(ipv4_checksum(ip), 0);
    }

    /// Walk pcapng blocks, returning (type, body) pairs, checking lengths.
    fn blocks(buf: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut off = 0;
        let mut out = Vec::new();
        while off < buf.len() {
            let ty = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let len = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
            let tail = u32::from_le_bytes(buf[off + len - 4..off + len].try_into().unwrap()) as usize;
            assert_eq!(len, tail);
            assert_eq!(len % 4, 0);
            out.push((ty, buf[off + 8..off + len - 4].to_vec()));
            off += len;
        }
        assert_eq!(off, buf.len());
        out
    }

    #[test]
    fn frames_carry_their_comments() {
        let mut w = PcapngFrames::new(Vec::new(), 1, 65535, "lab default").unwrap();
        w.write_frame(5, 60, &[0xAA; 13], &["ru-sni-1: rst".to_string(), "second".to_string()]).unwrap();
        w.write_frame(6, 60, &[0xBB; 16], &[]).unwrap();
        let buf = w.finish().unwrap();
        let b = blocks(&buf);
        assert_eq!(b.iter().map(|x| x.0).collect::<Vec<_>>(), [0x0A0D_0D0A, 1, 6, 6]);
        let epb = &b[2].1;
        assert_eq!(u32::from_le_bytes(epb[12..16].try_into().unwrap()), 13);
        // Options start after the 13-byte frame padded to 16.
        let opts = &epb[20 + 16..];
        assert_eq!(u16::from_le_bytes([opts[0], opts[1]]), 1);
        let n = u16::from_le_bytes([opts[2], opts[3]]) as usize;
        assert_eq!(&opts[4..4 + n], b"ru-sni-1: rst");
        // The frame without comments has no options at all.
        assert_eq!(b[3].1.len(), 20 + 16);
    }
}
