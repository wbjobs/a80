use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const PCAP_MAGIC_LITTLE_ENDIAN: u32 = 0xa1b2c3d4;
const PCAP_MAGIC_BIG_ENDIAN: u32 = 0xd4c3b2a1;
const PCAP_NS_MAGIC_LITTLE_ENDIAN: u32 = 0xa1b23c4d;
const PCAP_NS_MAGIC_BIG_ENDIAN: u32 = 0x4d3cb2a1;

#[derive(Debug, Clone)]
pub struct PcapPacket {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PcapReader {
    packets: Vec<PcapPacket>,
}

impl PcapReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open pcap file: {:?}", path.as_ref()))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Self::parse(&data)
    }

    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 24 {
            anyhow::bail!("File too small to be a valid PCAP file");
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let (little_endian, _nanosecond) = match magic {
            PCAP_MAGIC_LITTLE_ENDIAN => (true, false),
            PCAP_MAGIC_BIG_ENDIAN => (false, false),
            PCAP_NS_MAGIC_LITTLE_ENDIAN => (true, true),
            PCAP_NS_MAGIC_BIG_ENDIAN => (false, true),
            _ => anyhow::bail!("Invalid PCAP magic number: 0x{:08x}", magic),
        };

        let mut offset = 24;
        let mut packets = Vec::new();

        while offset + 16 <= data.len() {
            let ts_sec = Self::read_u32(&data[offset..offset + 4], little_endian);
            let ts_usec = Self::read_u32(&data[offset + 4..offset + 8], little_endian);
            let incl_len = Self::read_u32(&data[offset + 8..offset + 12], little_endian) as usize;
            let orig_len = Self::read_u32(&data[offset + 12..offset + 16], little_endian);

            offset += 16;

            if offset + incl_len > data.len() {
                break;
            }

            let packet_data = data[offset..offset + incl_len].to_vec();
            offset += incl_len;

            packets.push(PcapPacket {
                ts_sec,
                ts_usec,
                orig_len,
                data: packet_data,
            });
        }

        Ok(PcapReader { packets })
    }

    fn read_u32(bytes: &[u8], little_endian: bool) -> u32 {
        if little_endian {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
    }

    pub fn packets(&self) -> &[PcapPacket] {
        &self.packets
    }

    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }
}

pub fn extract_l7_payload(packet: &[u8]) -> &[u8] {
    let mut offset: usize;

    if packet.len() < 14 {
        return packet;
    }

    let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    offset = 14;

    if ethertype == 0x8100 && packet.len() >= 18 {
        let ethertype_inner = u16::from_be_bytes([packet[16], packet[17]]);
        offset = 18;
        if ethertype_inner != 0x0800 {
            return &packet[offset..];
        }
    } else if ethertype != 0x0800 {
        return &packet[offset..];
    }

    if offset >= packet.len() {
        return &packet[offset..];
    }

    let ihl = (packet[offset] & 0x0f) as usize * 4;
    let protocol = packet[offset + 9];
    offset += ihl;

    match protocol {
        6 => {
            if offset + 20 > packet.len() {
                return &packet[offset.min(packet.len())..];
            }
            let data_offset = ((packet[offset + 12] >> 4) & 0x0f) as usize * 4;
            offset += data_offset;
            &packet[offset.min(packet.len())..]
        }
        17 => {
            offset += 8;
            &packet[offset.min(packet.len())..]
        }
        _ => &packet[offset.min(packet.len())..],
    }
}
