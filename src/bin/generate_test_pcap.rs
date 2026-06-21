use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

fn write_pcap_header<W: Write>(writer: &mut W, little_endian: bool) -> std::io::Result<()> {
    let magic: u32 = if little_endian { 0xa1b2c3d4 } else { 0xd4c3b2a1 };
    let magic_bytes = if little_endian {
        magic.to_le_bytes()
    } else {
        magic.to_be_bytes()
    };
    writer.write_all(&magic_bytes)?;
    let version_major: u16 = 2;
    let version_minor: u16 = 4;
    writer.write_all(&version_major.to_le_bytes())?;
    writer.write_all(&version_minor.to_le_bytes())?;
    let thiszone: i32 = 0;
    writer.write_all(&thiszone.to_le_bytes())?;
    let sigfigs: u32 = 0;
    writer.write_all(&sigfigs.to_le_bytes())?;
    let snaplen: u32 = 65535;
    writer.write_all(&snaplen.to_le_bytes())?;
    let network: u32 = 1;
    writer.write_all(&network.to_le_bytes())?;
    Ok(())
}

fn write_packet<W: Write>(writer: &mut W, ts_sec: u32, ts_usec: u32, data: &[u8]) -> std::io::Result<()> {
    writer.write_all(&ts_sec.to_le_bytes())?;
    writer.write_all(&ts_usec.to_le_bytes())?;
    let incl_len: u32 = data.len() as u32;
    let orig_len: u32 = data.len() as u32;
    writer.write_all(&incl_len.to_le_bytes())?;
    writer.write_all(&orig_len.to_le_bytes())?;
    writer.write_all(data)?;
    Ok(())
}

fn make_ether_ip_tcp_payload(payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();

    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt.extend_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());

    let ip_total_len = 20 + 20 + payload.len() as u16;
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&ip_total_len.to_be_bytes());
    pkt.extend_from_slice(&0x1234u16.to_be_bytes());
    pkt.extend_from_slice(&0x4000u16.to_be_bytes());
    pkt.push(64);
    pkt.push(6);
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    pkt.extend_from_slice(&[192, 168, 1, 1]);
    pkt.extend_from_slice(&[192, 168, 1, 2]);

    pkt.extend_from_slice(&0x1234u16.to_be_bytes());
    pkt.extend_from_slice(&0x5678u16.to_be_bytes());
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes());
    pkt.extend_from_slice(&0x00000002u32.to_be_bytes());
    let tcp_data_offset = 5u8;
    pkt.push((tcp_data_offset << 4) | 0);
    pkt.push(0x18);
    pkt.extend_from_slice(&0xffffu16.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());

    pkt.extend_from_slice(payload);
    pkt
}

fn main() {
    let out_path = PathBuf::from("test_data.pcap");
    let mut file = File::create(&out_path).expect("Failed to create test pcap");

    write_pcap_header(&mut file, true).expect("Failed to write pcap header");

    {
        let mut payload = Vec::new();
        let method = b"GET";
        let msg_len = 4 + 1 + 1 + method.len() as u16;
        payload.extend_from_slice(&msg_len.to_be_bytes());
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&42u32.to_be_bytes());
        payload.push(method.len() as u8);
        payload.extend_from_slice(method);
        payload.extend_from_slice(&1u8.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(b"AB");
        let ether_pkt = make_ether_ip_tcp_payload(&payload);
        write_packet(&mut file, 1_700_000_000, 123456, &ether_pkt).expect("Failed to write packet 1");
    }

    {
        let mut payload = Vec::new();
        let body = b"OK";
        let msg_len = 4 + 4 + 2 + 4 + body.len() as u16;
        payload.extend_from_slice(&msg_len.to_be_bytes());
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&42u32.to_be_bytes());
        payload.extend_from_slice(&200u16.to_be_bytes());
        payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
        payload.extend_from_slice(body);
        let ether_pkt = make_ether_ip_tcp_payload(&payload);
        write_packet(&mut file, 1_700_000_001, 234567, &ether_pkt).expect("Failed to write packet 2");
    }

    {
        let mut payload = Vec::new();
        let names = vec!["Alice", "Bob"];
        let mut items_bytes = Vec::new();
        for (i, name) in names.iter().enumerate() {
            items_bytes.extend_from_slice(&(i as u32 + 100).to_be_bytes());
            items_bytes.push(name.len() as u8);
            items_bytes.extend_from_slice(name.as_bytes());
        }
        let msg_len = 4 + 2 + items_bytes.len() as u16;
        payload.extend_from_slice(&msg_len.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(&(names.len() as u16).to_be_bytes());
        payload.extend_from_slice(&items_bytes);
        payload.extend_from_slice(&10u8.to_be_bytes());
        payload.extend_from_slice(&4u16.to_be_bytes());
        payload.extend_from_slice(b"test");
        let ether_pkt = make_ether_ip_tcp_payload(&payload);
        write_packet(&mut file, 1_700_000_002, 345678, &ether_pkt).expect("Failed to write packet 3");
    }

    println!("Test PCAP file generated: {:?}", out_path);
}
