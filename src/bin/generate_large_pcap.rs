use std::fs::File;
use std::io::Write;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let num_packets: usize = if args.len() > 1 {
        args[1].parse().unwrap_or(10000)
    } else {
        10000
    };
    let match_ratio: f64 = if args.len() > 2 {
        args[2].parse().unwrap_or(0.5)
    } else {
        0.5
    };

    let mut file = File::create("large_test.pcap")?;

    file.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    file.write_all(&2u16.to_le_bytes())?;
    file.write_all(&4u16.to_le_bytes())?;
    file.write_all(&0u32.to_le_bytes())?;
    file.write_all(&0u32.to_le_bytes())?;
    file.write_all(&65535u32.to_le_bytes())?;
    file.write_all(&1u32.to_le_bytes())?;

    let mut matched = 0usize;
    let mut mismatched = 0usize;

    for i in 0..num_packets {
        let ts_sec = 1700000000u32 + (i as u32 / 1000);
        let ts_usec = (i as u32 % 1000) * 1000;

        let is_match = (i as f64) < (num_packets as f64 * match_ratio);

        let payload = if is_match {
            matched += 1;
            let msg_type = (i % 3) + 1;
            build_matching_payload(msg_type, i as u32)
        } else {
            mismatched += 1;
            build_non_matching_payload(i as u32)
        };

        let eth_ip_tcp = build_eth_ip_tcp(&payload);
        let packet_len = eth_ip_tcp.len() as u32;

        file.write_all(&ts_sec.to_le_bytes())?;
        file.write_all(&ts_usec.to_le_bytes())?;
        file.write_all(&packet_len.to_le_bytes())?;
        file.write_all(&packet_len.to_le_bytes())?;
        file.write_all(&eth_ip_tcp)?;
    }

    println!("生成完成: {} 个包 (匹配: {}, 不匹配: {})", num_packets, matched, mismatched);
    Ok(())
}

fn build_eth_ip_tcp(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();

    v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    v.extend_from_slice(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    v.extend_from_slice(&[0x08, 0x00]);

    let total_len = 20 + 20 + payload.len();
    v.push(0x45);
    v.push(0x00);
    v.extend_from_slice(&(total_len as u16).to_be_bytes());
    v.extend_from_slice(&[0x00, 0x00]);
    v.extend_from_slice(&[0x40, 0x00]);
    v.push(0x40);
    v.push(0x06);
    v.extend_from_slice(&[0x00, 0x00]);
    v.extend_from_slice(&[192, 168, 1, 1]);
    v.extend_from_slice(&[192, 168, 1, 2]);

    v.extend_from_slice(&[0x1F, 0x90]);
    v.extend_from_slice(&[0x1F, 0x91]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    v.push(0x50);
    v.push(0x18);
    v.extend_from_slice(&[0x20, 0x00]);
    v.extend_from_slice(&[0x00, 0x00]);
    v.extend_from_slice(&[0x00, 0x00]);

    v.extend_from_slice(payload);
    v
}

fn build_matching_payload(msg_type: usize, seq: u32) -> Vec<u8> {
    let mut v = Vec::new();

    match msg_type {
        1 => {
            let method = b"GET";
            let total_len = 2 + 4 + 4 + 2 + method.len() + 5;
            v.extend_from_slice(&(total_len as u16).to_be_bytes());
            v.extend_from_slice(&(1u32).to_be_bytes());
            v.extend_from_slice(&seq.to_be_bytes());
            v.extend_from_slice(&(method.len() as u16).to_be_bytes());
            v.extend_from_slice(method);
            v.push(1u8);
            v.push(2u8);
            v.push(0x41);
            v.push(0x42);
        }
        2 => {
            let body = b"OK";
            let total_len = 2 + 4 + 4 + 2 + 2 + body.len();
            v.extend_from_slice(&(total_len as u16).to_be_bytes());
            v.extend_from_slice(&(2u32).to_be_bytes());
            v.extend_from_slice(&seq.to_be_bytes());
            v.extend_from_slice(&(200u16).to_be_bytes());
            v.extend_from_slice(&(body.len() as u16).to_be_bytes());
            v.extend_from_slice(body);
        }
        3 => {
            let name1 = b"Alice";
            let name2 = b"Bob";
            let item_len = 4 + 2 + name1.len();
            let total_len = 2 + 4 + 2 + 2 * item_len + 6;
            v.extend_from_slice(&(total_len as u16).to_be_bytes());
            v.extend_from_slice(&(3u32).to_be_bytes());
            v.extend_from_slice(&(2u16).to_be_bytes());
            v.extend_from_slice(&(100u32).to_be_bytes());
            v.extend_from_slice(&(name1.len() as u16).to_be_bytes());
            v.extend_from_slice(name1);
            v.extend_from_slice(&(101u32).to_be_bytes());
            v.extend_from_slice(&(name2.len() as u16).to_be_bytes());
            v.extend_from_slice(name2);
            v.push(10u8);
            v.push(4u8);
            v.extend_from_slice(b"test");
        }
        _ => unreachable!(),
    }
    v
}

fn build_non_matching_payload(seq: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(12u16).to_be_bytes());
    v.extend_from_slice(&0xFF00FF00u32.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    v
}
