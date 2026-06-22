use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ByteStats {
    pub offset: usize,
    pub count: usize,
    pub unique_values: Vec<u8>,
    pub value_counts: HashMap<u8, usize>,
    pub min: u8,
    pub max: u8,
    pub is_constant: bool,
    pub constant_value: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct PayloadAnalysis {
    pub total_packets: usize,
    pub min_length: usize,
    pub max_length: usize,
    pub avg_length: f64,
    pub byte_stats: Vec<ByteStats>,
}

pub fn analyze_payloads(payloads: &[&[u8]], max_offset: usize) -> PayloadAnalysis {
    let total_packets = payloads.len();

    let min_length = payloads.iter().map(|p| p.len()).min().unwrap_or(0);
    let max_length = payloads.iter().map(|p| p.len()).max().unwrap_or(0);
    let avg_length = if total_packets > 0 {
        payloads.iter().map(|p| p.len() as f64).sum::<f64>() / total_packets as f64
    } else {
        0.0
    };

    let analyze_up_to = max_offset.min(min_length);
    let mut byte_stats = Vec::with_capacity(analyze_up_to);

    for offset in 0..analyze_up_to {
        let mut value_counts: HashMap<u8, usize> = HashMap::new();
        let mut min = u8::MAX;
        let mut max = u8::MIN;

        for payload in payloads {
            if offset < payload.len() {
                let byte = payload[offset];
                *value_counts.entry(byte).or_insert(0) += 1;
                if byte < min {
                    min = byte;
                }
                if byte > max {
                    max = byte;
                }
            }
        }

        let unique_count = value_counts.len();
        let is_constant = unique_count == 1;
        let constant_value = if is_constant {
            Some(*value_counts.keys().next().unwrap())
        } else {
            None
        };

        let mut unique_values: Vec<u8> = value_counts.keys().copied().collect();
        unique_values.sort();

        byte_stats.push(ByteStats {
            offset,
            count: total_packets,
            unique_values,
            value_counts,
            min,
            max,
            is_constant,
            constant_value,
        });
    }

    PayloadAnalysis {
        total_packets,
        min_length,
        max_length,
        avg_length,
        byte_stats,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldPattern {
    Constant(Vec<u8>),
    UInt8 { min: u8, max: u8 },
    UInt16 { min: u16, max: u16, endian: EndianGuess },
    UInt32 { min: u32, max: u32, endian: EndianGuess },
    LengthField { field_size: usize, endian: EndianGuess, points_to: usize },
    CountField { field_size: usize, endian: EndianGuess },
    RandomBytes,
    AsciiChar,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndianGuess {
    Big,
    Little,
    Uncertain,
}

#[derive(Debug, Clone)]
pub struct InferredField {
    pub offset: usize,
    pub size: usize,
    pub pattern: FieldPattern,
    pub suggested_name: String,
    pub confidence: f64,
}

pub fn infer_fields(analysis: &PayloadAnalysis) -> Vec<InferredField> {
    let mut fields = Vec::new();
    let stats = &analysis.byte_stats;
    let mut offset = 0;

    while offset < stats.len() {
        let stat = &stats[offset];

        if stat.is_constant {
            let mut run_end = offset;
            while run_end < stats.len() && stats[run_end].is_constant {
                run_end += 1;
            }
            let const_len = run_end - offset;
            let const_bytes: Vec<u8> = (offset..run_end)
                .map(|i| stats[i].constant_value.unwrap())
                .collect();

            fields.push(InferredField {
                offset,
                size: const_len,
                pattern: FieldPattern::Constant(const_bytes),
                suggested_name: format!("magic_{}", offset),
                confidence: 0.95,
            });
            offset = run_end;
            continue;
        }

        let remaining = stats.len() - offset;
        let mut matched = false;

        if remaining >= 2 {
            if let Some((pattern, size)) = try_match_u16(&stats[offset..offset + 2]) {
                fields.push(InferredField {
                    offset,
                    size,
                    pattern,
                    suggested_name: format!("field_u16_{}", offset),
                    confidence: 0.7,
                });
                offset += size;
                matched = true;
            }
        }

        if !matched && remaining >= 4 {
            if let Some((pattern, size)) = try_match_u32(&stats[offset..offset + 4]) {
                fields.push(InferredField {
                    offset,
                    size,
                    pattern,
                    suggested_name: format!("field_u32_{}", offset),
                    confidence: 0.7,
                });
                offset += size;
                matched = true;
            }
        }

        if !matched {
            if is_likely_ascii(stat) {
                fields.push(InferredField {
                    offset,
                    size: 1,
                    pattern: FieldPattern::AsciiChar,
                    suggested_name: format!("char_{}", offset),
                    confidence: 0.6,
                });
            } else {
                fields.push(InferredField {
                    offset,
                    size: 1,
                    pattern: FieldPattern::UInt8 {
                        min: stat.min,
                        max: stat.max,
                    },
                    suggested_name: format!("field_u8_{}", offset),
                    confidence: 0.5,
                });
            }
            offset += 1;
        }
    }

    detect_length_fields(&mut fields, analysis);
    rename_fields_with_heuristics(&mut fields);

    fields
}

fn try_match_u16(stats: &[ByteStats]) -> Option<(FieldPattern, usize)> {
    if stats.len() < 2 {
        return None;
    }

    let mut big_values: Vec<u16> = Vec::new();
    let mut little_values: Vec<u16> = Vec::new();

    let count = stats[0].count.min(stats[1].count);
    for _ in 0..count.min(100) {
        let b0 = stats[0].unique_values[0];
        let b1 = stats[1].unique_values[0];
        big_values.push(u16::from_be_bytes([b0, b1]));
        little_values.push(u16::from_le_bytes([b0, b1]));
    }

    let has_const_high_byte_big = stats[0].is_constant;
    let has_const_high_byte_little = stats[1].is_constant;

    if has_const_high_byte_big && !stats[1].is_constant {
        return Some((
            FieldPattern::UInt16 {
                min: 0,
                max: 255,
                endian: EndianGuess::Big,
            },
            2,
        ));
    }
    if has_const_high_byte_little && !stats[0].is_constant {
        return Some((
            FieldPattern::UInt16 {
                min: 0,
                max: 255,
                endian: EndianGuess::Little,
            },
            2,
        ));
    }

    None
}

fn try_match_u32(stats: &[ByteStats]) -> Option<(FieldPattern, usize)> {
    if stats.len() < 4 {
        return None;
    }

    let const_count = stats.iter().filter(|s| s.is_constant).count();
    if const_count == 0 {
        return None;
    }

    let mut big_endian_likely = false;
    if stats[0].is_constant && stats[1].is_constant && !stats[2].is_constant && !stats[3].is_constant
    {
        big_endian_likely = true;
    }

    let mut little_endian_likely = false;
    if stats[3].is_constant && stats[2].is_constant && !stats[1].is_constant && !stats[0].is_constant
    {
        little_endian_likely = true;
    }

    let endian = if big_endian_likely && !little_endian_likely {
        EndianGuess::Big
    } else if little_endian_likely && !big_endian_likely {
        EndianGuess::Little
    } else {
        EndianGuess::Uncertain
    };

    if big_endian_likely || little_endian_likely {
        Some((
            FieldPattern::UInt32 {
                min: 0,
                max: u32::MAX,
                endian,
            },
            4,
        ))
    } else {
        None
    }
}

fn is_likely_ascii(stat: &ByteStats) -> bool {
    if stat.unique_values.is_empty() {
        return false;
    }
    let ascii_count = stat
        .unique_values
        .iter()
        .filter(|&&b| b >= 32 && b < 127)
        .count();
    ascii_count as f64 / stat.unique_values.len() as f64 > 0.8
}

fn detect_length_fields(fields: &mut Vec<InferredField>, analysis: &PayloadAnalysis) {
    let _avg = analysis.avg_length as usize;
    let min_len = analysis.min_length;
    let max_len = analysis.max_length;

    if min_len == max_len {
        return;
    }

    let mut candidates = Vec::new();

    for field in fields.iter() {
        match &field.pattern {
            FieldPattern::UInt16 { min, max, endian } => {
                if *max as usize >= min_len && *min as usize <= max_len.saturating_add(100) {
                    candidates.push((field.offset, field.size, endian.clone()));
                }
            }
            FieldPattern::UInt32 { min, max, endian } => {
                if *max as usize >= min_len && *min as usize <= max_len.saturating_add(100) {
                    candidates.push((field.offset, field.size, endian.clone()));
                }
            }
            _ => {}
        }
    }

    if let Some((offset, size, endian)) = candidates.first() {
        if *offset < 8 {
            for field in fields.iter_mut() {
                if field.offset == *offset {
                    field.pattern = FieldPattern::LengthField {
                        field_size: *size,
                        endian: endian.clone(),
                        points_to: offset + size,
                    };
                    field.suggested_name = "length".to_string();
                    field.confidence = 0.85;
                    break;
                }
            }
        }
    }
}

fn rename_fields_with_heuristics(fields: &mut Vec<InferredField>) {
    let mut type_idx = 0;
    let mut id_idx = 0;

    for field in fields.iter_mut() {
        if field.offset < 4 {
            if let FieldPattern::Constant(_) = field.pattern {
                field.suggested_name = "magic".to_string();
            }
        }

        match &field.pattern {
            FieldPattern::LengthField { .. } => {
                field.suggested_name = "length".to_string();
            }
            FieldPattern::UInt32 { .. } => {
                if field.offset >= 4 && field.offset <= 12 {
                    if type_idx == 0 {
                        field.suggested_name = "msg_type".to_string();
                        type_idx += 1;
                    } else if id_idx == 0 {
                        field.suggested_name = "request_id".to_string();
                        id_idx += 1;
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn detect_signature(analysis: &PayloadAnalysis) -> Option<(usize, Vec<u8>)> {
    let mut run_start: Option<usize> = None;
    let mut best_run: Option<(usize, usize)> = None;

    for (i, stat) in analysis.byte_stats.iter().enumerate() {
        if stat.is_constant {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else {
            if let Some(start) = run_start.take() {
                let len = i - start;
                if len >= 2 {
                    if best_run.map_or(true, |(_, bl)| len > bl) {
                        best_run = Some((start, len));
                    }
                }
            }
        }
    }

    if let Some(start) = run_start.take() {
        let len = analysis.byte_stats.len() - start;
        if len >= 2 {
            if best_run.map_or(true, |(_, bl)| len > bl) {
                best_run = Some((start, len));
            }
        }
    }

    best_run.map(|(start, len)| {
        let bytes: Vec<u8> = (start..start + len)
            .map(|i| analysis.byte_stats[i].constant_value.unwrap())
            .collect();
        (start, bytes)
    })
}
