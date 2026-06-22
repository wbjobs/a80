use crate::analyzer::{detect_signature, infer_fields, FieldPattern, InferredField, PayloadAnalysis};
use crate::template::{Endian, Field, FieldType, ProtocolTemplate, TemplateSignature};

pub fn generate_template(analysis: &PayloadAnalysis, name: Option<&str>) -> ProtocolTemplate {
    let inferred_fields = infer_fields(analysis);
    let signature = detect_signature(analysis).map(|(offset, bytes)| TemplateSignature {
        offset,
        bytes: hex::encode(&bytes),
    });

    let mut endian = Endian::default();
    for field in &inferred_fields {
        match &field.pattern {
            FieldPattern::UInt16 { endian: e, .. }
            | FieldPattern::UInt32 { endian: e, .. }
            | FieldPattern::LengthField { endian: e, .. }
            | FieldPattern::CountField { endian: e, .. } => {
                match e {
                    crate::analyzer::EndianGuess::Big => {
                        endian = Endian::Big;
                        break;
                    }
                    crate::analyzer::EndianGuess::Little => {
                        endian = Endian::Little;
                        break;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    let fields = inferred_fields
        .iter()
        .map(|f| inferred_to_field(f, endian))
        .collect();

    ProtocolTemplate {
        name: name.map(|s| s.to_string()),
        endian,
        signature,
        fields,
    }
}

fn inferred_to_field(inferred: &InferredField, default_endian: Endian) -> Field {
    match &inferred.pattern {
        FieldPattern::Constant(bytes) => {
            Field::Scalar {
                name: inferred.suggested_name.clone(),
                data_type: FieldType::Bytes,
                endian: None,
                length: Some(bytes.len()),
                length_field: None,
                encoding: None,
            }
        }
        FieldPattern::UInt8 { .. } => Field::Scalar {
            name: inferred.suggested_name.clone(),
            data_type: FieldType::U8,
            endian: None,
            length: None,
            length_field: None,
            encoding: None,
        },
        FieldPattern::UInt16 { endian, .. } => {
            let f_endian = match endian {
                crate::analyzer::EndianGuess::Big => Endian::Big,
                crate::analyzer::EndianGuess::Little => Endian::Little,
                _ => default_endian,
            };
            Field::Scalar {
                name: inferred.suggested_name.clone(),
                data_type: FieldType::U16,
                endian: if f_endian != default_endian {
                    Some(f_endian)
                } else {
                    None
                },
                length: None,
                length_field: None,
                encoding: None,
            }
        }
        FieldPattern::UInt32 { endian, .. } => {
            let f_endian = match endian {
                crate::analyzer::EndianGuess::Big => Endian::Big,
                crate::analyzer::EndianGuess::Little => Endian::Little,
                _ => default_endian,
            };
            Field::Scalar {
                name: inferred.suggested_name.clone(),
                data_type: FieldType::U32,
                endian: if f_endian != default_endian {
                    Some(f_endian)
                } else {
                    None
                },
                length: None,
                length_field: None,
                encoding: None,
            }
        }
        FieldPattern::LengthField {
            field_size, endian, ..
        } => {
            let f_endian = match endian {
                crate::analyzer::EndianGuess::Big => Endian::Big,
                crate::analyzer::EndianGuess::Little => Endian::Little,
                _ => default_endian,
            };
            let dtype = match field_size {
                2 => FieldType::U16,
                4 => FieldType::U32,
                _ => FieldType::U8,
            };
            Field::Scalar {
                name: "length".to_string(),
                data_type: dtype,
                endian: if f_endian != default_endian {
                    Some(f_endian)
                } else {
                    None
                },
                length: None,
                length_field: None,
                encoding: None,
            }
        }
        FieldPattern::CountField {
            field_size, endian, ..
        } => {
            let f_endian = match endian {
                crate::analyzer::EndianGuess::Big => Endian::Big,
                crate::analyzer::EndianGuess::Little => Endian::Little,
                _ => default_endian,
            };
            let dtype = match field_size {
                2 => FieldType::U16,
                4 => FieldType::U32,
                _ => FieldType::U8,
            };
            Field::Scalar {
                name: "count".to_string(),
                data_type: dtype,
                endian: if f_endian != default_endian {
                    Some(f_endian)
                } else {
                    None
                },
                length: None,
                length_field: None,
                encoding: None,
            }
        }
        FieldPattern::AsciiChar => Field::Scalar {
            name: inferred.suggested_name.clone(),
            data_type: FieldType::String,
            endian: None,
            length: Some(1),
            length_field: None,
            encoding: Some("utf-8".to_string()),
        },
        FieldPattern::RandomBytes | FieldPattern::Unknown => Field::Scalar {
            name: inferred.suggested_name.clone(),
            data_type: FieldType::U8,
            endian: None,
            length: None,
            length_field: None,
            encoding: None,
        },
    }
}

pub fn generate_analysis_summary(analysis: &PayloadAnalysis) -> String {
    let mut lines = Vec::new();

    lines.push(format!("总包数: {}", analysis.total_packets));
    lines.push(format!(
        "长度范围: {} - {} (平均 {:.1})",
        analysis.min_length, analysis.max_length, analysis.avg_length
    ));
    lines.push(format!(
        "分析字节范围: 0 - {}",
        analysis.byte_stats.len().saturating_sub(1)
    ));
    lines.push(String::new());
    lines.push("字节分布概览:".to_string());
    lines.push(format!(
        "  常数字节数: {}",
        analysis
            .byte_stats
            .iter()
            .filter(|s| s.is_constant)
            .count()
    ));
    lines.push(format!(
        "  变字节数: {}",
        analysis
            .byte_stats
            .iter()
            .filter(|s| !s.is_constant)
            .count()
    ));
    lines.push(String::new());
    lines.push("前32字节详情:".to_string());

    let display_up_to = 32.min(analysis.byte_stats.len());
    for i in 0..display_up_to {
        let stat = &analysis.byte_stats[i];
        let hex_str = if stat.is_constant {
            format!("0x{:02X}", stat.constant_value.unwrap())
        } else {
            format!(
                "0x{:02X}-0x{:02X}",
                stat.min, stat.max
            )
        };
        let label = if stat.is_constant {
            "常量"
        } else {
            "变化"
        };
        lines.push(format!(
            "  [{:3}] {:10} {} (唯一值: {})",
            i,
            hex_str,
            label,
            stat.unique_values.len()
        ));
    }

    lines.join("\n")
}
