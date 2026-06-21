use anyhow::Result;
use serde_json::{Map, Value};
use std::io::Write;

pub enum OutputFormat {
    Json,
    JsonPretty,
    Csv,
}

pub fn output_results<W: Write>(
    writer: &mut W,
    packets: &[crate::pcap::PcapPacket],
    results: &[Option<Value>],
    errors: &[Option<String>],
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let output: Vec<Value> = packets
                .iter()
                .zip(results.iter())
                .zip(errors.iter())
                .enumerate()
                .map(|(idx, ((pkt, res), err))| {
                    let mut obj = Map::new();
                    obj.insert("packet_index".to_string(), Value::from(idx + 1));
                    obj.insert(
                        "timestamp".to_string(),
                        Value::from(format!("{}.{:06}", pkt.ts_sec, pkt.ts_usec)),
                    );
                    obj.insert("original_length".to_string(), Value::from(pkt.orig_len));
                    if let Some(e) = err {
                        obj.insert("parse_error".to_string(), Value::from(e.clone()));
                    }
                    if let Some(r) = res {
                        obj.insert("parsed".to_string(), r.clone());
                    }
                    Value::Object(obj)
                })
                .collect();
            serde_json::to_writer(&mut *writer, &output)?;
            writer.write_all(b"\n")?;
        }
        OutputFormat::JsonPretty => {
            let output: Vec<Value> = packets
                .iter()
                .zip(results.iter())
                .zip(errors.iter())
                .enumerate()
                .map(|(idx, ((pkt, res), err))| {
                    let mut obj = Map::new();
                    obj.insert("packet_index".to_string(), Value::from(idx + 1));
                    obj.insert(
                        "timestamp".to_string(),
                        Value::from(format!("{}.{:06}", pkt.ts_sec, pkt.ts_usec)),
                    );
                    obj.insert("original_length".to_string(), Value::from(pkt.orig_len));
                    if let Some(e) = err {
                        obj.insert("parse_error".to_string(), Value::from(e.clone()));
                    }
                    if let Some(r) = res {
                        obj.insert("parsed".to_string(), r.clone());
                    }
                    Value::Object(obj)
                })
                .collect();
            serde_json::to_writer_pretty(&mut *writer, &output)?;
            writer.write_all(b"\n")?;
        }
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(writer);
            let mut headers = vec![
                "packet_index".to_string(),
                "timestamp".to_string(),
                "original_length".to_string(),
                "parse_error".to_string(),
            ];
            let mut data_keys: Vec<String> = Vec::new();
            for res in results {
                if let Some(Value::Object(obj)) = res {
                    collect_keys(obj, &mut data_keys, String::new());
                }
            }
            data_keys.sort();
            data_keys.dedup();
            headers.extend(data_keys.clone());
            wtr.write_record(&headers)?;

            for (idx, (pkt, (res, err))) in packets
                .iter()
                .zip(results.iter().zip(errors.iter()))
                .enumerate()
            {
                let mut record: Vec<String> = Vec::with_capacity(headers.len());
                record.push((idx + 1).to_string());
                record.push(format!("{}.{:06}", pkt.ts_sec, pkt.ts_usec));
                record.push(pkt.orig_len.to_string());
                record.push(err.clone().unwrap_or_default());

                if let Some(Value::Object(obj)) = res {
                    let flat = flatten_object(obj);
                    for key in &data_keys {
                        record.push(flat.get(key).cloned().unwrap_or_default());
                    }
                } else {
                    for _ in &data_keys {
                        record.push(String::new());
                    }
                }
                wtr.write_record(&record)?;
            }
            wtr.flush()?;
        }
    }
    Ok(())
}

fn collect_keys(obj: &Map<String, Value>, keys: &mut Vec<String>, prefix: String) {
    for (k, v) in obj {
        let full_key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{}.{}", prefix, k)
        };
        match v {
            Value::Object(sub) => collect_keys(sub, keys, full_key),
            Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    let array_key = format!("{}[{}]", full_key, i);
                    if let Value::Object(sub) = item {
                        collect_keys(sub, keys, array_key);
                    } else {
                        keys.push(array_key);
                    }
                }
                if arr.is_empty() {
                    keys.push(full_key);
                }
            }
            _ => keys.push(full_key),
        }
    }
}

fn flatten_object(obj: &Map<String, Value>) -> std::collections::BTreeMap<String, String> {
    let mut result = std::collections::BTreeMap::new();
    flatten_object_inner(obj, &mut result, String::new());
    result
}

fn flatten_object_inner(
    obj: &Map<String, Value>,
    result: &mut std::collections::BTreeMap<String, String>,
    prefix: String,
) {
    for (k, v) in obj {
        let full_key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{}.{}", prefix, k)
        };
        match v {
            Value::Object(sub) => flatten_object_inner(sub, result, full_key),
            Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    let array_key = format!("{}[{}]", full_key, i);
                    match item {
                        Value::Object(sub) => flatten_object_inner(sub, result, array_key),
                        other => {
                            result.insert(array_key, value_to_string(other));
                        }
                    }
                }
            }
            other => {
                result.insert(full_key, value_to_string(other));
            }
        }
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(v).unwrap_or_default(),
    }
}
