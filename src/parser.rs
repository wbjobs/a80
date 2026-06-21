use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::template::{
    Condition, ConditionalBranch, Endian, Field, FieldType, ProtocolTemplate,
};

pub struct BinaryParser<'a> {
    data: &'a [u8],
    offset: usize,
    default_endian: Endian,
}

impl<'a> BinaryParser<'a> {
    pub fn new(data: &'a [u8], default_endian: Endian) -> Self {
        BinaryParser {
            data,
            offset: 0,
            default_endian,
        }
    }

    pub fn parse_template(&mut self, template: &ProtocolTemplate) -> Result<Value> {
        let mut ctx = ParseContext::new();
        self.parse_fields(&template.fields, &mut ctx)?;
        Ok(ctx.into_value())
    }

    fn parse_fields(&mut self, fields: &[Field], ctx: &mut ParseContext) -> Result<()> {
        for field in fields {
            self.parse_field(field, ctx)?;
        }
        Ok(())
    }

    fn parse_field(&mut self, field: &Field, ctx: &mut ParseContext) -> Result<()> {
        match field {
            Field::Scalar {
                name,
                data_type,
                endian,
                length,
                length_field,
                encoding,
            } => {
                let eff_endian = endian.unwrap_or(self.default_endian);
                let value = self.parse_scalar(data_type, eff_endian, *length, length_field.as_deref(), encoding.as_deref(), ctx)?;
                ctx.set(name.clone(), value);
            }
            Field::Struct { name, fields } => {
                let mut sub_ctx = ParseContext::new();
                self.parse_fields(fields, &mut sub_ctx)?;
                let value = sub_ctx.into_value();
                match name {
                    Some(n) => ctx.set(n.clone(), value),
                    None => ctx.merge(value),
                }
            }
            Field::Conditional {
                name,
                conditions,
                default,
            } => {
                let matched = self.match_conditional(conditions, ctx)?;
                let fields_to_parse = match matched {
                    Some(branch) => &branch.fields,
                    None => default
                        .as_ref()
                        .ok_or_else(|| anyhow!("No conditional branch matched and no default provided"))?,
                };
                match name {
                    Some(n) => {
                        let mut sub_ctx = ParseContext::new();
                        self.parse_fields(fields_to_parse, &mut sub_ctx)?;
                        ctx.set(n.clone(), sub_ctx.into_value());
                    }
                    None => {
                        self.parse_fields(fields_to_parse, ctx)?;
                    }
                }
            }
            Field::Array {
                name,
                element,
                count,
                count_field,
                until_eof,
            } => {
                let items = self.parse_array(element, *count, count_field.as_deref(), *until_eof, ctx)?;
                ctx.set(name.clone(), Value::Array(items));
            }
        }
        Ok(())
    }

    fn parse_scalar(
        &mut self,
        data_type: &FieldType,
        endian: Endian,
        length: Option<usize>,
        length_field: Option<&str>,
        encoding: Option<&str>,
        ctx: &ParseContext,
    ) -> Result<Value> {
        match data_type {
            FieldType::U8 => {
                let v = self.read_u8()?;
                Ok(json!(v))
            }
            FieldType::U16 => {
                let v = self.read_u16(endian)?;
                Ok(json!(v))
            }
            FieldType::U32 => {
                let v = self.read_u32(endian)?;
                Ok(json!(v))
            }
            FieldType::U64 => {
                let v = self.read_u64(endian)?;
                Ok(json!(v))
            }
            FieldType::I8 => {
                let v = self.read_i8()?;
                Ok(json!(v))
            }
            FieldType::I16 => {
                let v = self.read_i16(endian)?;
                Ok(json!(v))
            }
            FieldType::I32 => {
                let v = self.read_i32(endian)?;
                Ok(json!(v))
            }
            FieldType::I64 => {
                let v = self.read_i64(endian)?;
                Ok(json!(v))
            }
            FieldType::F32 => {
                let bytes = self.read_bytes(4)?;
                let v = match endian {
                    Endian::Little => f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                    Endian::Big => f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                };
                Ok(json!(v))
            }
            FieldType::F64 => {
                let bytes = self.read_bytes(8)?;
                let v = match endian {
                    Endian::Little => f64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                    ]),
                    Endian::Big => f64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                    ]),
                };
                Ok(json!(v))
            }
            FieldType::Bytes => {
                let len = self.resolve_length(length, length_field, ctx)?;
                let bytes = self.read_bytes(len)?;
                Ok(json!(hex::encode(bytes)))
            }
            FieldType::String => {
                let len = self.resolve_length(length, length_field, ctx)?;
                let bytes = self.read_bytes(len)?;
                let s = match encoding {
                    Some("utf-16le") => {
                        let chars: Vec<u16> = bytes
                            .chunks(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&chars)
                    }
                    Some("utf-16be") => {
                        let chars: Vec<u16> = bytes
                            .chunks(2)
                            .map(|c| u16::from_be_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&chars)
                    }
                    _ => String::from_utf8_lossy(bytes).to_string(),
                };
                Ok(json!(s))
            }
        }
    }

    fn resolve_length(
        &self,
        length: Option<usize>,
        length_field: Option<&str>,
        ctx: &ParseContext,
    ) -> Result<usize> {
        if let Some(l) = length {
            return Ok(l);
        }
        if let Some(field_name) = length_field {
            let v = ctx
                .get(field_name)
                .ok_or_else(|| anyhow!("Length field '{}' not found in context", field_name))?;
            return v
                .as_u64()
                .map(|x| x as usize)
                .or_else(|| v.as_i64().map(|x| x as usize))
                .ok_or_else(|| anyhow!("Length field '{}' is not a valid integer", field_name));
        }
        Ok(self.data.len() - self.offset)
    }

    fn match_conditional<'b>(
        &self,
        branches: &'b [ConditionalBranch],
        ctx: &ParseContext,
    ) -> Result<Option<&'b ConditionalBranch>> {
        for branch in branches {
            if let Some(cond) = &branch.when {
                if self.eval_condition(cond, ctx)? {
                    return Ok(Some(branch));
                }
            }
        }
        Ok(None)
    }

    fn eval_condition(&self, cond: &Condition, ctx: &ParseContext) -> Result<bool> {
        let field_val = ctx
            .get(&cond.field)
            .ok_or_else(|| anyhow!("Condition field '{}' not found", cond.field))?;

        let mut result = true;
        let mut has_any = false;

        if let Some(eq) = &cond.eq {
            result = result && values_equal(field_val, eq);
            has_any = true;
        }
        if let Some(ne) = &cond.ne {
            result = result && !values_equal(field_val, ne);
            has_any = true;
        }
        if let Some(gt) = &cond.gt {
            result = result && values_compare(field_val, gt, |a, b| a > b);
            has_any = true;
        }
        if let Some(lt) = &cond.lt {
            result = result && values_compare(field_val, lt, |a, b| a < b);
            has_any = true;
        }
        if let Some(ge) = &cond.ge {
            result = result && values_compare(field_val, ge, |a, b| a >= b);
            has_any = true;
        }
        if let Some(le) = &cond.le {
            result = result && values_compare(field_val, le, |a, b| a <= b);
            has_any = true;
        }
        if let Some(in_list) = &cond.in_list {
            result = result && in_list.iter().any(|v| values_equal(field_val, v));
            has_any = true;
        }

        if !has_any {
            anyhow::bail!("Condition has no operators specified");
        }
        Ok(result)
    }

    fn parse_array(
        &mut self,
        element: &Field,
        count: Option<usize>,
        count_field: Option<&str>,
        until_eof: bool,
        ctx: &ParseContext,
    ) -> Result<Vec<Value>> {
        let n = if until_eof {
            usize::MAX
        } else if let Some(c) = count {
            c
        } else if let Some(field_name) = count_field {
            let v = ctx
                .get(field_name)
                .ok_or_else(|| anyhow!("Count field '{}' not found", field_name))?;
            v.as_u64()
                .map(|x| x as usize)
                .or_else(|| v.as_i64().map(|x| x as usize))
                .ok_or_else(|| anyhow!("Count field '{}' is not a valid integer", field_name))?
        } else {
            anyhow::bail!("Array must specify count, count_field, or until_eof");
        };

        let mut items = Vec::new();
        for _ in 0..n {
            if self.offset >= self.data.len() {
                if until_eof {
                    break;
                }
                anyhow::bail!("Unexpected end of data while parsing array element");
            }
            let mut sub_ctx = ParseContext::new();
            self.parse_field(element, &mut sub_ctx)?;
            let item_value = sub_ctx.into_value();
            let item = if let Value::Object(ref obj) = item_value {
                if obj.len() == 1 {
                    obj.values().next().unwrap().clone()
                } else {
                    item_value
                }
            } else {
                item_value
            };
            items.push(item);
        }
        Ok(items)
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.offset >= self.data.len() {
            anyhow::bail!("Unexpected end of data reading u8");
        }
        let v = self.data[self.offset];
        self.offset += 1;
        Ok(v)
    }

    fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    fn read_u16(&mut self, endian: Endian) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(match endian {
            Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
        })
    }

    fn read_i16(&mut self, endian: Endian) -> Result<i16> {
        Ok(self.read_u16(endian)? as i16)
    }

    fn read_u32(&mut self, endian: Endian) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(match endian {
            Endian::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endian::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    fn read_i32(&mut self, endian: Endian) -> Result<i32> {
        Ok(self.read_u32(endian)? as i32)
    }

    fn read_u64(&mut self, endian: Endian) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(match endian {
            Endian::Little => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            Endian::Big => u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
        })
    }

    fn read_i64(&mut self, endian: Endian) -> Result<i64> {
        Ok(self.read_u64(endian)? as i64)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&[u8]> {
        if self.offset + len > self.data.len() {
            anyhow::bail!(
                "Unexpected end of data: need {} bytes, have {} bytes remaining",
                len,
                self.data.len() - self.offset
            );
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.data[start..self.offset])
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(na), Value::Number(nb)) => {
            if let (Some(ia), Some(ib)) = (na.as_i64(), nb.as_i64()) {
                ia == ib
            } else if let (Some(ua), Some(ub)) = (na.as_u64(), nb.as_u64()) {
                ua == ub
            } else if let (Some(fa), Some(fb)) = (na.as_f64(), nb.as_f64()) {
                fa == fb
            } else {
                false
            }
        }
        (Value::String(sa), Value::String(sb)) => sa == sb,
        (Value::Bool(ba), Value::Bool(bb)) => ba == bb,
        (Value::Number(n), Value::String(s)) => {
            if let Some(i) = n.as_i64() {
                s.parse::<i64>().map(|x| x == i).unwrap_or(false)
            } else if let Some(u) = n.as_u64() {
                s.parse::<u64>().map(|x| x == u).unwrap_or(false)
            } else {
                false
            }
        }
        (Value::String(s), Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                s.parse::<i64>().map(|x| x == i).unwrap_or(false)
            } else if let Some(u) = n.as_u64() {
                s.parse::<u64>().map(|x| x == u).unwrap_or(false)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn values_compare(a: &Value, b: &Value, cmp: fn(f64, f64) -> bool) -> bool {
    let fa = value_to_f64(a);
    let fb = value_to_f64(b);
    match (fa, fb) {
        (Some(x), Some(y)) => cmp(x, y),
        _ => false,
    }
}

fn value_to_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

struct ParseContext {
    data: BTreeMap<String, Value>,
}

impl ParseContext {
    fn new() -> Self {
        ParseContext {
            data: BTreeMap::new(),
        }
    }

    fn set(&mut self, key: String, value: Value) {
        self.data.insert(key, value);
    }

    fn get(&self, key: &str) -> Option<&Value> {
        if let Some(v) = self.data.get(key) {
            return Some(v);
        }
        for (_, v) in &self.data {
            if let Value::Object(obj) = v {
                if let Some(found) = search_nested(obj, key) {
                    return Some(found);
                }
            }
        }
        None
    }

    fn merge(&mut self, value: Value) {
        if let Value::Object(obj) = value {
            for (k, v) in obj {
                self.data.insert(k, v);
            }
        }
    }

    fn into_value(self) -> Value {
        Value::Object(serde_json::Map::from_iter(self.data))
    }
}

fn search_nested<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a Value> {
    if let Some(v) = obj.get(key) {
        return Some(v);
    }
    for (_, v) in obj {
        if let Value::Object(sub) = v {
            if let Some(found) = search_nested(sub, key) {
                return Some(found);
            }
        }
    }
    None
}
