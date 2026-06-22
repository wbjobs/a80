use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use crate::bytecode::{
    BytecodeProgram, Instruction, JumpValue, LoopCount, ScalarType, StringEncoding, VarLength,
};
use crate::template::Endian;

struct VmValueSlot {
    value: Option<Value>,
}

struct Frame {
    name: Option<String>,
    object: Map<String, Value>,
}

struct LoopState {
    current: usize,
    count: usize,
    start_pc: usize,
    items: Vec<Value>,
}

pub struct VmParser<'a> {
    data: &'a [u8],
    offset: usize,
    program: &'a BytecodeProgram,
    vars: Vec<VmValueSlot>,
    frames: Vec<Frame>,
    loop_stack: Vec<LoopState>,
    result: Map<String, Value>,
}

impl<'a> VmParser<'a> {
    pub fn new(data: &'a [u8], program: &'a BytecodeProgram) -> Self {
        let vars = (0..program.num_vars)
            .map(|_| VmValueSlot { value: None })
            .collect();
        VmParser {
            data,
            offset: 0,
            program,
            vars,
            frames: Vec::new(),
            loop_stack: Vec::new(),
            result: Map::new(),
        }
    }

    pub fn check_signature(data: &[u8], program: &BytecodeProgram) -> bool {
        match &program.signature {
            Some(sig) => {
                if data.len() < sig.offset + sig.bytes.len() {
                    return false;
                }
                &data[sig.offset..sig.offset + sig.bytes.len()] == sig.bytes.as_slice()
            }
            None => true,
        }
    }

    pub fn run(&mut self) -> Result<Value> {
        let mut pc: usize = 0;
        let instructions = &self.program.instructions;
        let string_table = &self.program.string_table;

        while pc < instructions.len() {
            let inst = &instructions[pc];
            match inst {
                Instruction::ReadScalar {
                    name_idx,
                    var_idx,
                    scalar_type,
                    endian,
                } => {
                    let v = self.read_scalar(*scalar_type, *endian)?;
                    let field_name = string_table[*name_idx].clone();
                    self.set_current_scope(field_name, v.clone());
                    self.vars[*var_idx].value = Some(v);
                    pc += 1;
                }

                Instruction::ReadBytes {
                    name_idx,
                    var_idx,
                    length,
                } => {
                    let len = self.resolve_length(length)?;
                    let bytes = self.read_bytes(len)?;
                    let v = json!(hex::encode(bytes));
                    let field_name = string_table[*name_idx].clone();
                    self.set_current_scope(field_name, v.clone());
                    self.vars[*var_idx].value = Some(v);
                    pc += 1;
                }

                Instruction::ReadString {
                    name_idx,
                    var_idx,
                    length,
                    encoding,
                } => {
                    let len = self.resolve_length(length)?;
                    let bytes = self.read_bytes(len)?;
                    let s = match encoding {
                        StringEncoding::Utf8 => String::from_utf8_lossy(bytes).to_string(),
                        StringEncoding::Utf16Le => {
                            let chars: Vec<u16> = bytes
                                .chunks(2)
                                .map(|c| {
                                    if c.len() == 2 {
                                        u16::from_le_bytes([c[0], c[1]])
                                    } else {
                                        0
                                    }
                                })
                                .collect();
                            String::from_utf16_lossy(&chars)
                        }
                        StringEncoding::Utf16Be => {
                            let chars: Vec<u16> = bytes
                                .chunks(2)
                                .map(|c| {
                                    if c.len() == 2 {
                                        u16::from_be_bytes([c[0], c[1]])
                                    } else {
                                        0
                                    }
                                })
                                .collect();
                            String::from_utf16_lossy(&chars)
                        }
                    };
                    let v = json!(s);
                    let field_name = string_table[*name_idx].clone();
                    self.set_current_scope(field_name, v.clone());
                    self.vars[*var_idx].value = Some(v);
                    pc += 1;
                }

                Instruction::PushFrame { name_idx } => {
                    let name = name_idx.map(|i| string_table[i].clone());
                    self.frames.push(Frame {
                        name,
                        object: Map::new(),
                    });
                    pc += 1;
                }

                Instruction::PopFrame => {
                    let frame = self
                        .frames
                        .pop()
                        .ok_or_else(|| anyhow!("PopFrame with empty frame stack"))?;
                    let obj = Value::Object(frame.object);
                    self.add_to_current_scope(frame.name, obj);
                    pc += 1;
                }

                Instruction::Jump { target } => {
                    pc = *target;
                }

                Instruction::JumpIfEq {
                    var_idx,
                    value,
                    target,
                } => {
                    if let Some(ref v) = self.vars[*var_idx].value {
                        if value_matches(v, value) {
                            pc = *target;
                        } else {
                            pc += 1;
                        }
                    } else {
                        return Err(anyhow!("Variable {} not set for conditional jump", var_idx));
                    }
                }

                Instruction::JumpIfNe {
                    var_idx,
                    value,
                    target,
                } => {
                    if let Some(ref v) = self.vars[*var_idx].value {
                        if !value_matches(v, value) {
                            pc = *target;
                        } else {
                            pc += 1;
                        }
                    } else {
                        return Err(anyhow!("Variable {} not set for conditional jump", var_idx));
                    }
                }

                Instruction::JumpIfIn {
                    var_idx,
                    values,
                    target,
                } => {
                    if let Some(ref v) = self.vars[*var_idx].value {
                        let matched = values.iter().any(|jv| value_matches(v, jv));
                        if matched {
                            pc = *target;
                        } else {
                            pc += 1;
                        }
                    } else {
                        return Err(anyhow!("Variable {} not set for conditional jump", var_idx));
                    }
                }

                Instruction::JumpIfNotIn {
                    var_idx,
                    values,
                    target,
                } => {
                    if let Some(ref v) = self.vars[*var_idx].value {
                        let matched = values.iter().any(|jv| value_matches(v, jv));
                        if !matched {
                            pc = *target;
                        } else {
                            pc += 1;
                        }
                    } else {
                        return Err(anyhow!("Variable {} not set for conditional jump", var_idx));
                    }
                }

                Instruction::LoopStart {
                    var_idx,
                    count,
                    end_pc,
                } => {
                    let c = match count {
                        LoopCount::Fixed(n) => *n,
                        LoopCount::Ref(vi) => {
                            let v = &self.vars[*vi].value;
                            v.as_ref()
                                .and_then(|x| x.as_u64().map(|y| y as usize))
                                .or_else(|| v.as_ref().and_then(|x| x.as_i64().map(|y| y as usize)))
                                .ok_or_else(|| anyhow!("Invalid count variable for loop"))?
                        }
                        LoopCount::UntilEof => usize::MAX,
                    };

                    if c == usize::MAX && self.offset >= self.data.len() {
                        self.loop_stack.push(LoopState {
                            current: 0,
                            count: 0,
                            start_pc: pc + 1,
                            items: Vec::new(),
                        });
                        self.vars[*var_idx].value = None;
                        pc = *end_pc;
                        continue;
                    }

                    self.loop_stack.push(LoopState {
                        current: 0,
                        count: c,
                        start_pc: pc + 1,
                        items: Vec::new(),
                    });
                    self.vars[*var_idx].value = None;
                    self.frames.push(Frame {
                        name: None,
                        object: Map::new(),
                    });
                    pc += 1;
                }

                Instruction::LoopNext => {
                    let (start_pc, should_continue) = {
                        let loop_state = self
                            .loop_stack
                            .last_mut()
                            .ok_or_else(|| anyhow!("LoopNext without LoopStart"))?;

                        let elem_frame = self
                            .frames
                            .pop()
                            .ok_or_else(|| anyhow!("Missing element frame in loop"))?;
                        let elem_obj = Value::Object(elem_frame.object);
                        let item = if let Value::Object(ref obj) = elem_obj {
                            if obj.len() == 1 {
                                obj.values().next().unwrap().clone()
                            } else {
                                elem_obj
                            }
                        } else {
                            elem_obj
                        };
                        loop_state.items.push(item);

                        loop_state.current += 1;
                        let sc = if loop_state.count == usize::MAX {
                            self.offset < self.data.len()
                        } else {
                            loop_state.current < loop_state.count
                        };
                        (loop_state.start_pc, sc)
                    };

                    if should_continue {
                        self.frames.push(Frame {
                            name: None,
                            object: Map::new(),
                        });
                        pc = start_pc;
                    } else {
                        pc += 1;
                    }
                }

                Instruction::StoreArray { name_idx } => {
                    let field_name = string_table[*name_idx].clone();
                    let ls = self
                        .loop_stack
                        .pop()
                        .ok_or_else(|| anyhow!("StoreArray without active loop"))?;
                    let arr = Value::Array(ls.items);
                    self.set_current_scope(field_name, arr);
                    pc += 1;
                }

                Instruction::StoreVar { var_idx: _ } => {
                    pc += 1;
                }
            }
        }

        Ok(Value::Object(self.result.clone()))
    }

    fn add_to_current_scope(&mut self, name: Option<String>, value: Value) {
        if let Some(frame) = self.frames.last_mut() {
            if let Some(n) = name {
                frame.object.insert(n, value);
            } else {
                if let Value::Object(obj) = value {
                    for (k, v) in obj {
                        frame.object.insert(k, v);
                    }
                }
            }
        } else {
            if let Some(n) = name {
                self.result.insert(n, value);
            } else {
                if let Value::Object(obj) = value {
                    for (k, v) in obj {
                        self.result.insert(k, v);
                    }
                }
            }
        }
    }

    fn set_current_scope(&mut self, name: String, value: Value) {
        if let Some(frame) = self.frames.last_mut() {
            frame.object.insert(name, value);
        } else {
            self.result.insert(name, value);
        }
    }

    fn resolve_length(&self, vl: &VarLength) -> Result<usize> {
        match vl {
            VarLength::Fixed(n) => Ok(*n),
            VarLength::Ref(var_idx) => {
                let v = &self.vars[*var_idx].value;
                v.as_ref()
                    .and_then(|x| x.as_u64().map(|y| y as usize))
                    .or_else(|| v.as_ref().and_then(|x| x.as_i64().map(|y| y as usize)))
                    .ok_or_else(|| anyhow!("Invalid length variable"))
            }
            VarLength::Remaining => Ok(self.data.len() - self.offset),
        }
    }

    fn read_scalar(&mut self, st: ScalarType, endian: Endian) -> Result<Value> {
        Ok(match st {
            ScalarType::U8 => json!(self.read_u8()?),
            ScalarType::U16 => json!(self.read_u16(endian)?),
            ScalarType::U32 => json!(self.read_u32(endian)?),
            ScalarType::U64 => json!(self.read_u64(endian)?),
            ScalarType::I8 => json!(self.read_u8()? as i8),
            ScalarType::I16 => json!(self.read_u16(endian)? as i16),
            ScalarType::I32 => json!(self.read_u32(endian)? as i32),
            ScalarType::I64 => json!(self.read_u64(endian)? as i64),
            ScalarType::F32 => {
                let bytes = self.read_bytes(4)?;
                let v = match endian {
                    Endian::Little => f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                    Endian::Big => f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                };
                json!(v)
            }
            ScalarType::F64 => {
                let bytes = self.read_bytes(8)?;
                let v = match endian {
                    Endian::Little => f64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]),
                    Endian::Big => f64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]),
                };
                json!(v)
            }
        })
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.offset >= self.data.len() {
            anyhow::bail!("Unexpected end of data reading u8");
        }
        let v = self.data[self.offset];
        self.offset += 1;
        Ok(v)
    }

    fn read_u16(&mut self, endian: Endian) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(match endian {
            Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
        })
    }

    fn read_u32(&mut self, endian: Endian) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(match endian {
            Endian::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endian::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
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

fn value_matches(a: &Value, b: &JumpValue) -> bool {
    match b {
        JumpValue::Int(i) => a
            .as_i64()
            .map(|x| x == *i)
            .or_else(|| a.as_u64().map(|x| x as i64 == *i))
            .unwrap_or(false),
        JumpValue::UInt(u) => a
            .as_u64()
            .map(|x| x == *u)
            .or_else(|| a.as_i64().map(|x| x as u64 == *u))
            .unwrap_or(false),
        JumpValue::Float(f) => a.as_f64().map(|x| x == *f).unwrap_or(false),
        JumpValue::Str(s) => a.as_str().map(|x| x == s.as_str()).unwrap_or(false),
    }
}
