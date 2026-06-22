use anyhow::{anyhow, Result};
use std::collections::HashMap;

use crate::bytecode::{
    is_scalar_type, BytecodeProgram, Instruction, JumpValue, LoopCount, ScalarType, Signature,
    StringEncoding, VarLength,
};
use crate::template::{
    Condition, ConditionalBranch, Endian, Field, FieldType, ProtocolTemplate, TemplateSignature,
};

struct CompileContext {
    instructions: Vec<Instruction>,
    string_table: Vec<String>,
    string_map: HashMap<String, usize>,
    var_count: usize,
    var_map: HashMap<String, usize>,
    default_endian: Endian,
    loop_stack: Vec<usize>,
}

impl CompileContext {
    fn new(default_endian: Endian) -> Self {
        CompileContext {
            instructions: Vec::new(),
            string_table: Vec::new(),
            string_map: HashMap::new(),
            var_count: 0,
            var_map: HashMap::new(),
            default_endian,
            loop_stack: Vec::new(),
        }
    }

    fn intern_string(&mut self, s: &str) -> usize {
        if let Some(&idx) = self.string_map.get(s) {
            return idx;
        }
        let idx = self.string_table.len();
        self.string_table.push(s.to_string());
        self.string_map.insert(s.to_string(), idx);
        idx
    }

    fn get_or_create_var(&mut self, name: &str) -> usize {
        if let Some(&idx) = self.var_map.get(name) {
            return idx;
        }
        let idx = self.var_count;
        self.var_count += 1;
        self.var_map.insert(name.to_string(), idx);
        idx
    }

    fn emit(&mut self, inst: Instruction) {
        self.instructions.push(inst);
    }

    fn current_pc(&self) -> usize {
        self.instructions.len()
    }

    fn patch_jump(&mut self, pc: usize, target: usize) {
        match &mut self.instructions[pc] {
            Instruction::Jump { target: t }
            | Instruction::JumpIfEq { target: t, .. }
            | Instruction::JumpIfNe { target: t, .. }
            | Instruction::JumpIfIn { target: t, .. }
            | Instruction::JumpIfNotIn { target: t, .. } => {
                *t = target;
            }
            _ => panic!("Cannot patch non-jump instruction at pc={}", pc),
        }
    }
}

pub fn compile_template(template: &ProtocolTemplate) -> Result<BytecodeProgram> {
    let mut ctx = CompileContext::new(template.endian);

    let signature = match &template.signature {
        Some(sig) => Some(parse_signature(sig)?),
        None => None,
    };

    compile_fields(&template.fields, &mut ctx)?;

    Ok(BytecodeProgram {
        instructions: ctx.instructions,
        string_table: ctx.string_table,
        num_vars: ctx.var_count,
        signature,
    })
}

fn parse_signature(ts: &TemplateSignature) -> Result<Signature> {
    let bytes = hex::decode(&ts.bytes)
        .map_err(|e| anyhow!("Invalid signature hex bytes: {}", e))?;
    Ok(Signature {
        offset: ts.offset,
        bytes,
    })
}

fn compile_fields(fields: &[Field], ctx: &mut CompileContext) -> Result<()> {
    for field in fields {
        compile_field(field, ctx)?;
    }
    Ok(())
}

fn compile_field(field: &Field, ctx: &mut CompileContext) -> Result<()> {
    match field {
        Field::Scalar {
            name,
            data_type,
            endian,
            length,
            length_field,
            encoding,
        } => {
            let var_idx = ctx.get_or_create_var(name);
            let name_idx = ctx.intern_string(name);
            let eff_endian = endian.unwrap_or(ctx.default_endian);

            if is_scalar_type(data_type) {
                let scalar_type = ScalarType::from(data_type);
                ctx.emit(Instruction::ReadScalar {
                    name_idx,
                    var_idx,
                    scalar_type,
                    endian: eff_endian,
                });
            } else if data_type == &FieldType::Bytes {
                let var_len = resolve_var_length(*length, length_field.as_deref(), ctx)?;
                ctx.emit(Instruction::ReadBytes {
                    name_idx,
                    var_idx,
                    length: var_len,
                });
            } else if data_type == &FieldType::String {
                let var_len = resolve_var_length(*length, length_field.as_deref(), ctx)?;
                let enc = match encoding.as_deref() {
                    Some("utf-16le") => StringEncoding::Utf16Le,
                    Some("utf-16be") => StringEncoding::Utf16Be,
                    _ => StringEncoding::Utf8,
                };
                ctx.emit(Instruction::ReadString {
                    name_idx,
                    var_idx,
                    length: var_len,
                    encoding: enc,
                });
            }
        }

        Field::Struct { name, fields } => {
            let name_idx = name.as_ref().map(|n| ctx.intern_string(n));
            ctx.emit(Instruction::PushFrame { name_idx });
            compile_fields(fields, ctx)?;
            ctx.emit(Instruction::PopFrame);
        }

        Field::Conditional {
            name,
            conditions,
            default,
        } => {
            let name_idx = name.as_ref().map(|n| ctx.intern_string(n));
            if let Some(n) = name_idx {
                ctx.emit(Instruction::PushFrame { name_idx: Some(n) });
            }

            let mut end_jumps: Vec<usize> = Vec::new();
            let mut branch_end_pcs: Vec<usize> = Vec::new();

            for branch in conditions {
                let ConditionalBranch { when, fields } = branch;

                let skip_branch_pc = if let Some(cond) = when {
                    compile_cond_jump(cond, ctx, false)?
                } else {
                    ctx.emit(Instruction::Jump { target: 0 });
                    ctx.current_pc() - 1
                };

                compile_fields(fields, ctx)?;

                let end_jump_pc = ctx.current_pc();
                ctx.emit(Instruction::Jump { target: 0 });
                end_jumps.push(end_jump_pc);

                let branch_end = ctx.current_pc();
                ctx.patch_jump(skip_branch_pc, branch_end);
                branch_end_pcs.push(branch_end);
            }

            if let Some(default_fields) = default {
                compile_fields(default_fields, ctx)?;
            }

            let final_end = ctx.current_pc();
            for j in end_jumps {
                ctx.patch_jump(j, final_end);
            }

            if name_idx.is_some() {
                ctx.emit(Instruction::PopFrame);
            }
        }

        Field::Array {
            name,
            element,
            count,
            count_field,
            until_eof,
        } => {
            let array_name_idx = ctx.intern_string(name);

            let loop_count = if *until_eof {
                LoopCount::UntilEof
            } else if let Some(c) = count {
                LoopCount::Fixed(*c)
            } else if let Some(cf) = count_field {
                let var_idx = ctx
                    .var_map
                    .get(cf)
                    .ok_or_else(|| anyhow!("Count field '{}' not found", cf))?
                    .clone();
                LoopCount::Ref(var_idx)
            } else {
                LoopCount::UntilEof
            };

            let loop_var_idx = ctx.get_or_create_var("__loop_elem");
            let loop_start_pc = ctx.instructions.len();
            ctx.emit(Instruction::LoopStart {
                var_idx: loop_var_idx,
                count: loop_count,
                end_pc: 0,
            });
            ctx.loop_stack.push(loop_start_pc);

            match element.as_ref() {
                Field::Struct { fields, .. } => {
                    compile_fields(fields, ctx)?;
                }
                other => {
                    let single_field = vec![other.clone()];
                    compile_fields(&single_field, ctx)?;
                }
            }

            ctx.emit(Instruction::LoopNext);
            let store_array_pc = ctx.instructions.len();
            ctx.emit(Instruction::StoreArray {
                name_idx: array_name_idx,
            });
            let ls_pc = ctx.loop_stack.pop().unwrap();
            if let Instruction::LoopStart { end_pc, .. } = &mut ctx.instructions[ls_pc] {
                *end_pc = store_array_pc;
            }
        }
    }
    Ok(())
}

fn compile_cond_jump(
    cond: &Condition,
    ctx: &mut CompileContext,
    jump_on_true: bool,
) -> Result<usize> {
    let var_idx = ctx
        .var_map
        .get(&cond.field)
        .ok_or_else(|| anyhow!("Condition field '{}' not found in context", cond.field))?
        .clone();

    if let Some(eq_val) = &cond.eq {
        let jv = value_to_jump_value(eq_val)?;
        let inst = if jump_on_true {
            Instruction::JumpIfEq {
                var_idx,
                value: jv,
                target: 0,
            }
        } else {
            Instruction::JumpIfNe {
                var_idx,
                value: jv,
                target: 0,
            }
        };
        ctx.emit(inst);
        return Ok(ctx.current_pc() - 1);
    }

    if let Some(ne_val) = &cond.ne {
        let jv = value_to_jump_value(ne_val)?;
        let inst = if jump_on_true {
            Instruction::JumpIfNe {
                var_idx,
                value: jv,
                target: 0,
            }
        } else {
            Instruction::JumpIfEq {
                var_idx,
                value: jv,
                target: 0,
            }
        };
        ctx.emit(inst);
        return Ok(ctx.current_pc() - 1);
    }

    if let Some(in_vals) = &cond.in_list {
        let jvs: Result<Vec<JumpValue>> = in_vals.iter().map(value_to_jump_value).collect();
        let inst = if jump_on_true {
            Instruction::JumpIfIn {
                var_idx,
                values: jvs?,
                target: 0,
            }
        } else {
            Instruction::JumpIfNotIn {
                var_idx,
                values: jvs?,
                target: 0,
            }
        };
        ctx.emit(inst);
        return Ok(ctx.current_pc() - 1);
    }

    unimplemented!("Only eq, ne, and in conditions are supported in fast VM for now");
}

fn resolve_var_length(
    length: Option<usize>,
    length_field: Option<&str>,
    ctx: &CompileContext,
) -> Result<VarLength> {
    if let Some(l) = length {
        return Ok(VarLength::Fixed(l));
    }
    if let Some(field_name) = length_field {
        let var_idx = ctx
            .var_map
            .get(field_name)
            .ok_or_else(|| anyhow!("Length field '{}' not found", field_name))?
            .clone();
        return Ok(VarLength::Ref(var_idx));
    }
    Ok(VarLength::Remaining)
}

fn value_to_jump_value(v: &serde_json::Value) -> Result<JumpValue> {
    match v {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(JumpValue::Int(i))
            } else if let Some(u) = n.as_u64() {
                Ok(JumpValue::UInt(u))
            } else if let Some(f) = n.as_f64() {
                Ok(JumpValue::Float(f))
            } else {
                Err(anyhow!("Unsupported number type"))
            }
        }
        serde_json::Value::String(s) => Ok(JumpValue::Str(s.clone())),
        _ => Err(anyhow!("Unsupported value type for condition")),
    }
}
