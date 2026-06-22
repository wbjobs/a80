use crate::template::{Endian, FieldType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

#[derive(Debug, Clone)]
pub enum Instruction {
    ReadScalar {
        name_idx: usize,
        var_idx: usize,
        scalar_type: ScalarType,
        endian: Endian,
    },
    ReadBytes {
        name_idx: usize,
        var_idx: usize,
        length: VarLength,
    },
    ReadString {
        name_idx: usize,
        var_idx: usize,
        length: VarLength,
        encoding: StringEncoding,
    },
    PushFrame {
        name_idx: Option<usize>,
    },
    PopFrame,
    Jump {
        target: usize,
    },
    JumpIfEq {
        var_idx: usize,
        value: JumpValue,
        target: usize,
    },
    JumpIfNe {
        var_idx: usize,
        value: JumpValue,
        target: usize,
    },
    JumpIfIn {
        var_idx: usize,
        values: Vec<JumpValue>,
        target: usize,
    },
    JumpIfNotIn {
        var_idx: usize,
        values: Vec<JumpValue>,
        target: usize,
    },
    LoopStart {
        var_idx: usize,
        count: LoopCount,
        end_pc: usize,
    },
    LoopNext,
    StoreArray {
        name_idx: usize,
    },
    StoreVar {
        var_idx: usize,
    },
}

#[derive(Debug, Clone)]
pub enum VarLength {
    Fixed(usize),
    Ref(usize),
    Remaining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

#[derive(Debug, Clone)]
pub enum LoopCount {
    Fixed(usize),
    Ref(usize),
    UntilEof,
}

#[derive(Debug, Clone)]
pub enum JumpValue {
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
}

#[derive(Debug, Clone)]
pub struct BytecodeProgram {
    pub instructions: Vec<Instruction>,
    pub string_table: Vec<String>,
    pub num_vars: usize,
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

impl From<&FieldType> for ScalarType {
    fn from(ft: &FieldType) -> Self {
        match ft {
            FieldType::U8 => ScalarType::U8,
            FieldType::U16 => ScalarType::U16,
            FieldType::U32 => ScalarType::U32,
            FieldType::U64 => ScalarType::U64,
            FieldType::I8 => ScalarType::I8,
            FieldType::I16 => ScalarType::I16,
            FieldType::I32 => ScalarType::I32,
            FieldType::I64 => ScalarType::I64,
            FieldType::F32 => ScalarType::F32,
            FieldType::F64 => ScalarType::F64,
            _ => panic!("Cannot convert {:?} to ScalarType", ft),
        }
    }
}

pub fn is_scalar_type(ft: &FieldType) -> bool {
    matches!(
        ft,
        FieldType::U8
            | FieldType::U16
            | FieldType::U32
            | FieldType::U64
            | FieldType::I8
            | FieldType::I16
            | FieldType::I32
            | FieldType::I64
            | FieldType::F32
            | FieldType::F64
    )
}
