use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

impl Default for Endian {
    fn default() -> Self {
        Endian::Big
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
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
    Bytes,
    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub eq: Option<serde_json::Value>,
    pub ne: Option<serde_json::Value>,
    pub gt: Option<serde_json::Value>,
    pub lt: Option<serde_json::Value>,
    pub ge: Option<serde_json::Value>,
    pub le: Option<serde_json::Value>,
    #[serde(rename = "in")]
    pub in_list: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "field_type", rename_all = "lowercase")]
pub enum Field {
    Scalar {
        name: String,
        data_type: FieldType,
        #[serde(default)]
        endian: Option<Endian>,
        length: Option<usize>,
        length_field: Option<String>,
        encoding: Option<String>,
    },
    Struct {
        name: Option<String>,
        fields: Vec<Field>,
    },
    Conditional {
        name: Option<String>,
        conditions: Vec<ConditionalBranch>,
        default: Option<Vec<Field>>,
    },
    Array {
        name: String,
        element: Box<Field>,
        count: Option<usize>,
        count_field: Option<String>,
        #[serde(default)]
        until_eof: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalBranch {
    pub when: Option<Condition>,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTemplate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub endian: Endian,
    pub fields: Vec<Field>,
}

impl ProtocolTemplate {
    pub fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read template file: {:?}", path.as_ref()))?;
        let template: ProtocolTemplate = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse YAML template")?;
        Ok(template)
    }

    pub fn from_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read template file: {:?}", path.as_ref()))?;
        let template: ProtocolTemplate = serde_json::from_str(&content)
            .with_context(|| "Failed to parse JSON template")?;
        Ok(template)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let p = path.as_ref();
        match p.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => Self::from_yaml(p),
            Some("json") => Self::from_json(p),
            Some(ext) => anyhow::bail!("Unsupported template format: .{}", ext),
            None => anyhow::bail!("Template file has no extension"),
        }
    }
}
