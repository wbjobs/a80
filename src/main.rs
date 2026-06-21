mod parser;
mod output;
mod pcap;
mod template;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde_json::Value;
use std::fs::File;
use std::io;
use std::path::PathBuf;

use crate::output::{output_results, OutputFormat};
use crate::parser::BinaryParser;
use crate::pcap::{extract_l7_payload, PcapReader};
use crate::template::ProtocolTemplate;

#[derive(Parser, Debug)]
#[command(name = "pcap-parser", version, about = "PCAP二进制协议解析工具")]
struct Cli {
    #[arg(short, long, help = "PCAP包文件路径")]
    pcap: PathBuf,

    #[arg(short, long, help = "协议模板文件路径 (YAML或JSON)")]
    template: PathBuf,

    #[arg(
        short,
        long,
        value_enum,
        default_value_t = FormatArg::Json,
        help = "输出格式"
    )]
    format: FormatArg,

    #[arg(short, long, help = "输出文件路径 (默认输出到stdout)")]
    output: Option<PathBuf>,

    #[arg(
        long,
        default_value_t = false,
        help = "直接使用整个包数据解析，不提取L7 payload"
    )]
    raw: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "解析失败时跳过错误继续处理"
    )]
    keep_going: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum FormatArg {
    Json,
    JsonPretty,
    Csv,
}

impl From<FormatArg> for OutputFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Json => OutputFormat::Json,
            FormatArg::JsonPretty => OutputFormat::JsonPretty,
            FormatArg::Csv => OutputFormat::Csv,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let template = ProtocolTemplate::from_file(&cli.template)
        .with_context(|| format!("加载模板文件失败: {:?}", cli.template))?;

    let pcap_reader = PcapReader::open(&cli.pcap)
        .with_context(|| format!("打开PCAP文件失败: {:?}", cli.pcap))?;

    let packets = pcap_reader.packets();
    let mut results: Vec<Option<Value>> = Vec::with_capacity(packets.len());
    let mut errors: Vec<Option<String>> = Vec::with_capacity(packets.len());

    for pkt in packets {
        let payload = if cli.raw { &pkt.data } else { extract_l7_payload(&pkt.data) };
        let mut parser = BinaryParser::new(payload, template.endian);
        match parser.parse_template(&template) {
            Ok(v) => {
                results.push(Some(v));
                errors.push(None);
            }
            Err(e) => {
                let err_msg = format!("{}", e);
                results.push(None);
                errors.push(Some(err_msg.clone()));
                if !cli.keep_going {
                    eprintln!("解析错误: {}", e);
                }
            }
        }
    }

    let output_format: OutputFormat = cli.format.into();

    match cli.output {
        Some(path) => {
            let mut file = File::create(&path)
                .with_context(|| format!("创建输出文件失败: {:?}", path))?;
            output_results(&mut file, packets, &results, &errors, output_format)?;
        }
        None => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            output_results(&mut handle, packets, &results, &errors, output_format)?;
        }
    }

    Ok(())
}
