mod bytecode;
mod compiler;
mod parser;
mod output;
mod pcap;
mod template;
mod vm;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde_json::Value;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::Instant;

use crate::output::{output_results, OutputFormat};
use crate::parser::BinaryParser;
use crate::pcap::{extract_l7_payload, PcapReader};
use crate::template::ProtocolTemplate;
use crate::vm::VmParser;

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

    #[arg(
        long,
        value_enum,
        default_value_t = EngineArg::Vm,
        help = "解析引擎：vm（编译式字节码，快速）或 interpreter（解释式，兼容）"
    )]
    engine: EngineArg,

    #[arg(
        long,
        default_value_t = false,
        help = "显示解析统计信息"
    )]
    stats: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum FormatArg {
    Json,
    JsonPretty,
    Csv,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum EngineArg {
    Vm,
    Interpreter,
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

    let program = match cli.engine {
        EngineArg::Vm => {
            let start = Instant::now();
            let prog = compiler::compile_template(&template)
                .with_context(|| "编译模板到字节码失败")?;
            if cli.stats {
                eprintln!(
                    "[编译] 耗时 {:.2}ms, 指令数: {}, 变量数: {}, 字符串表: {}",
                    start.elapsed().as_secs_f64() * 1000.0,
                    prog.instructions.len(),
                    prog.num_vars,
                    prog.string_table.len()
                );
                if prog.signature.is_some() {
                    let sig = prog.signature.as_ref().unwrap();
                    eprintln!(
                        "[签名] 偏移={}, 字节={}",
                        sig.offset,
                        hex::encode(&sig.bytes)
                    );
                }
            }
            Some(prog)
        }
        EngineArg::Interpreter => None,
    };

    let pcap_reader = PcapReader::open(&cli.pcap)
        .with_context(|| format!("打开PCAP文件失败: {:?}", cli.pcap))?;

    let packets = pcap_reader.packets();
    let mut results: Vec<Option<Value>> = Vec::with_capacity(packets.len());
    let mut errors: Vec<Option<String>> = Vec::with_capacity(packets.len());

    let parse_start = Instant::now();
    let mut skipped = 0usize;

    for pkt in packets {
        let payload = if cli.raw { &pkt.data } else { extract_l7_payload(&pkt.data) };

        match cli.engine {
            EngineArg::Vm => {
                let prog = program.as_ref().unwrap();
                if !VmParser::check_signature(payload, prog) {
                    skipped += 1;
                    results.push(None);
                    errors.push(Some("签名不匹配，已跳过".to_string()));
                    continue;
                }
                let mut vm = VmParser::new(payload, prog);
                match vm.run() {
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
            EngineArg::Interpreter => {
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
        }
    }

    if cli.stats {
        let elapsed = parse_start.elapsed().as_secs_f64();
        eprintln!(
            "[解析] 总包数: {}, 成功: {}, 跳过: {}, 失败: {}, 耗时: {:.2}ms, 速度: {:.0} 包/秒",
            packets.len(),
            results.iter().filter(|r| r.is_some()).count(),
            skipped,
            errors.iter().filter(|e| e.is_some() && e.as_ref().map(|x| x != "签名不匹配，已跳过").unwrap_or(false)).count(),
            elapsed * 1000.0,
            packets.len() as f64 / elapsed.max(0.0001)
        );
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
