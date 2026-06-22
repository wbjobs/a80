mod analyzer;
mod bytecode;
mod compiler;
mod infer;
mod output;
mod parser;
mod pcap;
mod template;
mod tui;
mod vm;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::Instant;

use crate::analyzer::analyze_payloads;
use crate::infer::generate_analysis_summary;
use crate::output::{output_results, OutputFormat};
use crate::parser::BinaryParser;
use crate::pcap::{extract_l7_payload, PcapReader};
use crate::template::ProtocolTemplate;
use crate::tui::TemplateEditor;
use crate::vm::VmParser;

#[derive(Parser, Debug)]
#[command(name = "pcap-parser", version, about = "PCAP二进制协议解析工具")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "按模板解析PCAP文件")]
    Parse {
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
    },

    #[command(about = "自动分析PCAP并生成模板草案")]
    Infer {
        #[arg(short, long, help = "PCAP包文件路径")]
        pcap: PathBuf,

        #[arg(
            short,
            long,
            help = "输出模板文件路径 (如果指定且非交互模式，则直接保存)"
        )]
        output: Option<PathBuf>,

        #[arg(
            long,
            default_value_t = 64,
            help = "分析的字节数 (默认64)"
        )]
        bytes: usize,

        #[arg(
            long,
            default_value_t = false,
            help = "直接使用整个包数据解析，不提取L7 payload"
        )]
        raw: bool,

        #[arg(
            long,
            default_value_t = false,
            help = "非交互模式，仅输出分析结果和模板到stdout"
        )]
        no_ui: bool,

        #[arg(
            long,
            help = "模板名称"
        )]
        name: Option<String>,
    },

    #[command(about = "查看已保存的模板分析记录")]
    ListTemplates {
        #[arg(long, help = "模板存储目录")]
        dir: Option<PathBuf>,
    },
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

    match cli.command {
        Command::Parse {
            pcap,
            template,
            format,
            output,
            raw,
            keep_going,
            engine,
            stats,
        } => cmd_parse(pcap, template, format, output, raw, keep_going, engine, stats),
        Command::Infer {
            pcap,
            output,
            bytes,
            raw,
            no_ui,
            name,
        } => cmd_infer(pcap, output, bytes, raw, no_ui, name),
        Command::ListTemplates { dir } => cmd_list_templates(dir),
    }
}

fn cmd_parse(
    pcap: PathBuf,
    template: PathBuf,
    format: FormatArg,
    output: Option<PathBuf>,
    raw: bool,
    keep_going: bool,
    engine: EngineArg,
    stats: bool,
) -> Result<()> {
    let template = ProtocolTemplate::from_file(&template)
        .with_context(|| format!("加载模板文件失败: {:?}", template))?;

    let program = match engine {
        EngineArg::Vm => {
            let start = Instant::now();
            let prog = compiler::compile_template(&template)
                .with_context(|| "编译模板到字节码失败")?;
            if stats {
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

    let pcap_reader = PcapReader::open(&pcap)
        .with_context(|| format!("打开PCAP文件失败: {:?}", pcap))?;

    let packets = pcap_reader.packets();
    let mut results: Vec<Option<Value>> = Vec::with_capacity(packets.len());
    let mut errors: Vec<Option<String>> = Vec::with_capacity(packets.len());

    let parse_start = Instant::now();
    let mut skipped = 0usize;

    for pkt in packets {
        let payload = if raw { &pkt.data } else { extract_l7_payload(&pkt.data) };

        match engine {
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
                        if !keep_going {
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
                        if !keep_going {
                            eprintln!("解析错误: {}", e);
                        }
                    }
                }
            }
        }
    }

    if stats {
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

    let output_format: OutputFormat = format.into();

    match output {
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

fn cmd_infer(
    pcap: PathBuf,
    output: Option<PathBuf>,
    bytes: usize,
    raw: bool,
    no_ui: bool,
    name: Option<String>,
) -> Result<()> {
    let pcap_reader = PcapReader::open(&pcap)
        .with_context(|| format!("打开PCAP文件失败: {:?}", pcap))?;

    let packets = pcap_reader.packets();

    eprintln!("[分析] 正在读取 {} 个包...", packets.len());

    let payloads: Vec<&[u8]> = packets
        .iter()
        .map(|p| if raw { &p.data } else { extract_l7_payload(&p.data) })
        .collect();

    let analysis_start = Instant::now();
    let analysis = analyze_payloads(&payloads, bytes);
    let analysis_elapsed = analysis_start.elapsed().as_secs_f64() * 1000.0;

    eprintln!("[分析] 完成，耗时 {:.2}ms", analysis_elapsed);
    eprintln!();
    eprintln!("{}", generate_analysis_summary(&analysis));
    eprintln!();

    let template_name = name.or_else(|| {
        pcap.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| format!("{}_inferred", s))
    });

    let generated = infer::generate_template(&analysis, template_name.as_deref());

    if no_ui {
        let yaml_str = serde_yaml::to_string(&generated)?;
        match output {
            Some(path) => {
                std::fs::write(&path, yaml_str)?;
                eprintln!("[保存] 模板已保存到 {:?}", path);
            }
            None => {
                println!("{}", yaml_str);
            }
        }
        return Ok(());
    }

    eprintln!("[推断] 进入交互式模板编辑器...");
    eprintln!();

    let mut editor = TemplateEditor::new(generated);
    match editor.run() {
        Some(final_template) => {
            let yaml_str = serde_yaml::to_string(&final_template)?;

            match output {
                Some(path) => {
                    std::fs::write(&path, yaml_str)?;
                    eprintln!();
                    eprintln!("[保存] 模板已保存到 {:?}", path);
                }
                None => {
                    let default_path = format!(
                        "{}.yaml",
                        final_template
                            .name
                            .as_deref()
                            .unwrap_or("inferred_template")
                    );
                    eprintln!();
                    eprintln!("最终模板:");
                    println!("{}", yaml_str);
                    eprintln!();
                    eprintln!("提示: 可将上述内容保存为 .yaml 文件使用");
                    eprintln!("      例如: pcap-parser infer -p input.pcap -o my_template.yaml");
                    let _ = default_path;
                }
            }
        }
        None => {
            eprintln!("[取消] 用户取消了模板编辑");
        }
    }

    Ok(())
}

fn cmd_list_templates(dir: Option<PathBuf>) -> Result<()> {
    let search_dir = dir.unwrap_or_else(|| PathBuf::from("."));

    let mut templates = Vec::new();
    if search_dir.is_dir() {
        for entry in std::fs::read_dir(&search_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext == "yaml" || ext == "yml" || ext == "json" {
                        if let Ok(t) = ProtocolTemplate::from_file(&path) {
                            templates.push((path, t));
                        }
                    }
                }
            }
        }
    }

    if templates.is_empty() {
        println!("未找到模板文件");
    } else {
        println!("找到 {} 个模板文件:", templates.len());
        for (path, t) in templates {
            let name = t.name.unwrap_or_else(|| "(未命名)".to_string());
            let sig = t
                .signature
                .map(|s| format!("offset={}, bytes={}", s.offset, s.bytes))
                .unwrap_or_else(|| "无签名".to_string());
            println!(
                "  {:<30} 字段数: {:<3} 签名: {}",
                path.file_name().unwrap().to_string_lossy(),
                t.fields.len(),
                sig
            );
            println!("    名称: {}", name);
        }
    }

    Ok(())
}
