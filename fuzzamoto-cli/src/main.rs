pub mod ir;

use clap::{Parser, Subcommand, ValueEnum};
use log;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new fuzzamoto fuzzing campaign with Nyx
    Init {
        #[arg(long, help = "Path to the nyx share directory that should be created")]
        sharedir: PathBuf,
        #[arg(
            long,
            help = "Path to the crash handler that should be copied into the share directory"
        )]
        crash_handler: PathBuf,
        #[arg(
            long,
            help = "Path to the bitcoind binary that should be copied into the share directory"
        )]
        bitcoind: PathBuf,
        #[arg(
            long,
            help = "Path to the fuzzamoto scenario binary that should be copied into the share directory"
        )]
        scenario: PathBuf,
    },

    /// Create a html coverage report for a given corpus
    Coverage {
        #[arg(long, help = "Path to the output directory for the coverage report")]
        output: PathBuf,
        #[arg(long, help = "Path to the input corpus directory")]
        corpus: PathBuf,
        #[arg(
            long,
            help = "Path to the bitcoind binary that should be copied into the share directory"
        )]
        bitcoind: PathBuf,
        #[arg(
            long,
            help = "Path to the fuzzamoto scenario binary that should be copied into the share directory"
        )]
        scenario: PathBuf,
    },

    /// Record test cases from a corpus of a specialized scenario to be used as seeds for the
    /// generic scenario
    Record {
        #[arg(
            long,
            help = "Path to the output directory for the recorded test cases"
        )]
        output: PathBuf,
        #[arg(long, help = "Path to the input corpus directory")]
        corpus: PathBuf,
        #[arg(long, help = "Path to the fuzzamoto scenario scenario binary")]
        scenario: PathBuf,
    },
    /// Fuzzamoto intermediate representation (IR) commands
    IR {
        #[command(subcommand)]
        command: ir::IRCommands,
    },
}

fn create_sharedir(
    sharedir: PathBuf,
    crash_handler: PathBuf,
    bitcoind: PathBuf,
    scenario: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    if sharedir.exists() {
        return Err("Share directory already exists".into());
    }
    std::fs::create_dir_all(&sharedir)?;

    if !crash_handler.exists() {
        return Err("Crash handler does not exist".into());
    }

    let mut all_deps = Vec::new();
    let mut binary_names = Vec::new();

    // Copy each binary and its dependencies
    let binaries = vec![bitcoind, scenario.clone()];
    for binary in &binaries {
        // Copy the binary itself
        let binary_name = binary
            .file_name()
            .ok_or("Invalid binary path")?
            .to_str()
            .ok_or("Invalid binary name")?;
        std::fs::copy(binary, sharedir.join(binary_name))?;
        log::info!("Copied binary: {}", binary_name);
        all_deps.push(binary_name.to_string());
        binary_names.push(binary_name.to_string());
        // Get and copy dependencies using lddtree
        let output = std::process::Command::new("lddtree").arg(binary).output()?;

        if !output.status.success() {
            return Err(
                format!("lddtree error: {}", String::from_utf8_lossy(&output.stderr)).into(),
            );
        }

        // Parse lddtree output and copy dependencies
        let deps = String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1) // Skip first line
            .filter_map(|line| {
                let parts: Vec<&str> = line.split("=>").collect();
                if parts.len() == 2 {
                    let name = parts[0].trim();
                    let path = parts[1].trim();

                    // Copy the dependency
                    if let Err(e) = std::fs::copy(path, sharedir.join(name)) {
                        log::warn!("Failed to copy {}: {}", name, e);
                    } else {
                        log::info!("Copied dependency of {}: {}", binary_name, name);
                    }

                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<String>>();

        all_deps.extend(deps);
    }

    // Add crash handler to dependencies
    let crash_handler_name = crash_handler
        .file_name()
        .ok_or("Invalid crash handler path")?
        .to_str()
        .ok_or("Invalid crash handler name")?
        .to_string();
    std::fs::copy(&crash_handler, sharedir.join(&crash_handler_name))?;
    log::info!("Copied crash handler: {}", crash_handler_name);
    all_deps.push(crash_handler_name.clone());
    all_deps.sort();
    all_deps.dedup();

    // Create fuzz_no_pt.sh script
    let mut script = Vec::new();
    script.push("chmod +x hget".to_string());
    script.push("cp hget /tmp".to_string());
    script.push("cd /tmp".to_string());
    script.push("echo 0 > /proc/sys/kernel/randomize_va_space".to_string());
    script.push("echo 0 > /proc/sys/kernel/printk".to_string());
    script.push("./hget hcat_no_pt hcat".to_string());
    script.push("./hget habort_no_pt habort".to_string());

    // Add dependencies
    for dep in all_deps {
        script.push(format!("./hget {} {}", dep, dep));
    }

    // Make executables
    for exe in &[
        "habort",
        "hcat",
        "ld-linux-x86-64.so.2",
        &crash_handler_name,
    ] {
        script.push(format!("chmod +x {}\n", exe));
    }
    for binary_name in binary_names {
        script.push(format!("chmod +x {}", binary_name));
    }

    script.push("export __AFL_DEFER_FORKSRV=1".to_string());

    // Network setup
    script.push("ip addr add 127.0.0.1/8 dev lo".to_string());
    script.push("ip link set lo up".to_string());
    script.push("ip a | ./hcat".to_string());

    // Create bitcoind proxy script
    let asan_options = [
        "detect_leaks=1",
        "detect_stack_use_after_return=1",
        "check_initialization_order=1",
        "strict_init_order=1",
        "log_path=/tmp/asan.log",
        "abort_on_error=1",
        "handle_abort=1",
    ]
    .join(":");

    let asan_options = format!("ASAN_OPTIONS={}", asan_options);
    let crash_handler_preload = format!("LD_PRELOAD=./{}", crash_handler_name);
    let proxy_script = format!(
        "{} LD_LIBRARY_PATH=/tmp LD_BIND_NOW=1 {} ./bitcoind \\$@",
        asan_options, crash_handler_preload,
    );

    script.push(format!("echo \"#!/bin/sh\" > ./bitcoind_proxy"));
    script.push(format!("echo \"{}\" >> ./bitcoind_proxy", proxy_script));
    script.push("chmod +x ./bitcoind_proxy".to_string());

    // Run the scenario
    let scenario_name = scenario
        .file_name()
        .ok_or("Invalid scenario path")?
        .to_str()
        .ok_or("Invalid scenario name")?;
    script.push(format!(
        "RUST_LOG=debug LD_LIBRARY_PATH=/tmp LD_BIND_NOW=1 ./{} ./bitcoind_proxy > log.txt 2>&1",
        scenario_name
    ));

    // Debug info
    script.push("cat log.txt | ./hcat".to_string());
    script.push(
        "./habort \"target has terminated without initializing the fuzzing agent ...\"".to_string(),
    );

    let mut file = File::create(sharedir.join("fuzz_no_pt.sh"))?;
    for line in script {
        writeln!(file, "{}", line)?;
    }

    log::info!("Created share directory: {}", sharedir.display());

    Ok(())
}

fn run_one_input(
    output: PathBuf,
    input: PathBuf,
    bitcoind: PathBuf,
    scenario: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Running scenario with input: {}", input.display());
    let profraw_file = output.join(format!(
        "{}.coverage.profraw.%p",
        input.file_name().unwrap().to_str().unwrap()
    ));
    let status = std::process::Command::new(scenario)
        .arg(bitcoind)
        .env("LLVM_PROFILE_FILE", &profraw_file)
        .env("FUZZAMOTO_INPUT", input)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err("Scenario failed to run".into())
    }
}

fn record_one_input(
    input: PathBuf,
    output: PathBuf,
    scenario: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Recording input: {}", input.display());
    let status = std::process::Command::new(scenario)
        .arg("./foobar")
        .env("FUZZAMOTO_RECORD_FILE", output)
        .env("FUZZAMOTO_INPUT", input)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err("Scenario failed to run".into())
    }
}

fn get_llvm_command(base: &str) -> String {
    match std::env::var("LLVM_V") {
        Ok(version) => format!("{}-{}", base, version),
        Err(_) => base.to_string(),
    }
}

fn create_coverage_report(
    output: PathBuf,
    corpus: PathBuf,
    bitcoind: PathBuf,
    scenario: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in corpus.read_dir()? {
        let path = entry?.path();
        if let Err(e) = run_one_input(
            output.clone(),
            path.clone(),
            bitcoind.clone(),
            scenario.clone(),
        ) {
            log::error!("Failed to run input ({:?}): {}", path, e);
        }
    }

    let mut profraw_files = Vec::new();
    for entry in output.read_dir()? {
        let path = entry?.path();
        // Check if file name starts with "coverage.profraw"
        if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
            if file_name.contains("coverage.profraw") {
                profraw_files.push(path);
            }
        }
    }

    let merge_status = std::process::Command::new(get_llvm_command("llvm-profdata"))
        .arg("merge")
        .arg("-sparse")
        .args(&profraw_files)
        .arg("-o")
        .arg(output.join("coverage.profdata"))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if !merge_status.success() {
        return Err("Failed to merge profraw files".into());
    }

    let mut cmd = std::process::Command::new(get_llvm_command("llvm-cov"));
    cmd.args([
        "show",
        bitcoind.to_str().unwrap(),
        &format!(
            "-instr-profile={}",
            output.join("coverage.profdata").to_str().unwrap()
        ),
        "-format=html",
        "-show-directory-coverage",
        "-show-branches=count",
        &format!(
            "-output-dir={}",
            output.join("coverage-report").to_str().unwrap()
        ),
        "-Xdemangler=c++filt",
    ]);

    let status = cmd.status()?;

    if !status.success() {
        return Err("Failed to generate HTML report".into());
    }

    Ok(())
}

fn record_test_cases(
    output: PathBuf,
    corpus: PathBuf,
    scenario: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in corpus.read_dir()? {
        let path = entry?.path();
        if let Err(e) = record_one_input(
            path.clone(),
            output.join(format!(
                "{}.recording.bin",
                path.file_name().unwrap().to_str().unwrap()
            )),
            scenario.clone(),
        ) {
            log::error!("Failed to record input ({:?}): {}", path, e);
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Init {
            sharedir,
            crash_handler,
            bitcoind,
            scenario,
        } => {
            create_sharedir(
                sharedir.clone(),
                crash_handler.clone(),
                bitcoind.clone(),
                scenario.clone(),
            )?;
        }
        Commands::Coverage {
            output,
            corpus,
            bitcoind,
            scenario,
        } => {
            create_coverage_report(
                output.clone(),
                corpus.clone(),
                bitcoind.clone(),
                scenario.clone(),
            )?;
        }
        Commands::Record {
            output,
            corpus,
            scenario,
        } => {
            record_test_cases(output.clone(), corpus.clone(), scenario.clone())?;
        }
        Commands::IR { command } => match command {
            ir::IRCommands::Generate {
                output,
                iterations,
                programs,
                context,
            } => {
                ir::generate_ir(output, *iterations, *programs, context)?;
            }
            ir::IRCommands::Compile { input, output } => {
                ir::compile_ir(input, output)?;
            }
            ir::IRCommands::Print { input, json } => {
                ir::print_ir(input, *json)?;
            }
            ir::IRCommands::Convert {
                from,
                to,
                input,
                output,
            } => {
                ir::convert_ir(from, to, input, output)?;
            }
            ir::IRCommands::Analyze { input } => {
                ir::analyze_ir(input)?;
            }
        },
    }

    Ok(())
}
