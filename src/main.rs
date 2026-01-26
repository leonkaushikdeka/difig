use clap::{Parser, Subcommand};
use indicatif::{HumanDuration, ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

mod analyzer;
mod reporter;
mod scanner;

use crate::analyzer::Analyzer;
use crate::reporter::Reporter;
use crate::scanner::Scanner;

#[derive(Parser)]
#[command(name = "difig")]
#[command(author = "difig Developers")]
#[command(version = "0.1.0")]
#[command(about = "Digital Investigation & Forensics Intelligence Gear", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Scan a directory for forensic analysis")]
    Scan {
        #[arg(short, long, value_name = "PATH")]
        output: Option<String>,

        #[arg(short, long)]
        quick: bool,

        #[arg(long)]
        entropy: bool,

        #[arg(short, long)]
        all: bool,

        #[arg(value_name = "TARGET_PATH")]
        target_path: Option<PathBuf>,
    },

    #[command(about = "Display version information")]
    Version,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan {
            output,
            quick,
            entropy,
            all,
            target_path,
        } => {
            let target = match target_path {
                Some(p) => p.clone(),
                None => {
                    eprintln!("Error: No target path specified");
                    std::process::exit(1);
                }
            };

            if !target.exists() {
                eprintln!("Error: Target path does not exist: {}", target.display());
                std::process::exit(1);
            }

            if !target.is_dir() {
                eprintln!("Error: Target must be a directory");
                std::process::exit(1);
            }

            run_scan(&target, output.clone(), *quick, *entropy, *all);
        }

        Commands::Version => {
            println!("difig v{}", env!("CARGO_PKG_VERSION"));
            println!("Digital Investigation & Forensics Intelligence Gear");
            println!("Built with Rust for memory safety and performance");
        }
    }
}

fn run_scan(
    target: &PathBuf,
    output: Option<String>,
    quick_mode: bool,
    calculate_entropy: bool,
    show_hidden: bool,
) {
    println!("==========================================");
    println!("  DIFIG - Digital Forensics Scanner");
    println!("==========================================");
    println!();
    println!("Target: {}", target.display());
    println!(
        "Mode: {}",
        if quick_mode {
            "Quick (metadata only)"
        } else {
            "Full analysis"
        }
    );
    println!(
        "Entropy: {}",
        if calculate_entropy {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!(
        "Hidden files: {}",
        if show_hidden { "Included" } else { "Excluded" }
    );
    println!();

    let start_time = Instant::now();

    let scanner = Scanner::new(show_hidden);

    println!("[1/4] Scanning filesystem structure...");
    let files = scanner.scan_directory(target);
    let total_files = files.len();

    if total_files == 0 {
        println!("No files found to scan.");
        return;
    }

    println!("      Found {} files", total_files);
    println!();

    let (progress_tx, progress_rx) = mpsc::channel::<usize>();

    println!("[2/4] Analyzing files (parallel processing)...");

    let progress_bar = ProgressBar::new(total_files as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap(),
    );

    let analyzer = Analyzer::new();
    let calculate_hashes = !quick_mode;

    let files_clone = files.clone();
    let progress_bar_clone = progress_bar.clone();
    let _progress_thread = thread::spawn(move || {
        while let Ok(_) = progress_rx.recv() {
            progress_bar_clone.inc(1);
        }
    });

    let artifacts = analyzer.analyze_files(
        &files_clone,
        calculate_hashes,
        calculate_entropy,
        Some(progress_tx),
    );

    progress_bar.finish_with_message("Analysis complete");

    println!();
    println!("[3/4] Generating forensic report...");

    let reporter = Reporter::new();
    let report = reporter.generate_report(artifacts.clone(), target);

    let output_path = match output {
        Some(path) => reporter.save_report_path(&report, path),
        None => {
            let default_path = String::from(".");
            reporter.save_report_path(&report, default_path)
        }
    };

    match output_path {
        Ok(path) => {
            println!("      Report saved to: {}", path.display());
        }
        Err(e) => {
            eprintln!("Error saving report: {}", e);
        }
    }

    println!();
    println!("[4/4] Scan Summary");
    println!("==========================================");
    println!("Total files scanned:    {}", report.total_files_scanned);
    println!(
        "Total bytes scanned:    {} bytes",
        report.total_bytes_scanned
    );
    println!("Files with errors:      {}", report.files_with_errors);
    println!(
        "Hash calculation:       {}",
        if calculate_hashes { "Yes" } else { "No" }
    );
    println!(
        "Entropy analysis:       {}",
        if calculate_entropy { "Yes" } else { "No" }
    );
    println!(
        "Scan duration:          {}",
        HumanDuration(start_time.elapsed())
    );
    println!("==========================================");

    let high_entropy_count: usize = artifacts
        .iter()
        .filter(|a| {
            if let Some(entropy) = a.entropy_score {
                entropy > 7.5
            } else {
                false
            }
        })
        .count();

    if high_entropy_count > 0 {
        println!();
        println!(
            "WARNING: {} files have high entropy (possible encrypted/compressed content)",
            high_entropy_count
        );
    }
}
