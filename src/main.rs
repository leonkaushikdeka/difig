use clap::{Parser, Subcommand};
use indicatif::{HumanDuration, ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

mod analyzer;
mod carver;
mod case;
mod endpoint;
mod mobile;
mod reporter;
mod scanner;

use crate::analyzer::Analyzer;
use crate::carver::Carver;
use crate::case::CaseManager;
use crate::endpoint::EndpointForensics;
use crate::mobile::MobileForensics;
use crate::reporter::Reporter;
use crate::scanner::Scanner;

#[derive(Parser)]
#[command(name = "difig")]
#[command(author = "difig Developers")]
#[command(version = "0.3.0")]
#[command(about = "Digital Investigation & Forensics Intelligence Gear - Enterprise Suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Comprehensive forensic analysis")]
    Scan {
        #[arg(short, long, value_name = "PATH")]
        output: Option<String>,

        #[arg(short, long)]
        quick: bool,

        #[arg(long)]
        entropy: bool,

        #[arg(short, long)]
        all: bool,

        #[arg(long)]
        verify_signatures: bool,

        #[arg(long)]
        yara: bool,

        #[arg(long)]
        stego: bool,

        #[arg(long)]
        browser: bool,

        #[arg(long)]
        lnk: bool,

        #[arg(long)]
        timeline: bool,

        #[arg(long)]
        mobile: bool,

        #[arg(long)]
        carve: bool,

        #[arg(long)]
        endpoint: bool,

        #[arg(value_name = "TARGET_PATH")]
        target_path: Option<PathBuf>,
    },

    #[command(about = "Mobile device forensics analysis")]
    Mobile {
        #[arg(short, long, value_name = "PATH")]
        output: Option<String>,

        #[arg(value_name = "BACKUP_PATH")]
        backup_path: Option<PathBuf>,
    },

    #[command(about = "Carve files from disk image or unallocated space")]
    Carve {
        #[arg(short, long, value_name = "PATH")]
        output: Option<String>,

        #[arg(value_name = "IMAGE_PATH")]
        image_path: Option<PathBuf>,
    },

    #[command(about = "Endpoint detection and analysis")]
    Endpoint {
        #[arg(short, long, value_name = "PATH")]
        output: Option<String>,

        #[arg(long)]
        suspicious: bool,

        #[arg(value_name = "EVIDENCE_PATH")]
        evidence_path: Option<PathBuf>,
    },

    #[command(about = "Case management operations")]
    Case {
        #[command(subcommand)]
        case_command: CaseCommands,
    },

    #[command(about = "Display version information")]
    Version,
}

#[derive(Subcommand)]
enum CaseCommands {
    #[command(about = "Create a new case")]
    Create {
        #[arg(short, long)]
        name: String,

        #[arg(short, long)]
        examiner: String,

        #[arg(short, long, value_name = "DESCRIPTION")]
        description: Option<String>,

        #[arg(short, long, value_name = "PATH")]
        output: Option<String>,
    },

    #[command(about = "Generate chain of custody report")]
    Custody {
        #[arg(value_name = "CASE_FILE")]
        case_file: Option<PathBuf>,
    },

    #[command(about = "Export case for secure sharing")]
    Export {
        #[arg(value_name = "CASE_FILE")]
        case_file: Option<PathBuf>,

        #[arg(short, long, value_name = "PATH")]
        output: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan {
            output,
            quick,
            entropy,
            all,
            verify_signatures,
            yara,
            stego,
            browser,
            lnk,
            timeline,
            mobile,
            carve,
            endpoint,
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

            run_scan(
                &target,
                output.clone(),
                *quick,
                *entropy,
                *all,
                *verify_signatures,
                *yara,
                *stego,
                *browser,
                *lnk,
                *timeline,
                *mobile,
                *carve,
                *endpoint,
            );
        }

        Commands::Mobile {
            output,
            backup_path,
        } => {
            let backup = match backup_path {
                Some(p) => p.clone(),
                None => {
                    eprintln!("Error: No backup path specified");
                    std::process::exit(1);
                }
            };

            if !backup.exists() {
                eprintln!("Error: Backup path does not exist");
                std::process::exit(1);
            }

            run_mobile_analysis(&backup, output.clone());
        }

        Commands::Carve { output, image_path } => {
            let image = match image_path {
                Some(p) => p.clone(),
                None => {
                    eprintln!("Error: No image path specified");
                    std::process::exit(1);
                }
            };

            if !image.exists() {
                eprintln!("Error: Image path does not exist");
                std::process::exit(1);
            }

            run_carve(&image, output.clone());
        }

        Commands::Endpoint {
            output,
            suspicious,
            evidence_path,
        } => {
            let evidence = match evidence_path {
                Some(p) => p.clone(),
                None => {
                    eprintln!("Error: No evidence path specified");
                    std::process::exit(1);
                }
            };

            if !evidence.exists() {
                eprintln!("Error: Evidence path does not exist");
                std::process::exit(1);
            }

            run_endpoint_analysis(&evidence, output.clone(), *suspicious);
        }

        Commands::Case { case_command } => {
            run_case_command(case_command);
        }

        Commands::Version => {
            println!("difig v{}", env!("CARGO_PKG_VERSION"));
            println!("Digital Investigation & Forensics Intelligence Gear");
            println!("Enterprise Forensic Analysis Suite");
            println!();
            println!("Modules:");
            println!("  Scan      - Comprehensive file analysis");
            println!("  Mobile    - iOS/Android backup forensics");
            println!("  Carve     - File carving from disk images");
            println!("  Endpoint  - Process/network/registry analysis");
            println!("  Case      - Case management & chain of custody");
        }
    }
}

fn run_scan(
    target: &PathBuf,
    output: Option<String>,
    quick_mode: bool,
    calculate_entropy: bool,
    show_hidden: bool,
    verify_signatures: bool,
    scan_yara: bool,
    scan_stego: bool,
    scan_browser: bool,
    scan_lnk: bool,
    generate_timeline: bool,
    scan_mobile: bool,
    do_carve: bool,
    scan_endpoint: bool,
) {
    println!("==========================================");
    println!("  DIFIG - Enterprise Forensics Suite v0.3.0");
    println!("==========================================");
    println!();
    println!("Target: {}", target.display());
    println!("Mode: {}", if quick_mode { "Quick" } else { "Full" });
    println!(
        "Entropy: {} | YARA: {} | Stego: {} | Browser: {}",
        if calculate_entropy { "Yes" } else { "No" },
        if scan_yara { "Yes" } else { "No" },
        if scan_stego { "Yes" } else { "No" },
        if scan_browser { "Yes" } else { "No" }
    );
    println!(
        "Mobile: {} | Carve: {} | Endpoint: {} | Timeline: {}",
        if scan_mobile { "Yes" } else { "No" },
        if do_carve { "Yes" } else { "No" },
        if scan_endpoint { "Yes" } else { "No" },
        if generate_timeline { "Yes" } else { "No" }
    );
    println!();

    let start_time = Instant::now();
    let scanner = Scanner::new(show_hidden);

    println!("[1/5] Scanning filesystem...");
    let files = scanner.scan_directory(target);
    let total_files = files.len();

    if total_files == 0 {
        println!("No files found.");
        return;
    }

    println!("      Found {} files", total_files);

    let (progress_tx, progress_rx) = mpsc::channel::<usize>();

    println!("[2/5] Analyzing files...");

    let progress_bar = ProgressBar::new(total_files as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")
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
        verify_signatures,
        scan_yara,
        scan_stego,
        scan_browser,
        scan_lnk,
        Some(progress_tx),
    );

    progress_bar.finish_with_message("Analysis complete");

    if scan_mobile {
        println!("[3/5] Mobile forensics analysis...");
        let mobile = MobileForensics::new();
        let mobile_artifacts = mobile.analyze_mobile_backup(target);
        println!("      Found {} mobile artifacts", mobile_artifacts.len());
    }

    if do_carve {
        println!("[3/5] File carving...");
        let carver = Carver::new();
        let carved = carver.carve_disk_image(target, &target.join("carved"));
        println!("      Carved {} files", carved.len());
    }

    if scan_endpoint {
        println!("[3/5] Endpoint analysis...");
        let endpoint = EndpointForensics::new();
        let suspicious = endpoint.detect_suspicious_processes(target);
        println!("      Found {} suspicious processes", suspicious.len());
    }

    println!("[4/5] Generating report...");

    let reporter = Reporter::new();
    let report = reporter.generate_report(artifacts.clone(), target);

    let output_path = match output {
        Some(path) => reporter.save_report_path(&report, path),
        None => reporter.save_report_path(&report, String::from(".")),
    };

    match output_path {
        Ok(path) => println!("      Report: {}", path.display()),
        Err(e) => eprintln!("      Error: {}", e),
    }

    if generate_timeline {
        let timeline_path = reporter.save_timeline_path(&report.timeline, String::from("."));
        match timeline_path {
            Ok(path) => println!("      Timeline: {}", path.display()),
            Err(e) => eprintln!("      Timeline error: {}", e),
        }
    }

    println!();
    println!("[5/5] Summary");
    println!("==========================================");
    println!(
        "Files: {} | Bytes: {} | Duration: {}",
        report.total_files_scanned,
        report.total_bytes_scanned,
        HumanDuration(start_time.elapsed())
    );
    println!(
        "YARA: {} | Signatures: {} | High Entropy: {}",
        report.yara_matches_found, report.signature_warnings, report.high_entropy_files
    );
    println!("==========================================");

    if report.yara_matches_found > 0 {
        println!("\n⚠️  YARA matches detected - review immediately");
    }
}

fn run_mobile_analysis(backup: &PathBuf, output: Option<String>) {
    println!("==========================================");
    println!("  DIFIG Mobile Forensics (UFED-style)");
    println!("==========================================");

    let mobile = MobileForensics::new();
    let artifacts = mobile.analyze_mobile_backup(backup);

    println!("\nExtracted {} mobile artifacts:", artifacts.len());

    let mut sms_count = 0;
    let mut call_count = 0;
    let mut contact_count = 0;
    let mut location_count = 0;

    for artifact in &artifacts {
        match artifact.artifact_type.as_str() {
            "sms_messages" => {
                if let Some(count) = artifact.data.get("message_count") {
                    sms_count = count.as_u64().unwrap_or(0) as usize;
                }
            }
            "call_history" => {
                if let Some(count) = artifact.data.get("call_count") {
                    call_count = count.as_u64().unwrap_or(0) as usize;
                }
            }
            "contacts" => {
                if let Some(count) = artifact.data.get("contact_count") {
                    contact_count = count.as_u64().unwrap_or(0) as usize;
                }
            }
            "location_data" => {
                if let Some(count) = artifact.data.get("location_count") {
                    location_count = count.as_u64().unwrap_or(0) as usize;
                }
            }
            _ => {}
        }
    }

    println!("  SMS Messages:     {}", sms_count);
    println!("  Call History:     {}", call_count);
    println!("  Contacts:         {}", contact_count);
    println!("  Location Points:  {}", location_count);

    let reporter = Reporter::new();
    let report = ForensicReport::new(
        env!("CARGO_PKG_VERSION").to_string(),
        backup.to_string_lossy().to_string(),
    );

    let output_path = match output {
        Some(path) => reporter.save_report_path(&report, path),
        None => reporter.save_report_path(&report, String::from(".")),
    };

    match output_path {
        Ok(path) => println!("\nReport saved: {}", path.display()),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn run_carve(image: &PathBuf, output: Option<String>) {
    println!("==========================================");
    println!("  DIFIG File Carver (PATHFINDER-style)");
    println!("==========================================");

    let carver = Carver::new();
    println!(
        "\nAvailable signatures: {} file types",
        carver.get_signature_count()
    );

    let output_dir = match output {
        Some(p) => std::path::PathBuf::from(p),
        None => image
            .parent()
            .unwrap_or(&std::path::PathBuf::from("."))
            .to_path_buf(),
    };

    println!("\nCarving from: {}", image.display());
    println!("Output to: {}", output_dir.display());

    let carved = carver.carve_disk_image(image, &output_dir);

    println!("\nResults:");
    println!("  Total carved:    {}", carved.len());

    let mut by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for c in &carved {
        *by_type.entry(c.file_type.clone()).or_insert(0) += 1;
    }

    for (ext, count) in by_type.iter().take(10) {
        println!("    .{}: {}", ext, count);
    }

    if carved.len() > 10 {
        println!("    ... and {} more", carved.len() - 10);
    }
}

fn run_endpoint_analysis(evidence: &PathBuf, output: Option<String>, suspicious_only: bool) {
    println!("==========================================");
    println!("  DIFIG Endpoint Inspector (Falcon-style)");
    println!("==========================================");

    let endpoint = EndpointForensics::new();

    let data = if suspicious_only {
        endpoint.detect_suspicious_processes(evidence)
    } else {
        endpoint.analyze_endpoint(evidence)
    };

    println!("\nAnalyzed {} endpoint artifacts", data.len());

    let process_count = data
        .iter()
        .filter(|d| d.artifact_type == "process_list")
        .count();
    let network_count = data
        .iter()
        .filter(|d| d.artifact_type == "network_connections")
        .count();
    let registry_count = data
        .iter()
        .filter(|d| d.artifact_type == "registry_keys")
        .count();

    println!("  Process lists:   {}", process_count);
    println!("  Network:         {}", network_count);
    println!("  Registry:        {}", registry_count);

    if suspicious_only {
        println!("\n⚠️  SUSPICIOUS PROCESSES DETECTED");
        for d in &data {
            if let Some(ref name) = d.process_name {
                println!("    - {}", name);
            }
        }
    }
}

fn run_case_command(command: &CaseCommands) {
    let manager = CaseManager::new();

    match command {
        CaseCommands::Create {
            name,
            examiner,
            description,
            output,
        } => {
            let mut case = manager.create_case(name.clone(), examiner.clone(), description.clone());

            manager.add_custody_entry(
                &mut case,
                String::from("Case Created"),
                examiner.clone(),
                String::from("Initial"),
                None,
            );

            let output_path = match output {
                Some(p) => std::path::PathBuf::from(p),
                None => std::path::PathBuf::from(&format!("{}.json", name.replace(" ", "_"))),
            };

            if let Err(e) = manager.save_case(&case, &output_path) {
                eprintln!("Error saving case: {}", e);
                return;
            }

            println!("==========================================");
            println!("  DIFIG Case Manager (GUARDIAN-style)");
            println!("==========================================");
            println!();
            println!("Case Created Successfully!");
            println!("  Case ID:     {}", case.case_id);
            println!("  Name:        {}", case.case_name);
            println!("  Examiner:    {}", case.examiner);
            println!("  File:        {}", output_path.display());
        }

        CaseCommands::Custody { case_file } => {
            let path = match case_file {
                Some(p) => p.clone(),
                None => {
                    eprintln!("Error: No case file specified");
                    return;
                }
            };

            let case = match manager.load_case(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error loading case: {}", e);
                    return;
                }
            };

            let report = manager.generate_chain_of_custody_report(&case);
            println!("{}", report);
        }

        CaseCommands::Export { case_file, output } => {
            let path = match case_file {
                Some(p) => p.clone(),
                None => {
                    eprintln!("Error: No case file specified");
                    return;
                }
            };

            let case = match manager.load_case(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error loading case: {}", e);
                    return;
                }
            };

            let output_path = match output {
                Some(p) => std::path::PathBuf::from(p),
                None => std::path::PathBuf::from(&format!("{}_shared.json", case.case_id)),
            };

            if let Err(e) = manager.export_case_for_sharing(&case, &output_path) {
                eprintln!("Error exporting case: {}", e);
                return;
            }

            println!(
                "Case exported for secure sharing: {}",
                output_path.display()
            );
        }
    }
}

use difig::ForensicReport;
