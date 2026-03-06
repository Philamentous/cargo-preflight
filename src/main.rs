use clap::Parser;
use colored::Colorize;
use std::process;

mod metadata;
mod patterns;
mod scanner;

#[derive(Parser, Debug)]
#[command(
    name = "cargo-preflight",
    bin_name = "cargo preflight",
    version = env!("CARGO_PKG_VERSION"),
    about = "Static pre-build analysis of dependency build scripts and proc-macros"
)]
struct Cli {
    /// Analyze a specific crate by name (otherwise analyzes all dependencies)
    #[arg(long = "crate")]
    crate_name: Option<String>,

    /// Path to the project directory (defaults to current directory)
    #[arg(long, default_value = ".")]
    manifest_path: String,

    /// Show detailed findings for all risk levels
    #[arg(long, short)]
    verbose: bool,

    // Hidden subcommand arg that cargo passes
    #[arg(hide = true, default_value = "preflight")]
    _subcmd: String,
}

fn main() {
    let cli = Cli::parse();

    let manifest_dir = if cli.manifest_path == "." {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .to_string_lossy()
            .to_string()
    } else {
        cli.manifest_path.clone()
    };

    let packages = match metadata::get_dependency_packages(&manifest_dir) {
        Ok(pkgs) => pkgs,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            process::exit(2);
        }
    };

    let packages = if let Some(ref name) = cli.crate_name {
        packages
            .into_iter()
            .filter(|p| p.name == *name)
            .collect::<Vec<_>>()
    } else {
        packages
    };

    if packages.is_empty() {
        if let Some(ref name) = cli.crate_name {
            eprintln!(
                "{}: crate '{}' not found in dependencies",
                "Error".red().bold(),
                name
            );
            process::exit(2);
        }
        println!(
            "{}",
            "No dependencies with build scripts or proc-macros found.".green()
        );
        process::exit(0);
    }

    let results = scanner::scan_packages(&packages);

    let has_high_risk = print_results(&results, cli.verbose);

    if has_high_risk {
        process::exit(1);
    }
}

fn print_results(results: &[scanner::ScanResult], verbose: bool) -> bool {
    let mut high_risk = Vec::new();
    let mut medium_risk = Vec::new();
    let mut low_risk = Vec::new();

    for result in results {
        match result.risk_level {
            scanner::RiskLevel::High => high_risk.push(result),
            scanner::RiskLevel::Medium => medium_risk.push(result),
            scanner::RiskLevel::Low => low_risk.push(result),
        }
    }

    println!(
        "\n{}",
        "cargo-preflight: Pre-build dependency analysis"
            .bold()
            .underline()
    );
    println!(
        "Scanned {} dependencies with build scripts or proc-macros\n",
        results.len()
    );

    if !high_risk.is_empty() {
        println!(
            "{} {} {}",
            "!!!".red().bold(),
            format!("HIGH RISK ({})", high_risk.len()).red().bold(),
            "!!!".red().bold()
        );
        for result in &high_risk {
            print_finding(result, true);
        }
        println!();
    }

    if !medium_risk.is_empty() {
        println!(
            "{} {}",
            "!!".yellow().bold(),
            format!("MEDIUM RISK ({})", medium_risk.len()).yellow().bold()
        );
        for result in &medium_risk {
            print_finding(result, verbose);
        }
        println!();
    }

    if !low_risk.is_empty() {
        println!(
            "{} {}",
            "*".green(),
            format!("LOW RISK ({})", low_risk.len()).green()
        );
        if verbose {
            for result in &low_risk {
                print_finding(result, true);
            }
        } else {
            let names: Vec<&str> = low_risk.iter().map(|r| r.package_name.as_str()).collect();
            println!("  {}", names.join(", ").dimmed());
        }
        println!();
    }

    let has_high = !high_risk.is_empty();

    if has_high {
        println!(
            "{}",
            "Result: HIGH-RISK dependencies detected. Review before building."
                .red()
                .bold()
        );
    } else {
        println!(
            "{}",
            "Result: No high-risk dependencies detected.".green().bold()
        );
    }

    has_high
}

fn print_finding(result: &scanner::ScanResult, show_details: bool) {
    let risk_indicator = match result.risk_level {
        scanner::RiskLevel::High => "HIGH".red().bold(),
        scanner::RiskLevel::Medium => "MEDIUM".yellow().bold(),
        scanner::RiskLevel::Low => "LOW".green(),
    };

    let kind_str = match result.scan_kind {
        scanner::ScanKind::BuildScript => "build.rs",
        scanner::ScanKind::ProcMacro => "proc-macro",
    };

    println!(
        "  [{}] {} ({}) - {}",
        risk_indicator,
        result.package_name.bold(),
        result.version,
        kind_str.dimmed()
    );

    if show_details {
        for finding in &result.findings {
            let category_color = match finding.category {
                patterns::Category::NetworkAccess => finding.category.as_str().red(),
                patterns::Category::FileSystemWrite => finding.category.as_str().yellow(),
                patterns::Category::ProcessExecution => finding.category.as_str().red(),
                patterns::Category::EnvironmentProbing => finding.category.as_str().cyan(),
                patterns::Category::DynamicLibraryLoading => finding.category.as_str().magenta(),
            };
            println!(
                "    {} {} (line {})",
                "-".dimmed(),
                category_color,
                finding.line_number
            );
            println!("      {}", finding.matched_text.dimmed());
        }
    }
}
