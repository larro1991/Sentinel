use std::path::Path;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;

use sentinel::config::EngagementConfig;
use sentinel::engine::Engine;
use sentinel::finding::Severity;
use sentinel::recon;
use sentinel::report;
use sentinel::vuln;

#[derive(Parser)]
#[command(
    name = "sentinel",
    about = "Security assessment scanner with scope enforcement and professional reporting",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full security assessment
    Run {
        /// Path to engagement YAML config
        #[arg(short, long)]
        config: String,
    },
    /// Validate engagement config without running
    Validate {
        /// Path to engagement YAML config
        #[arg(short, long)]
        config: String,
    },
    /// Run recon phase only
    Recon {
        /// Path to engagement YAML config
        #[arg(short, long)]
        config: String,
    },
    /// Run vulnerability checks only (requires previous recon results)
    Scan {
        /// Path to engagement YAML config
        #[arg(short, long)]
        config: String,
    },
}

fn print_banner() {
    let banner = r#"
    ╔═══════════════════════════════════════╗
    ║           S E N T I N E L             ║
    ║     Security Assessment Scanner       ║
    ╚═══════════════════════════════════════╝
    "#;
    println!("{}", banner.cyan());
}

fn print_findings_summary(engine: &Engine) {
    let stats = engine.results().stats();
    println!();
    println!("{}", "═══ Findings Summary ═══".bold());
    println!(
        "  {} {}",
        "Critical:".red().bold(),
        stats.critical
    );
    println!("  {} {}", "High:".red(), stats.high);
    println!("  {} {}", "Medium:".yellow(), stats.medium);
    println!("  {} {}", "Low:".blue(), stats.low);
    println!("  {} {}", "Info:".white(), stats.info);
    println!("  ─────────────────────");
    println!("  {} {}", "Total:".bold(), stats.total);
    if stats.deduplicated > 0 {
        println!(
            "  {} {} duplicates removed",
            "Dedup:".dimmed(),
            stats.deduplicated
        );
    }
    println!();

    // Print each finding in a compact format.
    for finding in engine.results().findings() {
        let severity_colored = match finding.severity {
            Severity::Critical => format!("[{}]", "CRIT".red().bold()),
            Severity::High => format!("[{}]", "HIGH".red()),
            Severity::Medium => format!("[{}]", "MED ".yellow()),
            Severity::Low => format!("[{}]", "LOW ".blue()),
            Severity::Info => format!("[{}]", "INFO".white()),
        };
        println!(
            "  {} {} ({})",
            severity_colored, finding.title, finding.affected_asset
        );
    }
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the rustls crypto provider (ring) before any TLS operations.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    print_banner();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config } => cmd_run(&config).await?,
        Commands::Validate { config } => cmd_validate(&config)?,
        Commands::Recon { config } => cmd_recon(&config).await?,
        Commands::Scan { config } => cmd_scan(&config).await?,
    }

    Ok(())
}

async fn cmd_run(config_path: &str) -> Result<()> {
    println!(
        "{} {}",
        "Loading config:".bold(),
        config_path
    );

    let config = EngagementConfig::load(config_path)
        .context("Failed to load engagement config")?;

    println!(
        "{} {}",
        "Engagement:".bold(),
        config.name
    );
    println!(
        "{} {:?}",
        "Targets:".bold(),
        config.scope.targets
    );
    println!(
        "{} {}",
        "Authorization:".bold(),
        config.authorization.max_level
    );
    println!();

    let mut engine = Engine::new(config.clone())?;

    // Register recon modules (with port scan config if present).
    for module in recon::build_modules(&config) {
        engine.register_recon(module);
    }
    for check in vuln::default_checks() {
        engine.register_vuln(check);
    }

    // Run the full engagement.
    let result = engine.run().await?;

    // Print summary.
    print_findings_summary(&engine);

    println!(
        "{} {:.1}s",
        "Duration:".bold(),
        result.duration_secs
    );
    println!(
        "{} {}",
        "Targets scanned:".bold(),
        result.targets_scanned
    );
    println!(
        "{} {}",
        "Phase reached:".bold(),
        result.phase_reached
    );

    // Generate reports (filtered by config if specified).
    let output_dir = Path::new(&config.output_dir);
    let enabled_formats = config.report_formats.as_ref();
    for generator in report::all_generators() {
        if let Some(formats) = enabled_formats {
            if !formats.iter().any(|f| f == generator.format_name()) {
                continue;
            }
        }
        match generator.generate(&config, engine.results(), output_dir) {
            Ok(path) => {
                println!(
                    "{} {} report: {}",
                    "Generated".green().bold(),
                    generator.format_name(),
                    path.display()
                );
            }
            Err(e) => {
                eprintln!(
                    "{} {} report generation failed: {}",
                    "Error:".red().bold(),
                    generator.format_name(),
                    e
                );
            }
        }
    }

    Ok(())
}

fn cmd_validate(config_path: &str) -> Result<()> {
    println!(
        "{} {}",
        "Validating config:".bold(),
        config_path
    );

    let config = EngagementConfig::load(config_path)
        .context("Failed to load engagement config")?;

    config.validate().context("Configuration validation failed")?;

    println!("{}", "Configuration is valid!".green().bold());
    println!();
    println!("{}", "Engagement Details:".bold());
    println!("  ID:            {}", config.id);
    println!("  Name:          {}", config.name);
    println!("  Targets:       {:?}", config.scope.targets);
    println!("  Exclusions:    {:?}", config.scope.exclusions);
    println!("  Authorization: {}", config.authorization.max_level);
    println!("  Output:        {}", config.output_dir);
    println!("  Contact:       {}", config.emergency_contact);

    if !config.scope.time_windows.is_empty() {
        println!("  Time Windows:");
        for tw in &config.scope.time_windows {
            let days = tw
                .days
                .as_ref()
                .map(|d| d.join(", "))
                .unwrap_or_else(|| "All".to_string());
            let tz = tw.timezone.as_deref().unwrap_or("UTC");
            println!(
                "    {} - {} ({}) [{}]",
                tw.start, tw.end, tz, days
            );
        }
    }

    Ok(())
}

async fn cmd_recon(config_path: &str) -> Result<()> {
    println!(
        "{} {} (recon only)",
        "Loading config:".bold(),
        config_path
    );

    let config = EngagementConfig::load(config_path)
        .context("Failed to load engagement config")?;

    let mut engine = Engine::new(config.clone())?;

    // Register recon modules only.
    for module in recon::build_modules(&config) {
        engine.register_recon(module);
    }

    // Run recon phase.
    engine.run_recon().await?;

    // Save recon results.
    let output_dir = Path::new(&config.output_dir);
    std::fs::create_dir_all(output_dir)?;

    let recon_path = output_dir.join("recon_results.json");
    let recon_json = serde_json::to_string_pretty(engine.recon_results())?;
    std::fs::write(&recon_path, recon_json)?;

    println!(
        "{} Recon results saved to {}",
        "Done:".green().bold(),
        recon_path.display()
    );

    // Show discovered info.
    for result in engine.recon_results() {
        println!(
            "  [{}] {} -> {}",
            result.module_name,
            result.target,
            match &result.data {
                sentinel::recon::ReconData::DnsRecords(records) =>
                    format!("{} DNS records", records.len()),
                sentinel::recon::ReconData::OpenPorts(ports) =>
                    format!("{} open ports", ports.len()),
                sentinel::recon::ReconData::ServiceInfo(services) =>
                    format!("{} services", services.len()),
            }
        );
    }

    Ok(())
}

async fn cmd_scan(config_path: &str) -> Result<()> {
    println!(
        "{} {} (scan only)",
        "Loading config:".bold(),
        config_path
    );

    let config = EngagementConfig::load(config_path)
        .context("Failed to load engagement config")?;

    // Try to load previous recon results.
    let output_dir = Path::new(&config.output_dir);
    let recon_path = output_dir.join("recon_results.json");

    let recon_results: Vec<sentinel::recon::ReconResult> = if recon_path.exists() {
        let data = std::fs::read_to_string(&recon_path)?;
        serde_json::from_str(&data)?
    } else {
        println!(
            "{}",
            "Warning: No previous recon results found. Running quick recon first...".yellow()
        );
        // Run a quick recon.
        let mut engine = Engine::new(config.clone())?;
        for module in recon::build_modules(&config) {
            engine.register_recon(module);
        }
        engine.run_recon().await?;
        engine.recon_results().to_vec()
    };

    // Build services from recon.
    let mut services = Vec::new();
    for result in &recon_results {
        match &result.data {
            sentinel::recon::ReconData::OpenPorts(ports) => {
                for port in ports {
                    if port.state == "open" {
                        let tls = matches!(
                            port.port,
                            443 | 8443 | 993 | 995 | 465 | 636 | 5986
                        );
                        services.push(sentinel::vuln::Service {
                            host: result.target.clone(),
                            port: port.port,
                            service_name: port
                                .service
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string()),
                            version: None,
                            banner: port.banner.clone(),
                            tls,
                        });
                    }
                }
            }
            sentinel::recon::ReconData::ServiceInfo(infos) => {
                for info in infos {
                    services.push(sentinel::vuln::Service {
                        host: result.target.clone(),
                        port: info.port,
                        service_name: info.service_name.clone(),
                        version: info.version.clone(),
                        banner: info.banner.clone(),
                        tls: info.tls,
                    });
                }
            }
            sentinel::recon::ReconData::DnsRecords(_) => {}
        }
    }

    println!(
        "Running vulnerability checks against {} services",
        services.len()
    );

    let mut engine = Engine::new(config.clone())?;
    for check in vuln::default_checks() {
        engine.register_vuln(check);
    }
    engine.run_vulns(&services).await?;

    print_findings_summary(&engine);

    // Generate reports (filtered by config if specified).
    let enabled_formats = config.report_formats.as_ref();
    for generator in report::all_generators() {
        if let Some(formats) = enabled_formats {
            if !formats.iter().any(|f| f == generator.format_name()) {
                continue;
            }
        }
        match generator.generate(&config, engine.results(), output_dir) {
            Ok(path) => {
                println!(
                    "{} {} report: {}",
                    "Generated".green().bold(),
                    generator.format_name(),
                    path.display()
                );
            }
            Err(e) => {
                eprintln!(
                    "{} {} report generation failed: {}",
                    "Error:".red().bold(),
                    generator.format_name(),
                    e
                );
            }
        }
    }

    Ok(())
}
