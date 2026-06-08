use anyhow::Result;
use clap::Parser;

use niffler::config::NifflerConfig;
use niffler::config::cli::{Cli, NifflerCommand, ScanArgs, Verbosity};
use niffler::config::settings::ExportFormat;
use niffler::nfs::{ConnectorFactory, Nfs3Connector, Nfs4Connector, NfsConnector, NfsVersion};
use niffler::output::export::{export_csv, export_json, export_tsv};
use niffler::web::db::{Database, FindingsQuery};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let verbosity = cli.verbosity;

    match cli.command {
        NifflerCommand::Scan(args) => run_scan(*args, verbosity).await,
        NifflerCommand::Shell(args) => niffler::shell::run(*args).await,
        NifflerCommand::Serve { db, port, bind } => {
            niffler::web::server::start_server(&db, port, &bind).await
        }
        NifflerCommand::Export {
            db,
            format,
            min_severity,
            host,
            rule,
            scan_id,
        } => {
            if !db.exists() {
                anyhow::bail!("database file not found: {}", db.display());
            }
            let database = Database::open(&db).await?;
            let query = FindingsQuery {
                scan_id,
                host,
                rule,
                min_triage: min_severity.map(|t| t.to_string()),
                per_page: u64::MAX,
                ..Default::default()
            };
            let findings = database.list_findings(&query).await?;
            let stdout = std::io::stdout();
            let mut writer = stdout.lock();
            match format {
                ExportFormat::Json => export_json(&findings, &mut writer)?,
                ExportFormat::Csv => export_csv(&findings, &mut writer)?,
                ExportFormat::Tsv => export_tsv(&findings, &mut writer)?,
            }
            Ok(())
        }
    }
}

async fn run_scan(args: ScanArgs, verbosity: Verbosity) -> Result<()> {
    use std::io::IsTerminal;
    use std::sync::Arc;
    use std::time::Instant;

    use niffler::tui::{EffectiveDisplay, Reporter, ReporterHandle, ScanSummary, resolve_display};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let level = match verbosity {
        Verbosity::Trace => tracing::Level::TRACE,
        Verbosity::Debug => tracing::Level::DEBUG,
        Verbosity::Info => tracing::Level::INFO,
        Verbosity::Warn => tracing::Level::WARN,
        Verbosity::Error => tracing::Level::ERROR,
    };

    let mut config = NifflerConfig::from_scan_args(args)?;

    if config.generate_config {
        let toml = toml::to_string_pretty(&config)?;
        println!("{toml}");
        return Ok(());
    }

    // Detected before subscriber init; the warning is emitted afterward so it
    // is captured by whichever logging path we set up.
    let proxy_priv_conflict = config.discovery.proxy.is_some() && config.discovery.privileged_port;
    if proxy_priv_conflict {
        config.discovery.privileged_port = false;
    }

    let stdin_tty = std::io::stdin().is_terminal();
    let stderr_tty = std::io::stderr().is_terminal();
    let term_size = crossterm::terminal::size().ok();
    let effective = resolve_display(config.output.display, stdin_tty, stderr_tty, term_size);

    let target_label = config
        .discovery
        .targets
        .as_ref()
        .map(|t| t.join(", "))
        .or_else(|| {
            config.walker.local_paths.as_ref().map(|p| {
                p.iter()
                    .map(|x| x.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
        })
        .unwrap_or_else(|| "targets".to_string());

    let stats_for_reporter = Arc::new(niffler::pipeline::PipelineStats::default());
    let cancel = tokio_util::sync::CancellationToken::new();

    let reporter: Reporter = match effective {
        EffectiveDisplay::Tui => {
            let (log_tx, log_rx) = std::sync::mpsc::sync_channel(1024);
            tracing_subscriber::registry()
                .with(tracing_subscriber::filter::LevelFilter::from_level(level))
                .with(niffler::tui::log_layer::ChannelLogLayer::new(log_tx))
                .init();
            let tui = niffler::tui::TuiReporter::spawn(
                config.mode,
                target_label.clone(),
                Arc::clone(&stats_for_reporter),
                cancel.clone(),
                log_rx,
            );
            Reporter::Tui(tui)
        }
        EffectiveDisplay::Line => {
            let color = stderr_tty && std::env::var_os("NO_COLOR").is_none();
            tracing_subscriber::fmt()
                .with_max_level(level)
                .with_target(false)
                .with_ansi(color)
                .with_writer(std::io::stderr)
                .init();
            Reporter::Line(ReporterHandle::line(color))
        }
    };

    if proxy_priv_conflict {
        tracing::warn!("--privileged-port is incompatible with --proxy, ignoring privileged port");
    }

    let handle = reporter.handle();

    let max_dir_entries = config.walker.max_dir_entries;
    let v3: Arc<dyn NfsConnector> = match config.discovery.proxy {
        Some(proxy) => {
            Arc::new(Nfs3Connector::with_proxy(proxy).with_max_dir_entries(max_dir_entries))
        }
        None => Arc::new(
            Nfs3Connector::new(config.discovery.privileged_port)
                .with_max_dir_entries(max_dir_entries),
        ),
    };
    let v4: Arc<dyn NfsConnector> =
        Arc::new(Nfs4Connector::new().with_max_dir_entries(max_dir_entries));
    let forced = match config.discovery.nfs_version {
        Some(3) => Some(NfsVersion::V3),
        Some(4) => Some(NfsVersion::V4),
        _ => None,
    };
    let connector_factory = ConnectorFactory::new(v3, v4, forced);

    let mode = config.mode;
    let db_path = config.output.db_path.clone();
    let start = Instant::now();

    let heartbeat = if matches!(effective, EffectiveDisplay::Line) {
        let stats = Arc::clone(&stats_for_reporter);
        let cancel_hb = cancel.clone();
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
            tick.tick().await; // skip immediate fire
            loop {
                tokio::select! {
                    _ = cancel_hb.cancelled() => break,
                    _ = tick.tick() => {
                        if matches!(level, tracing::Level::ERROR) { continue; }
                        eprintln!("{}", niffler::tui::format_heartbeat(&stats, start.elapsed(), mode));
                    }
                }
            }
        }))
    } else {
        None
    };

    let stats = niffler::pipeline::run_pipeline_with_stats(
        config,
        connector_factory,
        cancel.clone(),
        handle,
        Arc::clone(&stats_for_reporter),
    )
    .await?;

    // Capture interruption state BEFORE cancelling to stop the heartbeat task.
    let interrupted = cancel.is_cancelled();
    cancel.cancel();
    if let Some(h) = heartbeat {
        let _ = h.await;
    }

    let summary = ScanSummary {
        target_label,
        mode,
        duration: start.elapsed(),
        cancelled: interrupted,
        db_path,
        stats: stats.snapshot(),
        tally: reporter.handle().tally_snapshot(),
    };
    reporter.finish(summary);

    Ok(())
}
