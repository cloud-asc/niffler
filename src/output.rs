pub mod export;
pub mod sqlite;
pub mod types;

pub use sqlite::SqliteWriter;
pub use types::DeduplicationKey;
pub use types::file_mode_to_rwx;

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::config::OutputConfig;
use crate::pipeline::{ExportMsg, PipelineStats, ResultMsg};
use crate::tui::{FindingEvent, ReporterHandle};

/// Async output sink — reads `ResultMsg` and `ExportMsg` from the pipeline
/// channels, writes findings and export metadata to SQLite, and tees findings
/// (post severity-filter) to the reporter for live display.
pub async fn run(
    rx: mpsc::Receiver<ResultMsg>,
    export_meta_rx: mpsc::Receiver<ExportMsg>,
    config: &OutputConfig,
    targets: &[String],
    mode: &str,
    stats: Arc<PipelineStats>,
    reporter: ReporterHandle,
) -> Result<()> {
    run_inner(rx, export_meta_rx, config, targets, mode, stats, reporter).await
}

/// Batch size for SQLite inserts — balance between latency and throughput.
const WRITE_BATCH_SIZE: usize = 500;

async fn run_inner(
    mut rx: mpsc::Receiver<ResultMsg>,
    mut export_meta_rx: mpsc::Receiver<ExportMsg>,
    config: &OutputConfig,
    targets: &[String],
    mode: &str,
    stats: Arc<PipelineStats>,
    reporter: ReporterHandle,
) -> Result<()> {
    let sqlite_writer = SqliteWriter::new(&config.db_path, targets, mode).await?;

    let mut reporter_seen = HashSet::new();
    let mut export_metas: Vec<ExportMsg> = Vec::new();
    let mut result_done = false;
    let mut exports_done = false;

    while !(result_done && exports_done) {
        tokio::select! {
            maybe = rx.recv(), if !result_done => {
                match maybe {
                    Some(first) => {
                        let mut batch: Vec<ResultMsg> = Vec::with_capacity(WRITE_BATCH_SIZE);
                        batch.push(first);
                        while batch.len() < WRITE_BATCH_SIZE {
                            match rx.try_recv() {
                                Ok(m) => batch.push(m),
                                Err(_) => break,
                            }
                        }
                        let mut db_batch: Vec<ResultMsg> = Vec::with_capacity(batch.len());
                        for msg in batch.drain(..) {
                            if msg.triage < config.min_severity {
                                continue;
                            }
                            let key = DeduplicationKey::from_result(&msg);
                            if reporter_seen.insert(key) {
                                reporter.finding(FindingEvent::from_result(&msg));
                            }
                            db_batch.push(msg);
                        }
                        if !db_batch.is_empty() {
                            let batch_len = db_batch.len() as u64;
                            if let Err(e) = sqlite_writer.write_batch(&db_batch).await {
                                tracing::warn!("failed to write finding batch to SQLite: {e}");
                            } else {
                                stats.add_findings_written(batch_len);
                            }
                        }
                    }
                    None => result_done = true,
                }
            }
            maybe = export_meta_rx.recv(), if !exports_done => {
                match maybe {
                    Some(em) => export_metas.push(em),
                    None => exports_done = true,
                }
            }
        }
    }

    if let Err(e) = sqlite_writer.write_exports(&export_metas).await {
        tracing::warn!("failed to write exports to SQLite: {e}");
    }

    sqlite_writer.finish(&stats).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Triage;
    use crate::tui::ReporterHandle;
    use crate::web::db::FindingsQuery;
    use chrono::Utc;
    use std::sync::Arc;

    fn make_msg(triage: Triage, rule: &str, file: &str, context: Option<String>) -> ResultMsg {
        ResultMsg {
            timestamp: Utc::now(),
            host: "nfs-server".into(),
            export_path: "/exports/home".into(),
            file_path: file.into(),
            triage,
            rule_name: rule.into(),
            matched_pattern: "test_pattern".into(),
            context,
            file_size: 1700,
            file_mode: 0o644,
            file_uid: 1001,
            file_gid: 1001,
            last_modified: Utc::now(),
        }
    }

    fn test_config(db_path: std::path::PathBuf, _live: bool) -> OutputConfig {
        OutputConfig {
            db_path,
            display: crate::tui::DisplayMode::Auto,
            min_severity: Triage::Green,
        }
    }

    #[tokio::test]
    async fn output_always_writes_sqlite() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(Triage::Black, "SSHKey", "id_rsa", None))
            .await
            .unwrap();
        drop(tx);

        let (_em_tx, em_rx) = mpsc::channel::<crate::pipeline::ExportMsg>(10);
        drop(_em_tx);

        run_inner(
            rx,
            em_rx,
            &config,
            &[],
            "scan",
            Arc::clone(&stats),
            ReporterHandle::null(),
        )
        .await
        .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 1, "finding should be in SQLite");
    }

    #[tokio::test]
    async fn output_severity_filter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut config = test_config(tmp.path().to_path_buf(), false);
        config.min_severity = Triage::Red;
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(Triage::Green, "RuleA", "readme.txt", None))
            .await
            .unwrap();
        tx.send(make_msg(Triage::Yellow, "RuleB", "config.yml", None))
            .await
            .unwrap();
        tx.send(make_msg(
            Triage::Red,
            "RuleC",
            "creds.txt",
            Some("password".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(
            Triage::Black,
            "RuleD",
            "id_rsa",
            Some("key".into()),
        ))
        .await
        .unwrap();
        drop(tx);

        let (_em_tx, em_rx) = mpsc::channel::<crate::pipeline::ExportMsg>(10);
        drop(_em_tx);

        run_inner(
            rx,
            em_rx,
            &config,
            &[],
            "scan",
            Arc::clone(&stats),
            ReporterHandle::null(),
        )
        .await
        .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 2, "only Red and Black should pass severity filter");
    }

    #[tokio::test]
    async fn output_dedup_in_sqlite() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(
            Triage::Black,
            "SSHKey",
            "id_rsa",
            Some("key1".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(
            Triage::Black,
            "SSHKey",
            "id_rsa",
            Some("key2".into()),
        ))
        .await
        .unwrap();
        drop(tx);

        let (_em_tx, em_rx) = mpsc::channel::<crate::pipeline::ExportMsg>(10);
        drop(_em_tx);

        run_inner(
            rx,
            em_rx,
            &config,
            &[],
            "scan",
            Arc::clone(&stats),
            ReporterHandle::null(),
        )
        .await
        .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 1, "DB UNIQUE constraint should dedup");
    }

    #[tokio::test]
    async fn output_empty_channel() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (_tx, rx) = mpsc::channel::<ResultMsg>(10);
        drop(_tx);

        let (_em_tx, em_rx) = mpsc::channel::<crate::pipeline::ExportMsg>(10);
        drop(_em_tx);

        let result = run_inner(
            rx,
            em_rx,
            &config,
            &[],
            "scan",
            Arc::clone(&stats),
            ReporterHandle::null(),
        )
        .await;
        assert!(result.is_ok(), "empty channel should return Ok");

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let scans = db.list_scans().await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].status, "completed");
    }

    #[tokio::test]
    async fn output_multiple_findings() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(
            Triage::Black,
            "RuleA",
            "file1.txt",
            Some("key1".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(
            Triage::Red,
            "RuleB",
            "file2.txt",
            Some("key2".into()),
        ))
        .await
        .unwrap();
        tx.send(make_msg(Triage::Green, "RuleC", "file3.txt", None))
            .await
            .unwrap();
        drop(tx);

        let (_em_tx, em_rx) = mpsc::channel::<crate::pipeline::ExportMsg>(10);
        drop(_em_tx);

        run_inner(
            rx,
            em_rx,
            &config,
            &[],
            "scan",
            Arc::clone(&stats),
            ReporterHandle::null(),
        )
        .await
        .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 3, "all three findings should be in DB");
    }

    #[tokio::test]
    async fn output_handles_large_batch_efficiently() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (tx, rx) = mpsc::channel::<ResultMsg>(1000);
        for i in 0..500 {
            tx.send(make_msg(
                Triage::Red,
                &format!("Rule{i}"),
                &format!("file{i}.txt"),
                None,
            ))
            .await
            .unwrap();
        }
        drop(tx);

        let (_em_tx, em_rx) = mpsc::channel::<crate::pipeline::ExportMsg>(10);
        drop(_em_tx);

        run_inner(
            rx,
            em_rx,
            &config,
            &[],
            "scan",
            Arc::clone(&stats),
            ReporterHandle::null(),
        )
        .await
        .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let count = db.count_findings(&FindingsQuery::default()).await.unwrap();
        assert_eq!(count, 500, "all 500 findings should be in DB");
    }

    #[tokio::test]
    async fn output_tees_findings_to_reporter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());
        let reporter = ReporterHandle::null();

        let (tx, rx) = mpsc::channel::<ResultMsg>(10);
        tx.send(make_msg(Triage::Black, "SSHKey", "id_rsa", None))
            .await
            .unwrap();
        tx.send(make_msg(
            Triage::Red,
            "Creds",
            "creds.txt",
            Some("pw".into()),
        ))
        .await
        .unwrap();
        drop(tx);

        let (_em_tx, em_rx) = mpsc::channel::<crate::pipeline::ExportMsg>(10);
        drop(_em_tx);

        run_inner(
            rx,
            em_rx,
            &config,
            &[],
            "scan",
            Arc::clone(&stats),
            reporter.clone(),
        )
        .await
        .unwrap();

        assert_eq!(reporter.tally_snapshot().total(), 2);
    }

    #[tokio::test]
    async fn output_persists_exports() {
        use crate::nfs::{ExportAccessOptions, Misconfiguration, NfsVersion};
        use crate::pipeline::ExportMsg;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let config = test_config(tmp.path().to_path_buf(), false);
        let stats = Arc::new(PipelineStats::default());

        let (res_tx, res_rx) = mpsc::channel::<ResultMsg>(10);
        drop(res_tx);
        let (em_tx, em_rx) = mpsc::channel::<ExportMsg>(10);
        em_tx
            .send(ExportMsg {
                host: "10.0.0.9".into(),
                export_path: "/srv/backups".into(),
                nfs_version: NfsVersion::V3,
                access_options: ExportAccessOptions {
                    allowed_hosts: vec![],
                },
                harvested_uids: vec![],
                misconfigs: vec![Misconfiguration::SubtreeBypass],
            })
            .await
            .unwrap();
        drop(em_tx);

        run_inner(
            res_rx,
            em_rx,
            &config,
            &[],
            "recon",
            Arc::clone(&stats),
            ReporterHandle::null(),
        )
        .await
        .unwrap();

        let db = crate::web::db::Database::open(tmp.path()).await.unwrap();
        let recs = db.export_records(None, "10.0.0.9").await.unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].export_path, "/srv/backups");
        assert_eq!(recs[0].misconfigs, vec!["subtree".to_string()]);
    }
}
