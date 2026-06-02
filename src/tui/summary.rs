//! End-of-scan summary card and line-mode progress heartbeat.

use std::path::PathBuf;
use std::time::Duration;

use bytesize::ByteSize;

use crate::config::OperatingMode;
use crate::pipeline::PipelineStats;
use crate::tui::Tally;

/// Everything the summary card needs. Built once at scan end from the stats
/// snapshot plus the reporter's tally.
pub struct ScanSummary {
    pub target_label: String,
    pub mode: OperatingMode,
    pub duration: Duration,
    pub cancelled: bool,
    pub db_path: PathBuf,
    pub stats: PipelineStats,
    pub tally: Tally,
}

use std::fmt::Write as _;
use std::sync::atomic::Ordering::Relaxed;

use colored::Colorize;

/// Format `mm:ss` (or `HhMMmSSs`-ish compact) for a duration.
fn fmt_dur(d: Duration) -> String {
    let secs = d.as_secs();
    let m = secs / 60;
    let s = secs % 60;
    if m >= 60 {
        let h = m / 60;
        format!("{h}h{:02}m{s:02}s", m % 60)
    } else {
        format!("{m}m{s:02}s")
    }
}

/// `mm:ss` clock for the heartbeat prefix.
fn fmt_clock(d: Duration) -> String {
    let secs = d.as_secs();
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// Render the end-of-scan summary card. `color` enables ANSI styling.
#[must_use]
pub fn format_summary(s: &ScanSummary, color: bool) -> String {
    let st = &s.stats;
    let mut out = String::new();

    let header = if s.cancelled {
        format!(
            "\u{26a0} Scan cancelled \u{b7} {} \u{b7} {}",
            s.target_label,
            fmt_dur(s.duration)
        )
    } else {
        format!(
            "\u{2713} Scan complete \u{b7} {} \u{b7} {}",
            s.target_label,
            fmt_dur(s.duration)
        )
    };
    let header = if color {
        if s.cancelled {
            header.yellow().bold().to_string()
        } else {
            header.green().bold().to_string()
        }
    } else {
        header
    };
    let _ = writeln!(out, "{header}\n");

    let t = &s.tally;
    let _ = writeln!(
        out,
        "  Findings   {}   \u{25a0} {} black \u{b7} \u{25a0} {} red \u{b7} \u{2593} {} yellow \u{b7} \u{2591} {} green",
        t.total(),
        t.black,
        t.red,
        t.yellow,
        t.green
    );

    let hosts = st.hosts_scanned.load(Relaxed);
    let with_nfs = t.per_host.len() as u64;
    let _ = writeln!(
        out,
        "  Hosts      {hosts} scanned \u{b7} {with_nfs} with findings"
    );

    let _ = writeln!(
        out,
        "  Exports    {} found \u{b7} {} denied \u{b7} {} failed",
        st.exports_found.load(Relaxed),
        st.exports_denied.load(Relaxed),
        st.exports_failed.load(Relaxed),
    );

    if s.mode.runs_content_scan() || s.mode.runs_walker() {
        let scanned = st.files_content_scanned.load(Relaxed);
        let skip_size = st.files_skipped_size.load(Relaxed);
        let skip_bin = st.files_skipped_binary.load(Relaxed);
        let skip_perm = st.files_skipped_permission.load(Relaxed);
        let skipped = skip_size + skip_bin + skip_perm;
        let mut line = format!("  Files      {scanned} scanned \u{b7} {skipped} skipped");
        if skipped > 0 {
            let _ = write!(
                line,
                " ({skip_size} size \u{b7} {skip_bin} binary \u{b7} {skip_perm} perm)"
            );
        }
        if !s.mode.runs_content_scan() {
            let _ = write!(line, "  [content not read]");
        }
        let _ = writeln!(out, "{line}");
    }

    let err_conn = st.errors_connection.load(Relaxed);
    let err_tr = st.errors_transient.load(Relaxed);
    let err_st = st.errors_stale.load(Relaxed);
    let err_total = err_conn + err_tr + err_st;
    if err_total > 0 {
        let _ = writeln!(
            out,
            "  Errors     {err_total} \u{b7} {err_conn} conn \u{b7} {err_tr} transient \u{b7} {err_st} stale"
        );
    }

    let _ = writeln!(
        out,
        "  Output     {}   \u{2192} niffler serve --db {}",
        s.db_path.display(),
        s.db_path.display()
    );

    let top = t.top_hosts(5);
    if !top.is_empty() {
        let joined = top
            .iter()
            .map(|(h, c)| format!("{h} ({c})"))
            .collect::<Vec<_>>()
            .join(" \u{b7} ");
        let _ = writeln!(out, "  Top hits   {joined}");
    }

    out
}

/// One-line progress heartbeat for line mode.
#[must_use]
pub fn format_heartbeat(stats: &PipelineStats, elapsed: Duration, mode: OperatingMode) -> String {
    let hosts = stats.hosts_scanned.load(Relaxed);
    let dirs = stats.dirs_walked.load(Relaxed);
    let files = stats.files_content_scanned.load(Relaxed);
    let found = stats.findings_written.load(Relaxed);
    let bytes = ByteSize::b(stats.bytes_read.load(Relaxed));
    let mut s = format!("[{}] discovery {hosts}", fmt_clock(elapsed));
    if mode.runs_walker() {
        let _ = write!(s, " \u{b7} walking {dirs} dirs");
    }
    if mode.runs_content_scan() {
        let _ = write!(s, " \u{b7} scanning {files} files \u{b7} {bytes}");
    }
    let _ = write!(s, " \u{b7} {found} found");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;

    fn sample(mode: OperatingMode, cancelled: bool) -> ScanSummary {
        let stats = PipelineStats::default();
        stats.hosts_scanned.store(82, Relaxed);
        stats.exports_found.store(12, Relaxed);
        stats.exports_denied.store(1, Relaxed);
        stats.files_content_scanned.store(3410, Relaxed);
        stats.files_skipped_size.store(308, Relaxed);
        stats.files_skipped_binary.store(104, Relaxed);
        stats.errors_connection.store(1, Relaxed);
        stats.errors_transient.store(2, Relaxed);
        let mut tally = Tally::default();
        for _ in 0..3 {
            tally.record("nfs01", crate::classifier::Triage::Black);
        }
        for _ in 0..11 {
            tally.record("nfs02", crate::classifier::Triage::Red);
        }
        ScanSummary {
            target_label: "10.0.0.0/24".into(),
            mode,
            duration: Duration::from_secs(64),
            cancelled,
            db_path: PathBuf::from("niffler.db"),
            stats,
            tally,
        }
    }

    #[test]
    fn complete_scan_card_has_key_rows() {
        let card = format_summary(&sample(OperatingMode::Scan, false), false);
        assert!(card.contains("Scan complete"), "card: {card}");
        assert!(card.contains("10.0.0.0/24"));
        assert!(card.contains("1m04s"), "duration: {card}");
        assert!(card.contains("Findings"));
        assert!(card.contains("Files"), "scan mode shows Files row");
        assert!(card.contains("niffler.db"));
        assert!(card.contains("nfs02 (11)"), "top hits: {card}");
    }

    #[test]
    fn cancelled_scan_says_cancelled() {
        let card = format_summary(&sample(OperatingMode::Scan, true), false);
        assert!(card.contains("Scan cancelled"), "card: {card}");
        assert!(!card.contains("Scan complete"));
    }

    #[test]
    fn recon_mode_omits_files_row() {
        let card = format_summary(&sample(OperatingMode::Recon, false), false);
        assert!(
            !card.contains("Files "),
            "recon should omit Files row: {card}"
        );
    }

    #[test]
    fn heartbeat_is_single_line_with_counts() {
        let s = sample(OperatingMode::Scan, false);
        let line = format_heartbeat(&s.stats, Duration::from_secs(10), OperatingMode::Scan);
        assert!(line.starts_with("[00:10]"), "line: {line}");
        assert!(line.contains("scanning 3410"), "line: {line}");
        assert!(!line.contains('\n'), "heartbeat must be one line");
    }
}
