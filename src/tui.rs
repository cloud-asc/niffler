//! Terminal UI for scans: a live ratatui dashboard with an automatic
//! plain line-mode fallback for non-interactive contexts.

pub mod app;
pub mod line_reporter;
pub mod log_layer;
pub mod render;
pub mod summary;
pub mod terminal;
pub mod tui_reporter;

use std::collections::HashMap;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::classifier::Triage;
use crate::pipeline::ResultMsg;

/// A finding projected for display. Cheap subset of `ResultMsg`.
#[derive(Debug, Clone)]
pub struct FindingEvent {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub export_path: String,
    pub file_path: String,
    pub triage: Triage,
    pub rule_name: String,
    pub context: Option<String>,
    pub file_size: u64,
    pub file_mode: u32,
    pub file_uid: u32,
    pub last_modified: DateTime<Utc>,
}

impl FindingEvent {
    #[must_use]
    pub fn from_result(msg: &ResultMsg) -> Self {
        Self {
            timestamp: msg.timestamp,
            host: msg.host.clone(),
            export_path: msg.export_path.clone(),
            file_path: msg.file_path.clone(),
            triage: msg.triage,
            rule_name: msg.rule_name.clone(),
            context: msg.context.clone(),
            file_size: msg.file_size,
            file_mode: msg.file_mode,
            file_uid: msg.file_uid,
            last_modified: msg.last_modified,
        }
    }
}

/// Severity of a captured log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// A captured log line for the dashboard's log pane.
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub level: LogLevel,
    pub message: String,
}

/// Running finding counts: per-host and per-severity. Single source of truth
/// for the tally row and the summary card's "Top hits".
#[derive(Debug, Clone, Default)]
pub struct Tally {
    pub per_host: HashMap<String, u64>,
    pub black: u64,
    pub red: u64,
    pub yellow: u64,
    pub green: u64,
}

impl Tally {
    pub fn record(&mut self, host: &str, triage: Triage) {
        *self.per_host.entry(host.to_string()).or_default() += 1;
        match triage {
            Triage::Black => self.black += 1,
            Triage::Red => self.red += 1,
            Triage::Yellow => self.yellow += 1,
            Triage::Green => self.green += 1,
        }
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.black + self.red + self.yellow + self.green
    }

    /// Hosts by finding count, descending, then host name ascending for a stable order.
    #[must_use]
    pub fn top_hosts(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> =
            self.per_host.iter().map(|(h, c)| (h.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

/// How the user asked the scan to present itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DisplayMode {
    /// Dashboard when attached to a usable terminal, else line mode.
    #[default]
    Auto,
    /// Force the dashboard.
    Tui,
    /// Force plain line output.
    Plain,
}

/// The resolved presentation after applying TTY detection and overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveDisplay {
    Tui,
    Line,
}

/// Minimum terminal size for the dashboard. Below this, auto falls back to line mode.
pub const MIN_TUI_COLS: u16 = 80;
pub const MIN_TUI_ROWS: u16 = 20;

/// Decide between the dashboard and line mode. Pure — all inputs are explicit
/// so this is exhaustively unit-tested without touching a real terminal.
#[must_use]
pub fn resolve_display(
    mode: DisplayMode,
    stdin_is_tty: bool,
    stderr_is_tty: bool,
    term_size: Option<(u16, u16)>,
) -> EffectiveDisplay {
    match mode {
        DisplayMode::Plain => EffectiveDisplay::Line,
        DisplayMode::Tui => EffectiveDisplay::Tui,
        DisplayMode::Auto => {
            let big_enough = term_size.is_some_and(|(c, r)| c >= MIN_TUI_COLS && r >= MIN_TUI_ROWS);
            if stderr_is_tty && stdin_is_tty && big_enough {
                EffectiveDisplay::Tui
            } else {
                EffectiveDisplay::Line
            }
        }
    }
}

/// Cloneable handle the async output sink uses to report findings. It updates
/// the shared tally and, in TUI mode, forwards a `FindingEvent` to the render
/// thread; in line mode it prints directly; null mode does nothing.
#[derive(Clone)]
pub struct ReporterHandle {
    inner: ReporterInner,
    tally: Arc<Mutex<Tally>>,
}

#[derive(Clone)]
enum ReporterInner {
    /// try_send to the render thread; drop on full so the pipeline never blocks.
    Tui(SyncSender<FindingEvent>),
    /// Print directly to a shared stdout writer.
    Line(Arc<Mutex<line_reporter::LineReporter<std::io::Stdout>>>),
    Null,
}

impl ReporterHandle {
    #[must_use]
    pub fn null() -> Self {
        Self {
            inner: ReporterInner::Null,
            tally: Arc::new(Mutex::new(Tally::default())),
        }
    }

    pub(crate) fn from_tui_sender(tx: SyncSender<FindingEvent>) -> Self {
        Self {
            inner: ReporterInner::Tui(tx),
            tally: Arc::new(Mutex::new(Tally::default())),
        }
    }

    #[must_use]
    pub fn line(color: bool) -> Self {
        let reporter = line_reporter::LineReporter::new(std::io::stdout(), color);
        Self {
            inner: ReporterInner::Line(Arc::new(Mutex::new(reporter))),
            tally: Arc::new(Mutex::new(Tally::default())),
        }
    }

    /// Record a finding: always update the tally; then route to the active sink.
    pub fn finding(&self, ev: FindingEvent) {
        if let Ok(mut t) = self.tally.lock() {
            t.record(&ev.host, ev.triage);
        }
        match &self.inner {
            ReporterInner::Tui(tx) => {
                let _ = tx.try_send(ev);
            }
            ReporterInner::Line(w) => {
                if let Ok(mut w) = w.lock() {
                    w.finding(&ev);
                }
            }
            ReporterInner::Null => {}
        }
    }

    /// Snapshot the tally (for the summary card).
    #[must_use]
    pub fn tally_snapshot(&self) -> Tally {
        self.tally.lock().map(|t| t.clone()).unwrap_or_default()
    }
}

pub use app::App;
pub use line_reporter::LineReporter;
pub use summary::{ScanSummary, format_heartbeat, format_summary};
pub use tui_reporter::TuiReporter;

/// What `main` owns for the duration of a scan. Produces a `ReporterHandle`
/// for the output sink and prints the summary card on `finish`.
pub enum Reporter {
    Tui(TuiReporter),
    Line(ReporterHandle),
    Null(ReporterHandle),
}

impl Reporter {
    #[must_use]
    pub fn handle(&self) -> ReporterHandle {
        match self {
            Reporter::Tui(t) => t.handle(),
            Reporter::Line(h) | Reporter::Null(h) => h.clone(),
        }
    }

    pub fn finish(self, summary: ScanSummary) {
        match self {
            Reporter::Tui(t) => t.finish(summary),
            Reporter::Line(_) | Reporter::Null(_) => {
                let color = std::io::IsTerminal::is_terminal(&std::io::stderr())
                    && std::env::var_os("NO_COLOR").is_none();
                eprint!("{}", format_summary(&summary, color));
            }
        }
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    #[test]
    fn plain_always_line() {
        assert_eq!(
            resolve_display(DisplayMode::Plain, true, true, Some((200, 60))),
            EffectiveDisplay::Line
        );
    }

    #[test]
    fn forced_tui_always_tui() {
        // Even with no TTY and tiny size, --tui forces the dashboard.
        assert_eq!(
            resolve_display(DisplayMode::Tui, false, false, Some((10, 5))),
            EffectiveDisplay::Tui
        );
    }

    #[test]
    fn auto_needs_both_ttys_and_size() {
        assert_eq!(
            resolve_display(DisplayMode::Auto, true, true, Some((80, 20))),
            EffectiveDisplay::Tui
        );
        assert_eq!(
            resolve_display(DisplayMode::Auto, false, true, Some((80, 20))),
            EffectiveDisplay::Line
        );
        assert_eq!(
            resolve_display(DisplayMode::Auto, true, false, Some((80, 20))),
            EffectiveDisplay::Line
        );
        assert_eq!(
            resolve_display(DisplayMode::Auto, true, true, Some((79, 20))),
            EffectiveDisplay::Line
        );
        assert_eq!(
            resolve_display(DisplayMode::Auto, true, true, None),
            EffectiveDisplay::Line
        );
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;
    use crate::classifier::Triage;

    #[test]
    fn tally_records_and_totals() {
        let mut t = Tally::default();
        t.record("nfs01", Triage::Black);
        t.record("nfs01", Triage::Red);
        t.record("nfs02", Triage::Green);
        assert_eq!(t.total(), 3);
        assert_eq!(t.black, 1);
        assert_eq!(t.red, 1);
        assert_eq!(t.green, 1);
        assert_eq!(t.yellow, 0);
        let top = t.top_hosts(5);
        assert_eq!(top[0], ("nfs01".to_string(), 2));
    }

    #[test]
    fn finding_event_from_result_projects_fields() {
        use crate::pipeline::ResultMsg;
        use chrono::Utc;
        let msg = ResultMsg {
            timestamp: Utc::now(),
            host: "h".into(),
            export_path: "/e".into(),
            file_path: "p".into(),
            triage: Triage::Red,
            rule_name: "R".into(),
            matched_pattern: "m".into(),
            context: Some("ctx".into()),
            file_size: 10,
            file_mode: 0o600,
            file_uid: 7,
            file_gid: 7,
            last_modified: Utc::now(),
        };
        let ev = FindingEvent::from_result(&msg);
        assert_eq!(ev.host, "h");
        assert_eq!(ev.triage, Triage::Red);
        assert_eq!(ev.context.as_deref(), Some("ctx"));
        assert_eq!(ev.file_uid, 7);
    }
}

#[cfg(test)]
mod handle_tests {
    use super::*;
    use crate::classifier::Triage;
    use chrono::Utc;

    fn ev(host: &str, t: Triage) -> FindingEvent {
        FindingEvent {
            timestamp: Utc::now(),
            host: host.into(),
            export_path: "/e".into(),
            file_path: "p".into(),
            triage: t,
            rule_name: "R".into(),
            context: None,
            file_size: 1,
            file_mode: 0,
            file_uid: 0,
            last_modified: Utc::now(),
        }
    }

    #[test]
    fn null_handle_updates_tally_only() {
        let h = ReporterHandle::null();
        h.finding(ev("h1", Triage::Red));
        h.finding(ev("h1", Triage::Black));
        let t = h.tally_snapshot();
        assert_eq!(t.total(), 2);
        assert_eq!(t.red, 1);
        assert_eq!(t.black, 1);
    }

    #[test]
    fn cloned_handle_shares_tally() {
        let h = ReporterHandle::null();
        let h2 = h.clone();
        h2.finding(ev("h", Triage::Green));
        assert_eq!(h.tally_snapshot().total(), 1);
    }
}
