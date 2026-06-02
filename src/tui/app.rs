//! Live dashboard state and its reducer. Pure and terminal-free so it can be
//! unit-tested and rendered against a `TestBackend`.

use std::collections::VecDeque;

use crate::classifier::Triage;
use crate::config::OperatingMode;
use crate::tui::{FindingEvent, LogEvent, Tally};

/// Max findings retained in the scrollable feed. Older rows drop; SQLite keeps all.
pub const FEED_CAP: usize = 10_000;
/// Max log lines retained for the log pane.
pub const LOG_CAP: usize = 500;

/// Which severities the feed currently shows. `f` cycles through these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFilter {
    All,
    Yellow,
    Red,
    Black,
}

impl FeedFilter {
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Yellow,
            Self::Yellow => Self::Red,
            Self::Red => Self::Black,
            Self::Black => Self::All,
        }
    }

    #[must_use]
    pub fn min_triage(self) -> Option<Triage> {
        match self {
            Self::All => None,
            Self::Yellow => Some(Triage::Yellow),
            Self::Red => Some(Triage::Red),
            Self::Black => Some(Triage::Black),
        }
    }
}

/// All live dashboard state. Mutated only by the reducer methods below.
pub struct App {
    pub mode: OperatingMode,
    pub feed: VecDeque<FindingEvent>,
    pub logs: VecDeque<LogEvent>,
    pub tally: Tally,
    pub filter: FeedFilter,
    pub autoscroll: bool,
    /// Rows scrolled back from the newest. 0 = pinned to the latest.
    pub scroll_offset: usize,
    pub should_quit: bool,
}

impl App {
    #[must_use]
    pub fn new(mode: OperatingMode) -> Self {
        Self {
            mode,
            feed: VecDeque::with_capacity(1024),
            logs: VecDeque::with_capacity(LOG_CAP),
            tally: Tally::default(),
            filter: FeedFilter::All,
            autoscroll: true,
            scroll_offset: 0,
            should_quit: false,
        }
    }

    pub fn push_finding(&mut self, ev: FindingEvent) {
        self.tally.record(&ev.host, ev.triage);
        self.feed.push_back(ev);
        // The viewport is positioned by `scroll_offset` rows back from the
        // newest finding. While paused or scrolled (autoscroll off), a freshly
        // appended finding shifts "newest", so advance the offset in lockstep
        // to keep the same rows on screen — otherwise the view drifts forward
        // and pause/scroll appear to do nothing during a live scan.
        if !self.autoscroll {
            self.scroll_offset = (self.scroll_offset + 1).min(self.feed.len());
        }
        while self.feed.len() > FEED_CAP {
            self.feed.pop_front();
            if !self.autoscroll && self.scroll_offset > 0 {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
        }
    }

    pub fn push_log(&mut self, ev: LogEvent) {
        self.logs.push_back(ev);
        while self.logs.len() > LOG_CAP {
            self.logs.pop_front();
        }
    }

    #[must_use]
    pub fn feed_len(&self) -> usize {
        self.feed.len()
    }

    /// Findings currently passing the feed filter, oldest->newest.
    pub fn visible_findings(&self) -> impl Iterator<Item = &FindingEvent> {
        let min = self.filter.min_triage();
        self.feed
            .iter()
            .filter(move |f| min.is_none_or(|m| f.triage >= m))
    }

    pub fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
    }

    pub fn toggle_pause(&mut self) {
        self.autoscroll = !self.autoscroll;
        if self.autoscroll {
            self.scroll_offset = 0;
        }
    }

    pub fn scroll_up(&mut self, n: usize) {
        self.autoscroll = false;
        self.scroll_offset = (self.scroll_offset + n).min(self.feed.len());
    }

    pub fn scroll_down(&mut self, n: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(n);
        if self.scroll_offset == 0 {
            self.autoscroll = true;
        }
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn finding(host: &str, triage: Triage) -> FindingEvent {
        FindingEvent {
            timestamp: Utc::now(),
            host: host.into(),
            export_path: "/e".into(),
            file_path: "p".into(),
            triage,
            rule_name: "R".into(),
            context: None,
            file_size: 1,
            file_mode: 0o600,
            file_uid: 0,
            last_modified: Utc::now(),
        }
    }

    #[test]
    fn push_finding_updates_feed_and_tally() {
        let mut app = App::new(OperatingMode::Scan);
        app.push_finding(finding("h1", Triage::Black));
        app.push_finding(finding("h1", Triage::Red));
        assert_eq!(app.tally.total(), 2);
        assert_eq!(app.feed_len(), 2);
    }

    #[test]
    fn autoscroll_stays_pinned_to_newest() {
        let mut app = App::new(OperatingMode::Scan);
        for _ in 0..10 {
            app.push_finding(finding("h", Triage::Green));
        }
        assert!(app.autoscroll);
        for _ in 0..5 {
            app.push_finding(finding("h", Triage::Green));
        }
        assert_eq!(
            app.scroll_offset, 0,
            "autoscroll must stay pinned to the newest finding"
        );
    }

    #[test]
    fn paused_viewport_does_not_drift_as_findings_stream() {
        let mut app = App::new(OperatingMode::Scan);
        for _ in 0..10 {
            app.push_finding(finding("h", Triage::Green));
        }
        app.toggle_pause(); // autoscroll off; viewport end = feed_len - offset = 10
        let anchor = app.feed_len() - app.scroll_offset;
        for _ in 0..5 {
            app.push_finding(finding("h", Triage::Green));
        }
        assert!(!app.autoscroll);
        assert_eq!(
            app.feed_len() - app.scroll_offset,
            anchor,
            "a paused feed must not drift toward the newest finding"
        );
    }

    #[test]
    fn scrolled_viewport_anchors_while_findings_stream() {
        let mut app = App::new(OperatingMode::Scan);
        for _ in 0..10 {
            app.push_finding(finding("h", Triage::Green));
        }
        app.scroll_up(3); // autoscroll off; viewport end = 7
        let anchor = app.feed_len() - app.scroll_offset;
        for _ in 0..4 {
            app.push_finding(finding("h", Triage::Green));
        }
        assert_eq!(
            app.feed_len() - app.scroll_offset,
            anchor,
            "scrolled-back feed must stay anchored as new findings arrive"
        );
    }

    #[test]
    fn feed_respects_cap() {
        let mut app = App::new(OperatingMode::Scan);
        for _ in 0..(FEED_CAP + 50) {
            app.push_finding(finding("h", Triage::Green));
        }
        assert_eq!(app.feed_len(), FEED_CAP);
        assert_eq!(app.tally.total() as usize, FEED_CAP + 50);
    }

    #[test]
    fn filter_cycles_and_filters_visible() {
        let mut app = App::new(OperatingMode::Scan);
        app.push_finding(finding("h", Triage::Green));
        app.push_finding(finding("h", Triage::Red));
        assert_eq!(app.filter, FeedFilter::All);
        assert_eq!(app.visible_findings().count(), 2);
        app.cycle_filter(); // Yellow
        app.cycle_filter(); // Red
        assert_eq!(app.filter, FeedFilter::Red);
        assert_eq!(app.visible_findings().count(), 1);
    }

    #[test]
    fn pause_toggles_autoscroll() {
        let mut app = App::new(OperatingMode::Scan);
        assert!(app.autoscroll);
        app.toggle_pause();
        assert!(!app.autoscroll);
        app.toggle_pause();
        assert!(app.autoscroll);
    }

    #[test]
    fn scroll_clamps_to_bounds() {
        let mut app = App::new(OperatingMode::Scan);
        for _ in 0..5 {
            app.push_finding(finding("h", Triage::Green));
        }
        app.scroll_up(3);
        assert!(!app.autoscroll);
        assert_eq!(app.scroll_offset, 3);
        app.scroll_up(100);
        assert_eq!(app.scroll_offset, 5, "cannot scroll past the buffer length");
        app.scroll_down(2);
        assert_eq!(app.scroll_offset, 3);
    }

    #[test]
    fn push_log_respects_cap() {
        let mut app = App::new(OperatingMode::Scan);
        for i in 0..(LOG_CAP + 10) {
            app.push_log(LogEvent {
                level: crate::tui::LogLevel::Warn,
                message: format!("m{i}"),
            });
        }
        assert_eq!(app.logs.len(), LOG_CAP);
        assert_eq!(
            app.logs.back().unwrap().message,
            format!("m{}", LOG_CAP + 9)
        );
    }
}
