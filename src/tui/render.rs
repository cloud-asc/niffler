//! Builds the dashboard widget tree from `&App` and draws it to a ratatui frame.

use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::classifier::Triage;
use crate::pipeline::PipelineStats;
use crate::tui::app::App;

/// Immutable per-frame inputs the render reads in addition to `App`.
pub struct FrameCtx<'a> {
    pub app: &'a App,
    pub stats: &'a PipelineStats,
    pub elapsed: Duration,
    pub target_label: &'a str,
}

fn triage_style(t: Triage) -> Style {
    match t {
        Triage::Black => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Triage::Red => Style::default().fg(Color::Red),
        Triage::Yellow => Style::default().fg(Color::Yellow),
        Triage::Green => Style::default().fg(Color::Green),
    }
}

fn triage_word(t: Triage) -> &'static str {
    match t {
        Triage::Black => "BLACK ",
        Triage::Red => "RED   ",
        Triage::Yellow => "YELLOW",
        Triage::Green => "GREEN ",
    }
}

fn clock(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}", s / 60, s % 60)
}

fn phase_rows(app: &App) -> u16 {
    let mut n = 1; // discovery always
    if app.mode.runs_walker() {
        n += 1;
    }
    if app.mode.runs_content_scan() {
        n += 1;
    }
    n + 1 // + padding row
}

pub fn draw(f: &mut Frame, ctx: &FrameCtx) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),                   // header
            Constraint::Length(phase_rows(ctx.app)), // phases
            Constraint::Min(3),                      // findings feed (flex)
            Constraint::Length(5),                   // log pane
            Constraint::Length(1),                   // footer
        ])
        .split(area);

    draw_header(f, chunks[0], ctx);
    draw_phases(f, chunks[1], ctx);
    draw_feed(f, chunks[2], ctx.app);
    draw_log(f, chunks[3], ctx.app);
    draw_footer(f, chunks[4], ctx.app);
}

fn draw_header(f: &mut Frame, area: Rect, ctx: &FrameCtx) {
    const FRAMES: [&str; 4] = ["\u{280b}", "\u{2819}", "\u{2839}", "\u{2838}"];
    let spinner = FRAMES[(ctx.elapsed.as_millis() / 120 % 4) as usize];
    let left = format!(" niffler \u{b7} {} {}", ctx.app.mode, ctx.target_label);
    let right = format!("{} {} ", clock(ctx.elapsed), spinner);
    let pad = (area.width as usize).saturating_sub(left.chars().count() + right.chars().count());
    let line = Line::from(vec![
        Span::styled(left, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" ".repeat(pad)),
        Span::raw(right),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_phases(f: &mut Frame, area: Rect, ctx: &FrameCtx) {
    use std::sync::atomic::Ordering::Relaxed;
    let app = ctx.app;
    let st = ctx.stats;

    let mut rows: Vec<Constraint> = vec![Constraint::Length(1)]; // padding
    rows.push(Constraint::Length(1)); // discovery
    if app.mode.runs_walker() {
        rows.push(Constraint::Length(1));
    }
    if app.mode.runs_content_scan() {
        rows.push(Constraint::Length(1));
    }
    let slots = Layout::default()
        .direction(Direction::Vertical)
        .constraints(rows)
        .split(area);

    let mut i = 1;
    let hosts = st.hosts_scanned.load(Relaxed);
    let exports = st.exports_found.load(Relaxed);
    f.render_widget(
        Paragraph::new(Line::from(format!(
            "  Discovery   {hosts} hosts \u{b7} {exports} exports"
        ))),
        slots[i],
    );
    i += 1;

    if app.mode.runs_walker() {
        let dirs = st.dirs_walked.load(Relaxed);
        f.render_widget(
            Paragraph::new(Line::from(format!("  Walking     {dirs} dirs"))),
            slots[i],
        );
        i += 1;
    }
    if app.mode.runs_content_scan() {
        let files = st.files_content_scanned.load(Relaxed);
        let bytes = bytesize::ByteSize::b(st.bytes_read.load(Relaxed));
        f.render_widget(
            Paragraph::new(Line::from(format!(
                "  Scanning    {files} files \u{b7} {bytes}"
            ))),
            slots[i],
        );
    }
}

fn draw_feed(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.tally;
    let title = format!(
        " Findings {} \u{2014} \u{25a0} {} black \u{b7} \u{25a0} {} red \u{b7} \u{2593} {} yellow \u{b7} \u{2591} {} green ",
        t.total(),
        t.black,
        t.red,
        t.yellow,
        t.green
    );
    let block = Block::default().borders(Borders::TOP).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = inner.height as usize;
    let visible: Vec<_> = app.visible_findings().collect();
    // scroll_offset is tracked against the unfiltered feed; clamp it to the
    // filtered view so an active filter can never scroll the feed fully blank.
    let off = app.scroll_offset.min(visible.len().saturating_sub(1));
    let end = visible.len().saturating_sub(off);
    let start = end.saturating_sub(rows);
    let lines: Vec<Line> = visible[start..end]
        .iter()
        .map(|ev| {
            Line::from(vec![
                Span::styled(
                    format!("{} ", triage_word(ev.triage)),
                    triage_style(ev.triage),
                ),
                Span::raw(format!("{}:{}/{}", ev.host, ev.export_path, ev.file_path)),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn log_level_style(level: crate::tui::LogLevel) -> Style {
    use crate::tui::LogLevel::{Error, Warn};
    match level {
        Error => Style::default().fg(Color::Red),
        Warn => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::DarkGray),
    }
}

fn draw_log(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::TOP).title(" Log ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let rows = inner.height as usize;
    let start = app.logs.len().saturating_sub(rows);
    let lines: Vec<Line> = app
        .logs
        .iter()
        .skip(start)
        .map(|ev| Line::from(Span::styled(ev.message.clone(), log_level_style(ev.level))))
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    use crate::tui::app::FeedFilter;
    let filter = match app.filter {
        FeedFilter::All => "all",
        FeedFilter::Yellow => "yellow",
        FeedFilter::Red => "red",
        FeedFilter::Black => "black",
    };
    let pause = if app.autoscroll {
        "\u{25b6} live"
    } else {
        "\u{2389} paused"
    };
    let line = format!(
        " q quit \u{b7} \u{2191}\u{2193}/PgUp/PgDn scroll \u{b7} f filter:{filter} \u{b7} p {pause}"
    );
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            line,
            Style::default().fg(Color::DarkGray),
        ))),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OperatingMode;
    use crate::tui::FindingEvent;
    use chrono::Utc;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::atomic::Ordering::Relaxed;

    fn finding(host: &str, t: Triage) -> FindingEvent {
        FindingEvent {
            timestamp: Utc::now(),
            host: host.into(),
            export_path: "/exports/home".into(),
            file_path: "u1/.ssh/id_rsa".into(),
            triage: t,
            rule_name: "SshKey".into(),
            context: None,
            file_size: 1700,
            file_mode: 0o600,
            file_uid: 1001,
            last_modified: Utc::now(),
        }
    }

    fn buffer_text(backend: &TestBackend) -> String {
        let buf = backend.buffer();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn renders_header_phases_and_feed() {
        let mut app = App::new(OperatingMode::Scan);
        app.push_finding(finding("nfs01", Triage::Black));
        let stats = PipelineStats::default();
        stats.hosts_scanned.store(82, Relaxed);
        let mut term = Terminal::new(TestBackend::new(90, 30)).unwrap();
        term.draw(|f| {
            draw(
                f,
                &FrameCtx {
                    app: &app,
                    stats: &stats,
                    elapsed: Duration::from_secs(64),
                    target_label: "10.0.0.0/24",
                },
            );
        })
        .unwrap();
        let text = buffer_text(term.backend());
        assert!(text.contains("niffler"), "header: {text}");
        assert!(text.contains("Discovery"), "phase label missing");
        assert!(text.contains("nfs01"), "feed row missing");
        assert!(text.contains("BLACK"), "severity chip missing");
    }

    #[test]
    fn recon_mode_hides_scanning_phase() {
        let app = App::new(OperatingMode::Recon);
        let stats = PipelineStats::default();
        let mut term = Terminal::new(TestBackend::new(90, 30)).unwrap();
        term.draw(|f| {
            draw(
                f,
                &FrameCtx {
                    app: &app,
                    stats: &stats,
                    elapsed: Duration::from_secs(1),
                    target_label: "t",
                },
            );
        })
        .unwrap();
        let text = buffer_text(term.backend());
        assert!(text.contains("Discovery"));
        assert!(
            !text.contains("Scanning"),
            "recon should hide Scanning: {text}"
        );
    }
}
