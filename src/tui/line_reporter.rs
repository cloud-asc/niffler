//! Plain line-mode finding output (non-TTY / `--plain`).

use std::io::Write;

use bytesize::ByteSize;
use colored::Colorize;

use crate::classifier::Triage;
use crate::output::file_mode_to_rwx;
use crate::tui::FindingEvent;

fn severity_word(t: Triage) -> &'static str {
    match t {
        Triage::Black => "BLACK",
        Triage::Red => "RED  ",
        Triage::Yellow => "YELLO",
        Triage::Green => "GREEN",
    }
}

fn colorize(word: &str, t: Triage) -> String {
    match t {
        Triage::Black => word.bright_red().bold().to_string(),
        Triage::Red => word.red().to_string(),
        Triage::Yellow => word.yellow().to_string(),
        Triage::Green => word.green().to_string(),
    }
}

/// One line per finding. `color` enables ANSI styling on the severity word.
#[must_use]
pub fn format_finding_line(ev: &FindingEvent, color: bool) -> String {
    let word_plain = severity_word(ev.triage);
    let word = if color {
        colorize(word_plain, ev.triage)
    } else {
        word_plain.to_string()
    };
    let size = ByteSize::b(ev.file_size);
    let perms = file_mode_to_rwx(ev.file_mode);
    let date = ev.last_modified.format("%Y-%m-%d");
    let base = format!(
        "{word}  {}:{}/{}  ({size}, {perms}, uid:{}, {date})",
        ev.host, ev.export_path, ev.file_path, ev.file_uid
    );
    match &ev.context {
        Some(c) => format!("{base}  {c}"),
        None => base,
    }
}

/// Writes findings as plain lines to a writer (stdout in production).
pub struct LineReporter<W: Write> {
    writer: W,
    color: bool,
}

impl<W: Write> LineReporter<W> {
    #[must_use]
    pub fn new(writer: W, color: bool) -> Self {
        Self { writer, color }
    }

    /// Print a finding line; I/O errors (e.g. broken pipe) are swallowed.
    pub fn finding(&mut self, ev: &FindingEvent) {
        let line = format_finding_line(ev, self.color);
        let _ = writeln!(self.writer, "{line}");
        let _ = self.writer.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Triage;
    use chrono::TimeZone;
    use chrono::Utc;

    fn finding(t: Triage, ctx: Option<&str>) -> FindingEvent {
        FindingEvent {
            timestamp: Utc::now(),
            host: "nfs01".into(),
            export_path: "/home".into(),
            file_path: "u1/.ssh/id_rsa".into(),
            triage: t,
            rule_name: "SshKey".into(),
            context: ctx.map(String::from),
            file_size: 1700,
            file_mode: 0o600,
            file_uid: 1001,
            last_modified: Utc.with_ymd_and_hms(2025, 11, 3, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn formats_black_no_context() {
        let s = format_finding_line(&finding(Triage::Black, None), false);
        assert!(s.starts_with("BLACK"), "line: {s}");
        assert!(s.contains("nfs01:/home/u1/.ssh/id_rsa"));
        assert!(s.contains("uid:1001"));
        assert!(s.contains("2025-11-03"));
        assert!(!s.contains('\n'), "no context -> single line");
    }

    #[test]
    fn formats_red_with_inline_context() {
        let s = format_finding_line(&finding(Triage::Red, Some("DB_PASSWORD=x")), false);
        assert!(s.starts_with("RED"));
        assert!(s.contains("DB_PASSWORD=x"), "context inline: {s}");
    }

    #[test]
    fn no_color_has_no_ansi() {
        let s = format_finding_line(&finding(Triage::Black, None), false);
        assert!(
            !s.contains('\u{1b}'),
            "plain output must have no ANSI escapes"
        );
    }
}
