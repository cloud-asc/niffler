use std::io::{self, Write};

use crate::web::db::Finding;

/// Write findings as JSON lines (one JSON object per line).
///
/// Empty input produces no output.
pub fn export_json(findings: &[Finding], writer: &mut dyn Write) -> io::Result<()> {
    for finding in findings {
        serde_json::to_writer(&mut *writer, finding).map_err(io::Error::other)?;
        writeln!(writer)?;
    }
    Ok(())
}

/// Write findings as CSV with a header row.
///
/// Empty input produces the header row only.
pub fn export_csv(findings: &[Finding], writer: &mut dyn Write) -> io::Result<()> {
    let mut wtr = csv::WriterBuilder::new().from_writer(writer);
    wtr.write_record([
        "timestamp",
        "triage",
        "host",
        "export_path",
        "file_path",
        "rule_name",
        "matched_pattern",
        "context",
        "file_size",
        "file_mode",
        "file_uid",
        "file_gid",
        "last_modified",
    ])
    .map_err(csv_to_io)?;
    for f in findings {
        wtr.write_record([
            f.timestamp.as_str(),
            f.triage.as_str(),
            f.host.as_str(),
            f.export_path.as_str(),
            f.file_path.as_str(),
            f.rule_name.as_str(),
            f.matched_pattern.as_str(),
            f.context.as_deref().unwrap_or(""),
            &f.file_size.to_string(),
            &f.file_mode.to_string(),
            &f.file_uid.to_string(),
            &f.file_gid.to_string(),
            f.last_modified.as_str(),
        ])
        .map_err(csv_to_io)?;
    }
    wtr.flush()?;
    Ok(())
}

/// Write findings as Snaffler-compatible TSV (no header, tab-delimited).
///
/// Empty input produces no output.
pub fn export_tsv(findings: &[Finding], writer: &mut dyn Write) -> io::Result<()> {
    for f in findings {
        writeln!(
            writer,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            escape_tsv(&f.timestamp),
            escape_tsv(&f.triage),
            escape_tsv(&f.host),
            escape_tsv(&f.export_path),
            escape_tsv(&f.file_path),
            escape_tsv(&f.rule_name),
            escape_tsv(&f.matched_pattern),
            escape_tsv(f.context.as_deref().unwrap_or("")),
            f.file_size,
            f.file_mode,
            f.file_uid,
            f.file_gid,
            escape_tsv(&f.last_modified),
        )?;
    }
    Ok(())
}

/// Write findings as a paste-ready Markdown report, grouped by severity
/// (Black → Red → Yellow → Green). Empty severities are omitted. With no
/// findings at all, emits the title and a "No findings" line.
pub fn export_markdown(findings: &[Finding], writer: &mut dyn Write) -> io::Result<()> {
    writeln!(writer, "# Niffler Findings Report")?;
    writeln!(writer)?;

    if findings.is_empty() {
        writeln!(writer, "No findings.")?;
        return Ok(());
    }

    for sev in ["Black", "Red", "Yellow", "Green"] {
        let group: Vec<&Finding> = findings.iter().filter(|f| f.triage == sev).collect();
        if group.is_empty() {
            continue;
        }
        writeln!(writer, "## {sev} ({})", group.len())?;
        writeln!(writer)?;
        for f in group {
            writeln!(
                writer,
                "- **{}**:`{}` — {} — `{}`",
                f.host,
                escape_md_code(&f.file_path),
                f.rule_name,
                escape_md_code(&f.matched_pattern)
            )?;
        }
        writeln!(writer)?;
    }
    Ok(())
}

/// Replace backticks so a value can sit safely inside a Markdown code span.
fn escape_md_code(s: &str) -> String {
    s.replace('`', "'")
}

/// Escape characters that break TSV line/column boundaries.
fn escape_tsv(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn csv_to_io(e: csv::Error) -> io::Error {
    io::Error::other(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::db::Finding;

    fn make_finding(id: i64, host: &str, triage: &str, rule: &str, file: &str) -> Finding {
        Finding {
            id,
            scan_id: 1,
            timestamp: "2025-01-15T10:30:00+00:00".to_string(),
            host: host.to_string(),
            export_path: "/exports/home".to_string(),
            file_path: file.to_string(),
            triage: triage.to_string(),
            rule_name: rule.to_string(),
            matched_pattern: "test_pattern".to_string(),
            context: Some("matched content".to_string()),
            file_size: 1024,
            file_mode: 0o644,
            file_uid: 1000,
            file_gid: 1000,
            last_modified: "2025-01-15T09:00:00+00:00".to_string(),
            starred: false,
            reviewed: false,
        }
    }

    fn sample_findings() -> Vec<Finding> {
        vec![
            make_finding(1, "10.0.0.1", "Black", "SSHKey", "/home/.ssh/id_rsa"),
            make_finding(2, "10.0.0.1", "Red", "EnvFile", "/home/.env"),
            make_finding(3, "10.0.0.2", "Green", "InfoFile", "/share/readme.txt"),
        ]
    }

    #[test]
    fn test_export_json_lines() {
        let findings = sample_findings();
        let mut buf = Vec::new();
        export_json(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3, "one JSON line per finding");
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.is_object());
            assert!(parsed.get("host").is_some());
            assert!(parsed.get("triage").is_some());
            assert!(parsed.get("file_path").is_some());
        }
    }

    #[test]
    fn test_export_json_contains_all_fields() {
        let findings = vec![make_finding(1, "10.0.0.1", "Black", "SSHKey", "/id_rsa")];
        let mut buf = Vec::new();
        export_json(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        for field in [
            "id",
            "scan_id",
            "timestamp",
            "host",
            "export_path",
            "file_path",
            "triage",
            "rule_name",
            "matched_pattern",
            "context",
            "file_size",
            "file_mode",
            "file_uid",
            "file_gid",
            "last_modified",
        ] {
            assert!(parsed.get(field).is_some(), "missing field: {field}");
        }
    }

    #[test]
    fn test_export_csv_headers() {
        let findings = sample_findings();
        let mut buf = Vec::new();
        export_csv(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let first_line = output.lines().next().unwrap();
        for col in [
            "timestamp",
            "triage",
            "host",
            "export_path",
            "file_path",
            "rule_name",
            "matched_pattern",
            "context",
            "file_size",
            "file_mode",
            "file_uid",
            "file_gid",
            "last_modified",
        ] {
            assert!(first_line.contains(col), "header missing: {col}");
        }
    }

    #[test]
    fn test_export_csv_rows_match_data() {
        let findings = vec![make_finding(1, "10.0.0.1", "Black", "SSHKey", "/id_rsa")];
        let mut buf = Vec::new();
        export_csv(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let data_line = output.lines().nth(1).unwrap();
        assert!(data_line.contains("10.0.0.1"));
        assert!(data_line.contains("Black"));
        assert!(data_line.contains("SSHKey"));
        assert!(data_line.contains("/id_rsa"));
    }

    #[test]
    fn test_export_tsv_tab_delimited() {
        let findings = sample_findings();
        let mut buf = Vec::new();
        export_tsv(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        for line in output.lines() {
            assert!(line.contains('\t'), "TSV line should contain tabs");
        }
    }

    #[test]
    fn test_export_tsv_snaffler_compat() {
        let findings = vec![make_finding(1, "10.0.0.1", "Black", "SSHKey", "/id_rsa")];
        let mut buf = Vec::new();
        export_tsv(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let line = output.lines().next().unwrap();
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 13, "TSV should have 13 fields");
        assert!(fields.contains(&"10.0.0.1"), "should contain host");
        assert!(fields.contains(&"Black"), "should contain triage");
        assert!(fields.contains(&"SSHKey"), "should contain rule");
    }

    #[test]
    fn test_export_json_empty() {
        let findings: Vec<Finding> = vec![];
        let mut buf = Vec::new();
        export_json(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.is_empty(), "empty findings should produce no output");
    }

    #[test]
    fn test_export_csv_empty_has_header_only() {
        let findings: Vec<Finding> = vec![];
        let mut buf = Vec::new();
        export_csv(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let line_count = output.lines().count();
        assert_eq!(line_count, 1, "empty findings should produce header only");
    }

    #[test]
    fn test_export_tsv_empty() {
        let findings: Vec<Finding> = vec![];
        let mut buf = Vec::new();
        export_tsv(&findings, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.is_empty(), "empty TSV should produce no output");
    }

    #[test]
    fn test_export_tsv_multiline_context() {
        let mut f = make_finding(1, "10.0.0.1", "Red", "EnvFile", "/home/.env");
        f.context = Some("line1\nline2\nline3".to_string());
        let mut buf = Vec::new();
        export_tsv(&[f], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "multiline context must not split into multiple lines"
        );
        let fields: Vec<&str> = lines[0].split('\t').collect();
        assert_eq!(fields.len(), 13, "should have 13 tab-separated fields");
        assert_eq!(fields[7], "line1\\nline2\\nline3");
    }

    #[test]
    fn test_export_tsv_tabs_in_context() {
        let mut f = make_finding(1, "10.0.0.1", "Red", "EnvFile", "/home/.env");
        f.context = Some("key\tvalue".to_string());
        let mut buf = Vec::new();
        export_tsv(&[f], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.lines().next().unwrap().split('\t').collect();
        assert_eq!(
            fields.len(),
            13,
            "tabs in context must be escaped, not treated as delimiters"
        );
        assert_eq!(fields[7], "key\\tvalue");
    }

    #[test]
    fn test_export_tsv_backslash_in_context() {
        let mut f = make_finding(1, "10.0.0.1", "Red", "EnvFile", "/home/.env");
        f.context = Some("path\\to\\file".to_string());
        let mut buf = Vec::new();
        export_tsv(&[f], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.lines().next().unwrap().split('\t').collect();
        assert_eq!(
            fields[7], "path\\\\to\\\\file",
            "backslashes must be escaped for round-trip safety"
        );
    }

    #[test]
    fn test_export_markdown_groups_by_severity() {
        let findings = sample_findings(); // Black, Red, Green (one each)
        let mut buf = Vec::new();
        export_markdown(&findings, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("# Niffler Findings Report"), "has a title");
        assert!(out.contains("## Black (1)"), "Black section with count");
        assert!(out.contains("## Red (1)"), "Red section with count");
        assert!(out.contains("## Green (1)"), "Green section with count");
        assert!(!out.contains("## Yellow"), "empty severities are omitted");
        let pb = out.find("## Black").unwrap();
        let pr = out.find("## Red").unwrap();
        let pg = out.find("## Green").unwrap();
        assert!(pb < pr && pr < pg, "sections ordered Black→Red→Green");
    }

    #[test]
    fn test_export_markdown_finding_line() {
        let findings = vec![make_finding(
            1,
            "10.0.0.5",
            "Black",
            "aws_keys",
            "/home/.aws/credentials",
        )];
        let mut buf = Vec::new();
        export_markdown(&findings, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("10.0.0.5"), "names the host");
        assert!(out.contains("/home/.aws/credentials"), "names the path");
        assert!(out.contains("aws_keys"), "names the rule");
        assert!(out.contains("test_pattern"), "shows the matched pattern");
    }

    #[test]
    fn test_export_markdown_empty() {
        let findings: Vec<Finding> = vec![];
        let mut buf = Vec::new();
        export_markdown(&findings, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("# Niffler Findings Report"),
            "title still present"
        );
        assert!(out.contains("No findings"), "states there are no findings");
    }

    #[test]
    fn test_export_markdown_escapes_backtick_in_path() {
        let mut f = make_finding(1, "10.0.0.1", "Black", "rule", "/tmp/od`d");
        f.matched_pattern = "se`cret".to_string();
        let mut buf = Vec::new();
        export_markdown(&[f], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("od`d"), "backtick in path must be escaped");
        assert!(
            !out.contains("se`cret"),
            "backtick in pattern must be escaped"
        );
        assert!(
            out.contains("od'd") && out.contains("se'cret"),
            "replaced with single-quote"
        );
    }

    #[test]
    fn finding_deserializes_from_exported_json() {
        let findings = vec![make_finding(1, "10.0.0.1", "Black", "SSHKey", "/id_rsa")];
        let mut buf = Vec::new();
        export_json(&findings, &mut buf).unwrap();
        let line = String::from_utf8(buf).unwrap();
        let parsed: crate::web::db::Finding =
            serde_json::from_str(line.trim()).expect("Finding must deserialize from its own JSON");
        assert_eq!(parsed.host, "10.0.0.1");
        assert_eq!(parsed.triage, "Black");
        assert_eq!(parsed.rule_name, "SSHKey");
    }
}
