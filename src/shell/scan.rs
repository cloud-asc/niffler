//! Helpers for the classifier shell commands: building `FileEntry`s, formatting
//! findings, and a bounded iterative tree walk.

use crate::classifier::{FileEntry, Triage};
use crate::nfs::{NfsAttrs, NfsFh};
use crate::shell::session::Session;
use colored::Colorize;

/// Max directory depth a `scan`/`find` walk descends.
pub const SCAN_MAX_DEPTH: usize = 20;
/// Max files a single `scan`/`find` walk will visit (interactive safety cap).
pub const SCAN_MAX_FILES: usize = 20_000;
/// Max bytes read from a file for content matching.
pub const SCAN_MAX_FILE_SIZE: u64 = 1 << 20; // 1 MiB

/// Build a classifier `FileEntry` from a filename, absolute path, and attrs.
pub fn file_entry(name: &str, path: &str, attrs: &NfsAttrs) -> FileEntry {
    let extension = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();
    FileEntry {
        name: name.to_string(),
        path: path.to_string(),
        extension,
        size: attrs.size,
        uid: attrs.uid,
        gid: attrs.gid,
        mode: attrs.mode,
    }
}

fn triage_tag(t: Triage, color: bool) -> String {
    let word = match t {
        Triage::Black => "BLACK",
        Triage::Red => "RED",
        Triage::Yellow => "YELLOW",
        Triage::Green => "GREEN",
    };
    if !color {
        return word.to_string();
    }
    match t {
        Triage::Black => word.bright_red().bold().to_string(),
        Triage::Red => word.red().to_string(),
        Triage::Yellow => word.yellow().to_string(),
        Triage::Green => word.green().to_string(),
    }
}

/// Format one finding line: `<TRIAGE>  <path>  [<rule>] <pattern>`.
pub fn format_finding(
    triage: Triage,
    path: &str,
    rule: &str,
    matched: &str,
    color: bool,
) -> String {
    format!(
        "{}  {}  [{}] {}",
        triage_tag(triage, color),
        path,
        rule,
        matched
    )
}

/// A file discovered by the walk: its handle, attrs, and absolute display path.
pub struct WalkedFile {
    pub fh: NfsFh,
    pub attrs: NfsAttrs,
    pub path: String,
}

/// Walk the subtree rooted at (`start_fh`, `start_path`), returning regular
/// files (bounded by depth and count). Directories the classifier flags as junk
/// (`should_discard_dir`) are pruned. Symlinks are not followed.
pub async fn collect_files(
    session: &mut Session,
    start_fh: NfsFh,
    start_path: String,
    engine: &crate::classifier::RuleEngine,
) -> anyhow::Result<Vec<WalkedFile>> {
    let mut files = Vec::new();
    let mut queue: std::collections::VecDeque<(NfsFh, String, usize)> =
        std::collections::VecDeque::new();
    queue.push_back((start_fh, start_path, 0));

    while let Some((dir_fh, dir_path, depth)) = queue.pop_front() {
        if files.len() >= SCAN_MAX_FILES {
            break;
        }
        let entries = match session.list_handle(&dir_fh).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries {
            let child_path = format!("{}/{}", dir_path.trim_end_matches('/'), entry.name);
            if entry.attrs.is_directory() {
                if depth < SCAN_MAX_DEPTH && !engine.should_discard_dir(&entry.name, &child_path) {
                    queue.push_back((entry.fh, child_path, depth + 1));
                }
            } else if entry.attrs.is_file() {
                files.push(WalkedFile {
                    fh: entry.fh,
                    attrs: entry.attrs,
                    path: child_path,
                });
                if files.len() >= SCAN_MAX_FILES {
                    break;
                }
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{AuthCreds, ConnectorFactory, DirEntry, NfsFileType, NfsVersion};
    use std::sync::Arc;

    fn attrs() -> NfsAttrs {
        NfsAttrs {
            file_type: NfsFileType::Regular,
            size: 7,
            mode: 0o600,
            uid: 5,
            gid: 6,
            mtime: 0,
        }
    }

    #[test]
    fn file_entry_extracts_extension() {
        let e = file_entry("creds.env", "/a/creds.env", &attrs());
        assert_eq!(e.name, "creds.env");
        assert_eq!(e.path, "/a/creds.env");
        assert_eq!(e.extension, "env");
        assert_eq!(e.size, 7);
        assert_eq!(e.uid, 5);
    }

    #[test]
    fn file_entry_no_extension() {
        assert_eq!(file_entry("id_rsa", "/a/id_rsa", &attrs()).extension, "");
    }

    #[test]
    fn format_finding_plain_contains_fields() {
        let line = format_finding(Triage::Red, "/a/b.env", "DotEnv", "password=", false);
        assert!(line.contains("RED"));
        assert!(line.contains("/a/b.env"));
        assert!(line.contains("DotEnv"));
        assert!(line.contains("password="));
    }

    #[tokio::test]
    async fn collect_files_walks_subtree() {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_readdirplus().returning(|dir| {
                if dir.as_bytes() == [0] {
                    Ok(vec![
                        DirEntry {
                            name: "top.txt".into(),
                            fh: NfsFh::new(vec![1]),
                            attrs: NfsAttrs {
                                file_type: NfsFileType::Regular,
                                size: 1,
                                mode: 0o644,
                                uid: 0,
                                gid: 0,
                                mtime: 0,
                            },
                        },
                        DirEntry {
                            name: "sub".into(),
                            fh: NfsFh::new(vec![2]),
                            attrs: NfsAttrs {
                                file_type: NfsFileType::Directory,
                                size: 0,
                                mode: 0o755,
                                uid: 0,
                                gid: 0,
                                mtime: 0,
                            },
                        },
                    ])
                } else {
                    Ok(vec![DirEntry {
                        name: "deep.txt".into(),
                        fh: NfsFh::new(vec![3]),
                        attrs: NfsAttrs {
                            file_type: NfsFileType::Regular,
                            size: 1,
                            mode: 0o644,
                            uid: 0,
                            gid: 0,
                            mtime: 0,
                        },
                    }])
                }
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        let engine = crate::classifier::RuleEngine::compile(
            crate::classifier::defaults::load_embedded_defaults().unwrap(),
        )
        .unwrap();
        let root = s.cwd_handle().unwrap().clone();
        let files = collect_files(&mut s, root, "/".into(), &engine)
            .await
            .unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"/top.txt"));
        assert!(paths.contains(&"/sub/deep.txt"));
    }
}
