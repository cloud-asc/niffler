use crate::nfs::types::{DirEntry, NfsExport};

/// Derive the NFSv4 export list from a `readdirplus` of the pseudo-root.
///
/// The common Linux layout is a pseudo-root (`fsid=0`) whose child directories
/// are the real exports, so each child directory becomes an export. When the
/// pseudo-root has no child directories — e.g. `fsid=0` set directly on a data
/// export, which is a valid layout — the root itself (`/`) is the scannable
/// export. `.`/`..` are never exports.
#[must_use]
pub fn exports_from_root_entries(entries: Vec<DirEntry>) -> Vec<NfsExport> {
    let child_dirs: Vec<NfsExport> = entries
        .into_iter()
        .filter(|e| e.attrs.is_directory() && e.name != "." && e.name != "..")
        .map(|e| NfsExport {
            path: format!("/{}", e.name),
            allowed_hosts: vec![],
        })
        .collect();

    if child_dirs.is_empty() {
        vec![NfsExport {
            path: "/".to_string(),
            allowed_hosts: vec![],
        }]
    } else {
        child_dirs
    }
}

pub async fn discover_v4_exports(host: &str) -> anyhow::Result<Vec<crate::nfs::types::NfsExport>> {
    use crate::nfs::auth::AuthCreds;
    use crate::nfs::connector::NfsConnector;
    use crate::nfs::v4::Nfs4Connector;

    let connector = Nfs4Connector::new();

    // Connect to pseudo-root with nobody credentials (least privilege)
    let mut ops = match connector.connect(host, "/", &AuthCreds::nobody()).await {
        Ok(ops) => ops,
        Err(e) => {
            tracing::debug!("NFSv4 pseudo-root connect failed for {}: {}", host, e);
            return Ok(vec![]);
        }
    };

    let root_fh = ops.root_handle().clone();
    let entries = match ops.readdirplus(&root_fh).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!("NFSv4 pseudo-root readdirplus failed for {}: {}", host, e);
            return Ok(vec![]);
        }
    };

    Ok(exports_from_root_entries(entries))
}

#[cfg(test)]
mod tests {
    use super::exports_from_root_entries;
    use crate::nfs::types::{DirEntry, NfsAttrs, NfsFh, NfsFileType};

    fn entry(name: &str, file_type: NfsFileType) -> DirEntry {
        DirEntry {
            name: name.to_string(),
            fh: NfsFh::new(vec![0, 0, 1]),
            attrs: NfsAttrs {
                file_type,
                size: 0,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        }
    }

    #[test]
    fn child_directories_become_exports() {
        let entries = vec![
            entry("data", NfsFileType::Directory),
            entry("home", NfsFileType::Directory),
            entry("readme.txt", NfsFileType::Regular),
        ];
        let exports = exports_from_root_entries(entries);
        assert_eq!(exports.len(), 2, "only directories, not the file");
        assert!(exports.iter().any(|e| e.path == "/data"));
        assert!(exports.iter().any(|e| e.path == "/home"));
    }

    #[test]
    fn dot_entries_are_not_exports() {
        let entries = vec![
            entry(".", NfsFileType::Directory),
            entry("..", NfsFileType::Directory),
            entry("share", NfsFileType::Directory),
        ];
        let exports = exports_from_root_entries(entries);
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].path, "/share");
    }

    #[test]
    fn no_child_dirs_falls_back_to_pseudo_root() {
        // fsid=0 set directly on a data export: the pseudo-root holds files (or is
        // empty), so the root itself must be the scannable export.
        let entries = vec![entry(".env", NfsFileType::Regular)];
        let exports = exports_from_root_entries(entries);
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].path, "/");
    }

    #[test]
    fn empty_root_falls_back_to_pseudo_root() {
        let exports = exports_from_root_entries(vec![]);
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].path, "/");
    }

    #[tokio::test]
    #[ignore = "requires NFSv4 server — set NFS_TEST_HOST"]
    async fn nfs4_pseudo_root_discovers_exports() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let exports = super::discover_v4_exports(&host)
            .await
            .expect("discover failed");
        assert!(!exports.is_empty(), "expected at least one export");
        for export in &exports {
            println!("discovered export: {}", export.path);
        }
    }
}
