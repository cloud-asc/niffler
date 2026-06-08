//! Interactive session state: the live connection, credentials, and cwd.

use crate::nfs::{
    AuthCreds, ConnectorFactory, DirEntry, NfsAttrs, NfsError, NfsFh, NfsOps, NfsVersion,
};

/// Compute a new display path from the current one and a single `cd` argument.
pub fn join_display_path(current: &str, arg: &str) -> String {
    if arg.starts_with('/') {
        return normalize(arg);
    }
    let mut parts: Vec<&str> = current.split('/').filter(|s| !s.is_empty()).collect();
    for comp in arg.split('/').filter(|s| !s.is_empty()) {
        match comp {
            "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Append a relative `arg` onto a handle-rooted display path (`<handle>...`),
/// resolving `.`/`..` in string space without ever popping the `<handle>` anchor.
pub fn join_handle_path(current: &str, arg: &str) -> String {
    let mut parts: Vec<&str> = current.split('/').filter(|s| !s.is_empty()).collect();
    for comp in arg.split('/').filter(|s| !s.is_empty()) {
        match comp {
            "." => {}
            ".." => {
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// Read an entire file from `ops` in `chunk`-byte reads, preserving the raw NFS
/// error so callers can detect `PermissionDenied` for UID cycling.
async fn read_all_from(
    ops: &mut Box<dyn NfsOps>,
    fh: &NfsFh,
    chunk: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = Vec::new();
    let mut offset: u64 = 0;
    loop {
        let res = ops.read(fh, offset, chunk).await?;
        let n = res.data.len() as u64;
        out.extend_from_slice(&res.data);
        offset += n;
        if res.eof || n == 0 {
            break;
        }
    }
    Ok(out)
}

fn normalize(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for p in path.split('/').filter(|s| !s.is_empty() && *s != ".") {
        if p == ".." {
            out.pop();
        } else {
            out.push(p);
        }
    }
    if out.is_empty() {
        "/".into()
    } else {
        format!("/{}", out.join("/"))
    }
}

/// Live interactive session.
pub struct Session {
    factory: ConnectorFactory,
    creds: AuthCreds,
    version: NfsVersion,
    host: Option<String>,
    export: Option<String>,
    conn: Option<Box<dyn NfsOps>>,
    cwd_handle: Option<NfsFh>,
    cwd_path: String,
    local_dir: std::path::PathBuf,
    harvested: Vec<AuthCreds>,
    auto_cycle: bool,
    classifier: Option<std::sync::Arc<crate::classifier::RuleEngine>>,
    db_path: Option<std::path::PathBuf>,
    writer: Option<crate::output::SqliteWriter>,
}

impl Session {
    pub fn new(factory: ConnectorFactory, creds: AuthCreds, version: NfsVersion) -> Self {
        Self {
            factory,
            creds,
            version,
            host: None,
            export: None,
            conn: None,
            cwd_handle: None,
            cwd_path: "/".to_string(),
            local_dir: std::env::current_dir().unwrap_or_else(|_| ".".into()),
            harvested: Vec::new(),
            auto_cycle: false,
            classifier: None,
            db_path: None,
            writer: None,
        }
    }

    pub fn set_host(&mut self, host: String) {
        self.host = Some(host);
    }
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
    pub fn export(&self) -> Option<&str> {
        self.export.as_deref()
    }
    pub fn creds(&self) -> &AuthCreds {
        &self.creds
    }
    pub fn version(&self) -> NfsVersion {
        self.version
    }
    pub fn set_version(&mut self, v: NfsVersion) {
        self.version = v;
    }
    pub fn cwd_path(&self) -> &str {
        &self.cwd_path
    }
    pub fn cwd_handle(&self) -> Option<&NfsFh> {
        self.cwd_handle.as_ref()
    }
    pub fn is_connected(&self) -> bool {
        self.conn.is_some()
    }
    pub fn local_dir(&self) -> &std::path::Path {
        &self.local_dir
    }
    pub fn set_local_dir(&mut self, dir: std::path::PathBuf) {
        self.local_dir = dir;
    }

    pub fn harvested(&self) -> &[AuthCreds] {
        &self.harvested
    }
    pub fn auto_cycle(&self) -> bool {
        self.auto_cycle
    }
    pub fn set_auto_cycle(&mut self, on: bool) {
        self.auto_cycle = on;
    }
    pub fn classifier(&self) -> Option<&std::sync::Arc<crate::classifier::RuleEngine>> {
        self.classifier.as_ref()
    }
    pub fn set_classifier(&mut self, engine: std::sync::Arc<crate::classifier::RuleEngine>) {
        self.classifier = Some(engine);
    }
    pub fn db_path(&self) -> Option<&std::path::Path> {
        self.db_path.as_deref()
    }
    pub fn set_db_path(&mut self, path: std::path::PathBuf) {
        self.db_path = Some(path);
    }

    /// Lazily open the snaffle SQLite writer (scan session "shell") and record
    /// the given result rows. Requires a db path.
    pub async fn record_findings(
        &mut self,
        msgs: &[crate::pipeline::ResultMsg],
    ) -> anyhow::Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        if self.writer.is_none() {
            let path = self
                .db_path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no db path set"))?;
            let host = self.host.clone().unwrap_or_else(|| "shell".to_string());
            let w = crate::output::SqliteWriter::new(&path, &[host], "shell").await?;
            self.writer = Some(w);
        }
        let w = self.writer.as_ref().expect("writer set above");
        for msg in msgs {
            w.write(msg).await?;
        }
        Ok(())
    }

    /// Finalize the snaffle writer (rebuild FTS, mark scan complete). No-op if
    /// nothing was recorded. Call on shell exit.
    pub async fn finish_recording(&mut self) -> anyhow::Result<()> {
        if let Some(w) = self.writer.take() {
            w.finish(&crate::pipeline::PipelineStats::default()).await?;
        }
        Ok(())
    }

    /// Merge new harvested creds, de-duplicating against existing ones.
    pub fn add_harvested(&mut self, creds: Vec<AuthCreds>) {
        for c in creds {
            if !self.harvested.contains(&c) {
                self.harvested.push(c);
            }
        }
    }
    /// Open a one-off connection to the current export as `creds`, WITHOUT
    /// touching the live session connection or cwd. NFS handles from the live
    /// connection are valid here (handles are connection-independent).
    pub async fn connect_as(&self, creds: &AuthCreds) -> anyhow::Result<Box<dyn NfsOps>> {
        let host = self
            .host
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no host set"))?;
        let export = self
            .export
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("not mounted"))?;
        self.factory
            .get(self.version)
            .connect(host, export, creds)
            .await
            .map_err(|e| anyhow::anyhow!("connect failed: {e}"))
    }

    pub fn ops(&mut self) -> anyhow::Result<&mut Box<dyn NfsOps>> {
        self.conn
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not connected — use `mount <export>` first"))
    }

    /// List a directory given its handle directly (used by recursive walks).
    pub async fn list_handle(&mut self, dir: &NfsFh) -> anyhow::Result<Vec<DirEntry>> {
        self.ops()?
            .readdirplus(dir)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn connect_only(&mut self, export: &str) -> anyhow::Result<Box<dyn NfsOps>> {
        let host = self
            .host
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no host set — use `open <host>` first"))?;
        self.factory
            .get(self.version)
            .connect(&host, export, &self.creds)
            .await
            .map_err(|e| anyhow::anyhow!("mount failed: {e}"))
    }

    pub async fn mount(&mut self, export: &str) -> anyhow::Result<()> {
        let ops = self.connect_only(export).await?;
        self.cwd_handle = Some(ops.root_handle().clone());
        self.cwd_path = "/".to_string();
        self.export = Some(export.to_string());
        self.conn = Some(ops);
        Ok(())
    }

    pub fn umount(&mut self) {
        self.conn = None;
        self.cwd_handle = None;
        self.cwd_path = "/".to_string();
        self.export = None;
    }

    /// Re-establish the connection after a credential change, PRESERVING cwd.
    /// NFS file handles are connection-independent (v3 opaque + v4 path alike),
    /// so the current directory — even one reached via a raw `handle` — carries
    /// over to the new identity.
    async fn reconnect(&mut self) -> anyhow::Result<()> {
        let export = self
            .export
            .clone()
            .ok_or_else(|| anyhow::anyhow!("nothing mounted to reconnect"))?;
        let ops = self.connect_only(&export).await?;
        self.conn = Some(ops);
        Ok(())
    }

    /// Walk path components from `start`, returning the final (handle, attrs).
    /// `.` is skipped; names go through LOOKUP. Does not enforce dir-ness.
    /// `getattr` is called on `start` only when there are no components to walk.
    async fn walk(
        &mut self,
        start: NfsFh,
        comps: Vec<String>,
    ) -> anyhow::Result<(NfsFh, NfsAttrs)> {
        let mut handle = start;
        let mut last_attrs: Option<NfsAttrs> = None;
        for comp in comps {
            if comp == "." {
                continue;
            }
            let (fh, at) = self
                .ops()?
                .lookup(&handle, &comp)
                .await
                .map_err(|e| anyhow::anyhow!("{comp}: {e}"))?;
            handle = fh;
            last_attrs = Some(at);
        }
        let attrs = match last_attrs {
            Some(a) => a,
            None => self
                .ops()?
                .getattr(&handle)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        };
        Ok((handle, attrs))
    }

    /// Choose the walk anchor (root vs cwd_handle), the components to walk, and
    /// the resulting display path for `arg`.
    fn plan_walk(&mut self, arg: &str) -> anyhow::Result<(NfsFh, Vec<String>, String)> {
        let split = |s: &str| -> Vec<String> {
            s.split('/')
                .filter(|c| !c.is_empty())
                .map(|c| c.to_string())
                .collect()
        };
        if arg.starts_with('/') {
            let abs = normalize(arg);
            Ok((self.ops()?.root_handle().clone(), split(&abs), abs))
        } else if self.cwd_path.starts_with('/') {
            let abs = join_display_path(&self.cwd_path, arg);
            Ok((self.ops()?.root_handle().clone(), split(&abs), abs))
        } else {
            let start = self
                .cwd_handle
                .clone()
                .ok_or_else(|| anyhow::anyhow!("not connected"))?;
            let disp = join_handle_path(&self.cwd_path, arg);
            Ok((start, split(arg), disp))
        }
    }

    pub async fn cd(&mut self, arg: &str) -> anyhow::Result<()> {
        if !self.is_connected() {
            anyhow::bail!("not connected — use `mount <export>` first");
        }
        let (start, comps, disp) = self.plan_walk(arg)?;
        let (handle, attrs) = self.walk(start, comps).await?;
        if !attrs.is_directory() {
            anyhow::bail!("{arg}: not a directory");
        }
        self.cwd_handle = Some(handle);
        self.cwd_path = disp;
        Ok(())
    }

    pub async fn resolve(&mut self, arg: &str) -> anyhow::Result<(NfsFh, NfsAttrs)> {
        let (start, comps, _disp) = self.plan_walk(arg)?;
        self.walk(start, comps).await
    }

    pub async fn list(&mut self, sub: Option<&str>) -> anyhow::Result<Vec<DirEntry>> {
        let dir = match sub {
            None => self
                .cwd_handle
                .clone()
                .ok_or_else(|| anyhow::anyhow!("not connected"))?,
            Some(p) => {
                let (fh, at) = self.resolve(p).await?;
                if !at.is_directory() {
                    anyhow::bail!("{p}: not a directory");
                }
                fh
            }
        };
        self.ops()?
            .readdirplus(&dir)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub async fn set_handle(&mut self, fh: NfsFh) -> anyhow::Result<()> {
        let attrs = self
            .ops()?
            .getattr(&fh)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if !attrs.is_directory() {
            anyhow::bail!("handle does not refer to a directory");
        }
        self.cwd_handle = Some(fh);
        self.cwd_path = "<handle>".to_string();
        Ok(())
    }

    /// Read an entire file by streaming `chunk`-byte reads until EOF.
    pub async fn read_all(&mut self, fh: &NfsFh, chunk: u32) -> anyhow::Result<Vec<u8>> {
        read_all_from(self.ops()?, fh, chunk)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Read a whole file, cycling through alternate credentials on a
    /// permission-denied error when auto-cycle is enabled. Candidate order:
    /// the file owner (if `owner` is given), then harvested creds. Returns the
    /// data and the credentials that succeeded (`None` = the primary worked).
    pub async fn read_all_auto(
        &mut self,
        fh: &NfsFh,
        chunk: u32,
        owner: Option<(u32, u32)>,
    ) -> anyhow::Result<(Vec<u8>, Option<AuthCreds>)> {
        match read_all_from(self.ops()?, fh, chunk).await {
            Ok(data) => return Ok((data, None)),
            Err(e) => {
                let denied = e
                    .downcast_ref::<NfsError>()
                    .is_some_and(NfsError::is_permission_denied);
                if !denied || !self.auto_cycle {
                    return Err(anyhow::anyhow!("{e}"));
                }
            }
        }

        let mut candidates: Vec<AuthCreds> = Vec::new();
        if let Some((u, g)) = owner {
            candidates.push(AuthCreds::new(u, g));
        }
        candidates.extend(self.harvested.iter().cloned());

        let mut tried = 0usize;
        for cred in candidates {
            if cred == self.creds {
                continue;
            }
            tried += 1;
            if let Ok(mut ops) = self.connect_as(&cred).await
                && let Ok(data) = read_all_from(&mut ops, fh, chunk).await
            {
                return Ok((data, Some(cred)));
            }
        }
        anyhow::bail!("permission denied (tried {tried} alternate credential(s))")
    }

    /// Resolve the parent directory of `arg`, returning (dir handle, leaf name).
    /// A bare name resolves against the current directory.
    pub async fn resolve_parent(&mut self, arg: &str) -> anyhow::Result<(NfsFh, String)> {
        if arg.ends_with('/') {
            anyhow::bail!("invalid path: {arg}");
        }
        let trimmed = arg;
        let (dir_part, leaf) = match trimmed.rsplit_once('/') {
            Some((d, l)) => (d, l),
            None => ("", trimmed),
        };
        if leaf.is_empty() {
            anyhow::bail!("invalid path: {arg}");
        }
        let dir = if dir_part.is_empty() {
            if trimmed.starts_with('/') {
                let (fh, _at) = self.resolve("/").await?;
                fh
            } else {
                self.cwd_handle
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("not connected"))?
            }
        } else {
            let resolve_arg = if trimmed.starts_with('/') {
                format!("/{}", dir_part.trim_start_matches('/'))
            } else {
                dir_part.to_string()
            };
            let (fh, at) = self.resolve(&resolve_arg).await?;
            if !at.is_directory() {
                anyhow::bail!("{dir_part}: not a directory");
            }
            fh
        };
        Ok((dir, leaf.to_string()))
    }

    pub async fn set_uid(&mut self, uid: u32) -> anyhow::Result<()> {
        self.creds = AuthCreds::new(uid, self.creds.gid);
        if self.is_connected() {
            self.reconnect().await?;
        }
        Ok(())
    }

    pub async fn set_gid(&mut self, gid: u32) -> anyhow::Result<()> {
        self.creds = AuthCreds::new(self.creds.uid, gid);
        if self.is_connected() {
            self.reconnect().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{AuthCreds, ConnectorFactory, NfsAttrs, NfsFh, NfsFileType, NfsVersion};
    use std::sync::Arc;

    fn attrs(ft: NfsFileType) -> NfsAttrs {
        NfsAttrs {
            file_type: ft,
            size: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn factory_with_dir_tree() -> ConnectorFactory {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr()
                .returning(|_| Ok(attrs(NfsFileType::Directory)));
            ops.expect_lookup().returning(|_dir, name| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    attrs(NfsFileType::Directory),
                ))
            });
            Ok(Box::new(ops))
        });
        ConnectorFactory::uniform(Arc::new(conn))
    }

    fn factory_parent_encoding() -> ConnectorFactory {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle()
                .return_const(NfsFh::new(b"ROOT".to_vec()));
            ops.expect_getattr()
                .returning(|_| Ok(attrs(NfsFileType::Directory)));
            ops.expect_lookup().returning(|dir, name| {
                let mut bytes = dir.as_bytes().to_vec();
                bytes.push(b'/');
                bytes.extend_from_slice(name.as_bytes());
                Ok((NfsFh::new(bytes), attrs(NfsFileType::Directory)))
            });
            Ok(Box::new(ops))
        });
        ConnectorFactory::uniform(Arc::new(conn))
    }

    #[tokio::test]
    async fn mount_sets_cwd_to_root() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/export").await.unwrap();
        assert_eq!(s.cwd_path(), "/");
        assert_eq!(s.cwd_handle().unwrap().as_bytes(), &[0]);
    }

    #[tokio::test]
    async fn cd_relative_resolves_and_updates_path() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/export").await.unwrap();
        s.cd("sub").await.unwrap();
        assert_eq!(s.cwd_path(), "/sub");
    }

    #[tokio::test]
    async fn cd_absolute_restarts_at_root() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/export").await.unwrap();
        s.cd("a").await.unwrap();
        s.cd("/b").await.unwrap();
        assert_eq!(s.cwd_path(), "/b");
    }

    #[tokio::test]
    async fn cd_dotdot_pops_path() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/export").await.unwrap();
        s.cd("a").await.unwrap();
        s.cd("b").await.unwrap();
        s.cd("..").await.unwrap();
        assert_eq!(s.cwd_path(), "/a");
    }

    #[tokio::test]
    async fn changing_uid_reconnects_and_keeps_cwd() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/export").await.unwrap();
        s.cd("keep").await.unwrap();
        s.set_uid(2000).await.unwrap();
        assert_eq!(s.creds().uid, 2000);
        assert_eq!(s.cwd_path(), "/keep");
    }

    #[tokio::test]
    async fn operations_require_connection() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        assert!(s.cd("x").await.is_err());
    }

    #[test]
    fn join_display_path_handles_root_and_dotdot() {
        assert_eq!(join_display_path("/", "sub"), "/sub");
        assert_eq!(join_display_path("/a", "b"), "/a/b");
        assert_eq!(join_display_path("/a/b", ".."), "/a");
        assert_eq!(join_display_path("/", ".."), "/");
        assert_eq!(join_display_path("/a", "/abs"), "/abs");
    }

    #[tokio::test]
    async fn read_all_concatenates_chunks_until_eof() {
        use crate::nfs::ReadResult;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            let mut call = 0;
            ops.expect_read().returning(move |_fh, _off, _cnt| {
                call += 1;
                if call == 1 {
                    Ok(ReadResult {
                        data: b"hello ".to_vec(),
                        eof: false,
                    })
                } else {
                    Ok(ReadResult {
                        data: b"world".to_vec(),
                        eof: true,
                    })
                }
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        let fh = NfsFh::new(vec![9]);
        let data = s.read_all(&fh, 64).await.unwrap();
        assert_eq!(&data, b"hello world");
    }

    #[tokio::test]
    async fn resolve_relative_anchors_on_handle_cwd() {
        let mut s = Session::new(
            factory_parent_encoding(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        s.set_handle(NfsFh::new(b"RAW".to_vec())).await.unwrap();
        let (fh, _attrs) = s.resolve("file").await.unwrap();
        assert_eq!(fh.as_bytes(), b"RAW/file");
    }

    #[tokio::test]
    async fn cd_relative_from_handle_walks_from_handle() {
        let mut s = Session::new(
            factory_parent_encoding(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        s.set_handle(NfsFh::new(b"RAW".to_vec())).await.unwrap();
        s.cd("sub").await.unwrap();
        assert_eq!(s.cwd_handle().unwrap().as_bytes(), b"RAW/sub");
        assert_eq!(s.cwd_path(), "<handle>/sub");
    }

    #[tokio::test]
    async fn uid_change_preserves_handle_cwd() {
        let mut s = Session::new(
            factory_parent_encoding(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        s.set_handle(NfsFh::new(b"RAW".to_vec())).await.unwrap();
        s.set_uid(2000).await.unwrap();
        assert_eq!(s.creds().uid, 2000);
        assert_eq!(s.cwd_handle().unwrap().as_bytes(), b"RAW");
        assert_eq!(s.cwd_path(), "<handle>");
    }

    #[test]
    fn join_handle_path_appends_and_pops() {
        assert_eq!(join_handle_path("<handle>", "a"), "<handle>/a");
        assert_eq!(join_handle_path("<handle>/a", "b"), "<handle>/a/b");
        assert_eq!(join_handle_path("<handle>/a/b", ".."), "<handle>/a");
        assert_eq!(join_handle_path("<handle>", ".."), "<handle>");
        assert_eq!(join_handle_path("<handle>/a", "."), "<handle>/a");
    }

    #[tokio::test]
    async fn resolve_parent_bare_name_uses_cwd() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        let (dir, name) = s.resolve_parent("file.txt").await.unwrap();
        assert_eq!(name, "file.txt");
        assert_eq!(dir.as_bytes(), &[0]); // cwd root handle
    }

    #[tokio::test]
    async fn resolve_parent_nested_path_resolves_dir() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        let (dir, name) = s.resolve_parent("sub/file.txt").await.unwrap();
        assert_eq!(name, "file.txt");
        assert_eq!(dir.as_bytes(), b"sub");
    }

    #[tokio::test]
    async fn resolve_parent_rejects_empty_leaf() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        assert!(s.resolve_parent("sub/").await.is_err());
    }

    #[test]
    fn new_session_has_empty_harvest_and_autocycle_off() {
        let s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        assert!(s.harvested().is_empty());
        assert!(!s.auto_cycle());
    }

    #[test]
    fn add_harvested_dedupes() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.add_harvested(vec![AuthCreds::new(1, 1), AuthCreds::new(2, 2)]);
        s.add_harvested(vec![AuthCreds::new(2, 2), AuthCreds::new(3, 3)]);
        assert_eq!(s.harvested().len(), 3);
    }

    #[test]
    fn set_auto_cycle_toggles() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_auto_cycle(true);
        assert!(s.auto_cycle());
        s.set_auto_cycle(false);
        assert!(!s.auto_cycle());
    }

    #[test]
    fn classifier_can_be_set_and_borrowed() {
        use std::sync::Arc;
        let engine = Arc::new(
            crate::classifier::RuleEngine::compile(
                crate::classifier::defaults::load_embedded_defaults().unwrap(),
            )
            .unwrap(),
        );
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        assert!(s.classifier().is_none());
        s.set_classifier(engine);
        assert!(s.classifier().is_some());
    }

    #[test]
    fn db_path_set_and_read() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_db_path(std::path::PathBuf::from("x.db"));
        assert_eq!(s.db_path().unwrap().to_str().unwrap(), "x.db");
    }

    #[tokio::test]
    async fn connect_as_returns_independent_ops() {
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        let ops = s.connect_as(&AuthCreds::root()).await.unwrap();
        assert_eq!(ops.root_handle().as_bytes(), &[0]);
    }

    #[tokio::test]
    async fn read_all_auto_cycles_to_harvested_uid() {
        use crate::nfs::{NfsError, ReadResult};
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_h, _e, creds| {
            let uid = creds.uid;
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            if uid == 2000 {
                ops.expect_read().returning(|_fh, _off, _cnt| {
                    Ok(ReadResult {
                        data: b"secret".to_vec(),
                        eof: true,
                    })
                });
            } else {
                ops.expect_read()
                    .returning(|_fh, _off, _cnt| Err(Box::new(NfsError::PermissionDenied)));
            }
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        s.set_auto_cycle(true);
        s.add_harvested(vec![AuthCreds::new(2000, 2000)]);

        let fh = NfsFh::new(vec![9]);
        let (data, used) = s.read_all_auto(&fh, 64, None).await.unwrap();
        assert_eq!(&data, b"secret");
        assert_eq!(used, Some(AuthCreds::new(2000, 2000)));
    }

    #[tokio::test]
    async fn read_all_auto_no_cycle_when_disabled() {
        use crate::nfs::NfsError;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_h, _e, _creds| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_read()
                .returning(|_fh, _off, _cnt| Err(Box::new(NfsError::PermissionDenied)));
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        // auto_cycle off by default
        s.add_harvested(vec![AuthCreds::new(2000, 2000)]);
        let fh = NfsFh::new(vec![9]);
        assert!(s.read_all_auto(&fh, 64, None).await.is_err());
    }

    #[tokio::test]
    async fn record_findings_writes_to_db() {
        use crate::pipeline::ResultMsg;
        use chrono::Utc;
        let dir = std::env::temp_dir().join(format!("niffler_snaffle_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("s.db");
        let mut s = Session::new(
            factory_with_dir_tree(),
            AuthCreds::new(1000, 1000),
            NfsVersion::V3,
        );
        s.set_host("h".into());
        s.set_db_path(db.clone());
        let msg = ResultMsg {
            timestamp: Utc::now(),
            host: "h".into(),
            export_path: "/e".into(),
            file_path: "/e/secret".into(),
            triage: crate::classifier::Triage::Red,
            rule_name: "Test".into(),
            matched_pattern: "x".into(),
            context: None,
            file_size: 1,
            file_mode: 0o600,
            file_uid: 0,
            file_gid: 0,
            last_modified: Utc::now(),
        };
        s.record_findings(&[msg]).await.unwrap();
        s.finish_recording().await.unwrap();
        assert!(db.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn read_all_auto_primary_succeeds_returns_none() {
        use crate::nfs::ReadResult;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_h, _e, _creds| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_read().returning(|_fh, _off, _cnt| {
                Ok(ReadResult {
                    data: b"ok".to_vec(),
                    eof: true,
                })
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s.mount("/e").await.unwrap();
        s.set_auto_cycle(true);
        let fh = NfsFh::new(vec![9]);
        let (data, used) = s.read_all_auto(&fh, 64, None).await.unwrap();
        assert_eq!(&data, b"ok");
        assert_eq!(used, None);
    }
}
