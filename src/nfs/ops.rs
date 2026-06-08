use crate::nfs::types::{DirEntry, FsStat, NfsAttrs, NfsFh, NodeKind, ReadResult, SetAttrs};

/// Result alias for NFS operations.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Default per-directory entry cap. Bounds client memory when a malicious or
/// misconfigured server returns a directory with a pathological number of
/// entries. `0` disables the cap.
pub const DEFAULT_MAX_DIR_ENTRIES: usize = 1_000_000;

/// Returns true once an accumulated directory listing has reached `cap`.
/// A `cap` of 0 means unlimited.
#[must_use]
pub(crate) fn dir_entry_cap_reached(len: usize, cap: usize) -> bool {
    cap != 0 && len >= cap
}

/// Operations on an established NFS connection.
/// The connection holds a mounted export and fixed AUTH_SYS credentials.
/// All async methods take &mut self because nfs3_client requires exclusive access.
#[cfg_attr(any(test, feature = "testing"), mockall::automock)]
#[async_trait::async_trait]
pub trait NfsOps: Send {
    /// List directory entries with attributes (READDIRPLUS).
    /// Falls back to READDIR + GETATTR if READDIRPLUS is unsupported.
    async fn readdirplus(&mut self, dir: &NfsFh) -> Result<Vec<DirEntry>>;

    /// Get file attributes (GETATTR).
    async fn getattr(&mut self, fh: &NfsFh) -> Result<NfsAttrs>;

    /// Read file contents. Returns up to count bytes starting at offset.
    async fn read(&mut self, fh: &NfsFh, offset: u64, count: u32) -> Result<ReadResult>;

    /// Lookup a name within a directory. Returns handle + attributes.
    async fn lookup(&mut self, dir: &NfsFh, name: &str) -> Result<(NfsFh, NfsAttrs)>;

    /// Read symlink target.
    async fn readlink(&mut self, link: &NfsFh) -> Result<String>;

    /// Write `data` at `offset`. `stable` requests FILE_SYNC durability.
    /// Returns the number of bytes the server reports written.
    async fn write(&mut self, fh: &NfsFh, offset: u64, data: &[u8], stable: bool) -> Result<u32>;

    /// Create regular file `name` in `dir` with `mode`. Returns its handle and attrs.
    async fn create(&mut self, dir: &NfsFh, name: &str, mode: u32) -> Result<(NfsFh, NfsAttrs)>;

    /// Create directory `name` in `dir` with `mode`. Returns its handle and attrs.
    async fn mkdir(&mut self, dir: &NfsFh, name: &str, mode: u32) -> Result<(NfsFh, NfsAttrs)>;

    /// Remove file `name` from `dir`.
    async fn remove(&mut self, dir: &NfsFh, name: &str) -> Result<()>;

    /// Remove empty directory `name` from `dir`.
    async fn rmdir(&mut self, dir: &NfsFh, name: &str) -> Result<()>;

    /// Apply a partial attribute update (chmod/chown/truncate/utime).
    async fn setattr(&mut self, fh: &NfsFh, attrs: SetAttrs) -> Result<()>;

    /// Filesystem statistics for the volume containing `fh` (FSSTAT).
    async fn fsstat(&mut self, fh: &NfsFh) -> Result<FsStat>;

    /// Rename `from_name` in `from_dir` to `to_name` in `to_dir`.
    async fn rename(
        &mut self,
        from_dir: &NfsFh,
        from_name: &str,
        to_dir: &NfsFh,
        to_name: &str,
    ) -> Result<()>;

    /// Create a hard link `name` in `dir` pointing at existing `target`.
    async fn link(&mut self, target: &NfsFh, dir: &NfsFh, name: &str) -> Result<()>;

    /// Create symlink `name` in `dir` whose contents are `target_path`.
    async fn symlink(
        &mut self,
        dir: &NfsFh,
        name: &str,
        target_path: &str,
        mode: u32,
    ) -> Result<(NfsFh, NfsAttrs)>;

    /// Create a special file (block/char/fifo/socket). `spec` = (major, minor) for device nodes.
    async fn mknod(
        &mut self,
        dir: &NfsFh,
        name: &str,
        kind: NodeKind,
        mode: u32,
        spec: Option<(u32, u32)>,
    ) -> Result<(NfsFh, NfsAttrs)>;

    /// Get the root file handle for the mounted export.
    fn root_handle(&self) -> &NfsFh;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_disabled_when_zero() {
        assert!(!dir_entry_cap_reached(0, 0));
        assert!(!dir_entry_cap_reached(1_000_000, 0));
    }

    #[test]
    fn cap_reached_at_or_above_limit() {
        assert!(!dir_entry_cap_reached(99, 100));
        assert!(dir_entry_cap_reached(100, 100));
        assert!(dir_entry_cap_reached(101, 100));
    }

    #[tokio::test]
    async fn mock_nfs_ops_compiles() {
        let mut mock = MockNfsOps::new();
        mock.expect_root_handle().return_const(NfsFh::default());

        let result = mock.root_handle();
        assert!(result.as_bytes().is_empty());

        let _: Box<dyn NfsOps> = Box::new(mock);
    }
}
