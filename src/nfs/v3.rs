use nfs3_client::error::{Error as ClientError, RpcError};
use nfs3_client::nfs3_types::mount::mountstat3;
use nfs3_client::nfs3_types::nfs3::{
    CREATE3args, FSSTAT3args, GETATTR3args, LINK3args, LOOKUP3args, MKDIR3args, MKNOD3args,
    Nfs3Option, Nfs3Result, READ3args, READDIRPLUS3args, READLINK3args, REMOVE3args, RENAME3args,
    RMDIR3args, SETATTR3args, SYMLINK3args, WRITE3args, cookieverf3, createhow3, devicedata3,
    diropargs3, entryplus3, fattr3, filename3, ftype3, mknoddata3, nfs_fh3, nfspath3, nfsstat3,
    nfstime3, post_op_attr, post_op_fh3, sattr3, set_mtime, specdata3, stable_how, symlinkdata3,
};
use nfs3_client::nfs3_types::rpc::{auth_unix, opaque_auth};
use nfs3_client::nfs3_types::xdr_codec::Opaque;
use nfs3_client::tokio::TokioIo;
use nfs3_client::{Nfs3Connection, Nfs3ConnectionBuilder, PortmapperClient};

use super::auth::AuthCreds;
use super::connector::{self, NfsConnector};
use super::errors::NfsError;
use super::ops::NfsOps;
use super::transport::NifflerTokioConnector;
use super::types::{
    DirEntry, FsStat, NfsAttrs, NfsFh, NfsFileType, NfsVersion, NodeKind, ReadResult, SetAttrs,
};

/// Map an NFS protocol status code to an `NfsError`.
pub(crate) fn map_nfsstat(status: nfsstat3) -> NfsError {
    match status {
        nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM => NfsError::PermissionDenied,
        nfsstat3::NFS3ERR_STALE | nfsstat3::NFS3ERR_BADHANDLE => NfsError::StaleHandle,
        nfsstat3::NFS3ERR_NOENT => NfsError::NotFound,
        nfsstat3::NFS3ERR_JUKEBOX | nfsstat3::NFS3ERR_IO => NfsError::Transient(status.to_string()),
        nfsstat3::NFS3ERR_SERVERFAULT => NfsError::ExportFatal(status.to_string()),
        _ => NfsError::Transient(status.to_string()),
    }
}

/// Map an `nfs3_client::Error` to an `NfsError`.
pub(crate) fn map_client_error(err: ClientError) -> NfsError {
    match err {
        ClientError::NfsError(stat) => map_nfsstat(stat),
        ClientError::MountError(mountstat3::MNT3ERR_ACCES) => NfsError::PermissionDenied,
        ClientError::MountError(stat) => NfsError::ExportFatal(stat.to_string()),
        ClientError::Rpc(RpcError::Auth) => NfsError::PermissionDenied,
        ClientError::Io(_)
        | ClientError::Xdr(_)
        | ClientError::Rpc(_)
        | ClientError::Portmap(_) => NfsError::ConnectionLost,
    }
}

impl From<nfs_fh3> for NfsFh {
    fn from(fh: nfs_fh3) -> Self {
        Self::new(fh.data.as_ref().to_vec())
    }
}

/// Convert a Niffler file handle back to the nfs3_types representation.
pub(crate) fn to_nfs_fh3(fh: &NfsFh) -> nfs_fh3 {
    nfs_fh3 {
        data: Opaque::owned(fh.as_bytes().to_vec()),
    }
}

fn sattr_from_setattrs(s: &SetAttrs) -> sattr3 {
    sattr3 {
        mode: s.mode.map_or(Nfs3Option::None, Nfs3Option::Some),
        uid: s.uid.map_or(Nfs3Option::None, Nfs3Option::Some),
        gid: s.gid.map_or(Nfs3Option::None, Nfs3Option::Some),
        size: s.size.map_or(Nfs3Option::None, Nfs3Option::Some),
        atime: Default::default(),
        mtime: Default::default(),
    }
}

fn sattr_with_mode(mode: u32) -> sattr3 {
    sattr3 {
        mode: Nfs3Option::Some(mode),
        ..Default::default()
    }
}

fn mknoddata_for(kind: NodeKind, mode: u32, spec: Option<(u32, u32)>) -> mknoddata3 {
    let (major, minor) = spec.unwrap_or((0, 0));
    let dev = devicedata3 {
        dev_attributes: sattr_with_mode(mode),
        spec: specdata3 {
            specdata1: major,
            specdata2: minor,
        },
    };
    match kind {
        NodeKind::Char => mknoddata3::NF3CHR(dev),
        NodeKind::Block => mknoddata3::NF3BLK(dev),
        NodeKind::Fifo => mknoddata3::NF3FIFO(sattr_with_mode(mode)),
        NodeKind::Socket => mknoddata3::NF3SOCK(sattr_with_mode(mode)),
    }
}

fn map_ftype(ft: ftype3) -> NfsFileType {
    match ft {
        ftype3::NF3REG => NfsFileType::Regular,
        ftype3::NF3DIR => NfsFileType::Directory,
        ftype3::NF3LNK => NfsFileType::Symlink,
        _ => NfsFileType::Other,
    }
}

impl From<fattr3> for NfsAttrs {
    fn from(attrs: fattr3) -> Self {
        Self {
            file_type: map_ftype(attrs.type_),
            size: attrs.size,
            mode: attrs.mode,
            uid: attrs.uid,
            gid: attrs.gid,
            mtime: attrs.mtime.seconds as u64,
        }
    }
}

/// Convert an nfs3_types READDIRPLUS entry to a Niffler `DirEntry`.
///
/// Returns `None` if the entry is missing a file handle or attributes.
pub(crate) fn convert_entry(entry: &entryplus3) -> Option<DirEntry> {
    let fh = match &entry.name_handle {
        Nfs3Option::Some(fh) => NfsFh::new(fh.data.as_ref().to_vec()),
        Nfs3Option::None => return None,
    };
    let attrs = match &entry.name_attributes {
        Nfs3Option::Some(a) => NfsAttrs::from(a.clone()),
        Nfs3Option::None => return None,
    };
    let name = String::from_utf8_lossy(entry.name.0.as_ref()).into_owned();
    Some(DirEntry { name, fh, attrs })
}

fn filter_dot_entries(entries: Vec<DirEntry>) -> Vec<DirEntry> {
    entries
        .into_iter()
        .filter(|e| e.name != "." && e.name != "..")
        .collect()
}

pub struct Nfs3Connector {
    privileged_port: bool,
    proxy: Option<std::net::SocketAddr>,
    max_dir_entries: usize,
}

impl Nfs3Connector {
    #[must_use]
    pub fn new(privileged_port: bool) -> Self {
        Self {
            privileged_port,
            proxy: None,
            max_dir_entries: super::ops::DEFAULT_MAX_DIR_ENTRIES,
        }
    }

    #[must_use]
    pub fn with_proxy(proxy: std::net::SocketAddr) -> Self {
        Self {
            privileged_port: false,
            proxy: Some(proxy),
            max_dir_entries: super::ops::DEFAULT_MAX_DIR_ENTRIES,
        }
    }

    /// Set the per-directory entry cap applied during `readdirplus` (0 = unlimited).
    #[must_use]
    pub fn with_max_dir_entries(mut self, max_dir_entries: usize) -> Self {
        self.max_dir_entries = max_dir_entries;
        self
    }
}

#[async_trait::async_trait]
impl NfsConnector for Nfs3Connector {
    async fn connect(
        &self,
        host: &str,
        export: &str,
        creds: &AuthCreds,
    ) -> connector::Result<Box<dyn NfsOps>> {
        let auth = auth_unix {
            stamp: 0,
            machinename: Opaque::owned(b"niffler".to_vec()),
            uid: creds.uid,
            gid: creds.gid,
            gids: creds.aux_gids.clone(),
        };
        let credential = opaque_auth::auth_unix(&auth);

        let conn = if let Some(proxy_addr) = self.proxy {
            let connector = super::socks::SocksConnector { proxy_addr };
            Nfs3ConnectionBuilder::new(connector, host, export)
                .connect_from_privileged_port(false)
                .credential(credential)
                .mount()
                .await
                .map_err(map_client_error)?
        } else {
            Nfs3ConnectionBuilder::new(NifflerTokioConnector, host, export)
                .connect_from_privileged_port(self.privileged_port)
                .credential(credential)
                .mount()
                .await
                .map_err(map_client_error)?
        };

        let root_fh = NfsFh::from(conn.root_nfs_fh3());
        Ok(Box::new(Nfs3Ops {
            conn,
            root_fh,
            max_dir_entries: self.max_dir_entries,
        }))
    }

    async fn detect_version(&self, host: &str) -> connector::Result<NfsVersion> {
        let stream = super::socks::tcp_connect_str(&format!("{host}:111"), self.proxy)
            .await
            .map_err(|_| NfsError::ConnectionLost)?;
        let io: NfsIo = TokioIo::new(stream);
        let mut pm = PortmapperClient::new(io);
        let _port: u16 = pm
            .getport(100_003, 3)
            .await
            .map_err(|_| NfsError::ConnectionLost)?;
        Ok(NfsVersion::V3)
    }
}

type NfsIo = TokioIo<tokio::net::TcpStream>;

struct Nfs3Ops {
    conn: Nfs3Connection<NfsIo>,
    root_fh: NfsFh,
    max_dir_entries: usize,
}

#[async_trait::async_trait]
impl NfsOps for Nfs3Ops {
    async fn readdirplus(&mut self, dir: &NfsFh) -> super::ops::Result<Vec<DirEntry>> {
        let mut all_entries = Vec::new();
        let mut cookie: u64 = 0;
        let mut verf = cookieverf3::default();

        loop {
            let args = READDIRPLUS3args {
                dir: to_nfs_fh3(dir),
                cookie,
                cookieverf: verf,
                dircount: 8192,
                maxcount: 32768,
            };
            let res = self
                .conn
                .readdirplus(&args)
                .await
                .map_err(map_client_error)?;
            let ok = match res {
                Nfs3Result::Ok(ok) => ok,
                Nfs3Result::Err((status, _)) => return Err(Box::new(map_nfsstat(status))),
            };

            verf = ok.cookieverf;
            let eof = ok.reply.eof;

            for entry in ok.reply.entries.0.iter() {
                cookie = entry.cookie;
                if let Some(de) = convert_entry(entry) {
                    all_entries.push(de);
                }
            }

            if super::ops::dir_entry_cap_reached(all_entries.len(), self.max_dir_entries) {
                tracing::warn!(
                    cap = self.max_dir_entries,
                    "directory entry cap reached; truncating listing"
                );
                all_entries.truncate(self.max_dir_entries);
                break;
            }

            if eof || ok.reply.entries.0.is_empty() {
                break;
            }
        }

        Ok(filter_dot_entries(all_entries))
    }

    async fn getattr(&mut self, fh: &NfsFh) -> super::ops::Result<NfsAttrs> {
        let args = GETATTR3args {
            object: to_nfs_fh3(fh),
        };
        let res = self.conn.getattr(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => Ok(NfsAttrs::from(ok.obj_attributes)),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn read(
        &mut self,
        fh: &NfsFh,
        offset: u64,
        count: u32,
    ) -> super::ops::Result<ReadResult> {
        let args = READ3args {
            file: to_nfs_fh3(fh),
            offset,
            count,
        };
        let res = self.conn.read(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => Ok(ReadResult {
                data: ok.data.as_ref().to_vec(),
                eof: ok.eof,
            }),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn lookup(&mut self, dir: &NfsFh, name: &str) -> super::ops::Result<(NfsFh, NfsAttrs)> {
        let args = LOOKUP3args {
            what: diropargs3 {
                dir: to_nfs_fh3(dir),
                name: filename3(Opaque::owned(name.as_bytes().to_vec())),
            },
        };
        let res = self.conn.lookup(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => {
                let fh = NfsFh::from(ok.object);
                let attrs = match ok.obj_attributes {
                    Nfs3Option::Some(a) => NfsAttrs::from(a),
                    Nfs3Option::None => self.getattr(&fh).await?,
                };
                Ok((fh, attrs))
            }
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn readlink(&mut self, link: &NfsFh) -> super::ops::Result<String> {
        let args = READLINK3args {
            symlink: to_nfs_fh3(link),
        };
        let res = self.conn.readlink(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => Ok(String::from_utf8_lossy(ok.data.0.as_ref()).into_owned()),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn write(
        &mut self,
        fh: &NfsFh,
        offset: u64,
        data: &[u8],
        stable: bool,
    ) -> super::ops::Result<u32> {
        debug_assert!(
            data.len() <= u32::MAX as usize,
            "write data exceeds u32 count; caller must chunk"
        );
        let args = WRITE3args {
            file: to_nfs_fh3(fh),
            offset,
            count: data.len() as u32,
            stable: if stable {
                stable_how::FILE_SYNC
            } else {
                stable_how::UNSTABLE
            },
            data: Opaque::owned(data.to_vec()),
        };
        let res = self.conn.write(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => Ok(ok.count),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn create(
        &mut self,
        dir: &NfsFh,
        name: &str,
        mode: u32,
    ) -> super::ops::Result<(NfsFh, NfsAttrs)> {
        let args = CREATE3args {
            where_: diropargs3 {
                dir: to_nfs_fh3(dir),
                name: filename3(Opaque::owned(name.as_bytes().to_vec())),
            },
            how: createhow3::UNCHECKED(sattr_with_mode(mode)),
        };
        let res = self.conn.create(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => {
                self.resolve_created(dir, name, ok.obj, ok.obj_attributes)
                    .await
            }
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn mkdir(
        &mut self,
        dir: &NfsFh,
        name: &str,
        mode: u32,
    ) -> super::ops::Result<(NfsFh, NfsAttrs)> {
        let args = MKDIR3args {
            where_: diropargs3 {
                dir: to_nfs_fh3(dir),
                name: filename3(Opaque::owned(name.as_bytes().to_vec())),
            },
            attributes: sattr_with_mode(mode),
        };
        let res = self.conn.mkdir(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => {
                self.resolve_created(dir, name, ok.obj, ok.obj_attributes)
                    .await
            }
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn remove(&mut self, dir: &NfsFh, name: &str) -> super::ops::Result<()> {
        let args = REMOVE3args {
            object: diropargs3 {
                dir: to_nfs_fh3(dir),
                name: filename3(Opaque::owned(name.as_bytes().to_vec())),
            },
        };
        let res = self.conn.remove(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(_) => Ok(()),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn rmdir(&mut self, dir: &NfsFh, name: &str) -> super::ops::Result<()> {
        let args = RMDIR3args {
            object: diropargs3 {
                dir: to_nfs_fh3(dir),
                name: filename3(Opaque::owned(name.as_bytes().to_vec())),
            },
        };
        let res = self.conn.rmdir(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(_) => Ok(()),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn setattr(&mut self, fh: &NfsFh, attrs: SetAttrs) -> super::ops::Result<()> {
        let mut sattr = sattr_from_setattrs(&attrs);
        if let Some(secs) = attrs.mtime {
            sattr.mtime = set_mtime::SET_TO_CLIENT_TIME(nfstime3 {
                seconds: secs as u32,
                nseconds: 0,
            });
        }
        let args = SETATTR3args {
            object: to_nfs_fh3(fh),
            new_attributes: sattr,
            guard: Nfs3Option::None,
        };
        let res = self.conn.setattr(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(_) => Ok(()),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn fsstat(&mut self, fh: &NfsFh) -> super::ops::Result<FsStat> {
        let args = FSSTAT3args {
            fsroot: to_nfs_fh3(fh),
        };
        let res = self.conn.fsstat(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => Ok(FsStat {
                total_bytes: ok.tbytes,
                free_bytes: ok.fbytes,
                avail_bytes: ok.abytes,
            }),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn rename(
        &mut self,
        from_dir: &NfsFh,
        from_name: &str,
        to_dir: &NfsFh,
        to_name: &str,
    ) -> super::ops::Result<()> {
        let args = RENAME3args {
            from: diropargs3 {
                dir: to_nfs_fh3(from_dir),
                name: filename3(Opaque::owned(from_name.as_bytes().to_vec())),
            },
            to: diropargs3 {
                dir: to_nfs_fh3(to_dir),
                name: filename3(Opaque::owned(to_name.as_bytes().to_vec())),
            },
        };
        let res = self.conn.rename(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(_) => Ok(()),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn link(&mut self, target: &NfsFh, dir: &NfsFh, name: &str) -> super::ops::Result<()> {
        let args = LINK3args {
            file: to_nfs_fh3(target),
            link: diropargs3 {
                dir: to_nfs_fh3(dir),
                name: filename3(Opaque::owned(name.as_bytes().to_vec())),
            },
        };
        let res = self.conn.link(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(_) => Ok(()),
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn symlink(
        &mut self,
        dir: &NfsFh,
        name: &str,
        target_path: &str,
        mode: u32,
    ) -> super::ops::Result<(NfsFh, NfsAttrs)> {
        let args = SYMLINK3args {
            where_: diropargs3 {
                dir: to_nfs_fh3(dir),
                name: filename3(Opaque::owned(name.as_bytes().to_vec())),
            },
            symlink: symlinkdata3 {
                symlink_attributes: sattr_with_mode(mode),
                symlink_data: nfspath3(Opaque::owned(target_path.as_bytes().to_vec())),
            },
        };
        let res = self.conn.symlink(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => {
                self.resolve_created(dir, name, ok.obj, ok.obj_attributes)
                    .await
            }
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    async fn mknod(
        &mut self,
        dir: &NfsFh,
        name: &str,
        kind: NodeKind,
        mode: u32,
        spec: Option<(u32, u32)>,
    ) -> super::ops::Result<(NfsFh, NfsAttrs)> {
        let args = MKNOD3args {
            where_: diropargs3 {
                dir: to_nfs_fh3(dir),
                name: filename3(Opaque::owned(name.as_bytes().to_vec())),
            },
            what: mknoddata_for(kind, mode, spec),
        };
        let res = self.conn.mknod(&args).await.map_err(map_client_error)?;
        match res {
            Nfs3Result::Ok(ok) => {
                self.resolve_created(dir, name, ok.obj, ok.obj_attributes)
                    .await
            }
            Nfs3Result::Err((status, _)) => Err(Box::new(map_nfsstat(status))),
        }
    }

    fn root_handle(&self) -> &NfsFh {
        &self.root_fh
    }
}

impl Nfs3Ops {
    async fn resolve_created(
        &mut self,
        dir: &NfsFh,
        name: &str,
        obj: post_op_fh3,
        attrs: post_op_attr,
    ) -> super::ops::Result<(NfsFh, NfsAttrs)> {
        let fh = match obj {
            Nfs3Option::Some(h) => Some(NfsFh::from(h)),
            Nfs3Option::None => None,
        };
        match fh {
            Some(fh) => {
                let a = match attrs {
                    Nfs3Option::Some(a) => NfsAttrs::from(a),
                    Nfs3Option::None => self.getattr(&fh).await?,
                };
                Ok((fh, a))
            }
            None => self.lookup(dir, name).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs3_client::error::RpcError;
    use nfs3_client::nfs3_types::mount::mountstat3;
    use nfs3_client::nfs3_types::nfs3::{nfstime3, specdata3};

    #[test]
    fn nfsstat_acces_maps_to_permission_denied() {
        assert!(matches!(
            map_nfsstat(nfsstat3::NFS3ERR_ACCES),
            NfsError::PermissionDenied
        ));
    }

    #[test]
    fn nfsstat_perm_maps_to_permission_denied() {
        assert!(matches!(
            map_nfsstat(nfsstat3::NFS3ERR_PERM),
            NfsError::PermissionDenied
        ));
    }

    #[test]
    fn nfsstat_stale_maps_to_stale_handle() {
        assert!(matches!(
            map_nfsstat(nfsstat3::NFS3ERR_STALE),
            NfsError::StaleHandle
        ));
    }

    #[test]
    fn nfsstat_badhandle_maps_to_stale_handle() {
        assert!(matches!(
            map_nfsstat(nfsstat3::NFS3ERR_BADHANDLE),
            NfsError::StaleHandle
        ));
    }

    #[test]
    fn nfsstat_noent_maps_to_not_found() {
        assert!(matches!(
            map_nfsstat(nfsstat3::NFS3ERR_NOENT),
            NfsError::NotFound
        ));
    }

    #[test]
    fn nfsstat_jukebox_maps_to_transient() {
        assert!(matches!(
            map_nfsstat(nfsstat3::NFS3ERR_JUKEBOX),
            NfsError::Transient(_)
        ));
    }

    #[test]
    fn nfsstat_io_maps_to_transient() {
        assert!(matches!(
            map_nfsstat(nfsstat3::NFS3ERR_IO),
            NfsError::Transient(_)
        ));
    }

    #[test]
    fn nfsstat_serverfault_maps_to_export_fatal() {
        assert!(matches!(
            map_nfsstat(nfsstat3::NFS3ERR_SERVERFAULT),
            NfsError::ExportFatal(_)
        ));
    }

    #[test]
    fn nfsstat_unmapped_falls_through_to_transient() {
        let err = map_nfsstat(nfsstat3::NFS3ERR_NOSPC);
        assert!(matches!(err, NfsError::Transient(ref msg) if msg.contains("NFS3ERR_NOSPC")));
    }

    #[test]
    fn client_io_error_maps_to_connection_lost() {
        let err = ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        assert!(matches!(map_client_error(err), NfsError::ConnectionLost));
    }

    #[test]
    fn client_rpc_auth_error_maps_to_permission_denied() {
        let err = ClientError::Rpc(RpcError::Auth);
        assert!(matches!(map_client_error(err), NfsError::PermissionDenied));
    }

    #[test]
    fn client_rpc_non_auth_error_maps_to_connection_lost() {
        let err = ClientError::Rpc(RpcError::RpcMismatch);
        assert!(matches!(map_client_error(err), NfsError::ConnectionLost));
    }

    #[test]
    fn mount_acces_maps_to_permission_denied() {
        let err = ClientError::MountError(mountstat3::MNT3ERR_ACCES);
        assert!(matches!(map_client_error(err), NfsError::PermissionDenied));
    }

    #[test]
    fn mount_noent_maps_to_export_fatal() {
        let err = ClientError::MountError(mountstat3::MNT3ERR_NOENT);
        assert!(matches!(map_client_error(err), NfsError::ExportFatal(_)));
    }

    #[test]
    fn client_nfs_error_delegates_to_map_nfsstat() {
        let err = ClientError::NfsError(nfsstat3::NFS3ERR_ACCES);
        assert!(matches!(map_client_error(err), NfsError::PermissionDenied));
    }

    #[test]
    fn nfs_fh3_to_niffler_fh() {
        let raw = nfs_fh3 {
            data: Opaque::owned(vec![1, 2, 3, 4]),
        };
        let fh = NfsFh::from(raw);
        assert_eq!(fh.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn niffler_fh_to_nfs_fh3() {
        let fh = NfsFh::new(vec![10, 20, 30]);
        let raw = to_nfs_fh3(&fh);
        assert_eq!(raw.data.as_ref(), &[10, 20, 30]);
    }

    #[test]
    fn empty_fh_round_trips() {
        let raw = nfs_fh3 {
            data: Opaque::owned(vec![]),
        };
        let fh = NfsFh::from(raw);
        assert!(fh.as_bytes().is_empty());
        let back = to_nfs_fh3(&fh);
        assert!(back.data.as_ref().is_empty());
    }

    fn make_test_fattr(
        type_: ftype3,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        mtime_secs: u32,
    ) -> fattr3 {
        fattr3 {
            type_,
            mode,
            nlink: 1,
            uid,
            gid,
            size,
            used: size,
            rdev: specdata3::default(),
            fsid: 0,
            fileid: 0,
            atime: nfstime3::default(),
            mtime: nfstime3 {
                seconds: mtime_secs,
                nseconds: 0,
            },
            ctime: nfstime3::default(),
        }
    }

    #[test]
    fn fattr3_regular_to_nfs_attrs() {
        let attrs = NfsAttrs::from(make_test_fattr(ftype3::NF3REG, 0o644, 0, 0, 0, 0));
        assert!(attrs.is_file());
        assert!(!attrs.is_directory());
        assert!(!attrs.is_symlink());
    }

    #[test]
    fn fattr3_directory_to_nfs_attrs() {
        let attrs = NfsAttrs::from(make_test_fattr(ftype3::NF3DIR, 0o755, 0, 0, 0, 0));
        assert!(attrs.is_directory());
    }

    #[test]
    fn fattr3_symlink_to_nfs_attrs() {
        let attrs = NfsAttrs::from(make_test_fattr(ftype3::NF3LNK, 0o777, 0, 0, 0, 0));
        assert!(attrs.is_symlink());
    }

    #[test]
    fn fattr3_other_types_map_to_other() {
        for ft in [
            ftype3::NF3BLK,
            ftype3::NF3CHR,
            ftype3::NF3SOCK,
            ftype3::NF3FIFO,
        ] {
            let attrs = NfsAttrs::from(make_test_fattr(ft, 0, 0, 0, 0, 0));
            assert_eq!(attrs.file_type, NfsFileType::Other);
        }
    }

    #[test]
    fn fattr3_numeric_fields_preserved() {
        let attrs = NfsAttrs::from(make_test_fattr(
            ftype3::NF3REG,
            0o644,
            1000,
            1000,
            1024,
            1_700_000_000,
        ));
        assert_eq!(attrs.size, 1024);
        assert_eq!(attrs.mode, 0o644);
        assert_eq!(attrs.uid, 1000);
        assert_eq!(attrs.gid, 1000);
        assert_eq!(attrs.mtime, 1_700_000_000);
    }

    fn make_test_entry<'a>(
        name: &[u8],
        fh: Nfs3Option<nfs_fh3>,
        attrs: Nfs3Option<fattr3>,
    ) -> entryplus3<'a> {
        entryplus3 {
            fileid: 12345,
            name: nfs3_client::nfs3_types::nfs3::filename3(Opaque::owned(name.to_vec())),
            cookie: 1,
            name_attributes: attrs,
            name_handle: fh,
        }
    }

    #[test]
    fn convert_entry_full() {
        let entry = make_test_entry(
            b"test.txt",
            Nfs3Option::Some(nfs_fh3 {
                data: Opaque::owned(vec![0xAA, 0xBB]),
            }),
            Nfs3Option::Some(make_test_fattr(ftype3::NF3REG, 0o644, 1000, 1000, 512, 0)),
        );
        let de = convert_entry(&entry).expect("should convert");
        assert_eq!(de.name, "test.txt");
        assert_eq!(de.fh.as_bytes(), &[0xAA, 0xBB]);
        assert!(de.attrs.is_file());
    }

    #[test]
    fn convert_entry_missing_handle_returns_none() {
        let entry = make_test_entry(
            b"orphan",
            Nfs3Option::None,
            Nfs3Option::Some(make_test_fattr(ftype3::NF3REG, 0, 0, 0, 0, 0)),
        );
        assert!(convert_entry(&entry).is_none());
    }

    #[test]
    fn convert_entry_missing_attrs_returns_none() {
        let entry = make_test_entry(
            b"no_attrs",
            Nfs3Option::Some(nfs_fh3 {
                data: Opaque::owned(vec![1]),
            }),
            Nfs3Option::None,
        );
        assert!(convert_entry(&entry).is_none());
    }

    fn make_dir_entry(name: &str) -> DirEntry {
        DirEntry {
            name: name.to_string(),
            fh: NfsFh::new(vec![1]),
            attrs: NfsAttrs {
                file_type: NfsFileType::Regular,
                size: 0,
                mode: 0,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        }
    }

    #[test]
    fn filter_removes_dot() {
        let entries = vec![make_dir_entry(".")];
        assert!(filter_dot_entries(entries).is_empty());
    }

    #[test]
    fn filter_removes_dotdot() {
        let entries = vec![make_dir_entry("..")];
        assert!(filter_dot_entries(entries).is_empty());
    }

    #[test]
    fn filter_keeps_dotenv() {
        let entries = vec![make_dir_entry(".env")];
        let result = filter_dot_entries(entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, ".env");
    }

    #[test]
    fn filter_keeps_normal_file() {
        let entries = vec![make_dir_entry("normal_file")];
        let result = filter_dot_entries(entries);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_mixed_input() {
        let entries = vec![
            make_dir_entry("."),
            make_dir_entry(".."),
            make_dir_entry(".bashrc"),
            make_dir_entry("data"),
        ];
        let result = filter_dot_entries(entries);
        let names: Vec<&str> = result.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec![".bashrc", "data"]);
    }

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs3_connector_connects_and_mounts() {
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let connector = Nfs3Connector::new(false);
        let ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .unwrap();
        assert!(!ops.root_handle().as_bytes().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs3_connect_and_list_root() {
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let connector = Nfs3Connector::new(false);
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .unwrap();
        let root = ops.root_handle().clone();
        let entries = ops.readdirplus(&root).await.unwrap();
        assert!(!entries.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs3_getattr_on_root() {
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let connector = Nfs3Connector::new(false);
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .unwrap();
        let root = ops.root_handle().clone();
        let attrs = ops.getattr(&root).await.unwrap();
        assert!(attrs.is_directory());
    }

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST, NFS_TEST_EXPORT, and NFS_TEST_FILE"]
    async fn nfs3_read_file() {
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let filename = std::env::var("NFS_TEST_FILE").unwrap();
        let connector = Nfs3Connector::new(false);
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .unwrap();
        let root = ops.root_handle().clone();
        let (fh, _attrs) = ops.lookup(&root, &filename).await.unwrap();
        let result = ops.read(&fh, 0, 1024).await.unwrap();
        assert!(!result.data.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs3_detect_version() {
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let connector = Nfs3Connector::new(false);
        let version = connector.detect_version(&host).await.unwrap();
        assert_eq!(version, NfsVersion::V3);
    }

    #[test]
    fn sattr_from_setattrs_sets_only_present_fields() {
        let s = crate::nfs::types::SetAttrs {
            mode: Some(0o600),
            uid: None,
            gid: Some(10),
            size: None,
            mtime: None,
        };
        let sattr = sattr_from_setattrs(&s);
        assert!(matches!(sattr.mode, Nfs3Option::Some(0o600)));
        assert!(matches!(sattr.uid, Nfs3Option::None));
        assert!(matches!(sattr.gid, Nfs3Option::Some(10)));
        assert!(matches!(sattr.size, Nfs3Option::None));
    }

    #[test]
    fn sattr_with_mode_helper_sets_mode() {
        let sattr = sattr_with_mode(0o755);
        assert!(matches!(sattr.mode, Nfs3Option::Some(0o755)));
        assert!(matches!(sattr.uid, Nfs3Option::None));
    }

    #[test]
    fn mknoddata_for_char_carries_specdata() {
        let data = mknoddata_for(NodeKind::Char, 0o644, Some((4, 2)));
        match data {
            mknoddata3::NF3CHR(dev) => {
                assert_eq!(dev.spec.specdata1, 4);
                assert_eq!(dev.spec.specdata2, 2);
            }
            _ => panic!("expected NF3CHR"),
        }
    }

    #[test]
    fn mknoddata_for_fifo_uses_sattr() {
        assert!(matches!(
            mknoddata_for(NodeKind::Fifo, 0o644, None),
            mknoddata3::NF3FIFO(_)
        ));
    }

    #[tokio::test]
    #[ignore = "requires writable NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs3_create_write_read_remove_round_trip() {
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let connector = Nfs3Connector::new(false);
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .unwrap();
        let root = ops.root_handle().clone();

        let (fh, _attrs) = ops.create(&root, "niffler_rt.txt", 0o644).await.unwrap();
        let n = ops.write(&fh, 0, b"hello niffler", true).await.unwrap();
        assert_eq!(n, 13);
        let data = ops.read(&fh, 0, 64).await.unwrap();
        assert_eq!(&data.data, b"hello niffler");
        ops.remove(&root, "niffler_rt.txt").await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires writable NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs3_mkdir_rmdir_round_trip() {
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let connector = Nfs3Connector::new(false);
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .unwrap();
        let root = ops.root_handle().clone();
        let (_fh, attrs) = ops.mkdir(&root, "niffler_rt_dir", 0o755).await.unwrap();
        assert!(attrs.is_directory());
        ops.rmdir(&root, "niffler_rt_dir").await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires writable NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs3_setattr_chmod_and_fsstat() {
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let connector = Nfs3Connector::new(false);
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .unwrap();
        let root = ops.root_handle().clone();
        let (fh, _) = ops
            .create(&root, "niffler_rt_chmod.txt", 0o644)
            .await
            .unwrap();
        ops.setattr(
            &fh,
            crate::nfs::types::SetAttrs {
                mode: Some(0o600),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let attrs = ops.getattr(&fh).await.unwrap();
        assert_eq!(attrs.mode & 0o777, 0o600);
        let fs = ops.fsstat(&root).await.unwrap();
        assert!(fs.total_bytes > 0);
        ops.remove(&root, "niffler_rt_chmod.txt").await.unwrap();
    }
}
