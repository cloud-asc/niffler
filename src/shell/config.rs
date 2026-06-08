use std::net::SocketAddr;
use std::path::PathBuf;

use crate::config::cli::ShellArgs;
use crate::nfs::NfsVersion;

/// Resolved configuration for an interactive shell session.
#[derive(Debug, Clone)]
pub struct ShellConfig {
    pub host: Option<String>,
    pub export: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub forced_version: Option<NfsVersion>,
    pub privileged_port: bool,
    pub proxy: Option<SocketAddr>,
    pub max_dir_entries: usize,
    pub db: PathBuf,
    pub command: Option<String>,
}

impl ShellConfig {
    /// Build from CLI args, resolving the proxy URL and version flag.
    pub fn from_args(args: ShellArgs) -> anyhow::Result<Self> {
        let proxy = match args.proxy.as_deref() {
            Some(url) => Some(parse_proxy(url)?),
            None => None,
        };
        let forced_version = match args.nfs_version {
            None => None,
            Some(3) => Some(NfsVersion::V3),
            Some(4) => Some(NfsVersion::V4),
            Some(v) => anyhow::bail!("unsupported NFS version: {v} (use 3 or 4)"),
        };
        let privileged_port = !args.no_privileged_port && proxy.is_none();
        Ok(Self {
            host: args.target,
            export: args.export,
            uid: args.uid,
            gid: args.gid,
            forced_version,
            privileged_port,
            proxy,
            max_dir_entries: args.max_dir_entries,
            db: args.db,
            command: args.command,
        })
    }
}

/// Parse a `socks5://host:port` (or bare `host:port`) proxy URL into a SocketAddr.
fn parse_proxy(url: &str) -> anyhow::Result<SocketAddr> {
    // Accept `socks5://host:port` or a bare `host:port`. Reject other schemes
    // (e.g. `socks5h://`) with a clear message rather than a parse error.
    let stripped = match url.split_once("://") {
        Some(("socks5", rest)) => rest,
        Some((scheme, _)) => {
            anyhow::bail!("unsupported proxy scheme '{scheme}://' (use socks5://)")
        }
        None => url,
    };
    stripped
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("invalid proxy address '{url}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> ShellArgs {
        ShellArgs {
            target: None,
            export: None,
            uid: 65534,
            gid: 65534,
            nfs_version: None,
            no_privileged_port: false,
            proxy: None,
            max_dir_entries: 1_000_000,
            db: PathBuf::from("niffler.db"),
            command: None,
        }
    }

    #[test]
    fn proxy_url_parsed_and_disables_privileged_port() {
        let mut a = base_args();
        a.proxy = Some("socks5://127.0.0.1:1080".into());
        let cfg = ShellConfig::from_args(a).unwrap();
        assert_eq!(cfg.proxy.unwrap().to_string(), "127.0.0.1:1080");
        assert!(!cfg.privileged_port);
    }

    #[test]
    fn version_flag_maps() {
        let mut a = base_args();
        a.nfs_version = Some(4);
        assert_eq!(
            ShellConfig::from_args(a).unwrap().forced_version,
            Some(NfsVersion::V4)
        );
    }

    #[test]
    fn bad_version_rejected() {
        let mut a = base_args();
        a.nfs_version = Some(2);
        assert!(ShellConfig::from_args(a).is_err());
    }

    #[test]
    fn unsupported_proxy_scheme_rejected() {
        let mut a = base_args();
        a.proxy = Some("socks5h://127.0.0.1:1080".into());
        assert!(ShellConfig::from_args(a).is_err());
    }
}
