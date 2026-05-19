use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;

use anyhow::{Result, bail};
use ipnet::IpNet;

use crate::config::settings::DiscoveryConfig;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetHost {
    Ip(IpAddr),
    Hostname(String),
}

impl std::fmt::Display for TargetHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

pub fn resolve_single_target(spec: &str) -> Result<Vec<TargetHost>> {
    if let Ok(network) = spec.parse::<IpNet>() {
        let hosts: Vec<TargetHost> = network.hosts().map(TargetHost::Ip).collect();
        if hosts.is_empty() {
            // /32 (IPv4) or /128 (IPv6): hosts() may return empty, use network addr
            return Ok(vec![TargetHost::Ip(network.addr())]);
        }
        return Ok(hosts);
    }
    if let Ok(addr) = spec.parse::<IpAddr>() {
        return Ok(vec![TargetHost::Ip(addr)]);
    }
    Ok(vec![TargetHost::Hostname(spec.to_string())])
}

pub fn resolve_targets_from_list(specs: &[String]) -> Result<Vec<TargetHost>> {
    let mut targets = Vec::new();
    for spec in specs {
        targets.extend(resolve_single_target(spec)?);
    }
    Ok(targets)
}

pub fn resolve_targets_from_file(path: &str) -> Result<Vec<TargetHost>> {
    let reader: Box<dyn BufRead> = if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(path)?))
    };

    let mut targets = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        targets.extend(resolve_single_target(trimmed)?);
    }
    Ok(targets)
}

/// Resolve `--exclude` specs and `--exclude-file` contents into a set of
/// hosts to drop from the target list.
///
/// Specs are parsed exactly like targets (CIDR expands to member IPs), so
/// matching against a resolved target list is a literal set lookup.
/// Returns an empty set when neither exclusion source is configured.
pub async fn resolve_exclusions(config: &DiscoveryConfig) -> Result<HashSet<TargetHost>> {
    let mut excluded = HashSet::new();
    if let Some(ref specs) = config.excludes {
        excluded.extend(resolve_targets_from_list(specs)?);
    }
    if let Some(ref file_path) = config.exclude_file {
        let path = file_path.clone();
        let file_excludes = tokio::task::spawn_blocking(move || resolve_targets_from_file(&path))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
        excluded.extend(file_excludes);
    }
    Ok(excluded)
}

pub async fn resolve_targets(config: &DiscoveryConfig) -> Result<Vec<TargetHost>> {
    let mut targets = Vec::new();
    if let Some(ref specs) = config.targets {
        targets.extend(resolve_targets_from_list(specs)?);
    }
    if let Some(ref file_path) = config.target_file {
        let path = file_path.clone();
        let file_targets = tokio::task::spawn_blocking(move || resolve_targets_from_file(&path))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
        targets.extend(file_targets);
    }

    // Deduplicate while preserving insertion order
    let mut seen = HashSet::with_capacity(targets.len());
    targets.retain(|t| seen.insert(t.clone()));

    // Drop any hosts named by --exclude / --exclude-file.
    let excluded = resolve_exclusions(config).await?;
    if !excluded.is_empty() {
        let pre_filter_count = targets.len();
        targets.retain(|t| !excluded.contains(t));
        if pre_filter_count > 0 && targets.is_empty() {
            bail!("all targets were excluded by --exclude/--exclude-file");
        }
    }

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn disco_with(
        targets: Option<Vec<String>>,
        excludes: Option<Vec<String>>,
        exclude_file: Option<String>,
    ) -> DiscoveryConfig {
        DiscoveryConfig {
            targets,
            target_file: None,
            excludes,
            exclude_file,
            nfs_version: None,
            privileged_port: false,
            discovery_tasks: 10,
            timeout_secs: 5,
            proxy: None,
            connect_timeout_secs: 10,
        }
    }

    #[test]
    fn parse_cidr_24_expands() {
        let result = resolve_single_target("10.0.0.0/24").unwrap();
        assert_eq!(result.len(), 254);
        assert!(result.iter().all(|t| matches!(t, TargetHost::Ip(_))));
    }

    #[test]
    fn parse_cidr_32_single_host() {
        let result = resolve_single_target("10.0.0.1/32").unwrap();
        assert_eq!(result.len(), 1, "/32 must produce exactly one host");
        assert_eq!(result[0], TargetHost::Ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_cidr_128_ipv6_single_host() {
        let result = resolve_single_target("::1/128").unwrap();
        assert_eq!(result.len(), 1, "/128 must produce exactly one host");
        assert_eq!(result[0], TargetHost::Ip("::1".parse().unwrap()));
    }

    #[test]
    fn parse_cidr_30_small_range() {
        let result = resolve_single_target("192.168.1.0/30").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], TargetHost::Ip("192.168.1.1".parse().unwrap()));
        assert_eq!(result[1], TargetHost::Ip("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6_address() {
        let result = resolve_single_target("::1").unwrap();
        assert_eq!(result, vec![TargetHost::Ip("::1".parse().unwrap())]);
    }

    #[test]
    fn parse_hostname_passthrough() {
        let result = resolve_single_target("nfs-server.internal").unwrap();
        assert_eq!(
            result,
            vec![TargetHost::Hostname("nfs-server.internal".into())]
        );
    }

    #[test]
    fn parse_fqdn_passthrough() {
        let result = resolve_single_target("prod-nfs.corp.example.com").unwrap();
        assert_eq!(
            result,
            vec![TargetHost::Hostname("prod-nfs.corp.example.com".into())]
        );
    }

    #[test]
    fn resolve_list_mixed_targets() {
        let specs: Vec<String> = vec![
            "10.0.0.1".into(),
            "nfs-server".into(),
            "192.168.0.0/30".into(),
        ];
        let result = resolve_targets_from_list(&specs).unwrap();
        // 1 IP + 1 hostname + 2 CIDR hosts = 4
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn file_skips_comments() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "# comment").unwrap();
        writeln!(tmp, "10.0.0.1").unwrap();
        writeln!(tmp, "# another").unwrap();
        writeln!(tmp, "10.0.0.2").unwrap();
        tmp.flush().unwrap();

        let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn file_skips_empty_lines() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "10.0.0.1").unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp, "10.0.0.2").unwrap();
        tmp.flush().unwrap();

        let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn file_trims_whitespace() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "  10.0.0.1  ").unwrap();
        writeln!(tmp, "  nfs-server  ").unwrap();
        tmp.flush().unwrap();

        let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], TargetHost::Ip("10.0.0.1".parse().unwrap()));
        assert_eq!(result[1], TargetHost::Hostname("nfs-server".into()));
    }

    #[tokio::test]
    async fn resolve_targets_deduplicates_identical_ips() {
        let config = DiscoveryConfig {
            targets: Some(vec!["10.0.0.1".into(), "10.0.0.1".into()]),
            target_file: None,
            excludes: None,
            exclude_file: None,
            nfs_version: None,
            privileged_port: false,
            discovery_tasks: 10,
            timeout_secs: 5,
            proxy: None,
            connect_timeout_secs: 10,
        };
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result.len(), 1, "duplicate IPs should be deduplicated");
    }

    #[tokio::test]
    async fn resolve_targets_deduplicates_identical_hostnames() {
        let config = DiscoveryConfig {
            targets: Some(vec!["nfs-server".into(), "nfs-server".into()]),
            target_file: None,
            excludes: None,
            exclude_file: None,
            nfs_version: None,
            privileged_port: false,
            discovery_tasks: 10,
            timeout_secs: 5,
            proxy: None,
            connect_timeout_secs: 10,
        };
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(
            result.len(),
            1,
            "duplicate hostnames should be deduplicated"
        );
    }

    #[tokio::test]
    async fn resolve_targets_preserves_order_after_dedup() {
        let config = DiscoveryConfig {
            targets: Some(vec![
                "10.0.0.2".into(),
                "10.0.0.1".into(),
                "10.0.0.2".into(),
            ]),
            target_file: None,
            excludes: None,
            exclude_file: None,
            nfs_version: None,
            privileged_port: false,
            discovery_tasks: 10,
            timeout_secs: 5,
            proxy: None,
            connect_timeout_secs: 10,
        };
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], TargetHost::Ip("10.0.0.2".parse().unwrap()));
        assert_eq!(result[1], TargetHost::Ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn file_mixed_content() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "10.0.0.1").unwrap();
        writeln!(tmp, "nfs-server").unwrap();
        writeln!(tmp, "192.168.1.0/30").unwrap();
        writeln!(tmp, "# skip this").unwrap();
        writeln!(tmp, "::1").unwrap();
        tmp.flush().unwrap();

        let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
        // 1 IPv4 + 1 hostname + 2 CIDR hosts + 1 IPv6 = 5
        assert_eq!(result.len(), 5);
    }

    #[tokio::test]
    async fn exclude_single_ip_removes_it() {
        // 10.0.0.0/30 -> .1, .2 ; exclude .1 leaves .2
        let config = disco_with(
            Some(vec!["10.0.0.0/30".into()]),
            Some(vec!["10.0.0.1".into()]),
            None,
        );
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result, vec![TargetHost::Ip("10.0.0.2".parse().unwrap())]);
    }

    #[tokio::test]
    async fn exclude_cidr_removes_range() {
        // 10.0.0.0/29 -> .1..=.6 ; exclude 10.0.0.0/30 (.1, .2) leaves 4
        let config = disco_with(
            Some(vec!["10.0.0.0/29".into()]),
            Some(vec!["10.0.0.0/30".into()]),
            None,
        );
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result.len(), 4);
        assert!(!result.contains(&TargetHost::Ip("10.0.0.1".parse().unwrap())));
        assert!(!result.contains(&TargetHost::Ip("10.0.0.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn exclude_hostname_removes_match() {
        let config = disco_with(
            Some(vec!["nfs-a".into(), "nfs-b".into()]),
            Some(vec!["nfs-a".into()]),
            None,
        );
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result, vec![TargetHost::Hostname("nfs-b".into())]);
    }

    #[tokio::test]
    async fn exclude_non_matching_spec_is_noop() {
        let config = disco_with(
            Some(vec!["10.0.0.1".into()]),
            Some(vec!["10.0.0.99".into()]),
            None,
        );
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], TargetHost::Ip("10.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn exclude_all_targets_errors() {
        let config = disco_with(
            Some(vec!["10.0.0.0/30".into()]),
            Some(vec!["10.0.0.0/30".into()]),
            None,
        );
        let result = resolve_targets(&config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("all targets were excluded")
        );
    }

    #[tokio::test]
    async fn no_targets_with_exclusion_no_error() {
        let config = disco_with(None, Some(vec!["10.0.0.1".into()]), None);
        let result = resolve_targets(&config).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn exclude_from_file_filters_targets() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "# skip these").unwrap();
        writeln!(tmp, "10.0.0.1").unwrap();
        tmp.flush().unwrap();
        let config = disco_with(
            Some(vec!["10.0.0.0/30".into()]),
            None,
            Some(tmp.path().to_str().unwrap().to_string()),
        );
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result, vec![TargetHost::Ip("10.0.0.2".parse().unwrap())]);
    }

    #[tokio::test]
    async fn resolve_exclusions_unions_list_and_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "10.0.0.2").unwrap();
        tmp.flush().unwrap();
        let config = disco_with(
            None,
            Some(vec!["10.0.0.1".into()]),
            Some(tmp.path().to_str().unwrap().to_string()),
        );
        let excluded = resolve_exclusions(&config).await.unwrap();
        assert_eq!(excluded.len(), 2);
        assert!(excluded.contains(&TargetHost::Ip("10.0.0.1".parse().unwrap())));
        assert!(excluded.contains(&TargetHost::Ip("10.0.0.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn resolve_exclusions_empty_when_unset() {
        let config = disco_with(Some(vec!["10.0.0.1".into()]), None, None);
        let excluded = resolve_exclusions(&config).await.unwrap();
        assert!(excluded.is_empty());
    }
}
