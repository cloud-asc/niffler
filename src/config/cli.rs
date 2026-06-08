use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::classifier::Triage;
use crate::config::settings::{ExportFormat, OperatingMode};

#[derive(Parser)]
#[command(
    name = "niffler",
    about = "NFS share secret finder and interactive client"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: NifflerCommand,

    /// Log verbosity level
    #[arg(short = 'v', long, default_value = "info", global = true)]
    pub verbosity: Verbosity,
}

#[derive(Subcommand, Debug)]
pub enum NifflerCommand {
    /// Scan NFS shares for secrets
    Scan(Box<ScanArgs>),
    /// Interactive NFS client shell
    Shell(Box<ShellArgs>),
    /// Launch web dashboard for interactive triage
    Serve {
        /// Path to SQLite database
        #[arg(long)]
        db: PathBuf,

        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,

        /// Address to bind to
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
    },
    /// Export findings from database to stdout
    Export {
        /// Path to SQLite database
        #[arg(long)]
        db: PathBuf,

        /// Output format
        #[arg(short = 'f', long)]
        format: ExportFormat,

        /// Minimum triage severity to include
        #[arg(short = 'b', long)]
        min_severity: Option<Triage>,

        /// Filter by host
        #[arg(long)]
        host: Option<String>,

        /// Filter by rule name
        #[arg(long)]
        rule: Option<String>,

        /// Filter by scan ID
        #[arg(long)]
        scan_id: Option<i64>,
    },
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Targets: IP addresses, hostnames, or CIDR ranges
    #[arg(short = 't', long, num_args = 1..)]
    pub targets: Option<Vec<String>>,

    /// Read targets from file (one per line), use '-' for stdin
    #[arg(short = 'T', long = "target-file")]
    pub target_file: Option<String>,

    /// Hosts to exclude: IP addresses, hostnames, or CIDR ranges
    #[arg(short = 'x', long, num_args = 1..)]
    pub exclude: Option<Vec<String>>,

    /// Read hosts to exclude from file (one per line), use '-' for stdin
    #[arg(short = 'X', long = "exclude-file")]
    pub exclude_file: Option<String>,

    /// Scan local/mounted paths instead of discovering NFS shares
    #[arg(short = 'i', long, num_args = 1..)]
    pub local_path: Option<Vec<PathBuf>>,

    /// Operating mode
    #[arg(short = 'm', long, default_value = "scan")]
    pub mode: OperatingMode,

    /// Path to custom rules directory (replaces defaults)
    #[arg(short = 'r', long)]
    pub rules_dir: Option<PathBuf>,

    /// Path to additional rules (merged with defaults)
    #[arg(short = 'R', long)]
    pub extra_rules: Option<PathBuf>,

    /// Minimum triage severity to report
    #[arg(short = 'b', long, default_value = "green")]
    pub min_severity: Triage,

    /// Database output path
    #[arg(short = 'o', long, default_value = "niffler.db")]
    pub output: PathBuf,

    /// Force the full-screen live dashboard (even without a detected TTY)
    #[arg(long, conflicts_with = "plain")]
    pub tui: bool,

    /// Force plain line output (no dashboard); also the automatic non-TTY mode
    #[arg(long, alias = "no-tui")]
    pub plain: bool,

    /// UID for NFS AUTH_SYS credentials
    #[arg(long, default_value = "65534")]
    pub uid: u32,

    /// GID for NFS AUTH_SYS credentials
    #[arg(long, default_value = "65534")]
    pub gid: u32,

    /// Disable auto-cycling through discovered UIDs on permission denied
    #[arg(long)]
    pub no_uid_cycle: bool,

    /// Max UID attempts per file before giving up
    #[arg(long, default_value = "5")]
    pub max_uid_attempts: usize,

    /// Force NFS version (auto-detect if not set)
    #[arg(long)]
    pub nfs_version: Option<u8>,

    /// Disable binding source port < 1024
    #[arg(long)]
    pub no_privileged_port: bool,

    /// SOCKS5 proxy for all connections (e.g., socks5://127.0.0.1:1080)
    #[arg(long)]
    pub proxy: Option<String>,

    /// Max concurrent NFS connections per host
    #[arg(long, default_value = "8")]
    pub max_connections_per_host: usize,

    /// Max concurrent discovery tasks
    #[arg(long, default_value = "30")]
    pub discovery_tasks: usize,

    /// Timeout in seconds for discovery network operations (portmapper, mount)
    #[arg(long, default_value = "5")]
    pub discovery_timeout: u64,

    /// Max concurrent tree walk tasks (one per export)
    #[arg(long, default_value = "20")]
    pub walker_tasks: usize,

    /// Max concurrent file scan tasks
    #[arg(long, default_value = "50")]
    pub scanner_tasks: usize,

    /// Max directory depth during tree walk
    #[arg(long, default_value = "50")]
    pub max_depth: usize,

    /// Max entries read per directory (0 = unlimited) — caps client memory
    /// against servers returning pathologically large directories
    #[arg(long, default_value = "1000000")]
    pub max_dir_entries: usize,

    /// Max concurrent directory listings per export during tree walk
    #[arg(long, default_value = "8")]
    pub parallel_dirs: usize,

    /// Max retries per export walk on connection loss (0 = no retry)
    #[arg(long, default_value = "2")]
    pub walk_retries: usize,

    /// Base delay in ms between walk retries (exponential backoff with jitter)
    #[arg(long, default_value = "500")]
    pub walk_retry_delay: u64,

    /// Max retries per file scan on connection loss (0 = no retry)
    #[arg(long, default_value = "2")]
    pub scan_retries: usize,

    /// Base delay in ms between scanner retries (exponential backoff with jitter)
    #[arg(long, default_value = "200")]
    pub scan_retry_delay: u64,

    /// Timeout in seconds for establishing NFS connections (TCP + mount)
    #[arg(long, default_value = "10")]
    pub connect_timeout: u64,

    /// Timeout in seconds for individual NFS operations (read, readdirplus)
    #[arg(long, default_value = "30")]
    pub nfs_timeout: u64,

    /// Timeout in seconds for entire scanner task (defense-in-depth)
    #[arg(long, default_value = "300")]
    pub task_timeout: u64,

    /// Max file size to read content from (bytes)
    #[arg(long, default_value = "1048576")]
    pub max_scan_size: u64,

    /// NFS read chunk size in bytes
    #[arg(long, default_value = "1048576")]
    pub read_chunk_size: u32,

    /// Minimum events in health window before circuit breaker evaluates error rate
    #[arg(long, default_value = "10")]
    pub error_threshold: u32,

    /// Cooldown duration in seconds after circuit breaker trips
    #[arg(long, default_value = "60")]
    pub cooldown_secs: u64,

    /// Attempt subtree_check bypass detection via filehandle manipulation
    #[arg(long)]
    pub check_subtree_bypass: bool,

    /// Serialize current config to TOML and exit
    #[arg(short = 'z', long)]
    pub generate_config: bool,

    /// Load config from TOML file (all settings from file, CLI flags ignored)
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,
}

/// Interactive NFS client shell.
#[derive(Args, Debug)]
pub struct ShellArgs {
    /// Target NFS server host (can also be set later with `open`).
    #[arg(short = 't', long)]
    pub target: Option<String>,

    /// Export to mount on startup (requires --target).
    #[arg(short = 'e', long)]
    pub export: Option<String>,

    /// UID to present via AUTH_SYS.
    #[arg(long, default_value = "65534")]
    pub uid: u32,

    /// GID to present via AUTH_SYS.
    #[arg(long, default_value = "65534")]
    pub gid: u32,

    /// Force NFS protocol version (3 or 4); auto-detect if unset.
    #[arg(long)]
    pub nfs_version: Option<u8>,

    /// Connect from an unprivileged source port.
    #[arg(long)]
    pub no_privileged_port: bool,

    /// SOCKS5 proxy URL, e.g. socks5://127.0.0.1:1080 (v3 only).
    #[arg(long)]
    pub proxy: Option<String>,

    /// Per-directory entry cap for listings (0 = unlimited).
    #[arg(long, default_value = "1000000")]
    pub max_dir_entries: usize,

    /// SQLite database for `snaffle` (used by a later plan).
    #[arg(short = 'o', long, default_value = "niffler.db")]
    pub db: PathBuf,

    /// Run a semicolon/newline-separated command string non-interactively, then exit.
    #[arg(short = 'c', long)]
    pub command: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Verbosity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("failed to parse CLI args")
    }

    fn parse_scan(args: &[&str]) -> ScanArgs {
        let cli = parse(args);
        match cli.command {
            NifflerCommand::Scan(args) => *args,
            _ => panic!("expected Scan subcommand"),
        }
    }

    #[test]
    fn scan_subcommand_required() {
        let result = Cli::try_parse_from(["niffler"]);
        assert!(
            result.is_err(),
            "bare niffler with no subcommand should fail"
        );
    }

    #[test]
    fn cli_default_numeric_values() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert_eq!(
            args.uid, 65534,
            "default UID should be nobody (65534) for predictable baseline access"
        );
        assert_eq!(
            args.gid, 65534,
            "default GID should be nobody (65534) to match default UID"
        );
        assert_eq!(args.max_depth, 50);
        assert_eq!(args.max_scan_size, 1_048_576);
        assert_eq!(args.discovery_tasks, 30);
        assert_eq!(args.walker_tasks, 20);
        assert_eq!(args.scanner_tasks, 50);
        assert_eq!(args.max_connections_per_host, 8);
        assert_eq!(args.max_uid_attempts, 5);
        assert_eq!(args.connect_timeout, 10);
        assert_eq!(args.task_timeout, 300);
        assert_eq!(args.read_chunk_size, 1_048_576);
    }

    #[test]
    fn cli_default_bool_flags() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert!(!args.no_uid_cycle);
        assert!(!args.no_privileged_port);
        assert!(!args.generate_config);
        assert!(!args.check_subtree_bypass);
    }

    #[test]
    fn uid_cycle_can_be_disabled() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--no-uid-cycle"]);
        assert!(args.no_uid_cycle);
    }

    #[test]
    fn privileged_port_can_be_disabled() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--no-privileged-port"]);
        assert!(args.no_privileged_port);
    }

    #[test]
    fn exclude_accepts_multiple_specs() {
        let args = parse_scan(&[
            "niffler",
            "scan",
            "-t",
            "10.0.0.0/24",
            "-x",
            "10.0.0.5",
            "10.0.0.99",
            "nfs-old",
        ]);
        let excludes = args.exclude.expect("exclude should be set");
        assert_eq!(excludes, vec!["10.0.0.5", "10.0.0.99", "nfs-old"]);
    }

    #[test]
    fn exclude_file_flag_parses() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "-X", "skip.txt"]);
        assert_eq!(args.exclude_file.as_deref(), Some("skip.txt"));
    }

    #[test]
    fn exclude_defaults_to_none() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert!(args.exclude.is_none());
        assert!(args.exclude_file.is_none());
    }

    #[test]
    fn verbosity_global_after_subcommand() {
        let cli = parse(&["niffler", "scan", "-t", "10.0.0.1", "-v", "debug"]);
        assert!(matches!(cli.verbosity, Verbosity::Debug));
    }

    #[test]
    fn display_defaults_to_auto() {
        let args = parse_scan(&["niffler", "scan", "-t", "10.0.0.1"]);
        assert!(!args.tui);
        assert!(!args.plain);
    }

    #[test]
    fn tui_and_plain_flags_parse() {
        let a = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--tui"]);
        assert!(a.tui);
        let b = parse_scan(&["niffler", "scan", "-t", "10.0.0.1", "--plain"]);
        assert!(b.plain);
    }

    #[test]
    fn tui_and_plain_conflict() {
        let r = Cli::try_parse_from(["niffler", "scan", "-t", "10.0.0.1", "--tui", "--plain"]);
        assert!(r.is_err(), "--tui and --plain must conflict");
    }

    #[test]
    fn live_flag_removed() {
        let r = Cli::try_parse_from(["niffler", "scan", "-t", "10.0.0.1", "--live"]);
        assert!(r.is_err(), "--live should no longer be accepted");
    }

    #[test]
    fn parses_shell_subcommand() {
        let cli = Cli::try_parse_from([
            "niffler", "shell", "-t", "10.0.0.5", "-e", "/export", "--uid", "1000",
        ])
        .unwrap();
        match cli.command {
            NifflerCommand::Shell(args) => {
                assert_eq!(args.target.as_deref(), Some("10.0.0.5"));
                assert_eq!(args.export.as_deref(), Some("/export"));
                assert_eq!(args.uid, 1000);
                assert_eq!(args.gid, 65534);
            }
            _ => panic!("expected Shell"),
        }
    }

    #[test]
    fn shell_command_string_parses() {
        let cli = Cli::try_parse_from(["niffler", "shell", "-c", "ls; cat foo"]).unwrap();
        match cli.command {
            NifflerCommand::Shell(args) => assert_eq!(args.command.as_deref(), Some("ls; cat foo")),
            _ => panic!("expected Shell"),
        }
    }
}
