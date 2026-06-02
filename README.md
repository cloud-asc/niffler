# Niffler

[![CI](https://github.com/dejisec/niffler/actions/workflows/ci.yml/badge.svg)](https://github.com/dejisec/niffler/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dejisec/niffler)](https://github.com/dejisec/niffler/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org/)

Niffler scans NFS servers for credentials, secrets, and misconfigurations. Think [Snaffler](https://github.com/SnaffCon/Snaffler), but for NFS instead of SMB.

## Why NFS?

NFS (especially v3) authenticates with AUTH_SYS, which means the client sends a UID/GID in plaintext and the server takes its word for it. No password, no Kerberos ticket, no challenge-response. Reach the NFS port and you can claim to be any non-root user and read their files, or root itself if `no_root_squash` is set.

Niffler handles the tedious parts: finding exports, walking the trees, spoofing UIDs, and matching file content against a library of credential patterns.

## Install

Three ways to get it:

**Prebuilt binary** — grab one from the [Releases](https://github.com/dejisec/niffler/releases) page.

**Cargo** (needs [libnfs-dev](https://github.com/sahlberg/libnfs)):

```bash
cargo install --git https://github.com/dejisec/niffler
```

**From source** (needs [libnfs-dev](https://github.com/sahlberg/libnfs)):

```bash
git clone https://github.com/dejisec/niffler && cd niffler
cargo build --release
cp target/release/niffler .
```

## Quick start

```bash
# Scan a single NFS server
./niffler scan -t 10.0.0.5

# Scan a whole subnet
./niffler scan -t 192.168.1.0/24

# Recon only: list servers, exports, and misconfigs without reading files
./niffler scan -t 10.0.0.0/24 --mode recon

# Review results in the web dashboard
./niffler serve --db niffler.db

# Export findings as JSON
./niffler export --db niffler.db -f json
```

## Operating modes

Niffler runs in three modes, so you can dial in how deep you want to go:

| Mode | What it does | Use when... |
|------|-------------|-------------|
| `recon` | Finds NFS servers, lists exports, checks for misconfigurations | You want a quiet lay of the land |
| `enum` | Above + walks directory trees, matches filenames against rules | You want to see what's there without reading file content |
| `scan` | Above + reads file content and applies regex patterns | You want the full picture (default) |

## Recipes

```bash
# Only show high-severity findings (Red and Black)
./niffler scan -t nfs-server.internal -b red

# Scan as a specific user (e.g. a UID you found during recon)
./niffler scan -t nfs-server.internal --uid 1000 --gid 1000

# Route through a SOCKS5 proxy
./niffler scan -t 10.0.0.5 --proxy socks5://127.0.0.1:1080

# Scan local or already-mounted shares, skipping network discovery
./niffler scan -i /mnt/nfs_share1 /mnt/nfs_share2

# Read targets from a file (one per line, CIDR ok; use - for stdin)
./niffler scan -T targets.txt

# Scan a subnet but skip a few hosts
./niffler scan -t 10.0.0.0/24 -x 10.0.0.5 10.0.0.99

# Write results to a custom database
./niffler scan -t 10.0.0.0/24 -o engagement.db

# Generate a config template, edit it, then reuse
./niffler scan -z > niffler.toml
./niffler scan -c niffler.toml -t 10.0.0.0/24

# Serve the dashboard on a specific address
./niffler serve --db niffler.db --port 9090 --bind 0.0.0.0

# Export Red+ findings as CSV, or a single host as TSV
./niffler export --db niffler.db -f csv -b red
./niffler export --db niffler.db -f tsv --host 10.0.0.5
```

Every flag is documented in `niffler scan --help` (and likewise `serve --help` and `export --help`).

## Output

All results land in a SQLite database (`niffler.db` by default).

### Live dashboard

In an interactive terminal, Niffler shows a full-screen dashboard while it scans: phase progress, a live severity-colored findings feed (scroll with the arrows/PgUp/PgDn, filter with `f`, pause with `p`), and a log pane. Press `q` or Ctrl-C to stop, and it prints a summary card on the way out.

Outside a terminal (pipes, redirects, CI), it switches to plain line output: heartbeat progress plus one line per finding on stdout, safe to pipe. Force either mode with `--tui` or `--plain`.

```
./niffler scan -t 10.0.0.5 --plain | grep BLACK
```

### Web dashboard (`serve`)

Launch a local web UI to review findings in your browser. Filter the list, star anything worth a second look, and open a finding to see its match in context:

```bash
./niffler serve --db niffler.db
# then open http://127.0.0.1:8080
```

### Export (`export`)

Pull findings out of the database as JSON lines, CSV, or TSV:

```bash
./niffler export --db niffler.db -f json                 # JSON lines to stdout
./niffler export --db niffler.db -f csv -b red           # CSV, Red and Black only
./niffler export --db niffler.db -f tsv --host 10.0.0.5  # TSV, single host
```

## Severity levels

Findings are triaged into four levels. Use `-b` to set a minimum severity threshold.

| Level | Meaning | Examples |
|-------|---------|----------|
| **Black** | Immediate, direct impact — usable credentials or key material | SSH private keys, shadow files, Vault tokens, KeePass databases |
| **Red** | High-value — likely contains secrets, needs a closer look | `.env` files with passwords, AWS access keys, database connection strings |
| **Yellow** | Interesting — worth noting but may not be directly exploitable | Config files, log files with potential info |
| **Green** | Informational — context that helps paint the bigger picture | Scripts, documentation, data files on interesting exports |

```bash
./niffler scan -t 10.0.0.5 -b red      # Only Red and Black findings
./niffler scan -t 10.0.0.5 -b black    # Only Black findings
```

## How it works

Niffler runs as a multi-phase async pipeline:

```
Targets ──► Discovery ──► Tree Walker ──► File Scanner ──► Output
              │                │                │
         find servers     walk exports     read content
         list exports     parallel dirs    match filenames
         harvest UIDs     prune junk dirs  match patterns
         detect misconfig retry on loss    check for keys
                                           UID cycling
                                           retry on loss
```

**Discovery** finds NFS servers (port scan on 111/2049), queries the portmapper and MOUNT service for exports, harvests UIDs from directory listings, and checks for misconfigurations.

**Tree Walker** does a parallel recursive READDIRPLUS traversal of each export (`--parallel-dirs` concurrent directory listings), applying directory discard rules to prune uninteresting paths early.

**File Scanner** reads file content and runs it through the rule engine using a connection pool (`--max-connections-per-host`). When a file is permission-denied, Niffler cycles through harvested UIDs (AUTH_SYS spoofing) to try reading it as different users. Failed reads are retried with exponential backoff (`--scan-retries`).

**Circuit Breaker** watches the error rate per host. If a server's error rate climbs past 80% within a sliding window (after at least `--error-threshold` events), the host is suspended so Niffler stops hammering an unhealthy server. The first cooldown lasts `--cooldown-secs`; each repeat trip doubles it, up to 64×.

**UID Cycling** is the secret sauce. When the scanner hits a permission wall, it tries:

1. The primary UID (from `--uid`/`--gid`, default: nobody/65534)
2. The file's owning UID (from stat — most likely to work)
3. UIDs harvested during discovery (from directory listings)

Each attempt opens a new NFS connection with fresh AUTH_SYS credentials. NFS file handles are valid across connections, so a handle the walker obtained can be read by the scanner under a completely different UID.

### NFSv4

Niffler supports NFSv4 via [libnfs](https://github.com/sahlberg/libnfs). When you don't specify a version it defaults to NFSv3; force v4 when the target only exposes v4 or you want to test v4-specific behavior:

```bash
./niffler scan -t 10.0.0.5 --nfs-version 4
```

## Rule engine

Rules are defined in TOML and compiled into the binary. The engine uses a **relay-chain architecture** (borrowed from Snaffler): cheap rules gate expensive ones.

Take a file named `.env`. It first matches a filename rule (instant). That rule *relays* to content rules, which read the file and apply regex patterns (expensive). So the regex only runs on files that are already likely to contain something interesting.

```
.env file found
  └─► FileEnumeration rule matches ".env" (Relay action)
        ├─► CredentialPatterns: scans for password=, api_key=, bearer tokens, etc.
        ├─► CloudKeyPatterns: scans for AKIA..., aws_secret_access_key, etc.
        └─► TokenPatterns: scans for Slack xox*, GitHub ghp_, JWT, etc.
```

Rules have four scopes:

- **ShareEnumeration** — applied to export paths during discovery
- **DirectoryEnumeration** — applied to directory names during tree walk
- **FileEnumeration** — applied to filenames/extensions/paths in the scanner
- **ContentsEnumeration** — applied to file content (most expensive, gated by relays)

### Custom rules

Replace the defaults entirely or merge your own on top:

```bash
# Replace all built-in rules with your own
./niffler scan -t 10.0.0.5 -r /path/to/my-rules/

# Keep defaults and add extra rules
./niffler scan -t 10.0.0.5 -R /path/to/extra-rules/
```

Rules are TOML files with a straightforward structure:

```toml
[[rules]]
name = "MyCustomPattern"
scope = "ContentsEnumeration"
match_location = "FileContentAsString"
match_type = "Regex"
patterns = ['(?i)internal_api_key\s*=\s*["\'][^"\']{16,}']
action = "Snaffle"
triage = "Red"
max_size = 1048576
context_bytes = 200
description = "Custom internal API key pattern"
```

## Misconfiguration detection

During discovery, Niffler probes each export for common NFS misconfigurations:

| Check | What it means | How Niffler tests it |
|-------|---------------|---------------------|
| **no_root_squash** | UID 0 isn't squashed, so root may be able to read or write anything | Connects as UID 0 and tries `getattr` on the export root. A success is a strong hint, not proof: a squashed `nobody` can still stat a world-readable root |
| **insecure** | Export accepts connections from unprivileged ports (>1024) | Connects from a high port, checks if `getattr` succeeds |
| **subtree_check bypass** | File handles can escape the export boundary | Looks up `..` from the export root, checks if the returned handle differs |

The subtree bypass check is off by default since it adds an extra probe per export. Turn it on with `--check-subtree-bypass`:

```bash
./niffler scan -t 10.0.0.0/24 --check-subtree-bypass
```
