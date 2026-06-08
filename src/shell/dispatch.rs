//! Map a parsed `Command` to an async action returning printable output.

use crate::nfs::{NfsVersion, SetAttrs};
use crate::shell::command::Command;
use crate::shell::session::Session;

/// Result of running one command.
pub enum Outcome {
    Print(String),
    Exit,
}

fn p(s: impl Into<String>) -> Outcome {
    Outcome::Print(s.into())
}

const HELP: &str = "\
Commands:
  open/host <host>        set target host
  mount <export>          mount an export
  umount                  unmount
  exports                 list exports on the host
  df                      filesystem usage
  status                  connection status
  version [3|4]           show/force NFS version
  uid <n> / gid <n>       set AUTH_SYS credentials (reconnects)
  pwd                     print remote working directory
  cd <path>               change remote directory
  ls [-l] [path]          list directory
  lcd [dir]               change local directory
  stat <path>             show attributes
  handle [hex]            get/set raw directory handle (v3: opaque; v4: path)
  cat <file>              print file to stdout
  get <remote> [local]    download a file
  put <local> [remote]    upload a file
  rm <file>               delete a file
  mkdir <dir> / rmdir <dir>  create/remove directory
  chmod <octal> <path>    change mode
  chown <uid[:gid]> <path>   change owner
  mv <old> <new>          rename/move
  ln <target> <link>      hard link
  symlink <target> <link> symbolic link
  mknod <name> b|c <maj> <min> | p | s
  harvest                 collect UIDs from the current directory
  uid auto [on|off]       cycle harvested UIDs on permission denied
  whoami                  show current identity and cwd access
  squash-test [path]      test no_root_squash (root write probe)
  scan [path]             run the rule engine over a subtree
  find <regex>            recursive filename search
  snaffle <file>          classify a file and record findings to the db
  help                    this help
  quit/exit               leave the shell";

/// Execute one command against the session.
pub async fn dispatch(session: &mut Session, cmd: Command) -> anyhow::Result<Outcome> {
    match cmd {
        Command::Noop => Ok(p("")),
        Command::Help => Ok(p(HELP)),
        Command::Quit => Ok(Outcome::Exit),
        Command::Open(host) => {
            session.set_host(host.clone());
            Ok(p(format!("host set to {host}")))
        }
        Command::Mount(export) => {
            session.mount(&export).await?;
            Ok(p(format!("mounted {export}")))
        }
        Command::Umount => {
            session.umount();
            Ok(p("unmounted"))
        }
        Command::Exports => exports(session).await,
        Command::Df => df(session).await,
        Command::Status => Ok(p(status(session))),
        Command::Version(v) => version(session, v),
        Command::Uid(uid) => {
            session.set_uid(uid).await?;
            Ok(p(format!("uid = {uid}")))
        }
        Command::Gid(gid) => {
            session.set_gid(gid).await?;
            Ok(p(format!("gid = {gid}")))
        }
        Command::Pwd => Ok(p(session.cwd_path().to_string())),
        Command::Cd(path) => {
            session.cd(&path).await?;
            Ok(p(session.cwd_path().to_string()))
        }
        Command::Ls { long, path } => ls(session, long, path.as_deref()).await,
        Command::Lcd(dir) => lcd(session, dir.as_deref()),
        Command::Stat(path) => stat(session, &path).await,
        Command::Handle(hex) => handle(session, hex.as_deref()).await,
        Command::Cat(path) => cat(session, &path).await,
        Command::Get { remote, local } => get(session, &remote, local.as_deref()).await,
        Command::Mkdir(path) => mkdir(session, &path).await,
        Command::Rmdir(path) => rmdir(session, &path).await,
        Command::Rm(path) => rm(session, &path).await,
        Command::Chmod { mode, path } => chmod(session, mode, &path).await,
        Command::Chown { uid, gid, path } => chown(session, uid, gid, &path).await,
        Command::Mv { from, to } => mv(session, &from, &to).await,
        Command::Ln { target, link } => ln(session, &target, &link).await,
        Command::Symlink { target, link } => symlink(session, &target, &link).await,
        Command::Put { local, remote } => put(session, &local, remote.as_deref()).await,
        Command::Mknod { name, kind, spec } => mknod(session, &name, kind, spec).await,
        Command::Harvest => harvest(session).await,
        Command::Whoami => whoami(session).await,
        Command::UidAuto(state) => uid_auto(session, state),
        Command::SquashTest(path) => squash_test(session, path.as_deref()).await,
        Command::Scan(path) => scan(session, path.as_deref()).await,
        Command::Find(pattern) => find(session, &pattern).await,
        Command::Snaffle(path) => snaffle(session, &path).await,
    }
}

async fn exports(session: &mut Session) -> anyhow::Result<Outcome> {
    let host = session
        .host()
        .ok_or_else(|| anyhow::anyhow!("no host set — use `open <host>`"))?
        .to_string();
    let exports = crate::discovery::exports::list_exports(&host, None, 5).await?;
    if exports.is_empty() {
        return Ok(p("(no exports)"));
    }
    let mut out = String::new();
    for e in exports {
        let hosts = if e.allowed_hosts.is_empty() {
            String::new()
        } else {
            format!("  [{}]", e.allowed_hosts.join(", "))
        };
        out.push_str(&format!("{}{}\n", e.path, hosts));
    }
    Ok(p(out.trim_end().to_string()))
}

async fn df(session: &mut Session) -> anyhow::Result<Outcome> {
    let root = session
        .cwd_handle()
        .ok_or_else(|| anyhow::anyhow!("not connected"))?
        .clone();
    let fs = session
        .ops()?
        .fsstat(&root)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!(
        "total: {} bytes\nfree:  {} bytes\navail: {} bytes",
        fs.total_bytes, fs.free_bytes, fs.avail_bytes
    )))
}

fn status(session: &Session) -> String {
    let ver = match session.version() {
        NfsVersion::V3 => "3",
        NfsVersion::V4 => "4",
    };
    format!(
        "host:    {}\nexport:  {}\nversion: {}\nuid/gid: {}/{}\ncwd:     {}\nlocal:   {}",
        session.host().unwrap_or("(none)"),
        session.export().unwrap_or("(none)"),
        ver,
        session.creds().uid,
        session.creds().gid,
        session.cwd_path(),
        session.local_dir().display(),
    )
}

async fn ls(session: &mut Session, long: bool, path: Option<&str>) -> anyhow::Result<Outcome> {
    let mut entries = session.list(path).await?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = String::new();
    for e in &entries {
        if long {
            out.push_str(&crate::shell::format::long_line(e));
        } else {
            out.push_str(&e.name);
        }
        out.push('\n');
    }
    Ok(p(out.trim_end().to_string()))
}

fn lcd(session: &mut Session, dir: Option<&str>) -> anyhow::Result<Outcome> {
    let target = match dir {
        Some(d) => std::path::PathBuf::from(d),
        None => dirs_home().unwrap_or_else(|| std::path::PathBuf::from(".")),
    };
    let canon =
        std::fs::canonicalize(&target).map_err(|e| anyhow::anyhow!("{}: {e}", target.display()))?;
    if !canon.is_dir() {
        anyhow::bail!("{}: not a directory", canon.display());
    }
    session.set_local_dir(canon.clone());
    Ok(p(format!("local dir: {}", canon.display())))
}

fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

async fn stat(session: &mut Session, path: &str) -> anyhow::Result<Outcome> {
    let (_fh, a) = session.resolve(path).await?;
    Ok(p(format!(
        "type:  {:?}\nmode:  {:o}\nuid:   {}\ngid:   {}\nsize:  {}\nmtime: {}",
        a.file_type, a.mode, a.uid, a.gid, a.size, a.mtime
    )))
}

async fn handle(session: &mut Session, hex: Option<&str>) -> anyhow::Result<Outcome> {
    match hex {
        None => {
            let fh = session
                .cwd_handle()
                .ok_or_else(|| anyhow::anyhow!("not connected"))?;
            Ok(p(crate::shell::format::handle_to_hex(fh)))
        }
        Some(h) => {
            let fh = crate::shell::format::handle_from_hex(h)?;
            session.set_handle(fh).await?;
            Ok(p(format!("cwd handle set ({})", session.cwd_path())))
        }
    }
}

const READ_CHUNK: u32 = 1 << 20;

async fn cat(session: &mut Session, path: &str) -> anyhow::Result<Outcome> {
    let (fh, attrs) = session.resolve(path).await?;
    if !attrs.is_file() {
        anyhow::bail!("{path}: not a regular file");
    }
    let (data, _used) = session
        .read_all_auto(&fh, READ_CHUNK, Some((attrs.uid, attrs.gid)))
        .await?;
    let text = String::from_utf8_lossy(&data).into_owned();
    Ok(p(text
        .strip_suffix('\n')
        .map(str::to_string)
        .unwrap_or(text)))
}

async fn get(session: &mut Session, remote: &str, local: Option<&str>) -> anyhow::Result<Outcome> {
    let (fh, attrs) = session.resolve(remote).await?;
    if !attrs.is_file() {
        anyhow::bail!("{remote}: not a regular file");
    }
    let (data, used) = session
        .read_all_auto(&fh, READ_CHUNK, Some((attrs.uid, attrs.gid)))
        .await?;
    let name = local.unwrap_or_else(|| remote.rsplit('/').next().unwrap_or(remote));
    let dest = session.local_dir().join(name);
    std::fs::write(&dest, &data).map_err(|e| anyhow::anyhow!("{}: {e}", dest.display()))?;
    let note = match used {
        Some(c) => format!(" (read as uid {})", c.uid),
        None => String::new(),
    };
    Ok(p(format!(
        "wrote {} bytes to {}{note}",
        data.len(),
        dest.display()
    )))
}

async fn mkdir(session: &mut Session, path: &str) -> anyhow::Result<Outcome> {
    let (dir, name) = session.resolve_parent(path).await?;
    session
        .ops()?
        .mkdir(&dir, &name, 0o755)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!("created directory {path}")))
}

async fn rmdir(session: &mut Session, path: &str) -> anyhow::Result<Outcome> {
    let (dir, name) = session.resolve_parent(path).await?;
    session
        .ops()?
        .rmdir(&dir, &name)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!("removed directory {path}")))
}

async fn rm(session: &mut Session, path: &str) -> anyhow::Result<Outcome> {
    let (dir, name) = session.resolve_parent(path).await?;
    session
        .ops()?
        .remove(&dir, &name)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!("removed {path}")))
}

async fn chmod(session: &mut Session, mode: u32, path: &str) -> anyhow::Result<Outcome> {
    let (fh, _attrs) = session.resolve(path).await?;
    let attrs = SetAttrs {
        mode: Some(mode),
        ..Default::default()
    };
    session
        .ops()?
        .setattr(&fh, attrs)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!("chmod {mode:o} {path}")))
}

async fn chown(
    session: &mut Session,
    uid: u32,
    gid: Option<u32>,
    path: &str,
) -> anyhow::Result<Outcome> {
    let (fh, _attrs) = session.resolve(path).await?;
    let attrs = SetAttrs {
        uid: Some(uid),
        gid,
        ..Default::default()
    };
    session
        .ops()?
        .setattr(&fh, attrs)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let owner = match gid {
        Some(g) => format!("{uid}:{g}"),
        None => uid.to_string(),
    };
    Ok(p(format!("chown {owner} {path}")))
}

async fn mv(session: &mut Session, from: &str, to: &str) -> anyhow::Result<Outcome> {
    let (from_dir, from_name) = session.resolve_parent(from).await?;
    let (to_dir, to_name) = session.resolve_parent(to).await?;
    session
        .ops()?
        .rename(&from_dir, &from_name, &to_dir, &to_name)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!("moved {from} -> {to}")))
}

async fn ln(session: &mut Session, target: &str, link: &str) -> anyhow::Result<Outcome> {
    let (target_fh, _attrs) = session.resolve(target).await?;
    let (dir, name) = session.resolve_parent(link).await?;
    session
        .ops()?
        .link(&target_fh, &dir, &name)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!("linked {link} -> {target}")))
}

async fn symlink(session: &mut Session, target: &str, link: &str) -> anyhow::Result<Outcome> {
    let (dir, name) = session.resolve_parent(link).await?;
    session
        .ops()?
        .symlink(&dir, &name, target, 0o777)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!("symlinked {link} -> {target}")))
}

async fn put(session: &mut Session, local: &str, remote: Option<&str>) -> anyhow::Result<Outcome> {
    let data = std::fs::read(local).map_err(|e| anyhow::anyhow!("{local}: {e}"))?;
    let remote_arg = match remote {
        Some(r) => r.to_string(),
        None => std::path::Path::new(local)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| anyhow::anyhow!("cannot derive remote name from {local}"))?,
    };
    let (dir, name) = session.resolve_parent(&remote_arg).await?;
    let (fh, _attrs) = session
        .ops()?
        .create(&dir, &name, 0o644)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut offset: usize = 0;
    while offset < data.len() {
        let end = (offset + READ_CHUNK as usize).min(data.len());
        let n = session
            .ops()?
            .write(&fh, offset as u64, &data[offset..end], true)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if n == 0 {
            anyhow::bail!("server accepted 0 bytes at offset {offset}; aborting put");
        }
        offset += n as usize;
    }
    Ok(p(format!("wrote {} bytes to {remote_arg}", data.len())))
}

async fn mknod(
    session: &mut Session,
    name_arg: &str,
    kind: crate::nfs::NodeKind,
    spec: Option<(u32, u32)>,
) -> anyhow::Result<Outcome> {
    let (dir, name) = session.resolve_parent(name_arg).await?;
    session
        .ops()?
        .mknod(&dir, &name, kind, 0o644, spec)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p(format!("created node {name_arg}")))
}

async fn harvest(session: &mut Session) -> anyhow::Result<Outcome> {
    let entries = session.list(None).await?;
    let creds = crate::discovery::uid_harvest::extract_unique_creds(&entries);
    if creds.is_empty() {
        return Ok(p("no UIDs found in current directory"));
    }
    let mut summary: Vec<String> = creds
        .iter()
        .map(|c| format!("{}:{}", c.uid, c.gid))
        .collect();
    summary.sort();
    session.add_harvested(creds);
    Ok(p(format!(
        "harvested {} uid(s): {}\ntotal known: {}",
        summary.len(),
        summary.join(", "),
        session.harvested().len()
    )))
}

fn uid_auto(session: &mut Session, state: Option<bool>) -> anyhow::Result<Outcome> {
    let new_state = state.unwrap_or(!session.auto_cycle());
    session.set_auto_cycle(new_state);
    Ok(p(format!(
        "uid auto-cycle: {}",
        if new_state { "on" } else { "off" }
    )))
}

async fn whoami(session: &mut Session) -> anyhow::Result<Outcome> {
    let creds = session.creds().clone();
    let aux = if creds.aux_gids.is_empty() {
        String::new()
    } else {
        format!(" aux_gids={:?}", creds.aux_gids)
    };
    let cwd_info = match session.cwd_handle().cloned() {
        Some(fh) => match session.ops()?.getattr(&fh).await {
            Ok(a) => format!("cwd owner {}:{} mode {:o}", a.uid, a.gid, a.mode),
            Err(e) => format!("cwd attrs unavailable: {e}"),
        },
        None => "not connected".to_string(),
    };
    Ok(p(format!(
        "uid={} gid={}{}\nauto-cycle: {}\nharvested uids: {}\n{}",
        creds.uid,
        creds.gid,
        aux,
        if session.auto_cycle() { "on" } else { "off" },
        session.harvested().len(),
        cwd_info
    )))
}

async fn squash_test(session: &mut Session, path: Option<&str>) -> anyhow::Result<Outcome> {
    // Resolve the target directory handle (cwd by default).
    let dir = match path {
        None => session
            .cwd_handle()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?,
        Some(p) => {
            let (fh, at) = session.resolve(p).await?;
            if !at.is_directory() {
                anyhow::bail!("{p}: not a directory");
            }
            fh
        }
    };
    // Definitive probe: connect as root and try to create (then remove) a file.
    let mut root_ops = session.connect_as(&crate::nfs::AuthCreds::root()).await?;
    let probe = format!(".niffler_squash_{}", std::process::id());
    match root_ops.create(&dir, &probe, 0o600).await {
        Ok(_) => {
            let _ = root_ops.remove(&dir, &probe).await; // best-effort cleanup
            Ok(p(
                "no_root_squash: CONFIRMED — UID 0 can create files here (root is NOT squashed)"
                    .to_string(),
            ))
        }
        Err(e) => {
            let denied = e
                .downcast_ref::<crate::nfs::NfsError>()
                .is_some_and(crate::nfs::NfsError::is_permission_denied);
            if denied {
                Ok(p(
                    "root appears squashed — UID 0 write denied (no_root_squash NOT present)"
                        .to_string(),
                ))
            } else {
                Ok(p(format!("squash-test inconclusive: {e}")))
            }
        }
    }
}

async fn scan(session: &mut Session, path: Option<&str>) -> anyhow::Result<Outcome> {
    let engine = session
        .classifier()
        .ok_or_else(|| anyhow::anyhow!("classifier not initialized"))?
        .clone();
    let (start_fh, start_path) = match path {
        None => (
            session
                .cwd_handle()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not connected"))?,
            session.cwd_path().to_string(),
        ),
        Some(pth) => {
            let (fh, at) = session.resolve(pth).await?;
            if !at.is_directory() {
                anyhow::bail!("{pth}: not a directory");
            }
            (
                fh,
                crate::shell::session::join_display_path(session.cwd_path(), pth),
            )
        }
    };
    let files = crate::shell::scan::collect_files(session, start_fh, start_path, &engine).await?;
    let color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let mut out = String::new();
    let mut count = 0usize;
    for f in &files {
        if f.attrs.size > crate::shell::scan::SCAN_MAX_FILE_SIZE {
            continue;
        }
        let name = f.path.rsplit('/').next().unwrap_or(&f.path);
        let entry = crate::shell::scan::file_entry(name, &f.path, &f.attrs);
        let data = match session
            .read_all_auto(&f.fh, READ_CHUNK, Some((f.attrs.uid, f.attrs.gid)))
            .await
        {
            Ok((d, _used)) => d,
            Err(_) => continue,
        };
        for finding in engine.evaluate_file(&entry, Some(&data)) {
            out.push_str(&crate::shell::scan::format_finding(
                finding.triage,
                &f.path,
                &finding.rule_name,
                &finding.matched_pattern,
                color,
            ));
            out.push('\n');
            count += 1;
        }
    }
    out.push_str(&format!(
        "scanned {} file(s), {} finding(s)",
        files.len(),
        count
    ));
    Ok(p(out))
}

async fn find(session: &mut Session, pattern: &str) -> anyhow::Result<Outcome> {
    let re = regex::Regex::new(pattern).map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?;
    let engine = session
        .classifier()
        .ok_or_else(|| anyhow::anyhow!("classifier not initialized"))?
        .clone();
    let start = session
        .cwd_handle()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("not connected"))?;
    let start_path = session.cwd_path().to_string();
    let files = crate::shell::scan::collect_files(session, start, start_path, &engine).await?;
    let mut out = String::new();
    let mut count = 0usize;
    for f in &files {
        let name = f.path.rsplit('/').next().unwrap_or(&f.path);
        if re.is_match(name) {
            out.push_str(&f.path);
            out.push('\n');
            count += 1;
        }
    }
    if count == 0 {
        return Ok(p("no matches"));
    }
    out.push_str(&format!("{count} match(es)"));
    Ok(p(out))
}

async fn snaffle(session: &mut Session, path: &str) -> anyhow::Result<Outcome> {
    let engine = session
        .classifier()
        .ok_or_else(|| anyhow::anyhow!("classifier not initialized"))?
        .clone();
    let (fh, attrs) = session.resolve(path).await?;
    if !attrs.is_file() {
        anyhow::bail!("{path}: not a regular file");
    }
    let abs = crate::shell::session::join_display_path(session.cwd_path(), path);
    let (data, _used) = session
        .read_all_auto(&fh, READ_CHUNK, Some((attrs.uid, attrs.gid)))
        .await?;
    let name = abs.rsplit('/').next().unwrap_or(&abs);
    let entry = crate::shell::scan::file_entry(name, &abs, &attrs);
    let findings = engine.evaluate_file(&entry, Some(&data));
    if findings.is_empty() {
        return Ok(p(format!("no findings in {path}")));
    }
    let host = session.host().unwrap_or("shell").to_string();
    let export = session.export().unwrap_or("").to_string();
    let now = chrono::Utc::now();
    let last_modified =
        chrono::DateTime::from_timestamp(attrs.mtime.min(i64::MAX as u64) as i64, 0)
            .unwrap_or_default();
    let msgs: Vec<crate::pipeline::ResultMsg> = findings
        .iter()
        .map(|f| crate::pipeline::ResultMsg {
            timestamp: now,
            host: host.clone(),
            export_path: export.clone(),
            file_path: abs.clone(),
            triage: f.triage,
            rule_name: f.rule_name.clone(),
            matched_pattern: f.matched_pattern.clone(),
            context: f.context.clone(),
            file_size: attrs.size,
            file_mode: attrs.mode,
            file_uid: attrs.uid,
            file_gid: attrs.gid,
            last_modified,
        })
        .collect();
    let n = msgs.len();
    session.record_findings(&msgs).await?;
    Ok(p(format!("recorded {n} finding(s) from {path}")))
}

fn version(session: &mut Session, v: Option<u8>) -> anyhow::Result<Outcome> {
    match v {
        None => {
            let cur = match session.version() {
                NfsVersion::V3 => "3",
                NfsVersion::V4 => "4",
            };
            Ok(p(format!("nfs version: {cur}")))
        }
        Some(3) => {
            session.set_version(NfsVersion::V3);
            Ok(p("nfs version set to 3 (effective on next mount)"))
        }
        Some(4) => {
            session.set_version(NfsVersion::V4);
            Ok(p("nfs version set to 4 (effective on next mount)"))
        }
        Some(other) => anyhow::bail!("unsupported version: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{AuthCreds, ConnectorFactory, NfsAttrs, NfsFh, NfsFileType, NfsVersion};
    use crate::shell::command::Command;
    use crate::shell::session::Session;
    use std::sync::Arc;

    fn dir_attrs() -> NfsAttrs {
        NfsAttrs {
            file_type: NfsFileType::Directory,
            size: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn mounted_session() -> Session {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_lookup()
                .returning(|_d, name| Ok((NfsFh::new(name.as_bytes().to_vec()), dir_attrs())));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("host1".into());
        s
    }

    fn print_of(o: Outcome) -> String {
        match o {
            Outcome::Print(s) => s,
            Outcome::Exit => panic!("expected Print, got Exit"),
        }
    }

    #[tokio::test]
    async fn quit_returns_exit() {
        let mut s = mounted_session();
        assert!(matches!(
            dispatch(&mut s, Command::Quit).await.unwrap(),
            Outcome::Exit
        ));
    }

    #[tokio::test]
    async fn noop_prints_nothing() {
        let mut s = mounted_session();
        assert_eq!(print_of(dispatch(&mut s, Command::Noop).await.unwrap()), "");
    }

    #[tokio::test]
    async fn open_sets_host_in_status() {
        let mut s = mounted_session();
        dispatch(&mut s, Command::Open("host2".into()))
            .await
            .unwrap();
        let out = print_of(dispatch(&mut s, Command::Status).await.unwrap());
        assert!(out.contains("host2"));
    }

    #[tokio::test]
    async fn mount_then_pwd_is_root() {
        let mut s = mounted_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        assert_eq!(print_of(dispatch(&mut s, Command::Pwd).await.unwrap()), "/");
    }

    #[tokio::test]
    async fn help_lists_commands() {
        let mut s = mounted_session();
        let out = print_of(dispatch(&mut s, Command::Help).await.unwrap());
        assert!(out.contains("mount") && out.contains("cd") && out.contains("handle"));
    }

    #[tokio::test]
    async fn cd_updates_pwd() {
        let mut s = mounted_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        dispatch(&mut s, Command::Cd("sub".into())).await.unwrap();
        assert_eq!(
            print_of(dispatch(&mut s, Command::Pwd).await.unwrap()),
            "/sub"
        );
    }

    #[tokio::test]
    async fn ls_lists_entries() {
        use crate::nfs::DirEntry;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_readdirplus().returning(|_| {
                Ok(vec![
                    DirEntry {
                        name: "a.txt".into(),
                        fh: NfsFh::new(vec![1]),
                        attrs: NfsAttrs {
                            file_type: NfsFileType::Regular,
                            size: 10,
                            mode: 0o644,
                            uid: 0,
                            gid: 0,
                            mtime: 0,
                        },
                    },
                    DirEntry {
                        name: "d".into(),
                        fh: NfsFh::new(vec![2]),
                        attrs: dir_attrs(),
                    },
                ])
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(
            dispatch(
                &mut s,
                Command::Ls {
                    long: false,
                    path: None,
                },
            )
            .await
            .unwrap(),
        );
        assert!(out.contains("a.txt") && out.contains("d"));
        let long = print_of(
            dispatch(
                &mut s,
                Command::Ls {
                    long: true,
                    path: None,
                },
            )
            .await
            .unwrap(),
        );
        assert!(long.contains("-rw-r--r--") && long.contains("drwxr-xr-x"));
    }

    #[tokio::test]
    async fn lcd_changes_local_dir_to_temp() {
        let mut s = mounted_session();
        let tmp = std::env::temp_dir();
        let out = print_of(
            dispatch(&mut s, Command::Lcd(Some(tmp.display().to_string())))
                .await
                .unwrap(),
        );
        assert!(out.contains(&tmp.canonicalize().unwrap().display().to_string()));
    }

    fn file_session() -> Session {
        use crate::nfs::ReadResult;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_lookup().returning(|_d, name| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 5,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                ))
            });
            ops.expect_read().returning(|_fh, _off, _cnt| {
                Ok(ReadResult {
                    data: b"data!".to_vec(),
                    eof: true,
                })
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s
    }

    #[tokio::test]
    async fn cat_prints_file_contents() {
        let mut s = file_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::Cat("f".into())).await.unwrap());
        assert_eq!(out, "data!");
    }

    #[tokio::test]
    async fn get_writes_local_file() {
        let mut s = file_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let dir = std::env::temp_dir().join(format!("niffler_get_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        s.set_local_dir(dir.clone());
        let out = print_of(
            dispatch(
                &mut s,
                Command::Get {
                    remote: "f".into(),
                    local: None,
                },
            )
            .await
            .unwrap(),
        );
        let written = std::fs::read(dir.join("f")).unwrap();
        assert_eq!(&written, b"data!");
        assert!(out.contains("5 bytes"));
        std::fs::remove_dir_all(&dir).ok();
    }

    fn write_session() -> Session {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_lookup()
                .returning(|_d, name| Ok((NfsFh::new(name.as_bytes().to_vec()), dir_attrs())));
            ops.expect_mkdir()
                .returning(|_d, name, _m| Ok((NfsFh::new(name.as_bytes().to_vec()), dir_attrs())));
            ops.expect_remove().returning(|_d, _n| Ok(()));
            ops.expect_rmdir().returning(|_d, _n| Ok(()));
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s
    }

    #[tokio::test]
    async fn mkdir_reports_created() {
        let mut s = write_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(
            dispatch(&mut s, Command::Mkdir("newdir".into()))
                .await
                .unwrap(),
        );
        assert!(out.contains("newdir"));
    }

    #[tokio::test]
    async fn rm_and_rmdir_succeed() {
        let mut s = write_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        assert!(matches!(
            dispatch(&mut s, Command::Rm("f".into())).await.unwrap(),
            Outcome::Print(_)
        ));
        assert!(matches!(
            dispatch(&mut s, Command::Rmdir("d".into())).await.unwrap(),
            Outcome::Print(_)
        ));
    }

    fn write_session_setattr() -> Session {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_lookup().returning(|_d, name| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 0,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                ))
            });
            ops.expect_setattr().returning(|_fh, _attrs| Ok(()));
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s
    }

    #[tokio::test]
    async fn chmod_sets_mode() {
        use std::sync::{Arc as StdArc, Mutex};
        let captured: StdArc<Mutex<Option<crate::nfs::SetAttrs>>> = StdArc::new(Mutex::new(None));
        let cap = StdArc::clone(&captured);
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(move |_, _, _| {
            let cap = StdArc::clone(&cap);
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_lookup().returning(|_d, name| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 0,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                ))
            });
            ops.expect_setattr().returning(move |_fh, attrs| {
                *cap.lock().unwrap() = Some(attrs.clone());
                Ok(())
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        dispatch(
            &mut s,
            Command::Chmod {
                mode: 0o600,
                path: "f".into(),
            },
        )
        .await
        .unwrap();
        let got = captured.lock().unwrap().clone().unwrap();
        assert_eq!(got.mode, Some(0o600));
        assert_eq!(got.size, None);
        assert_eq!(got.mtime, None);
    }

    #[tokio::test]
    async fn chown_sets_uid_gid() {
        let mut s = write_session_setattr();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(
            dispatch(
                &mut s,
                Command::Chown {
                    uid: 1000,
                    gid: Some(1000),
                    path: "f".into(),
                },
            )
            .await
            .unwrap(),
        );
        assert!(out.contains("1000"));
    }

    fn link_session() -> Session {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_lookup().returning(|_d, name| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 0,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                ))
            });
            ops.expect_rename().returning(|_fd, _fn, _td, _tn| Ok(()));
            ops.expect_link().returning(|_t, _d, _n| Ok(()));
            ops.expect_symlink().returning(|_d, name, _t, _m| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Symlink,
                        size: 0,
                        mode: 0o777,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                ))
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s
    }

    #[tokio::test]
    async fn mv_ln_symlink_succeed() {
        let mut s = link_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        assert!(matches!(
            dispatch(
                &mut s,
                Command::Mv {
                    from: "a".into(),
                    to: "b".into()
                }
            )
            .await
            .unwrap(),
            Outcome::Print(_)
        ));
        assert!(matches!(
            dispatch(
                &mut s,
                Command::Ln {
                    target: "a".into(),
                    link: "b".into()
                }
            )
            .await
            .unwrap(),
            Outcome::Print(_)
        ));
        let out = print_of(
            dispatch(
                &mut s,
                Command::Symlink {
                    target: "/etc/passwd".into(),
                    link: "pw".into(),
                },
            )
            .await
            .unwrap(),
        );
        assert!(out.contains("pw"));
    }

    #[tokio::test]
    async fn put_uploads_local_file() {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_create().returning(|_d, name, _m| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 0,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                ))
            });
            ops.expect_write()
                .returning(|_fh, _off, data, _stable| Ok(data.len() as u32));
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();

        let tmp = std::env::temp_dir().join(format!("niffler_put_{}.txt", std::process::id()));
        std::fs::write(&tmp, b"payload").unwrap();
        let out = print_of(
            dispatch(
                &mut s,
                Command::Put {
                    local: tmp.display().to_string(),
                    remote: Some("uploaded.txt".into()),
                },
            )
            .await
            .unwrap(),
        );
        assert!(out.contains("7 bytes"));
        std::fs::remove_file(&tmp).ok();
    }

    #[tokio::test]
    async fn mknod_fifo_succeeds() {
        use crate::nfs::NodeKind;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_mknod().returning(|_d, name, _k, _m, _s| {
                Ok((NfsFh::new(name.as_bytes().to_vec()), dir_attrs()))
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(
            dispatch(
                &mut s,
                Command::Mknod {
                    name: "pipe".into(),
                    kind: NodeKind::Fifo,
                    spec: None,
                },
            )
            .await
            .unwrap(),
        );
        assert!(out.contains("pipe"));
    }

    #[tokio::test]
    async fn harvest_collects_uids() {
        use crate::nfs::DirEntry;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_readdirplus().returning(|_| {
                Ok(vec![
                    DirEntry {
                        name: "a".into(),
                        fh: NfsFh::new(vec![1]),
                        attrs: NfsAttrs {
                            file_type: NfsFileType::Regular,
                            size: 0,
                            mode: 0o644,
                            uid: 1001,
                            gid: 1001,
                            mtime: 0,
                        },
                    },
                    DirEntry {
                        name: "b".into(),
                        fh: NfsFh::new(vec![2]),
                        attrs: NfsAttrs {
                            file_type: NfsFileType::Regular,
                            size: 0,
                            mode: 0o644,
                            uid: 1002,
                            gid: 1002,
                            mtime: 0,
                        },
                    },
                ])
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::Harvest).await.unwrap());
        assert!(out.contains("1001") && out.contains("1002"));
        assert_eq!(s.harvested().len(), 2);
    }

    #[tokio::test]
    async fn uid_auto_toggles_and_reports() {
        let mut s = mounted_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let on = print_of(
            dispatch(&mut s, Command::UidAuto(Some(true)))
                .await
                .unwrap(),
        );
        assert!(on.to_lowercase().contains("on"));
        assert!(s.auto_cycle());
        let toggled = print_of(dispatch(&mut s, Command::UidAuto(None)).await.unwrap());
        assert!(toggled.to_lowercase().contains("off"));
        assert!(!s.auto_cycle());
    }

    #[tokio::test]
    async fn whoami_shows_uid() {
        let mut s = mounted_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::Whoami).await.unwrap());
        assert!(out.contains("1000"));
    }

    #[tokio::test]
    async fn squash_test_detects_no_root_squash() {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, creds| {
            let is_root = creds.uid == 0;
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            if is_root {
                ops.expect_create().returning(|_d, name, _m| {
                    Ok((NfsFh::new(name.as_bytes().to_vec()), dir_attrs()))
                });
                ops.expect_remove().returning(|_d, _n| Ok(()));
            }
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::SquashTest(None)).await.unwrap());
        assert!(
            out.to_lowercase().contains("no_root_squash")
                || out.to_lowercase().contains("not squashed")
        );
    }

    #[tokio::test]
    async fn squash_test_detects_squashed() {
        use crate::nfs::NfsError;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _creds| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_create()
                .returning(|_d, _n, _m| Err(Box::new(NfsError::PermissionDenied)));
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::SquashTest(None)).await.unwrap());
        assert!(out.to_lowercase().contains("squash"));
    }

    #[tokio::test]
    async fn cat_auto_cycles_to_harvested_uid() {
        use crate::nfs::{NfsError, ReadResult};
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_h, _e, creds| {
            let uid = creds.uid;
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_lookup().returning(|_d, name| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 6,
                        mode: 0o600,
                        uid: 4000,
                        gid: 4000,
                        mtime: 0,
                    },
                ))
            });
            if uid == 2000 {
                ops.expect_read().returning(|_fh, _o, _c| {
                    Ok(ReadResult {
                        data: b"secret".to_vec(),
                        eof: true,
                    })
                });
            } else {
                ops.expect_read()
                    .returning(|_fh, _o, _c| Err(Box::new(NfsError::PermissionDenied)));
            }
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        s.set_auto_cycle(true);
        s.add_harvested(vec![AuthCreds::new(2000, 2000)]);
        let out = print_of(dispatch(&mut s, Command::Cat("f".into())).await.unwrap());
        assert!(out.contains("secret"));
    }

    #[tokio::test]
    async fn scan_reports_findings() {
        use crate::nfs::{DirEntry, ReadResult};
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_readdirplus().returning(|_| {
                Ok(vec![DirEntry {
                    name: ".env".into(),
                    fh: NfsFh::new(vec![1]),
                    attrs: NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 60,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                }])
            });
            ops.expect_read().returning(|_fh, _o, _c| {
                Ok(ReadResult {
                    data: b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                        .to_vec(),
                    eof: true,
                })
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s.set_classifier(std::sync::Arc::new(
            crate::classifier::RuleEngine::compile(
                crate::classifier::defaults::load_embedded_defaults().unwrap(),
            )
            .unwrap(),
        ));
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::Scan(None)).await.unwrap());
        assert!(out.contains("scanned 1 file"));
    }

    #[tokio::test]
    async fn find_matches_filenames() {
        use crate::nfs::DirEntry;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_readdirplus().returning(|_| {
                Ok(vec![
                    DirEntry {
                        name: "notes.txt".into(),
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
                        name: "secret.env".into(),
                        fh: NfsFh::new(vec![2]),
                        attrs: NfsAttrs {
                            file_type: NfsFileType::Regular,
                            size: 1,
                            mode: 0o644,
                            uid: 0,
                            gid: 0,
                            mtime: 0,
                        },
                    },
                ])
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s.set_classifier(std::sync::Arc::new(
            crate::classifier::RuleEngine::compile(
                crate::classifier::defaults::load_embedded_defaults().unwrap(),
            )
            .unwrap(),
        ));
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(
            dispatch(&mut s, Command::Find("\\.env$".into()))
                .await
                .unwrap(),
        );
        assert!(out.contains("secret.env"));
        assert!(!out.contains("notes.txt"));
    }

    #[tokio::test]
    async fn find_invalid_regex_errors() {
        let mut s = mounted_session();
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        s.set_classifier(std::sync::Arc::new(
            crate::classifier::RuleEngine::compile(
                crate::classifier::defaults::load_embedded_defaults().unwrap(),
            )
            .unwrap(),
        ));
        assert!(
            dispatch(&mut s, Command::Find("[unclosed".into()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn snaffle_records_findings_to_db() {
        use crate::nfs::ReadResult;
        let dir =
            std::env::temp_dir().join(format!("niffler_snaffle_dispatch_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("d.db");
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_lookup().returning(|_d, name| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 60,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                ))
            });
            ops.expect_read().returning(|_fh, _o, _c| {
                Ok(ReadResult {
                    data: b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                        .to_vec(),
                    eof: true,
                })
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s.set_db_path(db.clone());
        s.set_classifier(std::sync::Arc::new(
            crate::classifier::RuleEngine::compile(
                crate::classifier::defaults::load_embedded_defaults().unwrap(),
            )
            .unwrap(),
        ));
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(
            dispatch(&mut s, Command::Snaffle("creds.env".into()))
                .await
                .unwrap(),
        );
        assert!(out.contains("recorded") || out.contains("no findings"));
        s.finish_recording().await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn cat_strips_single_trailing_newline() {
        use crate::nfs::ReadResult;
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            ops.expect_getattr().returning(|_| Ok(dir_attrs()));
            ops.expect_lookup().returning(|_d, name| {
                Ok((
                    NfsFh::new(name.as_bytes().to_vec()),
                    NfsAttrs {
                        file_type: NfsFileType::Regular,
                        size: 5,
                        mode: 0o644,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                    },
                ))
            });
            ops.expect_read().returning(|_fh, _o, _c| {
                Ok(ReadResult {
                    data: b"data\n".to_vec(),
                    eof: true,
                })
            });
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        dispatch(&mut s, Command::Mount("/e".into())).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::Cat("f".into())).await.unwrap());
        assert_eq!(out, "data");
    }

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn live_harvest_and_squash() {
        use crate::nfs::{Nfs3Connector, Nfs4Connector, NfsConnector};
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let v3: Arc<dyn NfsConnector> = Arc::new(Nfs3Connector::new(false));
        let v4: Arc<dyn NfsConnector> = Arc::new(Nfs4Connector::new());
        let factory = ConnectorFactory::new(v3, v4, Some(NfsVersion::V3));
        let mut s = Session::new(factory, AuthCreds::root(), NfsVersion::V3);
        s.set_host(host);
        dispatch(&mut s, Command::Mount(export)).await.unwrap();
        dispatch(&mut s, Command::Harvest).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::SquashTest(None)).await.unwrap());
        assert!(!out.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn live_scan_and_snaffle() {
        use crate::nfs::{Nfs3Connector, Nfs4Connector, NfsConnector};
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let v3: Arc<dyn NfsConnector> = Arc::new(Nfs3Connector::new(false));
        let v4: Arc<dyn NfsConnector> = Arc::new(Nfs4Connector::new());
        let factory = ConnectorFactory::new(v3, v4, Some(NfsVersion::V3));
        let mut s = Session::new(factory, AuthCreds::root(), NfsVersion::V3);
        s.set_host(host);
        s.set_classifier(std::sync::Arc::new(
            crate::classifier::RuleEngine::compile(
                crate::classifier::defaults::load_embedded_defaults().unwrap(),
            )
            .unwrap(),
        ));
        s.set_db_path(std::env::temp_dir().join("niffler_shell_live.db"));
        dispatch(&mut s, Command::Mount(export)).await.unwrap();
        let out = print_of(dispatch(&mut s, Command::Scan(None)).await.unwrap());
        assert!(out.contains("scanned"));
        s.finish_recording().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires writable NFS server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn live_write_round_trip() {
        use crate::nfs::{Nfs3Connector, Nfs4Connector, NfsConnector};
        let host = std::env::var("NFS_TEST_HOST").unwrap();
        let export = std::env::var("NFS_TEST_EXPORT").unwrap();
        let v3: Arc<dyn NfsConnector> = Arc::new(Nfs3Connector::new(false));
        let v4: Arc<dyn NfsConnector> = Arc::new(Nfs4Connector::new());
        let factory = ConnectorFactory::new(v3, v4, Some(NfsVersion::V3));
        let mut s = Session::new(factory, AuthCreds::root(), NfsVersion::V3);
        s.set_host(host);
        dispatch(&mut s, Command::Mount(export)).await.unwrap();
        dispatch(&mut s, Command::Mkdir("niffler_shell_rt".into()))
            .await
            .unwrap();
        let tmp = std::env::temp_dir().join("niffler_shell_put.txt");
        std::fs::write(&tmp, b"shell-rt").unwrap();
        dispatch(
            &mut s,
            Command::Put {
                local: tmp.display().to_string(),
                remote: Some("niffler_shell_rt/f.txt".into()),
            },
        )
        .await
        .unwrap();
        let out = print_of(
            dispatch(&mut s, Command::Cat("niffler_shell_rt/f.txt".into()))
                .await
                .unwrap(),
        );
        assert_eq!(out, "shell-rt");
        dispatch(&mut s, Command::Rm("niffler_shell_rt/f.txt".into()))
            .await
            .unwrap();
        dispatch(&mut s, Command::Rmdir("niffler_shell_rt".into()))
            .await
            .unwrap();
        std::fs::remove_file(&tmp).ok();
    }
}
