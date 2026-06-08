//! Interactive read-eval loop (rustyline) and non-interactive `-c` runner.

use rustyline::Editor;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;

use crate::shell::command::parse;
use crate::shell::completion::ShellHelper;
use crate::shell::dispatch::{Outcome, dispatch};
use crate::shell::session::Session;

/// Run a `;`/newline-separated script, returning all collected output. Stops at
/// `quit`. Command errors are reported inline and do not abort the run.
pub async fn run_script(session: &mut Session, script: &str) -> String {
    let mut out = String::new();
    for raw in script.split([';', '\n']) {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match parse(line) {
            Err(e) => out.push_str(&format!("error: {e}\n")),
            Ok(cmd) => match dispatch(session, cmd).await {
                Ok(Outcome::Exit) => break,
                Ok(Outcome::Print(text)) => {
                    if !text.is_empty() {
                        out.push_str(&text);
                        out.push('\n');
                    }
                }
                Err(e) => out.push_str(&format!("error: {e}\n")),
            },
        }
    }
    out
}

fn history_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".niffler_history"))
}

/// Run the interactive rustyline loop until EOF/quit.
pub async fn run_interactive(session: &mut Session) -> anyhow::Result<()> {
    let mut editor: Editor<ShellHelper, DefaultHistory> = Editor::new()?;
    editor.set_helper(Some(ShellHelper));
    let hist = history_path();
    if let Some(ref hp) = hist {
        let _ = editor.load_history(hp);
    }
    loop {
        let prompt = format!("niffler:{}> ", session.cwd_path());
        match editor.readline(&prompt) {
            Ok(line) => {
                let _ = editor.add_history_entry(line.as_str());
                match parse(&line) {
                    Err(e) => eprintln!("error: {e}"),
                    Ok(cmd) => match dispatch(session, cmd).await {
                        Ok(Outcome::Exit) => break,
                        Ok(Outcome::Print(text)) => {
                            if !text.is_empty() {
                                println!("{text}");
                            }
                        }
                        Err(e) => eprintln!("error: {e}"),
                    },
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => return Err(e.into()),
        }
    }
    if let Some(ref hp) = hist {
        let _ = editor.save_history(hp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{AuthCreds, ConnectorFactory, NfsFh, NfsVersion};
    use crate::shell::session::Session;
    use std::sync::Arc;

    fn session() -> Session {
        let mut conn = MockNfsConnector::new();
        conn.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle().return_const(NfsFh::new(vec![0]));
            Ok(Box::new(ops))
        });
        let factory = ConnectorFactory::uniform(Arc::new(conn));
        let mut s = Session::new(factory, AuthCreds::new(1000, 1000), NfsVersion::V3);
        s.set_host("h".into());
        s
    }

    #[tokio::test]
    async fn runs_semicolon_separated_script() {
        let mut s = session();
        let out = run_script(&mut s, "open h2; status").await;
        assert!(out.contains("h2"));
    }

    #[tokio::test]
    async fn stops_on_quit() {
        let mut s = session();
        let out = run_script(&mut s, "status; quit; open SHOULD_NOT_RUN").await;
        assert!(!out.contains("SHOULD_NOT_RUN"));
    }

    #[tokio::test]
    async fn reports_command_errors_without_aborting() {
        let mut s = session();
        let out = run_script(&mut s, "frobnicate; status").await;
        assert!(out.contains("error"));
        assert!(out.contains("uid/gid"));
    }
}
