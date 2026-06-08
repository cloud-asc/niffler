//! rustyline helper providing command-name tab-completion.

use rustyline::completion::Completer;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

/// Shell command keywords offered for completion of the first word.
pub const COMMANDS: &[&str] = &[
    "open",
    "host",
    "mount",
    "umount",
    "exports",
    "df",
    "status",
    "version",
    "uid",
    "gid",
    "cd",
    "ls",
    "pwd",
    "lcd",
    "stat",
    "handle",
    "cat",
    "get",
    "put",
    "rm",
    "mkdir",
    "rmdir",
    "chmod",
    "chown",
    "mv",
    "ln",
    "symlink",
    "mknod",
    "harvest",
    "whoami",
    "squash-test",
    "scan",
    "find",
    "snaffle",
    "help",
    "quit",
    "exit",
];

/// Compute completions for the first word at `pos`. Returns (start, candidates).
/// Pure — unit-testable. Only completes the first word (no completion after a space).
pub fn complete_command(line: &str, pos: usize) -> (usize, Vec<String>) {
    let prefix = &line[..pos];
    if prefix.contains(char::is_whitespace) {
        return (pos, Vec::new());
    }
    let candidates: Vec<String> = COMMANDS
        .iter()
        .filter(|c| c.starts_with(prefix))
        .map(|c| (*c).to_string())
        .collect();
    (0, candidates)
}

pub struct ShellHelper;

impl Completer for ShellHelper {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        Ok(complete_command(line, pos))
    }
}
impl Hinter for ShellHelper {
    type Hint = String;
}
impl Highlighter for ShellHelper {}
impl Validator for ShellHelper {}
impl Helper for ShellHelper {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_command_prefix() {
        let (start, cands) = complete_command("sn", 2);
        assert_eq!(start, 0);
        assert!(cands.contains(&"snaffle".to_string()));
    }

    #[test]
    fn no_completion_after_first_word() {
        let (_start, cands) = complete_command("cat ", 4);
        assert!(cands.is_empty());
    }

    #[test]
    fn ambiguous_prefix_returns_multiple() {
        let (_start, cands) = complete_command("s", 1);
        assert!(cands.len() >= 4);
    }
}
