//! Parse a REPL input line into a `Command`.

use crate::nfs::NodeKind;

/// A parsed shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Open(String),
    Mount(String),
    Umount,
    Exports,
    Df,
    Status,
    Version(Option<u8>),
    Uid(u32),
    Gid(u32),
    Cd(String),
    Ls {
        long: bool,
        path: Option<String>,
    },
    Pwd,
    Lcd(Option<String>),
    Stat(String),
    Handle(Option<String>),
    Cat(String),
    Get {
        remote: String,
        local: Option<String>,
    },
    Put {
        local: String,
        remote: Option<String>,
    },
    Rm(String),
    Mkdir(String),
    Rmdir(String),
    Chmod {
        mode: u32,
        path: String,
    },
    Chown {
        uid: u32,
        gid: Option<u32>,
        path: String,
    },
    Mv {
        from: String,
        to: String,
    },
    Ln {
        target: String,
        link: String,
    },
    Symlink {
        target: String,
        link: String,
    },
    Mknod {
        name: String,
        kind: NodeKind,
        spec: Option<(u32, u32)>,
    },
    Harvest,
    Whoami,
    SquashTest(Option<String>),
    UidAuto(Option<bool>),
    Scan(Option<String>),
    Find(String),
    Snaffle(String),
    Help,
    Quit,
    Noop,
}

/// Error returned when a line cannot be parsed into a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ParseError {}

fn err(msg: impl Into<String>) -> ParseError {
    ParseError(msg.into())
}

/// Parse a single input line into a `Command`. Whitespace-only lines are `Noop`.
pub fn parse(line: &str) -> Result<Command, ParseError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(Command::Noop);
    }
    let mut parts = trimmed.split_whitespace();
    let cmd = parts.next().unwrap();
    let rest: Vec<&str> = parts.collect();

    let one = |args: &[&str]| -> Result<String, ParseError> {
        match args {
            [a] => Ok((*a).to_string()),
            _ => Err(err(format!("`{cmd}` takes exactly one argument"))),
        }
    };

    match cmd {
        "open" | "host" => Ok(Command::Open(one(&rest)?)),
        "mount" => Ok(Command::Mount(one(&rest)?)),
        "umount" => Ok(Command::Umount),
        "exports" => Ok(Command::Exports),
        "df" => Ok(Command::Df),
        "status" => Ok(Command::Status),
        "version" => match rest.as_slice() {
            [] => Ok(Command::Version(None)),
            [v] => Ok(Command::Version(Some(
                v.parse().map_err(|_| err("version must be 3 or 4"))?,
            ))),
            _ => Err(err("`version` takes at most one argument")),
        },
        "uid" => match rest.as_slice() {
            ["auto"] => Ok(Command::UidAuto(None)),
            ["auto", "on"] => Ok(Command::UidAuto(Some(true))),
            ["auto", "off"] => Ok(Command::UidAuto(Some(false))),
            ["auto", _] => Err(err("usage: uid auto [on|off]")),
            [n] => Ok(Command::Uid(
                n.parse().map_err(|_| err("uid must be a number"))?,
            )),
            _ => Err(err("usage: uid <n> | uid auto [on|off]")),
        },
        "gid" => Ok(Command::Gid(
            one(&rest)?
                .parse()
                .map_err(|_| err("gid must be a number"))?,
        )),
        "cd" => Ok(Command::Cd(one(&rest)?)),
        "pwd" => Ok(Command::Pwd),
        "lcd" => match rest.as_slice() {
            [] => Ok(Command::Lcd(None)),
            [p] => Ok(Command::Lcd(Some((*p).to_string()))),
            _ => Err(err("`lcd` takes at most one argument")),
        },
        "stat" => Ok(Command::Stat(one(&rest)?)),
        "cat" => Ok(Command::Cat(one(&rest)?)),
        "ls" => {
            let long = rest.first() == Some(&"-l");
            let path = if long { rest.get(1) } else { rest.first() };
            if (long && rest.len() > 2) || (!long && rest.len() > 1) {
                return Err(err("usage: ls [-l] [path]"));
            }
            Ok(Command::Ls {
                long,
                path: path.map(|s| s.to_string()),
            })
        }
        "get" => match rest.as_slice() {
            [r] => Ok(Command::Get {
                remote: (*r).to_string(),
                local: None,
            }),
            [r, l] => Ok(Command::Get {
                remote: (*r).to_string(),
                local: Some((*l).to_string()),
            }),
            _ => Err(err("usage: get <remote> [local]")),
        },
        "handle" => match rest.as_slice() {
            [] => Ok(Command::Handle(None)),
            [h] => Ok(Command::Handle(Some((*h).to_string()))),
            _ => Err(err("usage: handle [hex]")),
        },
        "put" => match rest.as_slice() {
            [l] => Ok(Command::Put {
                local: (*l).to_string(),
                remote: None,
            }),
            [l, r] => Ok(Command::Put {
                local: (*l).to_string(),
                remote: Some((*r).to_string()),
            }),
            _ => Err(err("usage: put <local> [remote]")),
        },
        "rm" => Ok(Command::Rm(one(&rest)?)),
        "mkdir" => Ok(Command::Mkdir(one(&rest)?)),
        "rmdir" => Ok(Command::Rmdir(one(&rest)?)),
        "chmod" => match rest.as_slice() {
            [m, path] => Ok(Command::Chmod {
                mode: u32::from_str_radix(m, 8).map_err(|_| err("mode must be octal, e.g. 644"))?,
                path: (*path).to_string(),
            }),
            _ => Err(err("usage: chmod <octal-mode> <path>")),
        },
        "chown" => match rest.as_slice() {
            [owner, path] => {
                let (uid, gid) = parse_owner(owner)?;
                Ok(Command::Chown {
                    uid,
                    gid,
                    path: (*path).to_string(),
                })
            }
            _ => Err(err("usage: chown <uid[:gid]> <path>")),
        },
        "mv" => match rest.as_slice() {
            [a, b] => Ok(Command::Mv {
                from: (*a).to_string(),
                to: (*b).to_string(),
            }),
            _ => Err(err("usage: mv <old> <new>")),
        },
        "ln" => match rest.as_slice() {
            [t, l] => Ok(Command::Ln {
                target: (*t).to_string(),
                link: (*l).to_string(),
            }),
            _ => Err(err("usage: ln <target> <link>")),
        },
        "symlink" => match rest.as_slice() {
            [t, l] => Ok(Command::Symlink {
                target: (*t).to_string(),
                link: (*l).to_string(),
            }),
            _ => Err(err("usage: symlink <target-path> <link>")),
        },
        "mknod" => parse_mknod(&rest),
        "harvest" => Ok(Command::Harvest),
        "whoami" => Ok(Command::Whoami),
        "squash-test" | "squash" => match rest.as_slice() {
            [] => Ok(Command::SquashTest(None)),
            [p] => Ok(Command::SquashTest(Some((*p).to_string()))),
            _ => Err(err("usage: squash-test [path]")),
        },
        "scan" => match rest.as_slice() {
            [] => Ok(Command::Scan(None)),
            [p] => Ok(Command::Scan(Some((*p).to_string()))),
            _ => Err(err("usage: scan [path]")),
        },
        "find" => Ok(Command::Find(one(&rest)?)),
        "snaffle" => Ok(Command::Snaffle(one(&rest)?)),
        "help" | "?" => Ok(Command::Help),
        "quit" | "exit" | "bye" => Ok(Command::Quit),
        other => Err(err(format!("unknown command: {other}"))),
    }
}

fn parse_owner(owner: &str) -> Result<(u32, Option<u32>), ParseError> {
    match owner.split_once(':') {
        None => Ok((
            owner.parse().map_err(|_| err("uid must be a number"))?,
            None,
        )),
        Some((u, g)) => Ok((
            u.parse().map_err(|_| err("uid must be a number"))?,
            Some(g.parse().map_err(|_| err("gid must be a number"))?),
        )),
    }
}

fn parse_mknod(rest: &[&str]) -> Result<Command, ParseError> {
    let (name, kind_args) = match rest {
        [name, kind_args @ ..] => (*name, kind_args),
        _ => return Err(err("usage: mknod <name> b|c <major> <minor> | p | s")),
    };
    let (kind, spec) = match kind_args {
        ["b", major, minor] => (
            NodeKind::Block,
            Some((parse_u32(major)?, parse_u32(minor)?)),
        ),
        ["c", major, minor] => (NodeKind::Char, Some((parse_u32(major)?, parse_u32(minor)?))),
        ["p"] => (NodeKind::Fifo, None),
        ["s"] => (NodeKind::Socket, None),
        _ => return Err(err("usage: mknod <name> b|c <major> <minor> | p | s")),
    };
    Ok(Command::Mknod {
        name: name.to_string(),
        kind,
        spec,
    })
}

fn parse_u32(s: &str) -> Result<u32, ParseError> {
    s.parse().map_err(|_| err("major/minor must be numbers"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_open_and_aliases() {
        assert_eq!(parse("open host1").unwrap(), Command::Open("host1".into()));
        assert_eq!(parse("host host2").unwrap(), Command::Open("host2".into()));
    }

    #[test]
    fn parses_mount_umount() {
        assert_eq!(
            parse("mount /export").unwrap(),
            Command::Mount("/export".into())
        );
        assert_eq!(parse("umount").unwrap(), Command::Umount);
    }

    #[test]
    fn parses_ls_with_and_without_flag_and_path() {
        assert_eq!(
            parse("ls").unwrap(),
            Command::Ls {
                long: false,
                path: None
            }
        );
        assert_eq!(
            parse("ls -l").unwrap(),
            Command::Ls {
                long: true,
                path: None
            }
        );
        assert_eq!(
            parse("ls -l sub").unwrap(),
            Command::Ls {
                long: true,
                path: Some("sub".into())
            }
        );
        assert_eq!(
            parse("ls sub").unwrap(),
            Command::Ls {
                long: false,
                path: Some("sub".into())
            }
        );
    }

    #[test]
    fn parses_cd_pwd_lcd_stat_cat() {
        assert_eq!(parse("cd /a/b").unwrap(), Command::Cd("/a/b".into()));
        assert_eq!(parse("pwd").unwrap(), Command::Pwd);
        assert_eq!(
            parse("lcd /tmp").unwrap(),
            Command::Lcd(Some("/tmp".into()))
        );
        assert_eq!(parse("lcd").unwrap(), Command::Lcd(None));
        assert_eq!(parse("stat f").unwrap(), Command::Stat("f".into()));
        assert_eq!(parse("cat f").unwrap(), Command::Cat("f".into()));
    }

    #[test]
    fn parses_get_one_and_two_args() {
        assert_eq!(
            parse("get remote").unwrap(),
            Command::Get {
                remote: "remote".into(),
                local: None
            }
        );
        assert_eq!(
            parse("get remote local").unwrap(),
            Command::Get {
                remote: "remote".into(),
                local: Some("local".into())
            }
        );
    }

    #[test]
    fn parses_handle_get_and_set() {
        assert_eq!(parse("handle").unwrap(), Command::Handle(None));
        assert_eq!(
            parse("handle aabb01").unwrap(),
            Command::Handle(Some("aabb01".into()))
        );
    }

    #[test]
    fn parses_identity_and_misc() {
        assert_eq!(parse("uid 1000").unwrap(), Command::Uid(1000));
        assert_eq!(parse("gid 1000").unwrap(), Command::Gid(1000));
        assert_eq!(parse("version 4").unwrap(), Command::Version(Some(4)));
        assert_eq!(parse("version").unwrap(), Command::Version(None));
        assert_eq!(parse("exports").unwrap(), Command::Exports);
        assert_eq!(parse("df").unwrap(), Command::Df);
        assert_eq!(parse("status").unwrap(), Command::Status);
        assert_eq!(parse("help").unwrap(), Command::Help);
        assert_eq!(parse("quit").unwrap(), Command::Quit);
        assert_eq!(parse("exit").unwrap(), Command::Quit);
    }

    #[test]
    fn blank_line_is_noop() {
        assert_eq!(parse("   ").unwrap(), Command::Noop);
        assert_eq!(parse("").unwrap(), Command::Noop);
    }

    #[test]
    fn unknown_command_errors() {
        assert!(parse("frobnicate x").is_err());
    }

    #[test]
    fn missing_required_arg_errors() {
        assert!(parse("mount").is_err());
        assert!(parse("cd").is_err());
        assert!(parse("uid").is_err());
        assert!(parse("uid notanumber").is_err());
    }

    #[test]
    fn parses_put_rm_mkdir_rmdir() {
        assert_eq!(
            parse("put local.txt").unwrap(),
            Command::Put {
                local: "local.txt".into(),
                remote: None
            }
        );
        assert_eq!(
            parse("put local.txt remote.txt").unwrap(),
            Command::Put {
                local: "local.txt".into(),
                remote: Some("remote.txt".into())
            }
        );
        assert_eq!(parse("rm f").unwrap(), Command::Rm("f".into()));
        assert_eq!(parse("mkdir d").unwrap(), Command::Mkdir("d".into()));
        assert_eq!(parse("rmdir d").unwrap(), Command::Rmdir("d".into()));
    }

    #[test]
    fn parses_chmod_octal() {
        assert_eq!(
            parse("chmod 644 f").unwrap(),
            Command::Chmod {
                mode: 0o644,
                path: "f".into()
            }
        );
        assert_eq!(
            parse("chmod 0755 d").unwrap(),
            Command::Chmod {
                mode: 0o755,
                path: "d".into()
            }
        );
        assert!(parse("chmod 999 f").is_err());
        assert!(parse("chmod f").is_err());
    }

    #[test]
    fn parses_chown_uid_and_uid_gid() {
        assert_eq!(
            parse("chown 1000 f").unwrap(),
            Command::Chown {
                uid: 1000,
                gid: None,
                path: "f".into()
            }
        );
        assert_eq!(
            parse("chown 1000:1000 f").unwrap(),
            Command::Chown {
                uid: 1000,
                gid: Some(1000),
                path: "f".into()
            }
        );
        assert!(parse("chown x f").is_err());
    }

    #[test]
    fn parses_mv_ln_symlink() {
        assert_eq!(
            parse("mv a b").unwrap(),
            Command::Mv {
                from: "a".into(),
                to: "b".into()
            }
        );
        assert_eq!(
            parse("ln target link").unwrap(),
            Command::Ln {
                target: "target".into(),
                link: "link".into()
            }
        );
        assert_eq!(
            parse("symlink /etc/passwd link").unwrap(),
            Command::Symlink {
                target: "/etc/passwd".into(),
                link: "link".into()
            }
        );
    }

    #[test]
    fn parses_identity_commands() {
        assert_eq!(parse("harvest").unwrap(), Command::Harvest);
        assert_eq!(parse("whoami").unwrap(), Command::Whoami);
        assert_eq!(parse("squash-test").unwrap(), Command::SquashTest(None));
        assert_eq!(
            parse("squash-test /export/dir").unwrap(),
            Command::SquashTest(Some("/export/dir".into()))
        );
    }

    #[test]
    fn parses_uid_auto_subcommand() {
        assert_eq!(parse("uid auto").unwrap(), Command::UidAuto(None));
        assert_eq!(parse("uid auto on").unwrap(), Command::UidAuto(Some(true)));
        assert_eq!(
            parse("uid auto off").unwrap(),
            Command::UidAuto(Some(false))
        );
        assert_eq!(parse("uid 1000").unwrap(), Command::Uid(1000));
        assert!(parse("uid bogus").is_err());
        assert!(parse("uid auto maybe").is_err());
    }

    #[test]
    fn parses_classifier_commands() {
        assert_eq!(parse("scan").unwrap(), Command::Scan(None));
        assert_eq!(
            parse("scan sub").unwrap(),
            Command::Scan(Some("sub".into()))
        );
        assert_eq!(
            parse("find secret").unwrap(),
            Command::Find("secret".into())
        );
        assert_eq!(
            parse("find \\.env$").unwrap(),
            Command::Find("\\.env$".into())
        );
        assert_eq!(parse("snaffle f").unwrap(), Command::Snaffle("f".into()));
        assert!(parse("find").is_err());
        assert!(parse("snaffle").is_err());
    }

    #[test]
    fn parses_mknod_variants() {
        use crate::nfs::NodeKind;
        assert_eq!(
            parse("mknod dev b 8 0").unwrap(),
            Command::Mknod {
                name: "dev".into(),
                kind: NodeKind::Block,
                spec: Some((8, 0))
            }
        );
        assert_eq!(
            parse("mknod dev c 1 3").unwrap(),
            Command::Mknod {
                name: "dev".into(),
                kind: NodeKind::Char,
                spec: Some((1, 3))
            }
        );
        assert_eq!(
            parse("mknod pipe p").unwrap(),
            Command::Mknod {
                name: "pipe".into(),
                kind: NodeKind::Fifo,
                spec: None
            }
        );
        assert!(parse("mknod dev b 8").is_err());
        assert!(parse("mknod dev x 1 2").is_err());
    }
}
