//! Interactive NFS client shell (`niffler shell`).

pub mod command;
pub mod completion;
pub mod config;
pub mod dispatch;
pub mod format;
pub mod repl;
pub mod scan;
pub mod session;

use std::sync::Arc;

use crate::config::cli::ShellArgs;
use crate::nfs::{
    AuthCreds, ConnectorFactory, Nfs3Connector, Nfs4Connector, NfsConnector, NfsVersion,
};

pub use config::ShellConfig;
pub use session::Session;

/// Entry point for `niffler shell`.
pub async fn run(args: ShellArgs) -> anyhow::Result<()> {
    let cfg = ShellConfig::from_args(args)?;

    let v3: Arc<dyn NfsConnector> = match cfg.proxy {
        Some(proxy) => {
            Arc::new(Nfs3Connector::with_proxy(proxy).with_max_dir_entries(cfg.max_dir_entries))
        }
        None => Arc::new(
            Nfs3Connector::new(cfg.privileged_port).with_max_dir_entries(cfg.max_dir_entries),
        ),
    };
    let v4: Arc<dyn NfsConnector> =
        Arc::new(Nfs4Connector::new().with_max_dir_entries(cfg.max_dir_entries));
    let factory = ConnectorFactory::new(v3, v4, cfg.forced_version);

    let initial_version = cfg.forced_version.unwrap_or(NfsVersion::V3);
    let mut session = Session::new(factory, AuthCreds::new(cfg.uid, cfg.gid), initial_version);

    let rules = crate::classifier::defaults::load_embedded_defaults()?;
    let engine = std::sync::Arc::new(crate::classifier::RuleEngine::compile(rules)?);
    session.set_classifier(engine);
    session.set_db_path(cfg.db.clone());

    if let Some(host) = &cfg.host {
        session.set_host(host.clone());
        if let Some(export) = &cfg.export
            && let Err(e) = session.mount(export).await
        {
            eprintln!("error: {e}");
        }
    }

    let result = match cfg.command {
        Some(script) => {
            let out = repl::run_script(&mut session, &script).await;
            print!("{out}");
            Ok(())
        }
        None => repl::run_interactive(&mut session).await,
    };
    session.finish_recording().await?;
    result
}
