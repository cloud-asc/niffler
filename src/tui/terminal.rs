//! Terminal lifecycle: enter/leave raw mode + alternate screen safely.

/// RAII guard that runs a restore closure exactly once on drop. The real TUI
/// passes a closure that disables raw mode and leaves the alternate screen;
/// tests inject a flag-setter to prove `Drop` fires.
pub struct RestoreGuard<F: FnMut()> {
    restore: F,
    done: bool,
}

impl<F: FnMut()> RestoreGuard<F> {
    pub fn new(restore: F) -> Self {
        Self {
            restore,
            done: false,
        }
    }
}

impl<F: FnMut()> Drop for RestoreGuard<F> {
    fn drop(&mut self) {
        if !self.done {
            self.done = true;
            (self.restore)();
        }
    }
}

use std::io::{self, Stderr};

use crossterm::ExecutableCommand;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

pub type StderrTerminal = Terminal<CrosstermBackend<Stderr>>;

/// Enter raw mode + alternate screen on stderr and return a ratatui terminal.
/// The caller MUST keep the returned `RestoreGuard` alive for the session.
pub fn enter() -> io::Result<(StderrTerminal, RestoreGuard<impl FnMut()>)> {
    enable_raw_mode()?;
    let mut stderr = io::stderr();
    stderr.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stderr());
    let terminal = Terminal::new(backend)?;
    let guard = RestoreGuard::new(|| {
        let _ = disable_raw_mode();
        let _ = io::stderr().execute(LeaveAlternateScreen);
    });
    Ok((terminal, guard))
}

/// Install a panic hook that restores the terminal before the default hook
/// prints the panic, so a mid-scan panic never leaves a wrecked shell.
pub fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = io::stderr().execute(LeaveAlternateScreen);
        original(info);
    }));
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn restore_runs_on_drop() {
        let flag = Arc::new(AtomicBool::new(false));
        {
            let f = flag.clone();
            let _g = RestoreGuard::new(move || f.store(true, Ordering::SeqCst));
            assert!(!flag.load(Ordering::SeqCst), "not restored before drop");
        }
        assert!(flag.load(Ordering::SeqCst), "restore must run on drop");
    }

    #[test]
    fn restore_runs_during_unwind() {
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = RestoreGuard::new(move || f.store(true, Ordering::SeqCst));
            panic!("boom");
        }));
        assert!(result.is_err());
        assert!(
            flag.load(Ordering::SeqCst),
            "restore must run while unwinding"
        );
    }
}
