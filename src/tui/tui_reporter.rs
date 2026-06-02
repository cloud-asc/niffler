//! The interactive dashboard reporter: owns the render/input thread.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::config::OperatingMode;
use crate::pipeline::PipelineStats;
use crate::tui::app::App;
use crate::tui::render::{FrameCtx, draw};
use crate::tui::summary::{ScanSummary, format_summary};
use crate::tui::{FindingEvent, LogEvent, ReporterHandle};

/// Channel bounds: large enough to absorb bursts, bounded to cap memory.
const FINDING_CHAN: usize = 4096;

pub struct TuiReporter {
    finding_tx: SyncSender<FindingEvent>,
    handle: ReporterHandle,
    join: Option<JoinHandle<()>>,
    cancel: CancellationToken,
}

impl TuiReporter {
    /// Spawn the render thread. `log_rx` is the receiver end of the channel the
    /// `ChannelLogLayer` sends into (created by the caller so the tracing
    /// subscriber can be wired first).
    pub fn spawn(
        mode: OperatingMode,
        target_label: String,
        stats: Arc<PipelineStats>,
        cancel: CancellationToken,
        log_rx: Receiver<LogEvent>,
    ) -> Self {
        let (finding_tx, finding_rx) = sync_channel::<FindingEvent>(FINDING_CHAN);
        let handle = ReporterHandle::from_tui_sender(finding_tx.clone());

        let render_cancel = cancel.clone();
        let join = std::thread::spawn(move || {
            run_render_loop(mode, target_label, stats, render_cancel, finding_rx, log_rx);
        });

        Self {
            finding_tx,
            handle,
            join: Some(join),
            cancel,
        }
    }

    #[must_use]
    pub fn handle(&self) -> ReporterHandle {
        self.handle.clone()
    }

    /// Block until the render thread exits, then print the summary card to
    /// stderr (the alternate screen has been left by the guard inside the loop).
    pub fn finish(mut self, summary: ScanSummary) {
        self.cancel.cancel();
        drop(self.finding_tx);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        let color = std::io::IsTerminal::is_terminal(&std::io::stderr())
            && std::env::var_os("NO_COLOR").is_none();
        eprint!("{}", format_summary(&summary, color));
    }
}

const FRAME: Duration = Duration::from_millis(50); // ~20fps

fn run_render_loop(
    mode: OperatingMode,
    target_label: String,
    stats: Arc<PipelineStats>,
    cancel: CancellationToken,
    finding_rx: Receiver<FindingEvent>,
    log_rx: Receiver<LogEvent>,
) {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

    crate::tui::terminal::install_panic_hook();
    let Ok((mut terminal, _guard)) = crate::tui::terminal::enter() else {
        return;
    };

    let mut app = App::new(mode);
    let start = Instant::now();

    while !cancel.is_cancelled() && !app.should_quit {
        for _ in 0..2048 {
            match finding_rx.try_recv() {
                Ok(ev) => app.push_finding(ev),
                Err(_) => break,
            }
        }
        for _ in 0..512 {
            match log_rx.try_recv() {
                Ok(ev) => app.push_log(ev),
                Err(_) => break,
            }
        }

        let _ = terminal.draw(|f| {
            draw(
                f,
                &FrameCtx {
                    app: &app,
                    stats: &stats,
                    elapsed: start.elapsed(),
                    target_label: &target_label,
                },
            );
        });

        if event::poll(FRAME).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') => app.quit(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.quit();
                }
                KeyCode::Char('f') => app.cycle_filter(),
                KeyCode::Char('p') => app.toggle_pause(),
                KeyCode::Up => app.scroll_up(1),
                KeyCode::Down => app.scroll_down(1),
                KeyCode::PageUp => app.scroll_up(10),
                KeyCode::PageDown => app.scroll_down(10),
                _ => {}
            }
        }
    }

    if app.should_quit {
        cancel.cancel();
    }
    // `_guard` drops here -> raw mode disabled + alternate screen left.
}
