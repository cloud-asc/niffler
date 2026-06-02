//! A tracing layer that converts events into `LogEvent`s for the dashboard.

use std::sync::mpsc::SyncSender;

use tracing::field::{Field, Visit};

use crate::tui::{LogEvent, LogLevel};

/// Collects the `message` field of a tracing event into a string.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write as _;
            let _ = write!(self.message, "{value:?}");
            if self.message.starts_with('"')
                && self.message.ends_with('"')
                && self.message.len() >= 2
            {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        }
    }
}

fn level_of(meta: &tracing::Level) -> LogLevel {
    match *meta {
        tracing::Level::ERROR => LogLevel::Error,
        tracing::Level::WARN => LogLevel::Warn,
        tracing::Level::INFO => LogLevel::Info,
        tracing::Level::DEBUG => LogLevel::Debug,
        tracing::Level::TRACE => LogLevel::Trace,
    }
}

use tracing::Event;
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer};

/// Non-blocking send: drop the event if the UI channel is full so logging
/// never back-pressures the pipeline.
pub fn send_log(tx: &SyncSender<LogEvent>, level: LogLevel, message: String) {
    let _ = tx.try_send(LogEvent { level, message });
}

/// Tracing layer that forwards formatted events to the dashboard channel.
pub struct ChannelLogLayer {
    tx: SyncSender<LogEvent>,
}

impl ChannelLogLayer {
    #[must_use]
    pub fn new(tx: SyncSender<LogEvent>) -> Self {
        Self { tx }
    }
}

impl<S: Subscriber> Layer<S> for ChannelLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let level = level_of(event.metadata().level());
        let target = event.metadata().target();
        let message = if visitor.message.is_empty() {
            target.to_string()
        } else {
            visitor.message
        };
        send_log(&self.tx, level, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_of_maps_tracing_levels() {
        assert_eq!(level_of(&tracing::Level::WARN), LogLevel::Warn);
        assert_eq!(level_of(&tracing::Level::ERROR), LogLevel::Error);
    }

    #[test]
    fn build_event_sends_to_channel() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<LogEvent>(4);
        send_log(&tx, LogLevel::Warn, "hello".to_string());
        let got = rx.try_recv().expect("event delivered");
        assert_eq!(got.level, LogLevel::Warn);
        assert_eq!(got.message, "hello");
    }
}
