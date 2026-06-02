use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Exponential backoff with full jitter.
///
/// Formula: uniform_random(0, min(max_delay, base * 2^attempt))
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub max_attempts: usize,
}

impl RetryPolicy {
    #[must_use]
    pub fn new(base_delay: Duration, max_delay: Duration, max_attempts: usize) -> Self {
        Self {
            base_delay,
            max_delay,
            max_attempts,
        }
    }

    #[must_use]
    pub fn delay_for_attempt(&self, attempt: usize) -> Duration {
        let base_ms = self.base_delay.as_millis() as u64;
        let exp_ms = base_ms.saturating_mul(1u64 << attempt.min(30));
        let max_ms = self.max_delay.as_millis() as u64;
        let capped = exp_ms.min(max_ms);
        Duration::from_millis(fastrand::u64(0..=capped))
    }

    pub async fn backoff_or_cancel(
        &self,
        attempt: usize,
        token: &CancellationToken,
    ) -> Result<(), ()> {
        let delay = self.delay_for_attempt(attempt);
        tokio::select! {
            _ = tokio::time::sleep(delay) => Ok(()),
            _ = token.cancelled() => Err(()),
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            max_attempts: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_window_grows_with_attempt() {
        let policy = RetryPolicy::new(Duration::from_millis(100), Duration::from_secs(60), 5);
        for _ in 0..200 {
            assert!(policy.delay_for_attempt(0).as_millis() <= 100);
            assert!(policy.delay_for_attempt(2).as_millis() <= 400);
        }
    }

    #[test]
    fn delay_capped_at_max() {
        let policy = RetryPolicy::new(Duration::from_millis(1000), Duration::from_secs(5), 10);
        for _ in 0..200 {
            assert!(policy.delay_for_attempt(20).as_millis() <= 5000);
        }
    }

    #[test]
    fn full_jitter_stays_within_capped_window() {
        let policy = RetryPolicy::new(Duration::from_millis(100), Duration::from_secs(60), 5);
        let capped = 3200u128;
        let mut min_seen = u128::MAX;
        let mut max_seen = 0u128;
        for _ in 0..2000 {
            let d = policy.delay_for_attempt(5).as_millis();
            assert!(d <= capped, "delay {d} exceeds capped window {capped}");
            min_seen = min_seen.min(d);
            max_seen = max_seen.max(d);
        }
        assert!(
            min_seen < capped / 4,
            "min {min_seen} not near 0 — jitter not full"
        );
        assert!(max_seen > capped * 3 / 4, "max {max_seen} not near capped");
    }

    #[test]
    fn zero_base_delay_returns_zero() {
        let policy = RetryPolicy::new(Duration::ZERO, Duration::from_secs(10), 3);
        let d = policy.delay_for_attempt(0);
        assert_eq!(d, Duration::ZERO);
    }

    #[tokio::test]
    async fn backoff_or_cancel_returns_ok_on_sleep() {
        let policy = RetryPolicy::new(Duration::from_millis(1), Duration::from_millis(10), 3);
        let token = CancellationToken::new();
        let result = policy.backoff_or_cancel(0, &token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn backoff_or_cancel_returns_err_on_cancellation() {
        let policy = RetryPolicy::new(Duration::from_secs(60), Duration::from_secs(120), 3);
        let token = CancellationToken::new();
        token.cancel();
        let result = policy.backoff_or_cancel(0, &token).await;
        assert!(result.is_err());
    }

    #[test]
    fn default_values() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.base_delay, Duration::from_millis(500));
        assert_eq!(policy.max_delay, Duration::from_secs(30));
        assert_eq!(policy.max_attempts, 2);
    }
}
