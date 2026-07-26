use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};

const RATE_LIMIT_WINDOW: Duration = Duration::from_mins(1);

#[derive(Debug)]
pub(crate) struct PrincipalRateLimiter {
    calls_per_window: usize,
    calls: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl PrincipalRateLimiter {
    pub(crate) fn new(calls_per_minute: usize) -> Self {
        Self {
            calls_per_window: calls_per_minute,
            calls: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn check(&self, principal: &str) -> Result<()> {
        self.check_at(principal, Instant::now())
    }

    fn check_at(&self, principal: &str, now: Instant) -> Result<()> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| anyhow!("rate limit lock failed"))?;
        let cutoff = now.checked_sub(RATE_LIMIT_WINDOW).unwrap_or(now);
        for entries in calls.values_mut() {
            while entries.front().is_some_and(|instant| *instant < cutoff) {
                entries.pop_front();
            }
        }
        calls.retain(|_, entries| !entries.is_empty());

        let entries = calls.entry(principal.to_owned()).or_default();
        if entries.len() >= self.calls_per_window {
            bail!("principal rate limit reached");
        }
        entries.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_calls_after_the_configured_limit() -> Result<()> {
        let limiter = PrincipalRateLimiter::new(2);
        let now = Instant::now();

        limiter.check_at("local", now)?;
        limiter.check_at("local", now + Duration::from_secs(1))?;
        assert!(
            limiter
                .check_at("local", now + Duration::from_secs(2))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn tracks_principals_independently() -> Result<()> {
        let limiter = PrincipalRateLimiter::new(1);
        let now = Instant::now();

        limiter.check_at("oauth:client-a", now)?;
        assert!(limiter.check_at("oauth:client-a", now).is_err());
        limiter.check_at("oauth:client-b", now)?;
        Ok(())
    }

    #[test]
    fn expired_calls_release_capacity() -> Result<()> {
        let limiter = PrincipalRateLimiter::new(1);
        let now = Instant::now();

        limiter.check_at("stdio", now)?;
        limiter.check_at("stdio", now + RATE_LIMIT_WINDOW + Duration::from_millis(1))?;
        Ok(())
    }

    #[test]
    fn zero_limit_fails_closed() {
        let limiter = PrincipalRateLimiter::new(0);
        assert!(limiter.check_at("stdio", Instant::now()).is_err());
    }
}
