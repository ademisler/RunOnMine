use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::streamable_http_server::session::{
    RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
    local::{LocalSessionManager, LocalSessionManagerError},
};

#[derive(Debug)]
pub(crate) struct SessionPermit {
    counter: Arc<AtomicUsize>,
}

impl SessionPermit {
    pub(crate) fn acquire(counter: &Arc<AtomicUsize>, max_sessions: usize) -> Result<Self> {
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if current >= max_sessions {
                bail!("connector session limit reached");
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Self {
                        counter: Arc::clone(counter),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `rmcp` leaves expiry policy to the embedding application. This wrapper
/// records every protocol operation and closes a worker before reporting an
/// idle session as missing.
#[derive(Debug)]
pub(crate) struct IdleSessionManager {
    inner: LocalSessionManager,
    last_seen: tokio::sync::RwLock<HashMap<SessionId, Instant>>,
    idle_ttl: Duration,
}

impl IdleSessionManager {
    pub(crate) fn new(idle_ttl: Duration) -> Self {
        Self {
            inner: LocalSessionManager::default(),
            last_seen: tokio::sync::RwLock::new(HashMap::new()),
            idle_ttl,
        }
    }

    async fn touch(&self, id: &SessionId) -> Result<(), LocalSessionManagerError> {
        let expired = self
            .last_seen
            .read()
            .await
            .get(id)
            .is_some_and(|last_seen| last_seen.elapsed() >= self.idle_ttl);
        if expired {
            self.last_seen.write().await.remove(id);
            self.inner.close_session(id).await?;
            return Err(LocalSessionManagerError::SessionNotFound(id.clone()));
        }
        self.last_seen
            .write()
            .await
            .insert(id.clone(), Instant::now());
        Ok(())
    }

    pub(crate) async fn close_expired(&self) -> usize {
        let expired = {
            let mut last_seen = self.last_seen.write().await;
            let expired = last_seen
                .iter()
                .filter(|(_, seen)| seen.elapsed() >= self.idle_ttl)
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            for id in &expired {
                last_seen.remove(id);
            }
            expired
        };
        let mut closed = 0_usize;
        for id in expired {
            if self.inner.close_session(&id).await.is_ok() {
                closed += 1;
            }
        }
        closed
    }
}

impl SessionManager for IdleSessionManager {
    type Error = LocalSessionManagerError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let (id, transport) = self.inner.create_session().await?;
        self.last_seen
            .write()
            .await
            .insert(id.clone(), Instant::now());
        Ok((id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.touch(id).await?;
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        if self.touch(id).await.is_err() {
            return Ok(false);
        }
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.last_seen.write().await.remove(id);
        self.inner.close_session(id).await
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.touch(id).await?;
        self.inner.create_stream(id, message).await
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.touch(id).await?;
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.touch(id).await?;
        self.inner.create_standalone_stream(id).await
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.touch(id).await?;
        self.inner.resume(id, last_event_id).await
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        let outcome = self.inner.restore_session(id.clone()).await?;
        if !matches!(outcome, RestoreOutcome::NotSupported) {
            self.last_seen.write().await.insert(id, Instant::now());
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn session_limit_is_released_when_permit_drops() -> Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let permit = SessionPermit::acquire(&counter, 1)?;
        assert_eq!(counter.load(Ordering::Acquire), 1);
        assert!(SessionPermit::acquire(&counter, 1).is_err());

        drop(permit);
        assert_eq!(counter.load(Ordering::Acquire), 0);
        let _replacement = SessionPermit::acquire(&counter, 1)?;
        Ok(())
    }

    #[tokio::test]
    async fn idle_sessions_expire() -> Result<()> {
        let idle_ttl = Duration::from_secs(30);
        let manager = IdleSessionManager::new(idle_ttl);
        let (id, _transport) = manager.create_session().await?;
        assert!(manager.has_session(&id).await?);

        let expired_at = Instant::now()
            .checked_sub(idle_ttl + Duration::from_millis(1))
            .context("test clock cannot represent an expired session")?;
        manager
            .last_seen
            .write()
            .await
            .insert(id.clone(), expired_at);

        assert!(!manager.has_session(&id).await?);
        Ok(())
    }
}
