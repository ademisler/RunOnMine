use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
pub(crate) struct SharedOutputBudget {
    remaining: AtomicUsize,
    truncated: AtomicBool,
}

impl SharedOutputBudget {
    pub(crate) const fn new(maximum: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(maximum),
            truncated: AtomicBool::new(false),
        }
    }

    pub(crate) fn reserve(&self, requested: usize) -> usize {
        let mut remaining = self.remaining.load(Ordering::Acquire);
        loop {
            if remaining == 0 {
                self.truncated.store(true, Ordering::Release);
                return 0;
            }
            let accepted = requested.min(remaining);
            match self.remaining.compare_exchange_weak(
                remaining,
                remaining - accepted,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if accepted < requested {
                        self.truncated.store(true, Ordering::Release);
                    }
                    return accepted;
                }
                Err(actual) => remaining = actual,
            }
        }
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated.load(Ordering::Acquire)
    }
}

pub(crate) async fn read_with_shared_budget<R>(
    mut reader: R,
    budget: Arc<SharedOutputBudget>,
) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let accepted = budget.reserve(count);
        output.extend_from_slice(&buffer[..accepted]);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[tokio::test]
    async fn concurrent_readers_share_one_limit_and_keep_draining() -> std::io::Result<()> {
        let budget = Arc::new(SharedOutputBudget::new(1_024));
        let (mut first_writer, first_reader) = tokio::io::duplex(4_096);
        let (mut second_writer, second_reader) = tokio::io::duplex(4_096);
        let first_budget = Arc::clone(&budget);
        let second_budget = Arc::clone(&budget);
        let first = tokio::spawn(read_with_shared_budget(first_reader, first_budget));
        let second = tokio::spawn(read_with_shared_budget(second_reader, second_budget));
        let write_first = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut first_writer, &[b'A'; 800]).await
        });
        let write_second = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut second_writer, &[b'B'; 800]).await
        });
        write_first
            .await
            .map_err(|error| io::Error::other(format!("first writer task failed: {error}")))??;
        write_second
            .await
            .map_err(|error| io::Error::other(format!("second writer task failed: {error}")))??;
        let first = first
            .await
            .map_err(|error| io::Error::other(format!("first reader task failed: {error}")))??;
        let second = second
            .await
            .map_err(|error| io::Error::other(format!("second reader task failed: {error}")))??;
        assert!(budget.truncated());
        assert!(first.len() + second.len() <= 1_024);
        Ok(())
    }
}
