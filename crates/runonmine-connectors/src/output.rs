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
