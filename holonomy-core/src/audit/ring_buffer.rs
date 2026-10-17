// @trace TASK-007
use chrono::{DateTime, Utc};
use crossbeam_queue::ArrayQueue;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Read,
    Write,
    Shred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub user_hash: String,
    pub file_signature: String,
    pub accessed_columns: Option<Vec<String>>,
    pub business_purpose: String,
    pub action: Action,
}

pub struct AuditRingBuffer {
    queue: ArrayQueue<AuditEvent>,
}

impl AuditRingBuffer {
    /// Creates a new bounded lock-free ring buffer with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
        }
    }

    /// Pushes an event into the ring buffer.
    /// Implements the "Overflow-Drop" strategy mandated by LCOMP-007 to prevent backpressure.
    pub fn push(&self, event: AuditEvent) {
        // We attempt to push. If it's full, we drop the oldest item and try again.
        // In a highly concurrent environment, the queue might become full again between pop and push,
        // so we loop until successful or decide to just drop the new item if under extreme contention.
        // A simple "force push" approach:
        let mut e = event;
        while let Err(err) = self.queue.push(e) {
            // Buffer is full. Pop the oldest event to make room.
            let _ = self.queue.pop();
            // Retry pushing the event we failed to push.
            e = err;
        }
    }

    /// Returns the current number of events in the buffer.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Pops an event from the ring buffer. Useful for the async consumer.
    pub fn pop(&self) -> Option<AuditEvent> {
        self.queue.pop()
    }
}
