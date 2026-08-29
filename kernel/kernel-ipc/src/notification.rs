//! ============================================================================
//! notification.rs
//!
//! Purpose: `Notification` — the asynchronous signalling object
//! (02-Microkernel-Layer.md §5.1: "Notification برای async signal"). A
//! signal sets sticky bits in a word; a blocked waiter is woken and a
//! later `poll` consumes the bits. Used for "data is ready in the shared
//! buffer" wakeups that pair with `SharedRegion` bulk transfer (§5.2), and
//! for delivering hardware IRQs to a driver process (the HAL `IrqHandler`
//! trampoline signals the driver's notification —
//! 03-Kernel-Subsystems-Layer.md §2.1).
//!
//! Architecture reference: 02-Microkernel-Layer.md §5.1, §6 (a notification
//! is signalled via `Send` on a `Notification` capability), and
//! 03-Kernel-Subsystems-Layer.md §2.1 (IRQ → notification).
//!
//! Position in the system: `kernel-core` owns the notification table; the
//! syscall dispatcher calls `signal` / `poll` / `wait`.
//!
//! Safety/invariants: signal bits are sticky (OR-accumulated) until
//! consumed by `poll`; the waiter list is a bounded fixed-capacity array;
//! `signal` returns the woken threads by value and leaves the list empty.
//! ============================================================================

use kernel_cap::ThreadId;

/// Errors specific to notification operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationError {
    /// The waiter list is at capacity.
    QueueFull,
}

/// The set of threads woken by one `signal` call, returned by value so no
/// allocation and no borrow of the notification is needed. At most `W`
/// entries; `as_slice()` gives the live prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Woken<const W: usize> {
    threads: [ThreadId; W],
    len: usize,
}

impl<const W: usize> Woken<W> {
    /// The woken threads, in FIFO wait order. `kernel-core` makes each
    /// runnable.
    pub fn as_slice(&self) -> &[ThreadId] {
        &self.threads[..self.len]
    }

    /// How many threads were woken.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no thread was waiting.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// An asynchronous notification object. `W` is the max number of threads
/// that can be simultaneously blocked waiting on it.
pub struct Notification<const W: usize> {
    /// Sticky signal bits, OR-accumulated by `signal`, cleared by `poll`.
    signal_word: u64,
    waiters: [ThreadId; W],
    waiters_len: usize,
}

impl<const W: usize> Notification<W> {
    /// Creates a notification with no pending signal and no waiters.
    pub const fn new() -> Self {
        Self {
            signal_word: 0,
            waiters: [ThreadId::new(0); W],
            waiters_len: 0,
        }
    }

    /// OR-accumulates `bits` into the signal word and returns (by value)
    /// the threads that were blocked waiting; the waiter list is left
    /// empty. `bits` typically encodes a badge or an IRQ line.
    ///
    /// Postcondition: waiter list empty; `pending()` includes `bits`
    /// (sticky until a `poll`).
    pub fn signal(&mut self, bits: u64) -> Woken<W> {
        self.signal_word |= bits;
        let mut out = Woken {
            threads: [ThreadId::new(0); W],
            len: self.waiters_len,
        };
        out.threads[..self.waiters_len].copy_from_slice(&self.waiters[..self.waiters_len]);
        self.waiters_len = 0;
        out
    }

    /// Consumes and returns the current signal bits, clearing them.
    /// Returns `0` if nothing is pending.
    pub fn poll(&mut self) -> u64 {
        core::mem::replace(&mut self.signal_word, 0)
    }

    /// The pending signal bits without consuming them.
    pub fn pending(&self) -> u64 {
        self.signal_word
    }

    /// Blocks `thread` on this notification. `kernel-core` should only
    /// call this when `poll` would return `0` — otherwise the thread
    /// should consume the pending signal instead of blocking.
    ///
    /// Errors `QueueFull` if the waiter list is at capacity.
    pub fn wait(&mut self, thread: ThreadId) -> Result<(), NotificationError> {
        if self.waiters_len >= W {
            return Err(NotificationError::QueueFull);
        }
        self.waiters[self.waiters_len] = thread;
        self.waiters_len += 1;
        Ok(())
    }
}

impl<const W: usize> Default for Notification<W> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: usize = 4;

    #[test]
    fn signal_is_sticky_until_polled() {
        let mut n: Notification<W> = Notification::new();
        assert!(n.signal(0b101).is_empty());
        assert_eq!(n.pending(), 0b101);
        let _ = n.signal(0b010);
        assert_eq!(n.poll(), 0b111);
        assert_eq!(n.poll(), 0);
    }

    #[test]
    fn waiters_are_returned_on_signal_and_list_drains() {
        let mut n: Notification<W> = Notification::new();
        n.wait(ThreadId::new(1)).unwrap();
        n.wait(ThreadId::new(2)).unwrap();
        let woken = n.signal(0b1);
        assert_eq!(woken.as_slice(), &[ThreadId::new(1), ThreadId::new(2)]);
        // Drained: full capacity is available again.
        for i in 0..W {
            n.wait(ThreadId::new(10 + i as u32)).unwrap();
        }
        assert_eq!(n.wait(ThreadId::new(99)), Err(NotificationError::QueueFull));
    }
}
