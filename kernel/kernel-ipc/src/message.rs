//! ============================================================================
//! message.rs
//!
//! Purpose: `SmallMessage` — the fixed, register-sized payload of a
//! synchronous IPC (02-Microkernel-Layer.md §5.1: "حداکثر چند word، مستقیم
//! در رجیستر منتقل می‌شود، بدون کپی حافظه").
//!
//! Architecture reference: 02-Microkernel-Layer.md §5.1 (`SmallMessage`) and
//! §5.3 (fast path — the message must fit in registers for the fast path to
//! avoid touching memory at all).
//!
//! Position in the system: passed by value through `Endpoint` rendezvous
//! and returned from `ipc_call`. `kernel-core` copies it between the
//! sender's and receiver's saved register state; `ipc-protocol` (layer
//! 2↔3 contract) encodes its higher-level request/response types into
//! these words.
//!
//! Safety/invariants: contains only inline `u64` words and a length — no
//! pointers — so copying one between address spaces can never create a
//! dangling reference. `len <= MSG_MAX_WORDS` always.
//! ============================================================================

/// Maximum number of payload words in a `SmallMessage`.
///
/// Six 64-bit words = 48 bytes. Chosen to fit comfortably in the
/// argument/return registers of all three target architectures' calling
/// conventions (x86_64 SysV: rdi,rsi,rdx,rcx,r8,r9; AArch64: x0–x7;
/// RISC-V: a0–a7), so a fast-path IPC (§5.3) can move the whole message
/// register-to-register without ever spilling to memory.
pub const MSG_MAX_WORDS: usize = 6;

/// A synchronous IPC payload: a label plus up to `MSG_MAX_WORDS` data
/// words. `Copy` — messages are values, never heap objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmallMessage {
    /// Caller-defined message selector (which operation this invokes on
    /// the receiving endpoint). `ipc-protocol` assigns stable label
    /// values to each request kind (`FsRequest::Open`, etc.).
    pub label: u64,
    /// Payload words. Only `words[..len]` are meaningful.
    words: [u64; MSG_MAX_WORDS],
    /// Number of meaningful words in `words`.
    len: u8,
}

impl SmallMessage {
    /// An empty message with the given `label` and no data words.
    pub const fn new(label: u64) -> Self {
        Self {
            label,
            words: [0; MSG_MAX_WORDS],
            len: 0,
        }
    }

    /// Builds a message from `label` and a slice of data words.
    ///
    /// Errors `MessageTooLong` if `data.len() > MSG_MAX_WORDS`.
    pub fn from_words(label: u64, data: &[u64]) -> Result<Self, crate::IpcError> {
        if data.len() > MSG_MAX_WORDS {
            return Err(crate::IpcError::MessageTooLong);
        }
        let mut words = [0u64; MSG_MAX_WORDS];
        words[..data.len()].copy_from_slice(data);
        Ok(Self {
            label,
            words,
            len: data.len() as u8,
        })
    }

    /// The meaningful payload words.
    pub fn words(&self) -> &[u64] {
        &self.words[..self.len as usize]
    }

    /// Number of payload words.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// True if the message has a label but no data words.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends one data word. Errors `MessageTooLong` if already full.
    pub fn push(&mut self, word: u64) -> Result<(), crate::IpcError> {
        let i = self.len as usize;
        if i >= MSG_MAX_WORDS {
            return Err(crate::IpcError::MessageTooLong);
        }
        self.words[i] = word;
        self.len += 1;
        Ok(())
    }

    /// Reads payload word `i`, or `None` if out of range.
    pub fn word(&self, i: usize) -> Option<u64> {
        if i < self.len as usize {
            Some(self.words[i])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_words_roundtrips() {
        let m = SmallMessage::from_words(7, &[1, 2, 3]).unwrap();
        assert_eq!(m.label, 7);
        assert_eq!(m.words(), &[1, 2, 3]);
        assert_eq!(m.word(2), Some(3));
        assert_eq!(m.word(3), None);
    }

    #[test]
    fn too_long_is_rejected() {
        let data = [0u64; MSG_MAX_WORDS + 1];
        assert_eq!(
            SmallMessage::from_words(0, &data),
            Err(crate::IpcError::MessageTooLong)
        );
    }

    #[test]
    fn push_fills_then_errors() {
        let mut m = SmallMessage::new(1);
        for i in 0..MSG_MAX_WORDS {
            m.push(i as u64).unwrap();
        }
        assert_eq!(m.push(99), Err(crate::IpcError::MessageTooLong));
        assert_eq!(m.len(), MSG_MAX_WORDS);
    }
}
