//! The size bound of a text the host hands back for the core to parse: a Request Object and a
//! Verifier's reply. The host reads at most the bound of each.

/// A text longer than the parse of its kind takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{size} bytes, over the {limit} its parse takes")]
pub struct TooLarge {
    size: usize,
    limit: usize,
}

impl TooLarge {
    /// The length of the text, in bytes.
    #[must_use]
    pub fn size(self) -> usize {
        self.size
    }

    /// The most bytes the parse takes.
    #[must_use]
    pub fn limit(self) -> usize {
        self.limit
    }
}

/// Refuses `text` when it holds more than `limit` bytes.
pub(crate) fn within(text: &[u8], limit: usize) -> Result<(), TooLarge> {
    match text.len() {
        size if size > limit => Err(TooLarge { size, limit }),
        _ => Ok(()),
    }
}
