//! The transport trait: the seam adapters implement to carry WMP messages.

/// Why a transport operation failed.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TransportError {
    /// The transport is closed, or was never there.
    #[error("transport closed")]
    Closed,
    /// The transport failed.
    #[error("transport: {0}")]
    Other(String),
}

/// Abstracts the underlying connection (WebSocket, HTTPS, stdio, or an
/// in-memory pair). Adapters own the blocking, buffering and cancellation;
/// the core only moves bytes.
pub trait Transport: Send + Sync {
    /// Reads the next raw JSON message. Blocks until one is available.
    fn read_message(&self) -> Result<Vec<u8>, TransportError>;

    /// Sends raw JSON bytes.
    fn write_message(&self, data: &[u8]) -> Result<(), TransportError>;

    /// Closes the connection.
    fn close(&self) -> Result<(), TransportError>;
}
