//! A transport backed by queues: incoming messages arrive through
//! [`ChannelTransport::push`] (from an HTTP POST handler, say) and outgoing
//! messages are consumed from the outbound end — the mirror of go-wmp's
//! `ChannelTransport`, designed for HTTP+SSE usage.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

use crate::transport::TransportError;

/// One bounded end of the channel transport: a queue with a capacity, closed
/// flag, and a signal.
#[derive(Default)]
struct End {
    queue: Mutex<(VecDeque<Vec<u8>>, bool)>,
    signal: Condvar,
}

impl End {
    fn send(&self, data: Vec<u8>, capacity: usize) -> Result<(), TransportError> {
        let Ok(mut state) = self.queue.lock() else {
            return Err(TransportError::Other("poisoned".to_owned()));
        };
        if state.1 {
            return Err(TransportError::Closed);
        }
        if state.0.len() >= capacity {
            // As in go-wmp: a full outbound buffer is an error (the SSE
            // client reconnects and gets replayed events); a full inbound
            // buffer is an error for the pusher.
            return Err(TransportError::Other("message buffer full".to_owned()));
        }
        state.0.push_back(data);
        self.signal.notify_one();
        Ok(())
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let Ok(mut state) = self.queue.lock() else {
            return None;
        };
        loop {
            if let Some(data) = state.0.pop_front() {
                return Some(data);
            }
            if state.1 {
                return None;
            }
            let Ok(guard) = self.signal.wait(state) else {
                return None;
            };
            state = guard;
        }
    }

    fn try_recv(&self) -> Option<Vec<u8>> {
        self.queue.lock().ok()?.0.pop_front()
    }

    fn close(&self) {
        if let Ok(mut state) = self.queue.lock() {
            state.1 = true;
        }
        self.signal.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.queue.lock().is_ok_and(|state| state.1)
    }
}

/// A [`crate::transport::Transport`] backed by in-memory queues. The peer
/// writes notifications and responses to the outbound end (sent as SSE
/// events); incoming messages arrive through [`ChannelTransport::push`].
#[derive(Clone, Default)]
pub struct ChannelTransport {
    inbound: Arc<End>,
    outbound: Arc<End>,
    in_capacity: usize,
    out_capacity: usize,
}

impl ChannelTransport {
    /// A transport with the given buffer sizes: `in_capacity` for incoming
    /// messages (from HTTP POST), `out_capacity` for outgoing ones (to the
    /// SSE stream).
    pub fn new(in_capacity: usize, out_capacity: usize) -> Self {
        Self {
            inbound: Arc::new(End::default()),
            outbound: Arc::new(End::default()),
            in_capacity,
            out_capacity,
        }
    }

    /// Delivers an incoming message. Errors when the transport is closed or
    /// the buffer is full.
    pub fn push(&self, data: Vec<u8>) -> Result<(), TransportError> {
        self.inbound.send(data, self.in_capacity)
    }

    /// Takes one outgoing message without blocking, if one is queued — the
    /// consumer's poll (an SSE writer ranges over go-wmp's channel).
    pub fn try_take_outbound(&self) -> Option<Vec<u8>> {
        self.outbound.try_recv()
    }

    /// Waits for and takes one outgoing message, or `None` once closed.
    pub fn read_outbound(&self) -> Option<Vec<u8>> {
        self.outbound.recv()
    }

    /// Whether the transport has been closed.
    pub fn is_closed(&self) -> bool {
        self.inbound.is_closed()
    }
}

impl crate::transport::Transport for ChannelTransport {
    fn read_message(&self) -> Result<Vec<u8>, TransportError> {
        self.inbound.recv().ok_or(TransportError::Closed)
    }

    fn write_message(&self, data: &[u8]) -> Result<(), TransportError> {
        self.outbound.send(data.to_vec(), self.out_capacity)
    }

    fn close(&self) -> Result<(), TransportError> {
        self.inbound.close();
        self.outbound.close();
        Ok(())
    }
}
