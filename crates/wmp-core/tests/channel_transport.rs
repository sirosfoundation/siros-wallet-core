//! The queue-backed transport: messages in both directions, closing, and the
//! buffer capacity.

use wmp_core::channel_transport::ChannelTransport;
use wmp_core::transport::{Transport, TransportError};

#[test]
fn messages_cross_both_ways_until_closed() {
    let transport = ChannelTransport::new(4, 4);
    transport.push(b"hello".to_vec()).expect("push");
    assert_eq!(transport.read_message(), Ok(b"hello".to_vec()));

    transport.write_message(b"bye").expect("write");
    assert_eq!(transport.try_take_outbound(), Some(b"bye".to_vec()));
    assert_eq!(transport.try_take_outbound(), None);

    transport.close().expect("close");
    assert!(transport.is_closed());
    assert!(matches!(
        transport.push(b"x".to_vec()),
        Err(TransportError::Closed)
    ));
    assert!(matches!(
        transport.read_message(),
        Err(TransportError::Closed)
    ));
}

#[test]
fn a_full_buffer_refuses_and_reopens_after_draining() {
    let transport = ChannelTransport::new(1, 1);
    transport.push(b"one".to_vec()).expect("first");
    assert!(transport.push(b"two".to_vec()).is_err());
    assert_eq!(transport.read_message(), Ok(b"one".to_vec()));
    transport.push(b"two".to_vec()).expect("after drain");
}
