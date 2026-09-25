use alloc::vec;

use smoltcp::socket::tcp;

use crate::Config;

mod listener;
mod stream;

pub use listener::{ListenerHandle, TcpListenerState};

/// A new TCP socket with the configured buffers, keep-alive and timeout.
///
/// Takes the config rather than `&Netstack` so callers can hold other fields mutably.
fn new_tcp_socket(config: &Config) -> tcp::Socket<'static> {
    let buffer = || tcp::SocketBuffer::new(vec![0; config.tcp_buffer_size]);
    let to_smoltcp =
        |d: core::time::Duration| smoltcp::time::Duration::from_millis(d.as_millis() as u64);

    let mut sock = tcp::Socket::new(buffer(), buffer());
    sock.set_keep_alive(config.tcp_keep_alive.map(to_smoltcp));
    sock.set_timeout(config.tcp_timeout.map(to_smoltcp));
    sock
}
