use std::ffi;

use crate::TOKIO_RUNTIME;

/// Run a netstack future to completion on the calling (embedder's) thread.
///
/// The netstack's `*_blocking` calls park through `std::thread::current()`, which gives each
/// calling thread a `Thread` handle holding a pthread mutex and condvar. On ESP-IDF that handle
/// is never freed when an embedder's thread exits: std drops it in a second round of TLS
/// destructors, by which point ESP-IDF has already cleared the slot it lives in. A firmware that
/// starts threads per connection lost ~350 bytes of internal RAM per thread. tokio's `block_on`
/// parks through a thread-local with its own destructor, which ESP-IDF runs.
fn blocking<F: core::future::Future>(fut: F) -> F::Output {
    TOKIO_RUNTIME.block_on(fut)
}

/// A Tailscale TCP listener handle.
pub struct tcp_listener(tailscale::netstack::TcpListener);

/// A Tailscale TCP stream handle.
pub struct tcp_stream(tailscale::netstack::TcpStream);

/// Start a TCP listener on the given `addr`.
///
/// Returns null if the listener couldn't be created.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_listen(
    dev: &crate::device,
    addr: &crate::sockaddr,
) -> Option<Box<tcp_listener>> {
    let addr = addr.try_into().ok()?;

    match TOKIO_RUNTIME.block_on(dev.0.tcp_listen(addr)) {
        Ok(sock) => Some(Box::new(tcp_listener(sock))),
        Err(e) => {
            tracing::error!(err = %e, "tcp listen");
            None
        }
    }
}

/// Accept an incoming connection on the given listener.
///
/// Returns null if there was an error.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_accept(listener: &tcp_listener) -> Option<Box<tcp_stream>> {
    // block_on rather than the netstack's *_blocking calls throughout this file: see `blocking`.
    match blocking(listener.0.accept()) {
        Ok(sock) => Some(Box::new(tcp_stream(sock))),
        Err(e) => {
            tracing::error!(err = %e, "tcp accept");
            None
        }
    }
}

/// Get the local endpoint `listener` is listening on.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_listener_local_addr(listener: &tcp_listener) -> crate::sockaddr {
    listener.0.local_addr().into()
}

/// Close the specified socket.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_close_listener(sock: Box<tcp_listener>) {
    drop(sock)
}

/// Open a TCP connection to the specified `remote`.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_connect(
    dev: &crate::device,
    remote: &crate::sockaddr,
) -> Option<Box<tcp_stream>> {
    let addr = remote.try_into().ok()?;

    match TOKIO_RUNTIME.block_on(dev.0.tcp_connect(addr)) {
        Ok(sock) => Some(Box::new(tcp_stream(sock))),
        Err(e) => {
            tracing::error!(err = %e, "binding sock");
            None
        }
    }
}

/// Send bytes to the specified socket, blocking until at least one byte is sent.
///
/// Returns the number of bytes written, or a negative number if an error occurred. This is
/// guaranteed to be less than or equal to `len`.
///
/// # Safety
///
/// `buf` must be safe to convert into a Rust slice of length `len` (see
/// [`core::slice::from_raw_parts`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_tcp_send(
    stream: &tcp_stream,
    buf: *const u8,
    len: usize,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let b = unsafe { core::slice::from_raw_parts(buf, len) };

    match blocking(stream.0.send(b)) {
        Err(e) => {
            tracing::error!(err = %e, "tcp accept");
            -1
        }
        Ok(n) => n as _,
    }
}

/// Receive bytes from the specified socket, blocking until at least one byte is received.
///
/// Returns the number of bytes read, or a negative number if an error occurred. This is
/// guaranteed to be less than or equal to `len`.
///
/// # Safety
///
/// `buf` must be safe to convert into a mutable Rust slice of length `len` (see
/// [`core::slice::from_raw_parts_mut`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_tcp_recv(stream: &tcp_stream, buf: *mut u8, len: usize) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let b = unsafe { core::slice::from_raw_parts_mut(buf, len) };

    match blocking(stream.0.recv(b)) {
        Err(e) => {
            tracing::error!(err = %e, "tcp accept");
            -1
        }
        Ok(read) => read as _,
    }
}

/// Get the local endpoint for this TCP stream.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_local_addr(stream: &tcp_stream) -> crate::sockaddr {
    stream.0.local_addr().into()
}

/// Get the remote endpoint this TCP stream is connected to.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_remote_addr(stream: &tcp_stream) -> crate::sockaddr {
    stream.0.remote_addr().into()
}

/// Stop sending on `stream`: the remote sees end-of-stream once queued data is delivered.
///
/// Receiving continues until the remote closes its end, at which point a `ts_tcp_recv` blocked
/// on another thread returns 0. Unlike `ts_tcp_close` this does not free `stream`, so it is safe
/// while other threads are inside `ts_tcp_recv` / `ts_tcp_send`. Never blocks.
///
/// Returns 0 on success, or a negative number if the netstack has gone away.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_shutdown(stream: &tcp_stream) -> ffi::c_int {
    match stream.0.shutdown() {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(err = %e, "tcp shutdown");
            -1
        }
    }
}

/// Close the specified socket.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_close(sock: Box<tcp_stream>) {
    drop(sock);
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;
    use std::sync::Arc;

    use ts_netstack_smoltcp::{Netstack, WakingPipe, WakingPipeDev};
    use ts_netstack_smoltcp_core::{self as netcore, HasChannel, NetstackControl};
    use ts_netstack_smoltcp_socket::CreateSocket;

    use super::*;

    /// The embedder's shape: plain OS threads blocking in recv and send while the netstack runs on
    /// the runtime's single worker.
    #[test]
    fn blocking_calls_work_from_plain_threads() {
        let (a, b) = (
            Ipv4Addr::new(192, 168, 40, 1),
            Ipv4Addr::new(192, 168, 40, 2),
        );
        let (p1, p2) = WakingPipe::new(None);
        let dev = |pipe| WakingPipeDev {
            pipe,
            mtu: 1500,
            medium: netcore::smoltcp::phy::Medium::Ip,
        };
        let mut s1 = Netstack::new(dev(p1), Default::default());
        let mut s2 = Netstack::new(dev(p2), Default::default());
        let (c1, c2) = (s1.command_channel(), s2.command_channel());
        TOKIO_RUNTIME.spawn(async move { s1.run_tokio().await });
        TOKIO_RUNTIME.spawn(async move { s2.run_tokio().await });
        blocking(c1.set_ips([a.into()])).unwrap();
        blocking(c2.set_ips([b.into()])).unwrap();

        let listener = blocking(c2.tcp_listen((b, 4403).into())).unwrap();
        let client = blocking(c1.tcp_connect((a, 4403).into(), (b, 4403).into())).unwrap();
        let server = Arc::new(blocking(listener.accept()).unwrap());

        for round in 0..20 {
            let reader = std::thread::spawn({
                let server = server.clone();
                move || {
                    let mut buf = [0; 16];
                    let n = blocking(server.recv(&mut buf)).unwrap();
                    buf[..n].to_vec()
                }
            });
            blocking(client.send(format!("ping {round}").as_bytes())).unwrap();
            assert_eq!(reader.join().unwrap(), format!("ping {round}").as_bytes());

            std::thread::spawn({
                let server = server.clone();
                move || blocking(server.send(b"pong")).unwrap()
            })
            .join()
            .unwrap();
            let mut buf = [0; 16];
            let n = blocking(client.recv(&mut buf)).unwrap();
            assert_eq!(&buf[..n], b"pong");
        }
    }
}
