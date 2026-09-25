//! Measure the client-side CPU cost of one TLS handshake with the same provider,
//! root store and protocol versions `ts_tls_util::connect` uses.
//!
//! Network waits are excluded: only the synchronous rustls calls are timed, so the
//! numbers approximate what a single tokio worker is blocked for on a slow CPU.
//! Uses `ts_tls_util::client_config`, so connections after the first should
//! resume the session and skip certificate verification.
//!
//! Usage: cargo run --release -p ts_tls_util --example handshake_cost -- [host] [n]

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

use tokio_rustls::rustls::{ClientConnection, Stream, pki_types::ServerName};

fn main() {
    let mut args = std::env::args().skip(1);
    let host = args
        .next()
        .unwrap_or_else(|| "controlplane.tailscale.com".to_owned());
    let n: usize = args.next().map(|s| s.parse().unwrap()).unwrap_or(5);

    for i in 0..n {
        let t = Instant::now();
        let config = ts_tls_util::client_config(vec![]);
        let t_config = t.elapsed();

        let t = Instant::now();
        let mut conn =
            ClientConnection::new(config, ServerName::try_from(host.clone()).unwrap()).unwrap();
        let t_hello = t.elapsed();

        let mut sock = TcpStream::connect((host.as_str(), 443)).unwrap();
        let mut t_process = Duration::ZERO;
        let mut buf = [0u8; 16 * 1024];
        while conn.is_handshaking() {
            while conn.wants_write() {
                conn.write_tls(&mut sock).unwrap();
            }
            if !conn.is_handshaking() {
                break;
            }
            let got = sock.read(&mut buf).unwrap();
            assert!(got > 0, "server closed during handshake");
            let mut slice = &buf[..got];
            while !slice.is_empty() {
                conn.read_tls(&mut slice).unwrap();
            }
            let t = Instant::now();
            conn.process_new_packets().unwrap();
            t_process += t.elapsed();
        }
        while conn.wants_write() {
            conn.write_tls(&mut sock).unwrap();
        }
        sock.flush().unwrap();
        let kind = conn.handshake_kind();

        // Read a response so the server's post-handshake session tickets are
        // processed; without them there is nothing to resume next time.
        let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.write_all(request.as_bytes()).unwrap();
        tls.read_to_end(&mut Vec::new()).ok();

        println!(
            "#{i} {host}: {:?} {:?} {:?}  config {:>9.3?}  client_hello {:>9.3?}  process {:>9.3?}  cpu total {:>9.3?}",
            kind.unwrap(),
            conn.protocol_version().unwrap(),
            conn.negotiated_cipher_suite().unwrap().suite(),
            t_config,
            t_hello,
            t_process,
            t_config + t_hello + t_process,
        );
    }
}
