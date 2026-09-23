//! Measure the client-side CPU cost of one TLS handshake with the same provider,
//! root store and protocol versions `ts_tls_util::connect` uses.
//!
//! Network waits are excluded: only the synchronous rustls calls are timed, so the
//! numbers approximate what a single tokio worker is blocked for on a slow CPU.
//!
//! Usage: cargo run --release -p ts_tls_util --example handshake_cost -- [host] [n]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};

fn main() {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "controlplane.tailscale.com".to_owned());
    let n: usize = args.next().map(|s| s.parse().unwrap()).unwrap_or(5);

    for i in 0..n {
        let t = Instant::now();
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let config = ClientConfig::builder_with_provider(Arc::new(
            oxitls_rustcrypto_provider::provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let t_config = t.elapsed();

        let t = Instant::now();
        let mut conn =
            ClientConnection::new(Arc::new(config), ServerName::try_from(host.clone()).unwrap())
                .unwrap();
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

        println!(
            "#{i} {host}: {:?} {:?}  config {:>9.3?}  client_hello {:>9.3?}  process {:>9.3?}  cpu total {:>9.3?}",
            conn.protocol_version().unwrap(),
            conn.negotiated_cipher_suite().unwrap().suite(),
            t_config,
            t_hello,
            t_process,
            t_config + t_hello + t_process,
        );
    }
}
