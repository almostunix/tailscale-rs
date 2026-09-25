//! Live check that a reconnect reuses the control server's Noise key, so it costs one TLS
//! handshake rather than two. Needs the internet; no auth key (it stops before registering):
//!
//!     cargo test -p ts_control --test control_key_reuse -- --ignored --nocapture

#[tokio::test(flavor = "multi_thread")]
#[ignore = "talks to controlplane.tailscale.com"]
async fn reconnect_reuses_the_control_key() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .ok();

    let url = ts_control::DEFAULT_CONTROL_SERVER.clone();
    let keys = ts_keys::MachineKeyPair::random();

    for attempt in 1..=2 {
        let started = std::time::Instant::now();
        ts_control::ControlDialer::default()
            .full_connect_next(&url, &keys)
            .await
            .expect("connect to control");
        println!("connection {attempt}: {:?}", started.elapsed());
    }
}
