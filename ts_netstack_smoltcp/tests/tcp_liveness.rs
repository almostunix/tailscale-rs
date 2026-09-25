//! Connection liveness: a half-close reaches the peer, and a peer that vanishes is timed out.

#![cfg(feature = "tokio")]

use core::{net::Ipv4Addr, time::Duration};

use ts_netstack_smoltcp::{Netstack, WakingPipe, WakingPipeDev};
use ts_netstack_smoltcp_core::{self as netcore, HasChannel, NetstackControl};
use ts_netstack_smoltcp_socket::{CreateSocket, TcpStream};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 32, 33);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 32, 34);
const PORT: u16 = 1000;

struct Pair {
    client: TcpStream,
    server: TcpStream,
    client_stack: tokio::task::JoinHandle<()>,
}

async fn connected_pair(config: netcore::Config) -> Pair {
    let (p1, p2) = WakingPipe::new(None);
    let dev = |pipe| WakingPipeDev {
        pipe,
        mtu: 1500,
        medium: netcore::smoltcp::phy::Medium::Ip,
    };
    let mut stack1 = Netstack::new(dev(p1), config.clone());
    let mut stack2 = Netstack::new(dev(p2), config);
    let (ch1, ch2) = (stack1.command_channel(), stack2.command_channel());

    let client_stack = tokio::spawn(async move { stack1.run_tokio().await });
    tokio::spawn(async move { stack2.run_tokio().await });
    ch1.set_ips([CLIENT_IP.into()]).await.unwrap();
    ch2.set_ips([SERVER_IP.into()]).await.unwrap();

    let listener = ch2.tcp_listen((SERVER_IP, PORT).into()).await.unwrap();
    let client = ch1
        .tcp_connect((CLIENT_IP, PORT).into(), (SERVER_IP, PORT).into())
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();

    Pair {
        client,
        server,
        client_stack,
    }
}

fn with_liveness() -> netcore::Config {
    netcore::Config {
        tcp_keep_alive: Some(Duration::from_millis(200)),
        tcp_timeout: Some(Duration::from_secs(1)),
        ..Default::default()
    }
}

#[tokio::test]
async fn shutdown_delivers_end_of_stream_and_keeps_receiving() {
    let p = connected_pair(Default::default()).await;
    let mut buf = [0; 16];

    p.server.shutdown().unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), p.client.recv(&mut buf))
        .await
        .expect("client should see end-of-stream promptly")
        .unwrap();
    assert_eq!(n, 0, "a half-closed server sends FIN");

    // The server's receive side is still open.
    p.client.send(b"late").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), p.server.recv(&mut buf))
        .await
        .expect("server should still receive after shutdown")
        .unwrap();
    assert_eq!(&buf[..n], b"late");

    // And sees the client's own close as usual.
    drop(p.client);
    let n = tokio::time::timeout(Duration::from_secs(5), p.server.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn vanished_peer_releases_a_blocked_recv() {
    let p = connected_pair(with_liveness()).await;
    let mut buf = [0; 16];

    // The client's stack disappears: no FIN, no RST, nothing answers.
    p.client_stack.abort();

    let result = tokio::time::timeout(Duration::from_secs(10), p.server.recv(&mut buf))
        .await
        .expect("keep-alive + timeout should end a recv on a vanished peer");
    assert!(result.is_err(), "expected an error, got {result:?}");
    drop(p.client);
}

#[tokio::test]
async fn vanished_peer_releases_a_blocked_send() {
    let p = connected_pair(with_liveness()).await;

    p.client_stack.abort();

    // Fill the send buffer so the next send blocks, as it would behind a dead phone.
    let chunk = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            p.server.send(&chunk).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), netcore::Error>(())
    })
    .await
    .expect("timeout should end a send blocked on a vanished peer");
    assert!(result.is_err());
    drop(p.client);
}

#[tokio::test]
async fn without_liveness_a_vanished_peer_holds_recv_forever() {
    let p = connected_pair(Default::default()).await;
    let mut buf = [0; 16];

    p.client_stack.abort();

    assert!(
        tokio::time::timeout(Duration::from_secs(3), p.server.recv(&mut buf))
            .await
            .is_err(),
        "the default config has no keep-alive, so this recv never ends"
    );
    drop(p.client);
}

async fn within<F: core::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .expect("timed out")
}

/// The firmware's two teardowns, repeated: the client hangs up first; or the node drops the client
/// (idle timeout, a newer client) while its reader is still blocked in recv. Either way the node
/// shuts down, then frees the socket, and the netstack must survive.
#[tokio::test]
async fn firmware_close_sequences_keep_the_netstack_alive() {
    let (p1, p2) = WakingPipe::new(None);
    let dev = |pipe| WakingPipeDev {
        pipe,
        mtu: 1500,
        medium: netcore::smoltcp::phy::Medium::Ip,
    };
    let mut stack1 = Netstack::new(dev(p1), with_liveness());
    let mut stack2 = Netstack::new(dev(p2), with_liveness());
    let (ch1, ch2) = (stack1.command_channel(), stack2.command_channel());
    let client_stack = tokio::spawn(async move { stack1.run_tokio().await });
    let server_stack = tokio::spawn(async move { stack2.run_tokio().await });
    ch1.set_ips([CLIENT_IP.into()]).await.unwrap();
    ch2.set_ips([SERVER_IP.into()]).await.unwrap();
    let listener = ch2.tcp_listen((SERVER_IP, PORT).into()).await.unwrap();

    for round in 0..6 {
        let client = ch1
            .tcp_connect(
                (CLIENT_IP, PORT + 1 + round).into(),
                (SERVER_IP, PORT).into(),
            )
            .await
            .unwrap();
        let server = std::sync::Arc::new(listener.accept().await.unwrap());
        let mut buf = [0; 64];

        client.send(b"want_config").await.unwrap();
        let n = server.recv(&mut buf).await.unwrap();
        server.send(&buf[..n]).await.unwrap();
        client.recv(&mut buf).await.unwrap();

        if round % 2 == 0 {
            drop(client);
            assert_eq!(within(server.recv(&mut buf)).await.unwrap(), 0);
            server.shutdown().unwrap();
        } else {
            let reader = tokio::spawn({
                let server = server.clone();
                async move { server.recv(&mut [0; 8]).await }
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            server.shutdown().unwrap();

            // The client sees the node's FIN and closes, which ends the parked recv.
            assert_eq!(within(client.recv(&mut buf)).await.unwrap(), 0);
            drop(client);
            assert_eq!(within(reader).await.unwrap().unwrap(), 0);
        }
        drop(server);

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !server_stack.is_finished(),
            "server netstack died in round {round}"
        );
        assert!(
            !client_stack.is_finished(),
            "client netstack died in round {round}"
        );
    }

    // Past keep-alive and timeout, with every socket closed.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !server_stack.is_finished(),
        "server netstack died after teardown"
    );
}
