use core::fmt::{Debug, Formatter};
use std::{
    sync::{Mutex, PoisonError},
    time::Instant,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_util::future::FutureExt;
use ts_bitset::BitsetDyn;
use ts_capabilityversion::CapabilityVersion;
use ts_http_util::{BytesBody, Http2};
use url::Url;

use crate::{DialCandidate, DialMode, DialPlan, Error, InternalErrorKind, Operation};

/// Manages state for control dial plan and handles selection of successive dial candidates.
pub struct ControlDialer {
    plan: DialPlan,
    epoch: usize,
    timestamp: Instant,
    attempted_candidates: ts_dynbitset::DynBitset,
}

impl Default for ControlDialer {
    fn default() -> Self {
        Self {
            plan: DialPlan::default(),
            epoch: 0,
            timestamp: Instant::now(),
            attempted_candidates: Default::default(),
        }
    }
}

/// Creates a TCP connection on the basis of a specific [`DialCandidate`].
///
/// Produced by [`ControlDialer::next_dialer`].
pub trait TcpDialer {
    /// Open a TCP connection using the [`DialCandidate`] assigned to this dialer.
    ///
    /// - `host` is used if the [`DialCandidate`] requires DNS lookup.
    ///   **Ignored** for plain IP [`DialCandidate`]s.
    /// - `port` is the TCP port to connect to.
    ///
    /// Calling this function marks the current candidate as "attempted": the next call to
    /// [`ControlDialer::next_dialer`] will use the next available candidate.
    fn dial(
        self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = tokio::io::Result<TcpStream>> + Send;
}

enum ControlTcpDialer<'a> {
    UseDns,
    Planned {
        attempted: &'a mut ts_dynbitset::DynBitset,
        candidate: &'a DialCandidate,
        index: usize,
    },
}

impl Debug for ControlTcpDialer<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ControlTcpDialer::UseDns => write!(f, "TcpDialer::Dns"),
            ControlTcpDialer::Planned { candidate, .. } => match &candidate.mode {
                DialMode::Ip(ip) => f.debug_tuple("TcpDialer::Ip").field(ip).finish(),
                DialMode::Ace { ip: Some(ip), host } => f
                    .debug_tuple("TcpDialer::Ace")
                    .field(ip)
                    .field(host)
                    .finish(),
                DialMode::Ace { host, .. } => f.debug_tuple("TcpDialer::Ace").field(host).finish(),
            },
        }
    }
}

impl TcpDialer for ControlTcpDialer<'_> {
    async fn dial(self, host: &str, port: u16) -> tokio::io::Result<TcpStream> {
        match self {
            ControlTcpDialer::UseDns => TcpStream::connect(format!("{host}:{port}")).await,
            ControlTcpDialer::Planned {
                candidate,
                attempted: used,
                index,
            } => {
                used.set(index);

                match candidate.mode {
                    DialMode::Ip(ip) => {
                        TcpStream::connect((ip, port))
                            .timeout(candidate.timeout)
                            .await?
                    }
                    DialMode::Ace { .. } => {
                        unimplemented!()
                    }
                }
            }
        }
    }
}

impl ControlDialer {
    /// Update the stored dial plan with the new `plan`.
    ///
    /// Returns whether the dial plan changed. Resubmission of the same dial plan is
    /// idempotent.
    pub fn update_dial_plan(&mut self, plan: &DialPlan) -> bool {
        if &self.plan == plan {
            return false;
        }

        self.plan = plan.clone();
        self.epoch += 1;
        self.timestamp = Instant::now();

        true
    }

    /// Clear the set of attempted dial candidates.
    ///
    /// This will cause future connection attempts to retry all available dialers in
    /// priority order.
    pub fn clear_attempted(&mut self) {
        self.attempted_candidates.clear_all();
    }

    /// Get the next dialer candidate from the dial plan.
    ///
    /// If all dialers have already been tried, falls back to system DNS.
    ///
    /// NB: the returned [`TcpDialer`] does not mark its corresponding candidate as having
    /// been attempted until [`TcpDialer::dial`] is called -- it is fine semantically to
    /// drop the returned dialer without calling `dial`.
    pub fn next_dialer(&mut self) -> impl TcpDialer + Debug {
        self.next_candidate()
    }

    fn next_candidate(&mut self) -> ControlTcpDialer<'_> {
        match &self.plan {
            DialPlan::UseDns => ControlTcpDialer::UseDns,
            DialPlan::Plan(candidates) => {
                let mut selected_candidate: Option<(usize, usize, &DialCandidate)> = None;
                let now = Instant::now();

                // TODO(npry): ensure candidate sorting, optimistically stop early
                for (i, candidate) in candidates.iter().enumerate() {
                    if self.attempted_candidates.test(i) {
                        continue;
                    }

                    let start_after = self.timestamp + candidate.start_delay_sec;
                    if start_after > now {
                        continue;
                    }

                    if matches!(candidate.mode, DialMode::Ace { .. }) {
                        // TODO(npry): ACE unsupported
                        continue;
                    }

                    if selected_candidate.is_none_or(|(prio, _idx, elem)| prio < elem.priority) {
                        selected_candidate = Some((candidate.priority, i, candidate));
                    }
                }

                let (i, candidate) = match selected_candidate {
                    Some((_prio, i, elem)) => (i, elem),
                    None => {
                        tracing::warn!(
                            "no dialer candidates available: falling back to system dns"
                        );
                        return ControlTcpDialer::UseDns;
                    }
                };

                ControlTcpDialer::Planned {
                    candidate,
                    index: i,
                    attempted: &mut self.attempted_candidates,
                }
            }
        }
    }

    /// Convenience wrapper for [`next_dialer`][ControlDialer::next_dialer] followed by
    /// [`complete_connection`].
    #[tracing::instrument(skip_all, fields(control_url = %url))]
    pub async fn full_connect_next(
        &mut self,
        url: &Url,
        machine_keys: &ts_keys::MachineKeyPair,
    ) -> Result<Http2<BytesBody>, Error> {
        let host = url.host_str().ok_or(Error::InvalidUrl(url.clone()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::InvalidUrl(url.clone()))?;

        let conn = loop {
            let next = self.next_candidate();
            tracing::trace!(selected_control_dialer = ?next);
            let planned = format!("{next:?}");
            let is_planned = matches!(next, ControlTcpDialer::Planned { .. });

            match next.dial(host, port).await {
                Ok(conn) => break conn,
                // The dial plan control sends lists IPv6 addresses too. On a host
                // with no IPv6 route -- an ESP32 on an IPv4-only network -- those
                // fail locally, before a packet is sent, and each one used to cost
                // a full reconnect backoff. Move straight on to the next candidate;
                // the plan runs out into the DNS dialer, which ends the loop.
                Err(e) if is_planned && is_unusable_locally(&e) => {
                    tracing::debug!(error = %e, candidate = %planned, "control dial candidate unusable here, trying next");
                }
                Err(e) => {
                    tracing::error!(error = %e, %url, %host, port, candidate = %planned, "dialing tcp");
                    return Err(Error::Internal(
                        InternalErrorKind::Io,
                        Operation::ConnectToControlServer,
                    ));
                }
            }
        };

        tracing::debug!(
            remote_endpoint = ?conn.peer_addr(),
            "tcp connection to control"
        );

        let client = complete_connection(url, machine_keys, conn).await?;

        Ok(client)
    }
}

/// Whether a dial failed fast because the address cannot be reached from here
/// (no route to it, address family unavailable) -- unlike a timeout or a
/// refusal, which say something about the server rather than the path.
fn is_unusable_locally(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;

    matches!(
        e.kind(),
        HostUnreachable | NetworkUnreachable | AddrNotAvailable | Unsupported
    )
}

/// Complete a connection to control over the supplied I/O `stream`.
///
/// Establishes an http1 connection over `stream`, wrapping it in a TLS connection if
/// `url`'s scheme is `https`. Then upgrades the connection over ts2021 and establishes an
/// inner http2 connection.
pub async fn complete_connection<Io>(
    url: &Url,
    machine_keys: &ts_keys::MachineKeyPair,
    stream: Io,
) -> Result<Http2<BytesBody>, Error>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let h1_client = match url.scheme() {
        "https" => {
            let conn = ts_tls_util::connect(
                ts_tls_util::server_name(url).ok_or_else(|| Error::InvalidUrl(url.clone()))?,
                stream,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "establishing tls connection");
                Error::io_error(e, Operation::ConnectToControlServer)
            })?;
            ts_http_util::http1::connect(conn).await?
        }
        "http" => ts_http_util::http1::connect(stream).await?,
        other => {
            tracing::error!(invalid_scheme = other);
            return Err(Error::InvalidUrl(url.clone()));
        }
    };
    let cached_key = control_key_cache(url, KeyCacheOp::Get);
    let control_public_key = match cached_key {
        Some(key) => key,
        None => crate::client::fetch_control_key(url).await?,
    };

    let (handshake, init_msg) = ts_control_noise::Handshake::initialize(
        &crate::client::CONTROL_PROTOCOL_VERSION,
        machine_keys,
        &control_public_key,
        CapabilityVersion::CURRENT,
    );

    let upgraded = async {
        let conn =
            crate::client::upgrade_ts2021(url, &init_msg, handshake, machine_keys, h1_client)
                .await?;
        let conn = crate::client::read_challenge_packet(conn).await?;
        Ok::<_, Error>(ts_http_util::http2::connect(conn).await?)
    }
    .await;

    match &upgraded {
        Ok(_) => {
            control_key_cache(url, KeyCacheOp::Put(control_public_key));
            tracing::debug!(
                cached_key = cached_key.is_some(),
                "http2 connection to control established"
            );
        }
        // The server may have rotated its key: fetch it afresh next time.
        Err(_) if cached_key.is_some() => {
            control_key_cache(url, KeyCacheOp::Forget);
        }
        Err(_) => {}
    }

    upgraded
}

enum KeyCacheOp {
    Get,
    Put(ts_keys::MachinePublicKey),
    Forget,
}

/// Control servers' Noise public keys, by control URL, kept for the life of the process.
///
/// Fetching the key takes its own HTTPS connection, so without this every reconnect paid for
/// two TLS handshakes -- ~1.9 s each on an ESP32. Go's client keeps the key the same way. It
/// was fetched over a verified TLS connection, and a key that stops working is forgotten.
fn control_key_cache(url: &Url, op: KeyCacheOp) -> Option<ts_keys::MachinePublicKey> {
    static KEYS: Mutex<Vec<(String, ts_keys::MachinePublicKey)>> = Mutex::new(Vec::new());

    let mut keys = KEYS.lock().unwrap_or_else(PoisonError::into_inner);
    let at = keys.iter().position(|(u, _)| u == url.as_str());
    match (op, at) {
        (KeyCacheOp::Get, Some(i)) => return Some(keys[i].1),
        (KeyCacheOp::Get, None) => {}
        (KeyCacheOp::Put(key), Some(i)) => keys[i].1 = key,
        (KeyCacheOp::Put(key), None) => keys.push((url.as_str().to_owned(), key)),
        (KeyCacheOp::Forget, Some(i)) => {
            keys.swap_remove(i);
        }
        (KeyCacheOp::Forget, None) => {}
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_key_cache_is_per_url_and_forgets() {
        let url = Url::parse("https://control.test.invalid/").unwrap();
        let other = Url::parse("https://other.test.invalid/").unwrap();
        let key = ts_keys::MachineKeyPair::random().public;

        assert!(control_key_cache(&url, KeyCacheOp::Get).is_none());
        control_key_cache(&url, KeyCacheOp::Put(key));
        assert!(control_key_cache(&url, KeyCacheOp::Get) == Some(key));
        assert!(control_key_cache(&other, KeyCacheOp::Get).is_none());
        control_key_cache(&url, KeyCacheOp::Forget);
        assert!(control_key_cache(&url, KeyCacheOp::Get).is_none());
    }
}
