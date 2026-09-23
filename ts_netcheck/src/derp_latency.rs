//! Calculate latency to collections of derp servers.

use core::{fmt::Debug, net::SocketAddr, time::Duration};
use std::sync::Arc;

use ts_control::DerpMap;
use ts_derp::RegionId;

/// Configuration for probing derp map latency.
#[derive(Debug, Copy, Clone)]
pub struct Config {
    /// The number of region probes that must succeed for the probe to end.
    ///
    /// After `complete_threshold` and `min_timeout` are met (or all region probes
    /// complete), the derp map measurement ends.
    pub complete_threshold: usize,

    /// The shortest duration for a derp map probe.
    ///
    /// After `complete_threshold` and `min_timeout` are met (or all region probes
    /// complete), the derp map measurement ends.
    pub min_timeout: Duration,

    /// Config for HTTP probes.
    pub https: crate::https::Config,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            complete_threshold: 3,
            min_timeout: Duration::from_millis(250),

            https: Default::default(),
        }
    }
}

/// Result of measuring latency for a particular derp region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegionResult {
    // NOTE(npry): field order is load-bearing wrt. *Ord derives. `latency` must come first to
    // ensure results are primarily sorted by latency.
    /// The measured latency.
    pub latency: Duration,
    /// The id of the region.
    pub id: RegionId,
    /// The latency map key (in the format to be submitted to control).
    pub latency_map_key: String,
    /// The remote peer we successfully ran the measurement against.
    pub connected_remote: SocketAddr,
}

/// HTTPS probes in flight at once where concurrency is capped (ESP-IDF).
///
/// One. tokio runs on a single worker there, and a TLS handshake is CPU-bound
/// while it verifies the certificate chain, so concurrent handshakes do not
/// overlap -- they interleave, and each takes as long in wall time as all of
/// them together. DERP servers drop a connection whose handshake is not done
/// within 30 s (derper's http.Server read/write timeouts). With 3 at a time the
/// simulator saw every probe fail with an I/O error ~36 s in, and the worker
/// was busy long enough that the control connection died as well.
#[cfg(target_os = "espidf")]
const MAX_CONCURRENT_PROBES: usize = 1;

/// How long to wait for one STUN reply.
const STUN_REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// STUN requests per region, one after another; the fastest reply counts. The
/// first datagram to a new destination is the one most likely to be lost or
/// delayed (ARP, NAT state), and a region has several servers to spread over.
const STUN_PROBES_PER_REGION: usize = 3;

/// Upper bound on one region's probe: TLS dial plus warmup and sample requests.
/// Generous, because on an ESP32 a single TLS handshake can take seconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// Upper bound on the whole measurement, after which partial results are used.
const MEASUREMENT_DEADLINE: Duration = Duration::from_secs(60);

/// Measure all regions in the supplied [`DerpMap`] and return a binary heap sorted by
/// mean per-region sample time.
///
/// Where STUN is used first (ESP-IDF, or natively with `TS_TEST_DERP_STUN=1`),
/// HTTPS probing only runs if no region answered over UDP.
#[tracing::instrument(skip_all)]
pub async fn measure_derp_map(map: &DerpMap, config: &Config) -> Vec<RegionResult> {
    if stun_first() {
        let out = measure_derp_map_stun(map).await;
        if !out.is_empty() {
            log_home_region(&out, "stun");
            return out;
        }
        tracing::warn!("no derp region answered stun; falling back to https probes");
    }

    let out = measure_derp_map_https(map, config).await;
    log_home_region(&out, "https");
    out
}

/// Whether to measure region latency with STUN before trying HTTPS.
///
/// This is how the Go client measures: a STUN binding request is one small UDP
/// exchange, where an HTTPS probe is a TCP connection plus a full TLS handshake
/// per region -- milliseconds of CPU on a desktop, far more on an ESP32, and
/// the map has ~30 regions. HTTPS stays as the fallback for networks that
/// block UDP. Native builds keep HTTPS-first unless `TS_TEST_DERP_STUN=1`.
fn stun_first() -> bool {
    #[cfg(target_os = "espidf")]
    return true;

    #[cfg(not(target_os = "espidf"))]
    return std::env::var("TS_TEST_DERP_STUN").is_ok_and(|v| v == "1");
}

fn log_home_region(out: &[RegionResult], method: &str) {
    match out.first() {
        Some(best) => tracing::info!(
            region_id = %best.id,
            latency = ?best.latency,
            measured = out.len(),
            method,
            "derp latency measured; home region chosen"
        ),
        None => tracing::warn!(method, "derp latency measurement produced no results"),
    }
}

/// Measure every region's latency with STUN over IPv4, all regions at once.
///
/// Returns no results if the STUN sockets cannot be bound or nothing answers.
async fn measure_derp_map_stun(map: &DerpMap) -> Vec<RegionResult> {
    let prober = match crate::StunProber::try_new().await {
        Ok(prober) => Arc::new(prober),
        Err(e) => {
            tracing::warn!(error = %e, "binding stun sockets for latency probes");
            return vec![];
        }
    };

    let mut joinset = tokio::task::JoinSet::new();

    for (&id, region) in map {
        if region.info.no_measure_no_home {
            continue;
        }

        // Servers whose address needs a DNS lookup are left to the HTTPS
        // fallback; Tailscale's map gives fixed addresses.
        let targets = region
            .servers
            .iter()
            .filter_map(|server| match (server.ipv4, server.stun_port) {
                (ts_derp::IpUsage::FixedAddr(ip), Some(port)) => Some(SocketAddr::from((ip, port))),
                _ => None,
            })
            .collect::<Vec<_>>();
        if targets.is_empty() {
            continue;
        }

        let prober = prober.clone();
        joinset.spawn(async move {
            let mut best: Option<(Duration, SocketAddr)> = None;

            for target in targets.iter().cycle().take(STUN_PROBES_PER_REGION) {
                match tokio::time::timeout(STUN_REPLY_TIMEOUT, prober.measure(*target)).await {
                    Ok(Ok((rtt, _mapped))) => {
                        if best.is_none_or(|(fastest, _)| rtt < fastest) {
                            best = Some((rtt, *target));
                        }
                    }
                    Ok(Err(e)) => tracing::debug!(region_id = %id, %target, error = %e, "stun probe"),
                    Err(_) => tracing::debug!(region_id = %id, %target, "stun probe timed out"),
                }
            }

            best.map(|(latency, connected_remote)| RegionResult {
                latency,
                id,
                latency_map_key: format!("{id}-v4"),
                connected_remote,
            })
        });
    }

    let mut out = Vec::with_capacity(joinset.len());
    while let Some(ret) = joinset.join_next().await {
        match ret {
            Ok(Some(result)) => out.push(result),
            Ok(None) => {}
            Err(e) => tracing::error!(error = %e, "failed to join"),
        }
    }

    out.sort();
    out
}

/// Measure regions over HTTPS: a TLS connection and a latency-check request each.
async fn measure_derp_map_https(map: &DerpMap, config: &Config) -> Vec<RegionResult> {
    let mut joinset = tokio::task::JoinSet::new();

    // How many regions may be probed at once. Each probe is a TCP connection
    // plus a full TLS handshake, and there is one per region (~30). Launching
    // them together is fine on a desktop; on an ESP32 it exhausted the lwIP
    // socket table (16 sockets in the Arduino libs, shared with the host
    // application) and ran ~30 handshakes at once on one core, starving the
    // application's main loop until the task watchdog reset the chip.
    //
    // With a cap in force every region is still measured, just a few at a
    // time, until they finish or MEASUREMENT_DEADLINE passes. Stopping after
    // complete_threshold answers, as the uncapped path does, would pick the
    // home region from whichever regions were probed first -- the lowest IDs,
    // since the map is a BTreeMap: New York, San Francisco, Singapore. Every
    // packet to this node goes through its home region, so for a node in
    // Europe that would be a permanent transatlantic detour. The cost is up to
    // the deadline longer before the node is reachable at startup.
    #[cfg(target_os = "espidf")]
    let permits = Some(Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES)));
    // Native builds leave concurrency unbounded, but can impose the ESP-IDF
    // cap for testing: TS_TEST_DERP_PROBE_CONCURRENCY=N.
    #[cfg(not(target_os = "espidf"))]
    let permits: Option<Arc<tokio::sync::Semaphore>> = std::env::var("TS_TEST_DERP_PROBE_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|n| Arc::new(tokio::sync::Semaphore::new(n.max(1))));

    for (&id, region) in map {
        if region.info.no_measure_no_home {
            tracing::trace!(region_id = %id, "skip! region is no_measure_no_home");
            continue;
        }

        let servers = region.servers.clone();
        let latency_map_key = format!("{id}-v4");

        let config = config.https;
        let permits = permits.clone();

        joinset.spawn(async move {
            let _permit = match permits {
                Some(sem) => sem.acquire_owned().await.ok(),
                None => None,
            };
            // Nothing below this has a timeout of its own: a region whose
            // servers accept the TCP connection but never answer would hold
            // this task -- and, on ESP-IDF, one of the few permits -- forever.
            // Test hook, native only: TS_TEST_DERP_PROBE_HANG_REGIONS=1,2,3 makes
            // those regions' probes never finish -- the suspected ESP32 failure,
            // where stalled probes held every permit and no home region was
            // ever chosen.
            #[cfg(not(target_os = "espidf"))]
            if std::env::var("TS_TEST_DERP_PROBE_HANG_REGIONS")
                .map(|v| v.split(',').any(|r| r.trim() == id.to_string()))
                .unwrap_or(false)
            {
                tracing::warn!(region_id = %id, "TEST HOOK: latency probe will hang");
                let hang = core::future::pending::<Option<(Duration, SocketAddr)>>();
                let sample_info = tokio::time::timeout(PROBE_TIMEOUT, hang).await.ok().flatten();
                if sample_info.is_none() {
                    tracing::warn!(region_id = %id, "latency probe timed out");
                }
                return Result::<_, crate::https::Error>::Ok((id, latency_map_key, sample_info));
            }

            let sample_info =
                match tokio::time::timeout(PROBE_TIMEOUT, crate::measure_https_latency(&servers, config)).await {
                    Ok(result) => result.map(|(dur, _info, addr)| (dur, addr)),
                    Err(_) => {
                        tracing::warn!(region_id = %id, "latency probe timed out");
                        None
                    }
                };

            Result::<_, crate::https::Error>::Ok((id, latency_map_key, sample_info))
        });
    }

    let mut out = Vec::with_capacity(map.len());

    let process_joinset_result = |out: &mut Vec<_>, ret| {
        match ret {
            Ok(Ok((id, latency_map_key, Some((dur, addr))))) => {
                out.push(RegionResult {
                    latency: dur,
                    connected_remote: addr,
                    id,
                    latency_map_key,
                });
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "measuring region failed");
            }
            Ok(Ok((id, ..))) => {
                tracing::error!(%id, "region had no reachable servers");
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to join");
            }
        };
    };

    let mut timeout = core::pin::pin![tokio::time::sleep(config.min_timeout)];
    let mut deadline = core::pin::pin![tokio::time::sleep(MEASUREMENT_DEADLINE)];

    // See `permits`: when capped, wait for every region (or the deadline).
    let complete_threshold = if permits.is_some() {
        joinset.len()
    } else {
        config.complete_threshold
    };

    while !(out.len() >= complete_threshold && timeout.is_elapsed()) {
        // A tokio Sleep that has fired stays ready. Without this guard the
        // timeout branch wins every iteration once min_timeout has passed and
        // fewer than complete_threshold results are in -- a busy loop that holds
        // a worker until the probes finish. Invisible on a desktop, where
        // results arrive in milliseconds; seconds of pinned CPU on an ESP32,
        // where each probe is a TLS handshake.
        let timeout_pending = !timeout.is_elapsed();

        tokio::select! {
            ret = joinset.join_next() => {
                let Some(ret) = ret else {
                    break;
                };

                process_joinset_result(&mut out, ret);
            },
            _ = &mut timeout, if timeout_pending => {},
            _ = &mut deadline => {
                // Better a home region chosen from partial results than none:
                // with no measurement the node never advertises a preferred
                // DERP region and, being relay-only, is unreachable.
                tracing::warn!(results = out.len(), "derp latency measurement deadline reached");
                break;
            },
        }
    }

    // If there are any more ready results available without waiting, add them.
    while let Some(x) = joinset.try_join_next() {
        process_joinset_result(&mut out, x);
    }

    out.sort();
    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn map() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let map = load_derp_map().await;
        let result = measure_derp_map(&map, &Default::default()).await;

        tracing::info!("measured latencies:\n{result:#?}");
    }

    async fn load_derp_map() -> DerpMap {
        const DERP_MAP_URL: &str = "https://login.tailscale.com/derpmap/default";

        let result = reqwest::get(DERP_MAP_URL).await.unwrap();
        let body = result.bytes().await.unwrap();

        let map = serde_json::from_slice::<ts_control_serde::DerpMap>(&body).unwrap();

        ts_control::convert_derp_map(&map).collect()
    }
}
