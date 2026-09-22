use core::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use futures::{Stream, StreamExt};
use kameo::{
    actor::{ActorRef, Spawn, WeakActorRef},
    message::{Context, StreamMessage},
    prelude::{Message, ReplySender},
    reply::DelegatedReply,
    supervision::RestartPolicy,
};
use ts_control::{
    ControlDialer, DialPlan, Endpoint, Error as ControlError, Node, RegistrationError, StateUpdate,
    client::{HttpConn, handle_ping, map_stream, send_map_request},
};

use crate::{
    Task,
    derp_latency::{DerpLatencyMeasurement, DerpLatencyMeasurer},
    direct,
    env::Env,
};

// Reconnection.
//
// Recovery from a lost control connection already exists: every failure path
// ends in ctx.stop(), and ControlRunner is supervised with kameo's default
// RestartPolicy::Permanent, so it is restarted and on_start dials and
// registers again. What was missing is everything that makes that fire:
//
// - Nothing had a timeout. A connection that dies without an error -- a peer
//   or middlebox that stops answering -- left register() or the map stream
//   waiting forever, so ctx.stop() was never reached. Seen on an ESP32: one
//   dropped connection during the join, then five minutes of nothing.
//
// - Nothing throttled restarts. kameo gives up on a child for good after 5
//   restarts in 5 seconds; with the network down each attempt fails at once,
//   so a node would exhaust that in about a second and never reconnect.
//
// Hence timeouts on each stage, exponential backoff between attempts (which
// also keeps a battery-powered node from hammering a dead network), and a
// failure count shared across restarts through Params.

/// Bound on dialing control (TCP, TLS, Noise). Generous: an ESP32 in a
/// simulator took over a minute to dial and register on a good day.
const DIAL_TIMEOUT: Duration = Duration::from_secs(90);

/// Bound on the initial registration request. Not applied to the follow-up
/// long-poll that waits for interactive approval, which may take minutes.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(120);

/// The map stream is requested with keep_alive (see MapRequestBuilder::as_stream),
/// and map_stream turns every message, keepalives included, into a StateUpdate.
/// So a stream this quiet is dead, not idle. Deliberately conservative.
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Longest wait between reconnection attempts. Five minutes rather than one
/// because this runs on battery-powered nodes: during an outage every attempt
/// is a TLS handshake, which is expensive on a microcontroller, and a one-minute
/// cap would mean over 1,400 of them a day. The cost is up to five minutes'
/// extra delay rejoining once the network is back.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// 1s, 2s, 4s, ... up to MAX_BACKOFF, for the nth consecutive failure.
fn reconnect_backoff(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(16);
    Duration::from_secs(1u64 << exp).min(MAX_BACKOFF)
}

/// End `stream` if no item arrives within `idle`, so that a silently dead
/// connection reaches the StreamMessage::Finished path and is reconnected.
// The suggested async closure does not compile here: it would capture `idle`,
// and an async closure that captures is not FnMut, which unfold requires.
#[allow(closure_returning_async_block)]
fn end_when_idle<S>(stream: S, idle: Duration) -> impl Stream<Item = S::Item>
where
    S: Stream + Send + 'static,
{
    futures::stream::unfold(Box::pin(stream), move |mut stream| async move {
        match tokio::time::timeout(idle, stream.next()).await {
            Ok(Some(item)) => Some((item, stream)),
            Ok(None) => None,
            Err(_) => {
                tracing::error!(?idle, "no control update or keepalive; treating connection as dead");
                None
            }
        }
    })
}

/// Fault injection for exercising reconnection against a real control server
/// on demand, instead of waiting for a network to misbehave. Environment
/// variables, read once; compiled out of ESP-IDF firmware entirely.
///
/// - TS_TEST_FAIL_DIALS=N: the first N dial attempts fail immediately.
/// - TS_TEST_STREAM_IDLE_SECS=N: use N seconds as the map stream idle timeout.
#[cfg(not(target_os = "espidf"))]
mod test_hooks {
    use core::time::Duration;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn env_u64(name: &str) -> Option<u64> {
        std::env::var(name).ok()?.parse().ok()
    }

    pub fn should_fail_dial() -> bool {
        static FORCED: AtomicU32 = AtomicU32::new(0);
        let limit = env_u64("TS_TEST_FAIL_DIALS").unwrap_or(0) as u32;
        FORCED.fetch_add(1, Ordering::Relaxed) < limit
    }

    pub fn stream_idle_timeout(default: Duration) -> Duration {
        env_u64("TS_TEST_STREAM_IDLE_SECS").map_or(default, Duration::from_secs)
    }
}

#[cfg(target_os = "espidf")]
mod test_hooks {
    use core::time::Duration;

    pub fn should_fail_dial() -> bool {
        false
    }

    pub fn stream_idle_timeout(default: Duration) -> Duration {
        default
    }
}

/// Tell the control runner the connection attempt failed, so it stops and is
/// restarted by its supervisor.
async fn report_lost(aref: &WeakActorRef<ControlRunner>, reason: &'static str) {
    if let Some(aref) = aref.upgrade() {
        drop(aref.tell(ControlLost(reason)).await);
    }
}

/// Actor responsible for maintaining the connection to control.
///
/// This actor is responsible for proxying the map response stream onto the message bus.
pub struct ControlRunner {
    params: Params,
    state: RegState,

    derp_latency_measurement: Option<DerpLatencyMeasurement>,

    endpoints: Vec<Endpoint>,

    self_node: Option<Node>,
    pending_node_requests: Vec<PendingNodeRequest>,
}

enum RegState {
    NotRegistered {
        pending_auth_requests: Vec<ReplySender<Option<url::Url>>>,
    },
    AuthRequired(url::Url),
    Registered(HttpConn),
}

/// Control runner args.
#[derive(Clone)]
pub struct Params {
    /// Control config.
    pub(crate) config: ts_control::Config,

    /// Auth key (if needed).
    pub(crate) auth_key: Option<String>,

    /// The [`Env`] for this actor.
    pub(crate) env: Env,

    /// Consecutive failed connection attempts, for backoff. Shared across
    /// restarts: kameo re-runs on_start with a clone of these Params, and the
    /// Arc makes every clone see the same count. Reset once a map update
    /// arrives, i.e. once the connection has demonstrably worked end to end.
    pub(crate) failures: Arc<AtomicU32>,
}

#[doc(hidden)]
#[derive(Debug, Clone, thiserror::Error)]
pub enum ControlRunnerError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Crate(#[from] crate::Error),
}

#[derive(Clone)]
struct AuthRequired(url::Url);

struct RegisterResult(Result<HttpConn, RegistrationError>);

/// A connection attempt failed or timed out before registration completed.
struct ControlLost(&'static str);

impl kameo::Actor for ControlRunner {
    type Args = Params;
    type Error = ControlRunnerError;

    async fn on_start(params: Params, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        // Dialing happens in the task rather than here: on_start runs on every
        // restart, and a failure here would be an actor-start failure rather
        // than the ordinary stop-and-restart path the rest of this file uses.
        Task::supervise_with(&slf, {
            let aref = slf.downgrade();
            let params = params.clone();

            move || {
                let aref = aref.clone();
                let params = params.clone();

                async move {
                    let failures = params.failures.load(Ordering::Relaxed);
                    if failures > 0 {
                        let delay = reconnect_backoff(failures);
                        tracing::warn!(failures, ?delay, "reconnecting to control server");
                        tokio::time::sleep(delay).await;
                    }

                    if test_hooks::should_fail_dial() {
                        tracing::warn!("TEST HOOK: forcing dial failure");
                        report_lost(&aref, "forced dial failure (TS_TEST_FAIL_DIALS)").await;
                        return;
                    }

                    let dial = params.env.ask::<DialerActor, _>(
                        None,
                        DialNext {
                            url: params.config.server_url.clone(),
                        },
                        true,
                    );
                    let client = match tokio::time::timeout(DIAL_TIMEOUT, dial).await {
                        Ok(Ok(client)) => client,
                        Ok(Err(e)) => {
                            tracing::error!(error = %e, "dialing control server");
                            report_lost(&aref, "dial failed").await;
                            return;
                        }
                        Err(_) => {
                            tracing::error!(timeout = ?DIAL_TIMEOUT, "dialing control server timed out");
                            report_lost(&aref, "dial timed out").await;
                            return;
                        }
                    };

                    let mut followup = None;

                    loop {
                        let is_followup = followup.is_some();
                        let register = ts_control::register(
                            &params.config,
                            &params.config.server_url,
                            params.auth_key.as_deref(),
                            followup,
                            &params.env.keys,
                            &client,
                        );

                        let result = if is_followup {
                            register.await
                        } else {
                            match tokio::time::timeout(REGISTER_TIMEOUT, register).await {
                                Ok(result) => result,
                                Err(_) => {
                                    tracing::error!(timeout = ?REGISTER_TIMEOUT, "registering with control server timed out");
                                    report_lost(&aref, "register timed out").await;
                                    return;
                                }
                            }
                        };

                        if let Err(RegistrationError::MachineNotAuthorized(Some(u))) = result {
                            tracing::warn!(auth_url = %u, "machine not authorized");
                            followup = Some(u.clone());

                            let Some(aref) = aref.upgrade() else {
                                // if the control runner is dead, we should die shortly, no reason
                                // to keep running.
                                return;
                            };

                            if let Err(e) = aref.tell(AuthRequired(u)).await {
                                tracing::error!(error = %e, "failed to tell control runner required auth");
                            }

                            continue;
                        }

                        let Some(aref) = aref.upgrade() else {
                            return;
                        };
                        drop(aref.tell(RegisterResult(result.map(|_| client))).await);

                        break;
                    }
                }
            }
        })
        .restart_policy(RestartPolicy::Transient)
        .spawn()
        .await;

        params.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;
        params.env.subscribe::<direct::NewEndpoints>(&slf).await?;

        DerpLatencyMeasurer::supervise(&slf, params.env.clone())
            .spawn()
            .await;

        params.env.register(None, &slf).await?;

        Ok(Self {
            state: RegState::NotRegistered {
                pending_auth_requests: Default::default(),
            },
            params,
            derp_latency_measurement: None,
            endpoints: Default::default(),
            self_node: None,
            pending_node_requests: Default::default(),
        })
    }
}

#[kameo::messages]
impl ControlRunner {
    /// Fetch the IPv4 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv4(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv4Addr>>>,
    ) -> DelegatedReply<Option<Ipv4Addr>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.tailnet_address.ipv4.addr()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::Ipv4(replier));
        }

        deleg
    }

    /// Fetch the IPv6 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv6(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv6Addr>>>,
    ) -> DelegatedReply<Option<Ipv6Addr>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.tailnet_address.ipv6.addr()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::Ipv6(replier));
        }

        deleg
    }

    /// Fetch the self node for this tailscale device.
    #[message(ctx)]
    pub fn self_node(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
    ) -> DelegatedReply<Option<Node>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.clone()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::SelfNode(replier));
        }

        deleg
    }

    /// Wait for a report of whether interactive auth is needed, and if so, what the URL is.
    #[message(ctx)]
    pub fn auth_url(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<url::Url>>>,
    ) -> DelegatedReply<Option<url::Url>> {
        match &mut self.state {
            RegState::Registered(..) => ctx.reply(None),
            RegState::AuthRequired(u) => ctx.reply(Some(u.clone())),
            RegState::NotRegistered {
                pending_auth_requests,
            } => {
                let (deleg, replier) = ctx.reply_sender();
                if let Some(replier) = replier {
                    pending_auth_requests.push(replier);
                }

                deleg
            }
        }
    }
}

impl ControlRunner {
    /// Call `f` with a map request built from the current control actor state.
    ///
    /// `stream` dictates whether the request is built for a streaming netmap response or as a
    /// request to update to this node's fields in control.
    ///
    /// This takes a closure rather than returning the built request for lifetime reasons.
    async fn with_map_request<T>(
        &self,
        stream: bool,
        f: impl AsyncFnOnce(ts_control::MapRequest) -> T,
    ) -> T {
        let mut mrb = ts_control::MapRequestBuilder::new(&self.params.env.keys);

        mrb = if stream {
            mrb.as_stream()
        } else {
            mrb.as_request()
        };

        mrb = mrb.endpoints(self.endpoints.clone());

        if let Some(hostname) = self.params.config.hostname.as_deref() {
            mrb = mrb.hostname(hostname);
        }

        if let Some(latency) = &self.derp_latency_measurement {
            if let Some(result) = latency.measurement.first() {
                mrb = mrb.preferred_derp(result.id);
            };

            let iter = latency.measurement.iter().map(|result| {
                (
                    result.latency_map_key.as_str(),
                    result.latency.as_secs_f64(),
                )
            });

            mrb = mrb.derp_latencies(iter);
        }

        let client_name = self.params.config.format_client_name();

        let mut request = mrb.build();
        let host_info = request.host_info.get_or_insert_default();
        host_info.app = &client_name;
        host_info.ipn_version = ts_control::PKG_VERSION;

        f(request).await
    }

    /// Send a non-streaming map request with current endpoints and DERP
    /// preference. Returns false if it failed, meaning the connection should be
    /// treated as lost. (Was unwrap(): see the stream open above.)
    async fn update_map_request(&self) -> bool {
        let RegState::Registered(conn) = &self.state else {
            tracing::debug!("attempt to update map request while not registered");
            return true;
        };

        match self
            .with_map_request(false, async |req| {
                send_map_request(
                    req,
                    &self.params.config.server_url.join("machine/map").unwrap(),
                    conn,
                )
                .await
            })
            .await
        {
            Ok(_) => true,
            Err(e) => {
                tracing::error!(error = %e, "sending map update");
                false
            }
        }
    }
}

impl Message<AuthRequired> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        AuthRequired(auth_url): AuthRequired,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let RegState::NotRegistered {
            pending_auth_requests,
        } = core::mem::replace(&mut self.state, RegState::AuthRequired(auth_url.clone()))
        else {
            tracing::warn!("got duplicate authrequired message");
            return;
        };

        for req in pending_auth_requests.into_iter() {
            req.send(Some(auth_url.clone()));
        }
    }
}

impl Message<RegisterResult> for ControlRunner {
    type Reply = ();

    #[tracing::instrument(skip_all, fields(result = ?msg.0))]
    async fn handle(&mut self, msg: RegisterResult, ctx: &mut Context<Self, Self::Reply>) {
        if matches!(self.state, RegState::Registered(..)) {
            tracing::warn!("got register result after already in registered state");
            return;
        }

        let conn = match msg.0 {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "unable to register with control server");
                self.params.failures.fetch_add(1, Ordering::Relaxed);
                ctx.stop();
                return;
            }
        };

        let old_state = core::mem::replace(&mut self.state, RegState::Registered(conn.clone()));

        if let RegState::NotRegistered {
            pending_auth_requests,
        } = old_state
        {
            for req in pending_auth_requests {
                req.send(None);
            }
        }

        let reader = match self
            .with_map_request(true, async |req| {
                let map_url = self.params.config.server_url.join("machine/map").unwrap();

                send_map_request(req, &map_url, &conn).await
            })
            .await
        {
            Ok(reader) => reader,
            Err(e) => {
                // Was unwrap(). Builds that abort on panic would reboot the
                // device over one failed request.
                tracing::error!(error = %e, "opening map stream");
                self.params.failures.fetch_add(1, Ordering::Relaxed);
                ctx.stop();
                return;
            }
        };

        let idle = test_hooks::stream_idle_timeout(STREAM_IDLE_TIMEOUT);
        let stream = end_when_idle(map_stream(reader), idle).map(Arc::new);

        ctx.actor_ref().attach_stream(stream.boxed(), (), ());
    }
}

enum PendingNodeRequest {
    Ipv4(ReplySender<Option<Ipv4Addr>>),
    Ipv6(ReplySender<Option<Ipv6Addr>>),
    SelfNode(ReplySender<Option<Node>>),
}

impl Message<StreamMessage<Arc<StateUpdate>, (), ()>> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Arc<StateUpdate>, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let msg = match msg {
            StreamMessage::Started(_) => {
                tracing::trace!("started listening to state updates");
                return;
            }

            StreamMessage::Next(msg) => {
                // The connection has worked end to end; the next failure starts
                // backoff from the beginning.
                self.params.failures.store(0, Ordering::Relaxed);
                msg
            }

            StreamMessage::Finished(_) => {
                tracing::error!("state update stream terminated");
                self.params.failures.fetch_add(1, Ordering::Relaxed);
                ctx.stop();
                return;
            }
        };

        if let RegState::Registered(conn) = &self.state {
            let _ = handle_ping(&msg, &self.params.config.server_url, conn).await;
        }

        if let Some(dial_plan) = &msg.dial_plan
            && self
                .params
                .env
                .ask::<DialerActor, _>(
                    None,
                    UpdateDialPlan {
                        dial_plan: dial_plan.clone(),
                    },
                    true,
                )
                .await
                .unwrap()
        {
            tracing::trace!(new_dial_plan = ?dial_plan);
        }

        if let Some(node) = msg.node.as_ref() {
            self.self_node = Some(node.clone());
        }

        if let Err(e) = self.params.env.publish(msg).await {
            tracing::error!(error = %e, "publishing netmap update");
        }

        if let Some(node) = &self.self_node {
            for req in self.pending_node_requests.drain(..) {
                match req {
                    PendingNodeRequest::Ipv4(sender) => {
                        sender.send(Some(node.tailnet_address.ipv4.addr()));
                    }
                    PendingNodeRequest::Ipv6(sender) => {
                        sender.send(Some(node.tailnet_address.ipv6.addr()));
                    }
                    PendingNodeRequest::SelfNode(sender) => {
                        sender.send(Some(node.clone()));
                    }
                }
            }
        }
    }
}

impl Message<direct::NewEndpoints> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: direct::NewEndpoints, ctx: &mut Context<Self, Self::Reply>) {
        if self.endpoints == msg.0.as_ref() {
            return;
        }

        self.endpoints = msg.0.to_vec();
        if !self.update_map_request().await {
            self.params.failures.fetch_add(1, Ordering::Relaxed);
            ctx.stop();
        }
    }
}

impl Message<DerpLatencyMeasurement> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, ctx: &mut Context<Self, Self::Reply>) {
        if self.derp_latency_measurement.as_ref() == Some(&msg) {
            return;
        }

        self.derp_latency_measurement = Some(msg);
        if !self.update_map_request().await {
            self.params.failures.fetch_add(1, Ordering::Relaxed);
            ctx.stop();
        }
    }
}

impl Message<ControlLost> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: ControlLost, ctx: &mut Context<Self, Self::Reply>) {
        let failures = self.params.failures.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::error!(reason = msg.0, failures, "lost control connection; restarting");
        ctx.stop();
    }
}

/// Control server dialer.
pub struct DialerActor {
    dialer: ControlDialer,
    env: Env,
}

impl kameo::Actor for DialerActor {
    type Args = Env;
    type Error = crate::Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.register(None, &slf).await?;

        Ok(Self {
            dialer: Default::default(),
            env,
        })
    }
}

#[kameo::messages]
impl DialerActor {
    #[message]
    async fn dial_next(&mut self, url: url::Url) -> Result<HttpConn, ts_control::Error> {
        let result = self
            .dialer
            .full_connect_next(&url, &self.env.keys.machine_keys)
            .await;
        // Log the cause here: by the time this reaches the control runner it
        // has been flattened into a Copy error ("actor replied with an error")
        // and the reason is gone.
        if let Err(e) = &result {
            tracing::warn!(error = %e, "control dial attempt failed");
        }
        result
    }

    #[message]
    fn update_dial_plan(&mut self, dial_plan: DialPlan) -> bool {
        self.dialer.update_dial_plan(&dial_plan)
    }
}

#[cfg(test)]
mod reconnect_tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_one_second_and_caps() {
        assert_eq!(reconnect_backoff(1), Duration::from_secs(1));
        assert_eq!(reconnect_backoff(2), Duration::from_secs(2));
        assert_eq!(reconnect_backoff(3), Duration::from_secs(4));
        assert_eq!(reconnect_backoff(6), Duration::from_secs(32));
        assert_eq!(reconnect_backoff(9), Duration::from_secs(256));
        assert_eq!(reconnect_backoff(10), MAX_BACKOFF);
        assert_eq!(reconnect_backoff(u32::MAX), MAX_BACKOFF);
    }

    /// kameo stops restarting a child after 5 restarts in 5s. The first retry is
    /// immediate (no failures counted yet) and each later one waits the
    /// backoff, so restarts must never land 5 to a 5-second window.
    #[test]
    fn backoff_stays_under_kameos_restart_limit() {
        let mut t = Duration::ZERO;
        let mut restarts = vec![t];
        for failures in 1..20 {
            t += reconnect_backoff(failures);
            restarts.push(t);
        }
        for (i, start) in restarts.iter().enumerate() {
            let in_window = restarts[i..].iter().filter(|r| **r - *start < Duration::from_secs(5)).count();
            assert!(in_window < 5, "{in_window} restarts within 5s starting at {start:?}");
        }
    }
}
