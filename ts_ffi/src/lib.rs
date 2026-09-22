#![allow(non_camel_case_types)]

//! C FFI for tailscale-rs.
//!
//! # Safety
//!
//! All resources created by this library must be treated in accordance with the Rust
//! borrowing and ownership rules. Keep in mind that this _requires_ all memory to be
//! initialized before handing it into Rust-land.
//!
//! Null-checking is the responsibility of the caller, both on function call and return. We
//! don't check for parameter nullity: all params are assumed non-null unless noted
//! otherwise. Null return values are used for error signaling and must be inspected.
//!
//! Handles provided by this library are threadsafe -- operations will be implicitly
//! synchronized and serialized by the runtime. The only caveat is that you cannot `deinit`
//! or `close` a handle concurrently with other operations: this requires external
//! synchronization.

use std::{
    ffi::{self, CStr, c_char},
    sync::{LazyLock, Once},
};

use tracing::level_filters::LevelFilter;

mod config;
mod keys;
mod net_types;
mod tcp;
mod udp;
mod util;

pub use net_types::{
    AF_INET, AF_INET6, in_addr_t, in6_addr_t, sa_family_t, sockaddr, sockaddr_data, sockaddr_in,
    sockaddr_in6,
};
pub use tcp::{
    tcp_listener, tcp_stream, ts_tcp_close, ts_tcp_close_listener, ts_tcp_connect, ts_tcp_listen,
    ts_tcp_listener_local_addr, ts_tcp_local_addr, ts_tcp_recv, ts_tcp_remote_addr, ts_tcp_send,
};
pub use udp::{ts_udp_bind, ts_udp_close, ts_udp_recvfrom, ts_udp_sendto, udp_socket};

static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    // One worker, not a worker per core.
    //
    // A plain `new_current_thread()` runtime does NOT work here, and the
    // failure is silent-looking: the node joins the tailnet and reports a
    // listener, then every connection to it times out. With no worker, spawned
    // tasks -- the control-plane poll, the DERP connection, the netstack --
    // only advance while some thread is inside `block_on`, and ts_ffi's
    // blocking API returns as soon as its own future resolves. Measured: the
    // join succeeds, `ts_tcp_listen` succeeds, and `meshtastic --host <tailnet
    // ip>` fails with ETIMEDOUT.
    //
    // Making current_thread work would mean a dedicated driver thread parked
    // on the runtime plus reworking all 8 block_on sites to dispatch 'static
    // futures over a channel -- and that driver thread costs exactly the one
    // thread `worker_threads(1)` costs, so it buys no RAM. It does not buy
    // meaningful flash either: a current_thread build measured 4,233,724 bytes
    // of __text against 4,242,880 here, a 9KB (0.2%) difference.
    //
    // So cap the workers instead. On a 2-core ESP32-S3 tokio would otherwise
    // start 2.
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.worker_threads(1).enable_all();

    // Rust's default thread stack is 2 MiB, which is more than an ESP32-S3
    // has. Observed on hardware/simulator: runtime construction failed, the
    // `.unwrap()` below panicked, and the panic printer then tripped the TLSF
    // heap assert while allocating its own mutex -- so the visible symptom was
    // "assert failed: block_locate_free", several layers away from the cause.
    //
    // The blocking pool matters as much as the workers: its default cap is 512
    // threads, and each one would take a stack of this size the moment it is
    // spawned. ts_ffi only ever has a handful of blocking calls outstanding.
    //
    // This is the size that actually takes effect. Rust's std::thread calls
    // pthread_attr_setstacksize explicitly, which overrides the stack_size in
    // esp_pthread_set_cfg -- so the C++ side can choose *where* these stacks
    // are allocated (internal DRAM vs PSRAM) but not how big they are.
    //
    // Measured on an ESP32-S3 at the moment the runtime is built, with WiFi,
    // mDNS, NTP and both web servers already up: 110,700 bytes of internal DRAM
    // free, largest block 69,620. At 64 KiB the worker thread consumed that
    // block and the first blocking-pool thread -- which tokio::fs needs to read
    // the key state -- failed with ENOMEM, panicking the runtime and rebooting
    // the node. The pool is not optional: it is on the critical path.
    //
    // 24 KiB leaves room for a worker plus two or three blocking threads.
    // Still not a high-water-mark measurement; verify with
    // uxTaskGetStackHighWaterMark on hardware before trusting it, because the
    // rustls + p384 handshake is deeper than anything else here.
    #[cfg(target_os = "espidf")]
    {
        builder.thread_stack_size(24 * 1024);
        builder.max_blocking_threads(2);
    }

    let rt = builder.build().expect(
        "tokio runtime construction failed -- on ESP32 this is almost always \
         thread stack allocation; see thread_stack_size above",
    );

    tracing::info!("started tokio runtime");

    rt
});

/// A Tailscale device, also variously called a "node" or "peer".
///
/// A device is the unit of identity in a tailnet; it has a tailnet IP and can send and
/// receive IP datagrams to other peers.
pub struct device(tailscale::Device);

static TRACING_ONCE: Once = Once::new();

/// Initialize the Rust tailscale tracing subsystem.
///
/// This is automatically called during `ts_init`, but you may want to call this first to log any
/// errors if initialization needs to be done before `ts_init`.
#[unsafe(no_mangle)]
pub extern "C" fn ts_init_tracing() {
    TRACING_ONCE.call_once(|| {
        tracing_subscriber::fmt().with_max_level(LevelFilter::INFO).init();
    });
}

/// Initialize a new Tailscale device.
///
/// `config` is the configuration with which to initialize the device. You may pass `NULL`, and a
/// default ephemeral configuration will be used.
///
/// `auth_token` is an optional auth token (you may pass `NULL`) that is used to authenticate the
/// device if required. If you pass `NULL`, the credentials in `config_path` must already be
/// authorized to make a successful connection.
///
/// # Safety
///
/// `auth_token`  must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
/// The string fields of `config` may be `NULL`, but if they are not, they must
/// obey the same invariants. `tags` must be either `NULL`, or a `NULL` terminated
/// array of strings that must all obey the same invariant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_init(
    config: Option<&config::config>,
    auth_token: *const c_char,
) -> Option<Box<device>> {
    ts_init_tracing();

    let config = match config {
        Some(cfg) => unsafe { cfg.to_ts_config() },
        None => Default::default(),
    };

    let auth_token = if auth_token.is_null() {
        None
    } else {
        unsafe { util::str(auth_token).map(ToOwned::to_owned) }
    };

    match TOKIO_RUNTIME.block_on(tailscale::Device::new(&config, auth_token)) {
        Ok(dev) => Some(Box::new(device(dev))),
        Err(e) => {
            tracing::error!(err = %e, "ts_init failed");
            None
        }
    }
}

/// Initialize a new Tailscale device with a default configuration using the given key file for the
/// key state. The file is created with new keys if it doesn't exist.
///
/// `auth_token` is an optional auth token (you may pass `NULL`) that is used to authenticate the
/// device if required. If you pass `NULL`, the credentials in `key_file` must already be
/// authorized to make a successful connection.
///
/// # Safety
///
/// `auth_token` and `key_file` must be able to be read according to [`CStr`] rules, i.e.
/// they must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_init_from_key_file(
    key_file: *const c_char,
    auth_token: *const c_char,
) -> Option<Box<device>> {
    let mut state = keys::persisted_key_state::default();

    // SAFETY: CStr invariants maintained by function precondition
    if unsafe { keys::ts_load_key_file(key_file, false, &mut state) } < 0 {
        return None;
    }

    let config = config::config {
        key_state: Some(&mut state),
        ..Default::default()
    };

    // SAFETY: `auth_token` meets the CStr invariants by this function precondition. `config` is
    // safely default-initialized, except for key state, which has no safety requirements.
    unsafe { ts_init(Some(&config), auth_token) }
}

/// Deinitialize and shut down a Tailscale device.
#[unsafe(no_mangle)]
pub extern "C" fn ts_deinit(dev: Box<device>) {
    drop(dev)
}

/// Get the IPv4 address of the Tailscale node, blocking until it's available.
///
/// Returns a negative number on error.
#[unsafe(no_mangle)]
pub extern "C" fn ts_ipv4_addr(dev: &device, dst: &mut in_addr_t) -> ffi::c_int {
    let addr = match TOKIO_RUNTIME.block_on(dev.0.ipv4_addr()) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!(error = %e, "getting ipv4");
            return -1;
        }
    };

    dst.0 = addr.octets();

    0
}

/// Get the IPv6 address of the Tailscale node, blocking until it's available.
///
/// Returns a negative number on error.
#[unsafe(no_mangle)]
pub extern "C" fn ts_ipv6_addr(dev: &device, dst: &mut in6_addr_t) -> ffi::c_int {
    let addr = match TOKIO_RUNTIME.block_on(dev.0.ipv6_addr()) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!(error = %e, "getting ipv6");
            return -1;
        }
    };

    dst.0 = addr.segments();

    0
}

/// Get the IPv4 address of a specified peer by name.
///
/// `peer_name` can be a fully-qualified name (`$HOST.tail1234.ts.net`) or an unqualified
/// hostname (`$HOST`). The first match is returned: shared-in nodes may cause ambiguity
/// when unqualified hostnames are used.
///
/// Returns a negative number if there was an error, zero if no match was found, and a
/// positive number if `addr` has been populated with the address for the requested peer.
///
/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_peer_ipv4_addr(
    dev: &device,
    peer_name: *const c_char,
    addr: &mut in_addr_t,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    unsafe {
        _peer_by_addr(dev, peer_name, |n| {
            *addr = n.tailnet_address.ipv4.addr().into();
        })
    }
}

/// Get the IPv6 address of a specified peer by name.
///
/// `peer_name` can be a fully-qualified name (`$HOST.tail1234.ts.net`) or an unqualified
/// hostname (`$HOST`). The first match is returned: shared-in nodes may cause ambiguity
/// when unqualified hostnames are used.
///
/// Returns a negative number if there was an error, zero if no match was found, and a
/// positive number if `addr` has been populated with the address for the requested peer.
///
/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_peer_ipv6_addr(
    dev: &device,
    peer_name: *const c_char,
    addr: &mut in6_addr_t,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    unsafe {
        _peer_by_addr(dev, peer_name, |n| {
            *addr = n.tailnet_address.ipv6.addr().into();
        })
    }
}

/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
unsafe fn _peer_by_addr(
    dev: &device,
    peer_name: *const c_char,
    on_node_info: impl FnOnce(&tailscale::NodeInfo),
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let name = unsafe { CStr::from_ptr(peer_name) };

    let Ok(name) = name.to_str() else {
        tracing::error!("peer name: invalid utf-8");
        return -1;
    };

    match TOKIO_RUNTIME.block_on(dev.0.peer_by_name(name)) {
        Ok(Some(node)) => {
            on_node_info(&node);
            1
        }

        Ok(None) => 0,

        Err(e) => {
            tracing::error!(error = %e, "looking up peer");
            -1
        }
    }
}
