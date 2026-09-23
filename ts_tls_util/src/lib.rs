#![doc = include_str!("../README.md")]

use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, crypto::CryptoProvider},
};
pub use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};
use url::Url;

// Used on ESP-IDF only; compiled natively so its tests run on the host.
#[cfg(any(target_os = "espidf", test))]
mod ecdsa_offload;
#[cfg(feature = "insecure")]
mod insecure;

#[cfg(feature = "insecure")]
pub use insecure::connect_insecure;

static ROOT_CERT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    })
});

/// Establishes a TLS stream with a server over an existing connection.
///
/// See module-level documentation for information on root certificates.
pub async fn connect<Io>(server_name: ServerName<'_>, io: Io) -> std::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    connect_alpn::<Io>(server_name, io, []).await
}

/// Establishes a TLS stream with a server over an existing connection, with an optional set of
/// ALPN protocols to negotiate.
///
/// See module-level documentation for information on root certificates.
pub async fn connect_alpn<Io>(
    server_name: ServerName<'_>,
    io: Io,
    alpn: impl IntoIterator<Item = Vec<u8>>,
) -> tokio::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    let connector = TlsConnector::from(client_config(alpn.into_iter().collect()));

    // Worth seeing on slow targets. On an ESP32 the handshake is CPU-bound and
    // holds the runtime's only worker while the certificate chain is verified,
    // and servers drop handshakes that run too long (derper: 30 s).
    let started = std::time::Instant::now();
    let result = connector.connect(server_name.to_owned(), io).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(stream) => {
            let kind = stream.get_ref().1.handshake_kind();
            tracing::info!(server = ?server_name, elapsed_ms, ?kind, "tls handshake complete")
        }
        Err(e) => tracing::warn!(server = ?server_name, elapsed_ms, error = %e, kind = ?e.kind(), "tls handshake failed"),
    }

    result
}

/// The client configuration used for connections negotiating `alpn`.
///
/// Built once per ALPN list and shared. The config owns rustls' session cache,
/// so building one per connection -- as this crate did -- meant no connection
/// ever resumed a session. A resumed TLS 1.3 handshake skips certificate
/// verification, which is most of a handshake's cost on a slow CPU: the second
/// connection of every join goes to the same control server as the first, and
/// reconnects go to the same servers again.
pub fn client_config(alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    type Alpn = Vec<Vec<u8>>;
    static CONFIGS: Mutex<Vec<(Alpn, Arc<ClientConfig>)>> = Mutex::new(Vec::new());

    let mut configs = CONFIGS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, config)) = configs.iter().find(|(protocols, _)| *protocols == alpn) {
        return config.clone();
    }

    // TODO(npry): custom tls cert verifier to support commonname overrides and self-signed certs
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .expect("rustcrypto provider supports the default protocol versions")
        .with_root_certificates(ROOT_CERT_STORE.clone())
        .with_no_client_auth();
    config.alpn_protocols = alpn.clone();

    let config = Arc::new(config);
    configs.push((alpn, config.clone()));
    config
}

/// The crypto provider for every connection this crate makes.
///
/// Named explicitly rather than relying on rustls' process-wide default: with
/// no backend feature enabled there is no default to fall back on, and
/// `ClientConfig::builder()` would panic at run time instead of failing to
/// compile. On ESP-IDF, ECDSA signature checks go to mbedTLS; see
/// [`ecdsa_offload`].
fn provider() -> CryptoProvider {
    #[allow(unused_mut)]
    let mut provider = oxitls_rustcrypto_provider::provider();

    #[cfg(target_os = "espidf")]
    if let Some(algorithms) = *mbedtls::ALGORITHMS {
        provider.signature_verification_algorithms = algorithms;
    }

    provider
}

#[cfg(target_os = "espidf")]
mod mbedtls {
    use std::sync::LazyLock;

    use tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms;

    use crate::ecdsa_offload::{self, Outcome};

    unsafe extern "C" {
        /// Supplied by the firmware that links ts_ffi; for Meshtastic,
        /// src/mesh/api/TailscaleMbedtls.cpp. Returns 0 if the signature is
        /// valid, 1 if it is not, anything else if it cannot tell.
        fn ts_mbedtls_ecdsa_verify(
            curve_bits: u32,
            hash_bits: u32,
            public_key: *const u8,
            public_key_len: usize,
            message: *const u8,
            message_len: usize,
            signature: *const u8,
            signature_len: usize,
        ) -> i32;
    }

    fn verify(curve_bits: u32, hash_bits: u32, public_key: &[u8], message: &[u8], signature: &[u8]) -> Outcome {
        // SAFETY: each pointer/length pair describes a live slice, which the
        // callee only reads during the call.
        let rc = unsafe {
            ts_mbedtls_ecdsa_verify(
                curve_bits,
                hash_bits,
                public_key.as_ptr(),
                public_key.len(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            )
        };
        match rc {
            0 => Outcome::Valid,
            1 => Outcome::Invalid,
            _ => Outcome::CannotCheck,
        }
    }

    /// The provider's algorithms with ECDSA handed to mbedTLS, or `None` --
    /// keep RustCrypto for everything -- if mbedTLS fails the self-test.
    pub(crate) static ALGORITHMS: LazyLock<Option<WebPkiSupportedAlgorithms>> = LazyLock::new(|| {
        let started = std::time::Instant::now();
        match ecdsa_offload::self_test(verify) {
            Ok(()) => {
                tracing::info!(
                    self_test_ms = started.elapsed().as_millis() as u64,
                    "ecdsa certificate checks handed to mbedtls"
                );
                let base = oxitls_rustcrypto_provider::provider().signature_verification_algorithms;
                Some(ecdsa_offload::offload_ecdsa(&base, verify))
            }
            Err(e) => {
                tracing::error!(error = %e, "mbedtls ecdsa self-test failed; certificate checks stay on rustcrypto");
                None
            }
        }
    });
}

/// If possible, converts the host portion of the given [`Url`] to a [`ServerName`] for establishing
/// TLS streams.
pub fn server_name(url: &Url) -> Option<ServerName<'_>> {
    ServerName::try_from(url.host_str()?).ok()
}
