#![doc = include_str!("../README.md")]

use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, crypto::CryptoProvider},
};
pub use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};
use url::Url;

mod ecdsa_offload;
mod external_ecdsa;
#[cfg(feature = "insecure")]
mod insecure;

pub use external_ecdsa::{EcdsaVerifyFn, set_ecdsa_verifier};
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
            tracing::debug!(server = ?server_name, elapsed_ms, ?kind, "tls handshake complete")
        }
        Err(e) => {
            tracing::warn!(server = ?server_name, elapsed_ms, error = %e, kind = ?e.kind(), "tls handshake failed")
        }
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
/// compile. ECDSA signature checks go to the verifier registered with
/// [`set_ecdsa_verifier`], if any.
fn provider() -> CryptoProvider {
    let mut provider = oxitls_rustcrypto_provider::provider();
    if let Some(algorithms) = *external_ecdsa::ALGORITHMS {
        provider.signature_verification_algorithms = algorithms;
    }
    provider
}

/// If possible, converts the host portion of the given [`Url`] to a [`ServerName`] for establishing
/// TLS streams.
pub fn server_name(url: &Url) -> Option<ServerName<'_>> {
    ServerName::try_from(url.host_str()?).ok()
}
