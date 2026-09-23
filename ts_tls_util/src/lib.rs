#![doc = include_str!("../README.md")]

use std::sync::{Arc, LazyLock};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore},
};
pub use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};
use url::Url;

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
    // TODO(npry): custom tls cert verifier to support commonname overrides and self-signed certs
    // Name the provider explicitly rather than relying on rustls' process-wide
    // default: with no backend feature enabled there is no default to fall back
    // on, and `ClientConfig::builder()` would panic at run time instead of
    // failing to compile.
    let mut rustls_config = ClientConfig::builder_with_provider(Arc::new(oxitls_rustcrypto_provider::provider()))
        .with_safe_default_protocol_versions()
        .expect("rustcrypto provider supports the default protocol versions")
        .with_root_certificates(ROOT_CERT_STORE.clone())
        .with_no_client_auth();

    rustls_config
        .alpn_protocols
        .extend(alpn.into_iter().map(|x| x.to_owned()));

    let connector = TlsConnector::from(Arc::new(rustls_config));

    // Worth seeing on slow targets. On an ESP32 the handshake is CPU-bound and
    // holds the runtime's only worker while the certificate chain is verified,
    // and servers drop handshakes that run too long (derper: 30 s).
    let started = std::time::Instant::now();
    let result = connector.connect(server_name.to_owned(), io).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(_) => tracing::info!(server = ?server_name, elapsed_ms, "tls handshake complete"),
        Err(e) => tracing::warn!(server = ?server_name, elapsed_ms, error = %e, kind = ?e.kind(), "tls handshake failed"),
    }

    result
}

/// If possible, converts the host portion of the given [`Url`] to a [`ServerName`] for establishing
/// TLS streams.
pub fn server_name(url: &Url) -> Option<ServerName<'_>> {
    ServerName::try_from(url.host_str()?).ok()
}
