//! An ECDSA verifier supplied by the embedding program, such as ESP-IDF's mbedTLS in firmware.

use std::{
    sync::{
        LazyLock, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms;

use crate::ecdsa_offload::{self, Outcome};

/// Verifies a DER `signature` over `message` against a SEC1 `public_key`, on curve
/// P-`curve_bits`, hashing the message with SHA-`hash_bits` (256 or 384 for both).
///
/// Returns 0 if the signature is valid, 1 if it is not, and anything else if it cannot tell,
/// in which case the built-in RustCrypto verifier decides.
pub type EcdsaVerifyFn = unsafe extern "C" fn(
    curve_bits: u32,
    hash_bits: u32,
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32;

static VERIFIER: OnceLock<EcdsaVerifyFn> = OnceLock::new();

/// Set once the first TLS client config reads [`VERIFIER`]; later registrations would be ignored.
static IN_USE: AtomicBool = AtomicBool::new(false);

/// Hands certificate ECDSA checks (P-256/P-384 with SHA-256/384) to `verify`, a faster
/// implementation than the built-in one on small CPUs.
///
/// `verify` is used only if it passes a known-answer self-test, and only for signature checks:
/// the TLS protocol, chain building and name checks stay in rustls. Call it once, before the
/// first TLS connection. Returns `false`, and changes nothing, if a verifier is already set or
/// a connection has already been made.
///
/// # Safety
///
/// `verify` must be callable from any thread, must only read the three buffers it is given,
/// and only during the call.
pub unsafe fn set_ecdsa_verifier(verify: EcdsaVerifyFn) -> bool {
    !IN_USE.load(Ordering::SeqCst) && VERIFIER.set(verify).is_ok()
}

/// Calls `verify` and maps its result.
fn call(
    verify: EcdsaVerifyFn,
    curve_bits: u32,
    hash_bits: u32,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Outcome {
    // SAFETY: the caller of set_ecdsa_verifier vouched for `verify`, and each pointer and
    // length describes a live slice.
    let rc = unsafe {
        verify(
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

/// The registered verifier as an offload backend.
fn registered(
    curve_bits: u32,
    hash_bits: u32,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Outcome {
    match VERIFIER.get() {
        Some(&verify) => call(
            verify, curve_bits, hash_bits, public_key, message, signature,
        ),
        None => Outcome::CannotCheck,
    }
}

/// The provider's algorithms with ECDSA handed to the registered verifier, or `None` (keep
/// RustCrypto for everything) if none is registered or it fails the self-test.
pub(crate) static ALGORITHMS: LazyLock<Option<WebPkiSupportedAlgorithms>> = LazyLock::new(|| {
    IN_USE.store(true, Ordering::SeqCst);
    VERIFIER.get()?;

    let started = Instant::now();
    match ecdsa_offload::self_test(registered) {
        Ok(()) => {
            tracing::info!(
                self_test_ms = started.elapsed().as_millis() as u64,
                "ecdsa certificate checks handed to the registered verifier"
            );
            let base = oxitls_rustcrypto_provider::provider().signature_verification_algorithms;
            Some(ecdsa_offload::offload_ecdsa(&base, registered))
        }
        Err(e) => {
            tracing::error!(error = %e, "registered ecdsa verifier failed its self-test; certificate checks stay on rustcrypto");
            None
        }
    }
});

#[cfg(test)]
mod test {
    use core::sync::atomic::AtomicUsize;

    use super::*;

    /// Answers with the message length, so each C result can be chosen.
    unsafe extern "C" fn answer_is_message_len(
        _: u32,
        _: u32,
        _: *const u8,
        _: usize,
        _: *const u8,
        message_len: usize,
        _: *const u8,
        _: usize,
    ) -> i32 {
        message_len as i32
    }

    #[test]
    fn c_results_map_to_outcomes() {
        let check = |message: &[u8]| call(answer_is_message_len, 256, 256, b"", message, b"");
        assert_eq!(check(b""), Outcome::Valid);
        assert_eq!(check(b"x"), Outcome::Invalid);
        assert_eq!(check(b"xx"), Outcome::CannotCheck);
        assert_eq!(check(b"xxxxxxx"), Outcome::CannotCheck);
    }

    static REFERENCE_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// A correct verifier behind the C interface, built on RustCrypto.
    unsafe extern "C" fn reference(
        curve_bits: u32,
        hash_bits: u32,
        public_key: *const u8,
        public_key_len: usize,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
    ) -> i32 {
        REFERENCE_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `call` passes the pointer and length of live slices.
        let (public_key, message, signature) = unsafe {
            (
                std::slice::from_raw_parts(public_key, public_key_len),
                std::slice::from_raw_parts(message, message_len),
                std::slice::from_raw_parts(signature, signature_len),
            )
        };
        match ecdsa_offload::rustcrypto(curve_bits, hash_bits, public_key, message, signature) {
            Outcome::Valid => 0,
            Outcome::Invalid => 1,
            Outcome::CannotCheck => 2,
        }
    }

    /// The only test that touches the process-wide registration.
    #[test]
    fn a_registered_verifier_is_self_tested_then_used() {
        // SAFETY: `reference` only reads its buffers, during the call.
        assert!(unsafe { set_ecdsa_verifier(reference) });
        // SAFETY: as above.
        assert!(!unsafe { set_ecdsa_verifier(reference) }, "set twice");

        let algorithms = ALGORITHMS
            .as_ref()
            .expect("a correct verifier passes the self-test");
        let after_self_test = REFERENCE_CALLS.load(Ordering::Relaxed);
        assert!(after_self_test > 0);

        let offloaded = algorithms
            .all
            .iter()
            .find(|alg| format!("{alg:?}").starts_with("Offloaded"))
            .expect("ECDSA is offloaded");
        offloaded
            .verify_signature(b"not a key", b"message", b"not a signature")
            .unwrap_err();
        assert_eq!(REFERENCE_CALLS.load(Ordering::Relaxed), after_self_test + 1);
    }
}
