//! Certificate signature checks handed to a faster ECDSA implementation.
//!
//! On an ESP32 the RustCrypto provider took ~36 s per TLS handshake, nearly all
//! of it verifying Let's Encrypt's chain (three P-384 signatures and a P-256
//! one), and DERP servers reset handshakes still running at 30 s. ESP-IDF's
//! mbedTLS is already linked into the firmware, is optimised C, and uses the
//! chip's big-number and SHA hardware.
//!
//! Only the ECDSA P-256/P-384 with SHA-256/384 algorithms are handed over. The
//! TLS protocol, chain building, name checks and every other algorithm stay in
//! rustls and the provider. A backend must pass [`self_test`] before it is
//! used, and anything it reports it cannot check is decided by the provider's
//! own implementation, so a backend can make verification faster but never
//! more permissive.

use tokio_rustls::rustls::{
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id},
};

/// What an ECDSA backend concluded about one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Valid,
    Invalid,
    /// The backend cannot decide (an input form it does not support, an
    /// allocation failure). The provider's own implementation decides instead.
    CannotCheck,
}

/// Verify a DER `signature` over `message` against a SEC1 `public_key`, on
/// curve P-`curve_bits`, hashing the message with SHA-`hash_bits`.
pub(crate) type EcdsaBackend =
    fn(curve_bits: u32, hash_bits: u32, public_key: &[u8], message: &[u8], signature: &[u8]) -> Outcome;

#[derive(Debug)]
struct Offloaded {
    curve_bits: u32,
    hash_bits: u32,
    backend: EcdsaBackend,
    fallback: &'static dyn SignatureVerificationAlgorithm,
}

impl SignatureVerificationAlgorithm for Offloaded {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.fallback.public_key_alg_id()
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.fallback.signature_alg_id()
    }

    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        match (self.backend)(self.curve_bits, self.hash_bits, public_key, message, signature) {
            Outcome::Valid => Ok(()),
            Outcome::Invalid => Err(InvalidSignature),
            Outcome::CannotCheck => self.fallback.verify_signature(public_key, message, signature),
        }
    }
}

/// The (curve, hash) sizes of an ECDSA algorithm this module hands over.
fn ecdsa_params(alg: &dyn SignatureVerificationAlgorithm) -> Option<(u32, u32)> {
    let curve_bits = match alg.public_key_alg_id() {
        id if id == alg_id::ECDSA_P256 => 256,
        id if id == alg_id::ECDSA_P384 => 384,
        _ => return None,
    };
    let hash_bits = match alg.signature_alg_id() {
        id if id == alg_id::ECDSA_SHA256 => 256,
        id if id == alg_id::ECDSA_SHA384 => 384,
        _ => return None,
    };
    Some((curve_bits, hash_bits))
}

/// `base` with every ECDSA P-256/P-384 + SHA-256/384 algorithm routed to
/// `backend`, in both the certificate (`all`) and TLS signature (`mapping`)
/// tables. The new tables are leaked: rustls wants `'static`, and this is built
/// once per process.
pub(crate) fn offload_ecdsa(base: &WebPkiSupportedAlgorithms, backend: EcdsaBackend) -> WebPkiSupportedAlgorithms {
    let wrap = |alg: &'static dyn SignatureVerificationAlgorithm| -> &'static dyn SignatureVerificationAlgorithm {
        match ecdsa_params(alg) {
            Some((curve_bits, hash_bits)) => Box::leak(Box::new(Offloaded {
                curve_bits,
                hash_bits,
                backend,
                fallback: alg,
            })),
            None => alg,
        }
    };

    let all = base.all.iter().map(|&alg| wrap(alg)).collect::<Vec<_>>();
    let mapping = base
        .mapping
        .iter()
        .map(|&(scheme, algs)| {
            let algs: &'static [_] = Box::leak(algs.iter().map(|&alg| wrap(alg)).collect::<Vec<_>>().into_boxed_slice());
            (scheme, algs)
        })
        .collect::<Vec<_>>();

    WebPkiSupportedAlgorithms {
        all: Box::leak(all.into_boxed_slice()),
        mapping: Box::leak(mapping.into_boxed_slice()),
    }
}

struct Vector {
    name: &'static str,
    curve_bits: u32,
    hash_bits: u32,
    public_key: &'static [u8],
    signature: &'static [u8],
}

/// Signed by every vector below (openssl dgst -sign, fresh keys).
const MESSAGE: &[u8] = b"tailscale-rs: mbedtls ecdsa self-test";

const VECTORS: &[Vector] = &[
    Vector {
        name: "P256_SHA256",
        curve_bits: 256,
        hash_bits: 256,
        public_key: &[
            0x04, 0x14, 0x1d, 0x61, 0x77, 0xf4, 0x62, 0xf7, 0xe1, 0xf1, 0x86, 0x84,
            0x4b, 0xae, 0x99, 0xee, 0x68, 0x1a, 0x20, 0xc6, 0x0c, 0x29, 0xb5, 0xc2,
            0x31, 0x51, 0xe2, 0xf5, 0x2a, 0xe6, 0xdb, 0x41, 0x4f, 0x2e, 0x12, 0x41,
            0x01, 0x1c, 0xab, 0x71, 0x3d, 0x2d, 0x17, 0x10, 0xa0, 0x64, 0xd8, 0x8a,
            0xd3, 0x34, 0x33, 0xab, 0x47, 0x31, 0xfc, 0x47, 0x3b, 0xdc, 0x04, 0xb6,
            0x72, 0xbd, 0xc0, 0xb5, 0x72,
        ],
        signature: &[
            0x30, 0x44, 0x02, 0x20, 0x59, 0x4b, 0xb0, 0xcd, 0xe4, 0x4a, 0x50, 0x5f,
            0x05, 0x19, 0x40, 0x9f, 0x65, 0x9c, 0x3c, 0xde, 0x7a, 0xf8, 0xd5, 0x78,
            0x43, 0xb1, 0xc8, 0x5d, 0xd3, 0xa4, 0xf5, 0x9c, 0xf5, 0x7b, 0xd4, 0xed,
            0x02, 0x20, 0x4b, 0xa9, 0xcf, 0xd0, 0x73, 0x86, 0x4b, 0x13, 0x85, 0x4f,
            0xad, 0xca, 0x39, 0xe6, 0xb3, 0xd7, 0x50, 0x92, 0xea, 0x91, 0x79, 0xe2,
            0xff, 0xec, 0x4c, 0x54, 0x5b, 0xd8, 0x36, 0xe4, 0xe5, 0xe3,
        ],
    },
    Vector {
        name: "P256_SHA384",
        curve_bits: 256,
        hash_bits: 384,
        public_key: &[
            0x04, 0xa0, 0x86, 0xeb, 0xae, 0x74, 0x6d, 0x43, 0xb5, 0x9f, 0x44, 0xb5,
            0x7c, 0xb7, 0xad, 0xa2, 0xa3, 0x41, 0xaf, 0xd1, 0xe7, 0xaa, 0x29, 0xdb,
            0x83, 0xa6, 0xeb, 0x38, 0x97, 0xea, 0xa7, 0x50, 0x17, 0x87, 0xb3, 0x9b,
            0xf8, 0x5b, 0xa9, 0x57, 0xac, 0xf0, 0x24, 0xc8, 0x17, 0xf7, 0xa1, 0x28,
            0x94, 0xbc, 0x8b, 0xd4, 0x42, 0x19, 0xd8, 0xca, 0x8b, 0x90, 0x85, 0x77,
            0xbb, 0x54, 0x5c, 0xa2, 0x6d,
        ],
        signature: &[
            0x30, 0x45, 0x02, 0x21, 0x00, 0xd4, 0x00, 0x5a, 0x39, 0xe4, 0xcd, 0x0d,
            0x99, 0x81, 0x47, 0xf7, 0xaf, 0x3f, 0xe1, 0xed, 0x78, 0xd7, 0xd7, 0x12,
            0x68, 0xfe, 0x14, 0x84, 0x07, 0x3d, 0x95, 0x84, 0x71, 0xe3, 0x8f, 0x56,
            0x91, 0x02, 0x20, 0x1f, 0x5b, 0xf8, 0x75, 0x63, 0xc2, 0xf2, 0x16, 0x5e,
            0x86, 0x43, 0x48, 0xa9, 0x64, 0xbb, 0x54, 0x0b, 0xd3, 0xaa, 0xbe, 0xef,
            0xea, 0xa5, 0xa6, 0x69, 0x82, 0x7f, 0xb4, 0x38, 0xde, 0x88, 0x60,
        ],
    },
    Vector {
        name: "P384_SHA384",
        curve_bits: 384,
        hash_bits: 384,
        public_key: &[
            0x04, 0x10, 0xc9, 0xcd, 0x21, 0x75, 0xdf, 0xf7, 0x86, 0x3b, 0x9c, 0x7e,
            0x3f, 0xae, 0xb2, 0x4f, 0x50, 0xb9, 0xa0, 0xdb, 0x2d, 0x6a, 0xb9, 0x78,
            0x76, 0x5a, 0x67, 0xe7, 0x4a, 0xd4, 0xc6, 0x89, 0xc7, 0x41, 0xfa, 0xa0,
            0x2c, 0x04, 0x70, 0x27, 0x50, 0x70, 0x93, 0xc0, 0x7b, 0x30, 0x47, 0x27,
            0x35, 0xc2, 0x61, 0xd4, 0x62, 0x0c, 0x36, 0x50, 0x5a, 0xcc, 0x90, 0xb9,
            0xbb, 0xcf, 0x49, 0x7c, 0xa8, 0x8e, 0x8a, 0x78, 0xa2, 0x4d, 0x72, 0x62,
            0xfb, 0xc1, 0x42, 0x42, 0xb3, 0xa8, 0xfd, 0x81, 0x67, 0x92, 0x96, 0xfc,
            0xda, 0x27, 0xa6, 0x20, 0xdf, 0x03, 0x1c, 0x6c, 0x0b, 0x01, 0x9e, 0x7c,
            0x44,
        ],
        signature: &[
            0x30, 0x66, 0x02, 0x31, 0x00, 0xec, 0x98, 0x82, 0x08, 0xc1, 0x2d, 0x62,
            0xb7, 0xbe, 0xcf, 0xea, 0x59, 0x1a, 0xc9, 0x7e, 0x69, 0x7d, 0x8c, 0xd2,
            0xde, 0x8c, 0x06, 0x72, 0xb9, 0xd5, 0xa4, 0x3d, 0x5b, 0x2d, 0xe7, 0x5d,
            0xe1, 0x93, 0x73, 0xbc, 0xc6, 0xe3, 0x23, 0xfe, 0x1c, 0xd8, 0xbc, 0xe8,
            0xa1, 0x0b, 0x89, 0xf1, 0xae, 0x02, 0x31, 0x00, 0xc4, 0x60, 0x84, 0xd5,
            0xdc, 0x83, 0xce, 0xeb, 0xcd, 0xa1, 0x7c, 0xe0, 0x9c, 0x15, 0x47, 0xe0,
            0x0f, 0xca, 0x33, 0x5c, 0x68, 0xda, 0xc8, 0xf7, 0xe3, 0xf6, 0xdf, 0x31,
            0x4b, 0x36, 0xf6, 0xd4, 0x5f, 0x81, 0x04, 0x40, 0x87, 0xd4, 0x4a, 0x13,
            0x50, 0xa8, 0x14, 0x8d, 0x1a, 0xcb, 0xb2, 0x85,
        ],
    },
];

/// Known answers a correct backend must give, for each curve and hash: the
/// vector is valid; with the message altered, invalid; with a bit of `s`
/// flipped (still well-formed DER), invalid. A backend that accepts everything
/// fails here, so a broken one never gets to decide whether to trust a server.
pub(crate) fn self_test(backend: EcdsaBackend) -> Result<(), String> {
    for v in VECTORS {
        let check = |what: &str, message: &[u8], signature: &[u8], want: Outcome| {
            let got = backend(v.curve_bits, v.hash_bits, v.public_key, message, signature);
            if got == want {
                Ok(())
            } else {
                Err(format!("{} {what}: expected {want:?}, got {got:?}", v.name))
            }
        };

        check("valid", MESSAGE, v.signature, Outcome::Valid)?;

        let mut message = MESSAGE.to_vec();
        message[0] ^= 1;
        check("altered message", &message, v.signature, Outcome::Invalid)?;

        let mut signature = v.signature.to_vec();
        *signature.last_mut().unwrap() ^= 1;
        check("altered signature", MESSAGE, &signature, Outcome::Invalid)?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn base() -> WebPkiSupportedAlgorithms {
        oxitls_rustcrypto_provider::provider().signature_verification_algorithms
    }

    /// A correct backend, built on the provider's own RustCrypto verifiers.
    fn rustcrypto(curve_bits: u32, hash_bits: u32, public_key: &[u8], message: &[u8], signature: &[u8]) -> Outcome {
        let alg = base()
            .all
            .iter()
            .copied()
            .find(|&alg| ecdsa_params(alg) == Some((curve_bits, hash_bits)))
            .unwrap();
        match alg.verify_signature(public_key, message, signature) {
            Ok(()) => Outcome::Valid,
            Err(_) => Outcome::Invalid,
        }
    }

    #[test]
    fn vectors_verify_with_an_independent_implementation() {
        self_test(rustcrypto).unwrap();
    }

    #[test]
    fn self_test_rejects_a_backend_that_accepts_everything() {
        assert!(self_test(|_, _, _, _, _| Outcome::Valid).is_err());
    }

    #[test]
    fn self_test_rejects_a_backend_that_rejects_everything() {
        assert!(self_test(|_, _, _, _, _| Outcome::Invalid).is_err());
        assert!(self_test(|_, _, _, _, _| Outcome::CannotCheck).is_err());
    }

    #[test]
    fn only_ecdsa_is_offloaded_and_tables_keep_their_shape() {
        let base = base();
        let offloaded = offload_ecdsa(&base, rustcrypto);

        assert_eq!(base.all.len(), offloaded.all.len());
        for (a, b) in base.all.iter().zip(offloaded.all) {
            assert!(a.public_key_alg_id() == b.public_key_alg_id());
            assert!(a.signature_alg_id() == b.signature_alg_id());
            let wrapped = format!("{b:?}").starts_with("Offloaded");
            assert_eq!(wrapped, ecdsa_params(*a).is_some(), "{a:?}");
        }
        assert_eq!(4, offloaded.all.iter().filter(|a| format!("{a:?}").starts_with("Offloaded")).count());

        assert_eq!(base.mapping.len(), offloaded.mapping.len());
        for ((scheme_a, algs_a), (scheme_b, algs_b)) in base.mapping.iter().zip(offloaded.mapping) {
            assert_eq!(scheme_a, scheme_b);
            assert_eq!(algs_a.len(), algs_b.len());
        }
    }

    #[test]
    fn backend_decides_and_cannot_check_falls_back() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn cannot_check(_: u32, _: u32, _: &[u8], _: &[u8], _: &[u8]) -> Outcome {
            CALLS.fetch_add(1, Ordering::Relaxed);
            Outcome::CannotCheck
        }
        fn says_invalid(_: u32, _: u32, _: &[u8], _: &[u8], _: &[u8]) -> Outcome {
            Outcome::Invalid
        }

        for v in VECTORS {
            let pick = |algs: WebPkiSupportedAlgorithms| {
                algs.all
                    .iter()
                    .copied()
                    .find(|&alg| ecdsa_params(alg) == Some((v.curve_bits, v.hash_bits)))
                    .unwrap()
            };

            // CannotCheck: the provider's verifier runs, and gets it right.
            let before = CALLS.load(Ordering::Relaxed);
            let alg = pick(offload_ecdsa(&base(), cannot_check));
            alg.verify_signature(v.public_key, MESSAGE, v.signature).unwrap();
            alg.verify_signature(v.public_key, b"something else", v.signature).unwrap_err();
            assert_eq!(CALLS.load(Ordering::Relaxed), before + 2);

            // Invalid is final: no fallback overrules it.
            let alg = pick(offload_ecdsa(&base(), says_invalid));
            alg.verify_signature(v.public_key, MESSAGE, v.signature).unwrap_err();
        }
    }
}
