//! Host key blob parsing, exchange-hash signature verification, and fingerprinting.
//!
//! Deliberately only touches `ssh_key`'s inherent methods (`PublicKey::from_bytes`/`to_bytes`,
//! `Signature::try_from`/`TryFrom`) and the `signature` crate's `Verifier` trait - never
//! `ssh_key`'s own internal `ssh-encoding` dependency, which is pinned to an older major version
//! (0.2) than the one `ssh-core` uses directly (0.3) for its own wire types. Different major
//! versions of the same crate are different Rust types, so mixing them wouldn't even compile;
//! keeping host-key handling on ssh-key's own conversion surface sidesteps that entirely.

use std::string::String;
use std::vec::Vec;

use sha2::{Digest, Sha256};
use signature::Verifier;
use ssh_key::PublicKey;

use crate::error::{Result, SshError};

pub struct HostKey {
    public_key: PublicKey,
    raw_blob: Vec<u8>,
}

impl HostKey {
    /// Parse a raw SSH wire-format public key blob (`K_S` from `SSH_MSG_KEX_ECDH_REPLY`).
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let public_key = PublicKey::from_bytes(blob)?;
        Ok(Self {
            public_key,
            raw_blob: blob.to_vec(),
        })
    }

    pub fn algorithm_name(&self) -> String {
        self.public_key.algorithm().as_str().to_string()
    }

    pub fn raw_blob(&self) -> &[u8] {
        &self.raw_blob
    }

    /// OpenSSH-style `SHA256:<base64-nopad>` fingerprint, as shown by `ssh-keygen -lf` and in
    /// `ssh`'s "unknown host key" prompt - this is the string we surface to the JS host for its
    /// trust-decision callback, so it should be recognizable to anyone who's used OpenSSH.
    pub fn fingerprint_sha256(&self) -> String {
        let digest = Sha256::digest(&self.raw_blob);
        let encoded = <base64ct::Base64Unpadded as base64ct::Encoding>::encode_string(&digest);
        std::format!("SHA256:{encoded}")
    }

    /// Verify a signature (wire format: `string algorithm-name || string sig-blob`) over
    /// `message` (the KEX exchange hash `H`, for host key verification; or the userauth
    /// signed-data blob, for publickey auth) was produced by this key.
    ///
    /// Calls through the `Verifier<Signature>` trait explicitly (UFCS) rather than
    /// `self.public_key.verify(...)`, since `PublicKey` also has an *inherent* `verify` method
    /// for the unrelated "sshsig" file-signature format, which Rust would otherwise prefer over
    /// the trait method of the same name.
    pub fn verify_signature(&self, message: &[u8], signature_blob: &[u8]) -> Result<()> {
        let signature = ssh_key::Signature::try_from(signature_blob)?;
        Verifier::verify(&self.public_key, message, &signature)
            .map_err(|_| SshError::HostKeySignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::private::PrivateKey;

    struct FixedRng;
    impl rand_core_06::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            0x1234_5678
        }
        fn next_u64(&mut self) -> u64 {
            0x1234_5678_9abc_def0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for (i, b) in dest.iter_mut().enumerate() {
                *b = i as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core_06::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand_core_06::CryptoRng for FixedRng {}

    fn test_ed25519_keypair() -> PrivateKey {
        PrivateKey::random(&mut FixedRng, ssh_key::Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn parses_blob_and_reports_algorithm() {
        let private = test_ed25519_keypair();
        let blob = private.public_key().to_bytes().unwrap();

        let host_key = HostKey::parse(&blob).unwrap();
        assert_eq!(host_key.algorithm_name(), "ssh-ed25519");
        assert_eq!(host_key.raw_blob(), blob.as_slice());
    }

    #[test]
    fn fingerprint_has_expected_shape() {
        let private = test_ed25519_keypair();
        let blob = private.public_key().to_bytes().unwrap();
        let fp = HostKey::parse(&blob).unwrap().fingerprint_sha256();

        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.contains('='), "OpenSSH fingerprints are unpadded base64");
        assert_eq!(fp.len(), "SHA256:".len() + 43); // 32 bytes -> 43 base64 chars unpadded
    }

    #[test]
    fn verifies_genuine_signature_and_rejects_tampered_message() {
        use signature::Signer;

        let private = test_ed25519_keypair();
        let blob = private.public_key().to_bytes().unwrap();
        let host_key = HostKey::parse(&blob).unwrap();

        let message = b"exchange-hash-fixture";
        let signature = private.try_sign(message).unwrap();
        let sig_bytes: Vec<u8> = signature.try_into().unwrap();

        host_key.verify_signature(message, &sig_bytes).unwrap();

        let err = host_key.verify_signature(b"different-message", &sig_bytes);
        assert!(matches!(err, Err(SshError::HostKeySignatureInvalid)));
    }

    #[test]
    fn rejects_signature_from_a_different_key() {
        use signature::Signer;

        let private_a = test_ed25519_keypair();
        let blob_a = private_a.public_key().to_bytes().unwrap();
        let host_key_a = HostKey::parse(&blob_a).unwrap();

        struct OtherFixedRng;
        impl rand_core_06::RngCore for OtherFixedRng {
            fn next_u32(&mut self) -> u32 {
                0xdead_beef
            }
            fn next_u64(&mut self) -> u64 {
                0xdead_beef_dead_beef
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for (i, b) in dest.iter_mut().enumerate() {
                    *b = 0xFF - i as u8;
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core_06::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl rand_core_06::CryptoRng for OtherFixedRng {}
        let private_b = PrivateKey::random(&mut OtherFixedRng, ssh_key::Algorithm::Ed25519).unwrap();

        let message = b"exchange-hash-fixture";
        let signature = private_b.try_sign(message).unwrap();
        let sig_bytes: Vec<u8> = signature.try_into().unwrap();

        assert!(host_key_a.verify_signature(message, &sig_bytes).is_err());
    }
}
