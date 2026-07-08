//! `publickey` authentication method (RFC 4252 SS 7), two-phase query-then-sign flow collapsed
//! behind a small stateful [`PublicKeyAuth`] helper so `session.rs` doesn't need to track the
//! phase itself: [`PublicKeyAuth::build_query`] sends the "would you accept this key?" probe;
//! only once the server confirms with `SSH_MSG_USERAUTH_PK_OK` does
//! [`PublicKeyAuth::build_signed_request`] actually compute and send a signature - so we never
//! sign with a key the server was always going to reject.
//!
//! RSA client-auth signatures are always `rsa-sha2-512`: `ssh-key`'s `Signer<Signature>` impl
//! for RSA keypairs is hardcoded to SHA-512 (there's no public API to request SHA-256 through
//! it), and rsa-sha2-512 is RFC 8332-compliant and accepted by any modern OpenSSH server, so this
//! isn't a real interoperability gap - just documented here since it explains why
//! `client_auth_algorithm_name` never returns `"rsa-sha2-256"`.

use signature::Signer;
use ssh_key::PrivateKey;
use std::vec::Vec;

use crate::error::{Result, SshError};
use crate::wire::{write_bool, write_string, Reader};

use super::{write_request_prefix, SERVICE_CONNECTION};

pub fn client_auth_algorithm_name(key: &PrivateKey) -> Result<&'static str> {
    match key.algorithm() {
        ssh_key::Algorithm::Ed25519 => Ok("ssh-ed25519"),
        ssh_key::Algorithm::Rsa { .. } => Ok("rsa-sha2-512"),
        _ => Err(SshError::UnsupportedAuthMethod("publickey algorithm")),
    }
}

pub struct PublicKeyAuth {
    username: std::string::String,
    algorithm_name: &'static str,
    public_key_blob: Vec<u8>,
}

impl PublicKeyAuth {
    pub fn new(username: &str, key: &PrivateKey) -> Result<Self> {
        let algorithm_name = client_auth_algorithm_name(key)?;
        let public_key_blob = key.public_key().to_bytes()?;
        Ok(Self {
            username: username.into(),
            algorithm_name,
            public_key_blob,
        })
    }

    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm_name
    }

    pub fn public_key_blob(&self) -> &[u8] {
        &self.public_key_blob
    }

    /// Phase 1: `byte(50) || string user || string "ssh-connection" || string "publickey" ||
    /// boolean FALSE || string algorithm-name || string public-key-blob`.
    pub fn build_query(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_request_prefix(&mut out, &self.username, SERVICE_CONNECTION, "publickey");
        write_bool(&mut out, false);
        write_string(&mut out, self.algorithm_name.as_bytes());
        write_string(&mut out, &self.public_key_blob);
        out
    }

    /// Phase 2, called only after the server responds `SSH_MSG_USERAUTH_PK_OK` to the query:
    /// same shape as [`Self::build_query`] but with `boolean TRUE` and a trailing signature over
    /// `string session_id || <phase-2 request through the public-key-blob field>` (RFC 4252 SS
    /// 7).
    pub fn build_signed_request(&self, session_id: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>> {
        let signed_data = self.signed_data(session_id);
        let signature = private_key
            .try_sign(&signed_data)
            .map_err(|_| SshError::SigningFailed)?;
        let signature_wire: Vec<u8> = signature.try_into().map_err(SshError::from)?;

        let mut out = self.request_body_through_key_blob(true);
        write_string(&mut out, &signature_wire);
        Ok(out)
    }

    fn signed_data(&self, session_id: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, session_id);
        out.extend_from_slice(&self.request_body_through_key_blob(true));
        out
    }

    fn request_body_through_key_blob(&self, has_signature: bool) -> Vec<u8> {
        let mut out = Vec::new();
        write_request_prefix(&mut out, &self.username, SERVICE_CONNECTION, "publickey");
        write_bool(&mut out, has_signature);
        write_string(&mut out, self.algorithm_name.as_bytes());
        write_string(&mut out, &self.public_key_blob);
        out
    }
}

/// Parse `SSH_MSG_USERAUTH_PK_OK`: `byte(60) || string algorithm-name || string key-blob`.
/// Note message type `60` is shared with `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` - the caller must
/// only call this while a publickey query is actually outstanding.
pub fn parse_pk_ok(payload: &[u8]) -> Result<(std::string::String, Vec<u8>)> {
    let mut r = Reader::new(payload);
    let msg_type = r.read_u8()?;
    if msg_type != super::MSG_USERAUTH_PK_OK {
        return Err(SshError::UnexpectedMessage {
            expected_state: "UserAuthPkOk",
            msg_type,
        });
    }
    let algorithm_name = r.read_utf8_string()?;
    let key_blob = r.read_string()?.to_vec();
    Ok((algorithm_name, key_blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct KeygenRng;
    impl rand_core_06::RngCore for KeygenRng {
        fn next_u32(&mut self) -> u32 {
            42
        }
        fn next_u64(&mut self) -> u64 {
            42
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(42);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core_06::Error> {
            dest.fill(42);
            Ok(())
        }
    }
    impl rand_core_06::CryptoRng for KeygenRng {}

    fn test_keypair() -> PrivateKey {
        PrivateKey::random(&mut KeygenRng, ssh_key::Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn query_has_expected_wire_shape() {
        let key = test_keypair();
        let auth = PublicKeyAuth::new("bob", &key).unwrap();
        let query = auth.build_query();

        let mut r = Reader::new(&query);
        assert_eq!(r.read_u8().unwrap(), super::super::MSG_USERAUTH_REQUEST);
        assert_eq!(r.read_string().unwrap(), b"bob");
        assert_eq!(r.read_string().unwrap(), b"ssh-connection");
        assert_eq!(r.read_string().unwrap(), b"publickey");
        assert!(!r.read_bool().unwrap());
        assert_eq!(r.read_string().unwrap(), b"ssh-ed25519");
        assert_eq!(r.read_string().unwrap(), auth.public_key_blob());
        assert!(r.is_finished());
    }

    #[test]
    fn signed_request_signature_verifies_against_public_key() {
        use crate::transport::hostkey::HostKey;

        let key = test_keypair();
        let auth = PublicKeyAuth::new("bob", &key).unwrap();
        let session_id = b"fixture-session-id";

        let signed = auth.build_signed_request(session_id, &key).unwrap();

        let mut r = Reader::new(&signed);
        r.read_u8().unwrap();
        r.read_string().unwrap(); // username
        r.read_string().unwrap(); // service
        r.read_string().unwrap(); // method
        assert!(r.read_bool().unwrap()); // has_signature = true
        r.read_string().unwrap(); // algorithm name
        r.read_string().unwrap(); // key blob
        let signature_blob = r.read_string().unwrap();
        assert!(r.is_finished());

        let host_key = HostKey::parse(auth.public_key_blob()).unwrap();
        let expected_signed_data = auth.signed_data(session_id);
        host_key.verify_signature(&expected_signed_data, signature_blob).unwrap();
    }

    #[test]
    fn parses_pk_ok() {
        let mut payload = std::vec![super::super::MSG_USERAUTH_PK_OK];
        write_string(&mut payload, b"ssh-ed25519");
        write_string(&mut payload, b"fake-blob");

        let (algo, blob) = parse_pk_ok(&payload).unwrap();
        assert_eq!(algo, "ssh-ed25519");
        assert_eq!(blob, b"fake-blob");
    }
}
