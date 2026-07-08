//! curve25519-sha256 key exchange (RFC 8731).
//!
//! Flow: client generates an ephemeral X25519 keypair and sends `Q_C` in
//! `SSH_MSG_KEX_ECDH_INIT`; the server replies with its host key, its own ephemeral public key
//! `Q_S`, and a signature over the exchange hash `H`. The client computes the X25519 shared
//! secret, recomputes `H` itself, and verifies the server's signature over it before trusting
//! anything the server sent.

use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::error::{Result, SshError};
use crate::rng::{RngCore10, SecureRandom};
use crate::transport::hostkey::HostKey;
use crate::transport::kdf::encode_mpint;
use crate::wire::{write_string, Reader};

pub const MSG_KEX_ECDH_INIT: u8 = 30;
pub const MSG_KEX_ECDH_REPLY: u8 = 31;

pub struct EphemeralKeypair {
    secret: EphemeralSecret,
    public_bytes: [u8; 32],
}

impl EphemeralKeypair {
    pub fn generate(rng: &mut impl SecureRandom) -> Self {
        let secret = EphemeralSecret::random_from_rng(&mut RngCore10(rng));
        let public_bytes = X25519PublicKey::from(&secret).to_bytes();
        Self { secret, public_bytes }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public_bytes
    }

    /// `SSH_MSG_KEX_ECDH_INIT`: `byte(30) || string Q_C`.
    pub fn build_init_message(&self) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        out.push(MSG_KEX_ECDH_INIT);
        write_string(&mut out, &self.public_bytes);
        out
    }

    /// Consume `self` to compute the shared secret against the server's ephemeral public key.
    /// Rejects the all-zero/low-order-point result RFC 7748 warns about (a server sending a
    /// degenerate `Q_S` shouldn't be able to force a predictable shared secret).
    pub fn diffie_hellman(self, server_public_bytes: [u8; 32]) -> Result<[u8; 32]> {
        let their_public = X25519PublicKey::from(server_public_bytes);
        let shared = self.secret.diffie_hellman(&their_public);
        if !shared.was_contributory() {
            return Err(SshError::Negotiation("curve25519 shared secret was not contributory"));
        }
        Ok(shared.to_bytes())
    }
}

pub struct EcdhReply {
    pub host_key_blob: std::vec::Vec<u8>,
    pub server_public: [u8; 32],
    pub signature_blob: std::vec::Vec<u8>,
}

/// Parse `SSH_MSG_KEX_ECDH_REPLY`: `byte(31) || string K_S || string Q_S || string signature`.
pub fn parse_reply(payload: &[u8]) -> Result<EcdhReply> {
    let mut r = Reader::new(payload);
    let msg_type = r.read_u8()?;
    if msg_type != MSG_KEX_ECDH_REPLY {
        return Err(SshError::UnexpectedMessage {
            expected_state: "KexEcdhReply",
            msg_type,
        });
    }
    let host_key_blob = r.read_string()?.to_vec();
    let server_public_slice = r.read_string()?;
    let server_public: [u8; 32] = server_public_slice
        .try_into()
        .map_err(|_| SshError::Framing("Q_S must be exactly 32 bytes".into()))?;
    let signature_blob = r.read_string()?.to_vec();

    Ok(EcdhReply {
        host_key_blob,
        server_public,
        signature_blob,
    })
}

/// RFC 8731 exchange hash: `H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)`,
/// where each of `V_C`..`Q_S` is encoded as an SSH `string` (length-prefixed) and `K` as an
/// `mpint` - `V_C`/`V_S` are the identification lines *without* the trailing CRLF, `I_C`/`I_S`
/// are the complete `SSH_MSG_KEXINIT` payloads exactly as sent/received (including the message-
/// type byte), and `K_S`/`Q_C`/`Q_S` are raw bytes with no additional framing beyond the string
/// length prefix this function adds.
pub fn exchange_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8; 32],
    q_s: &[u8; 32],
    shared_secret: &[u8; 32],
) -> std::vec::Vec<u8> {
    let mut buf = std::vec::Vec::new();
    write_string(&mut buf, v_c);
    write_string(&mut buf, v_s);
    write_string(&mut buf, i_c);
    write_string(&mut buf, i_s);
    write_string(&mut buf, k_s);
    write_string(&mut buf, q_c);
    write_string(&mut buf, q_s);
    buf.extend_from_slice(&encode_mpint(shared_secret));

    Sha256::digest(&buf).to_vec()
}

/// Verify the server's signature (from [`EcdhReply::signature_blob`]) over `h` using the host
/// key parsed from [`EcdhReply::host_key_blob`]. Returns the parsed [`HostKey`] (the caller still
/// needs it to compute/surface the fingerprint for the JS trust-decision callback) on success.
pub fn verify_reply_signature(reply: &EcdhReply, h: &[u8]) -> Result<HostKey> {
    let host_key = HostKey::parse(&reply.host_key_blob)?;
    host_key.verify_signature(h, &reply.signature_blob)?;
    Ok(host_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u8);
    impl SecureRandom for FixedRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.0.wrapping_add(i as u8);
            }
        }
    }

    #[test]
    fn both_sides_derive_the_same_shared_secret() {
        let client = EphemeralKeypair::generate(&mut FixedRng(1));
        let server = EphemeralKeypair::generate(&mut FixedRng(200));

        let client_public = client.public_bytes();
        let server_public = server.public_bytes();

        let client_shared = client.diffie_hellman(server_public).unwrap();
        let server_shared = server.diffie_hellman(client_public).unwrap();

        assert_eq!(client_shared, server_shared);
    }

    #[test]
    fn init_message_has_expected_wire_shape() {
        let client = EphemeralKeypair::generate(&mut FixedRng(5));
        let msg = client.build_init_message();
        assert_eq!(msg[0], MSG_KEX_ECDH_INIT);
        assert_eq!(&msg[1..5], &32u32.to_be_bytes());
        assert_eq!(&msg[5..37], &client.public_bytes());
    }

    #[test]
    fn parses_reply_message() {
        let mut payload = std::vec![MSG_KEX_ECDH_REPLY];
        write_string(&mut payload, b"fake-host-key-blob");
        write_string(&mut payload, &[0x42; 32]);
        write_string(&mut payload, b"fake-signature-blob");

        let reply = parse_reply(&payload).unwrap();
        assert_eq!(reply.host_key_blob, b"fake-host-key-blob");
        assert_eq!(reply.server_public, [0x42; 32]);
        assert_eq!(reply.signature_blob, b"fake-signature-blob");
    }

    #[test]
    fn end_to_end_matches_a_hand_signed_reply() {
        use signature::Signer;
        use ssh_key::private::PrivateKey;

        struct KeygenRng;
        impl rand_core_06::RngCore for KeygenRng {
            fn next_u32(&mut self) -> u32 {
                7
            }
            fn next_u64(&mut self) -> u64 {
                7
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(7);
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core_06::Error> {
                dest.fill(7);
                Ok(())
            }
        }
        impl rand_core_06::CryptoRng for KeygenRng {}

        let host_private = PrivateKey::random(&mut KeygenRng, ssh_key::Algorithm::Ed25519).unwrap();
        let host_key_blob = host_private.public_key().to_bytes().unwrap();

        let client = EphemeralKeypair::generate(&mut FixedRng(11));
        let server = EphemeralKeypair::generate(&mut FixedRng(222));
        let q_c = client.public_bytes();
        let q_s = server.public_bytes();

        let v_c = b"SSH-2.0-wasmssh_test";
        let v_s = b"SSH-2.0-OpenSSH_test";
        let i_c = b"fake-client-kexinit-payload";
        let i_s = b"fake-server-kexinit-payload";

        let shared = client.diffie_hellman(q_s).unwrap();
        let h = exchange_hash(v_c, v_s, i_c, i_s, &host_key_blob, &q_c, &q_s, &shared);

        let signature = host_private.try_sign(&h).unwrap();
        let signature_blob: std::vec::Vec<u8> = signature.try_into().unwrap();

        let reply = EcdhReply {
            host_key_blob,
            server_public: q_s,
            signature_blob,
        };

        let host_key = verify_reply_signature(&reply, &h).unwrap();
        assert_eq!(host_key.algorithm_name(), "ssh-ed25519");

        // Tampering with H (e.g. a MITM's forged KEXINIT) must be caught.
        let mut bad_h = h.clone();
        bad_h[0] ^= 0xFF;
        assert!(verify_reply_signature(&reply, &bad_h).is_err());
    }
}
