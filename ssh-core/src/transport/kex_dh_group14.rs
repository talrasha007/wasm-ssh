//! diffie-hellman-group14-sha256 key exchange (RFC 8268 KEX method; RFC 4253 SS 8 message flow;
//! RFC 3526 SS 3 for the fixed 2048-bit MODP group 14 prime/generator). This is the broader-
//! compatibility fallback for servers that don't support curve25519-sha256.
//!
//! Unlike curve25519 (where `Q_C`/`Q_S` are raw fixed-length byte strings), classic
//! Diffie-Hellman represents everything - `e`, `f`, and the shared secret `K` - as `mpint`s.

use sha2::{Digest, Sha256};
use std::vec::Vec;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::prelude::*;
use crypto_bigint::BoxedUint;

use crate::error::{Result, SshError};
use crate::rng::{RngCore10, SecureRandom};
use crate::transport::hostkey::HostKey;
use crate::transport::kdf::encode_mpint;
use crate::wire::{write_string, Reader};

pub const MSG_KEXDH_INIT: u8 = 30;
pub const MSG_KEXDH_REPLY: u8 = 31;

const GROUP14_BITS: u32 = 2048;

/// RFC 3526 SS 3, 2048-bit MODP Group 14 prime. Cross-checked against the canonical plaintext
/// RFC (rfc-editor.org) rather than transcribed from memory alone, given how silently
/// catastrophic a wrong constant would be here (and how hard it'd be to notice without a live
/// server to test against).
const GROUP14_PRIME_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF";

fn group_params() -> BoxedMontyParams {
    let prime = BoxedUint::from_be_hex(GROUP14_PRIME_HEX, GROUP14_BITS)
        .expect("GROUP14_PRIME_HEX is a valid, fixed-length hex constant");
    let odd_prime = prime
        .to_odd()
        .expect("RFC 3526 group 14 prime is odd (it's prime and > 2)");
    BoxedMontyParams::new(odd_prime)
}

fn generator() -> BoxedUint {
    BoxedUint::from_be_slice(&[2], GROUP14_BITS).expect("2 fits trivially in 2048 bits")
}

pub struct ClientKeyExchange {
    params: BoxedMontyParams,
    x: BoxedUint,
    e_bytes: Vec<u8>,
}

impl ClientKeyExchange {
    pub fn generate(rng: &mut impl SecureRandom) -> Self {
        let params = group_params();
        // Full-width random exponent (RFC 4253 SS 8 just requires "a random number"; using the
        // full group width is the simple, conventional, secure choice - correctness of g^x mod p
        // doesn't depend on x being reduced below any particular bound).
        let x = BoxedUint::try_random_bits_with_precision(&mut RngCore10(rng), GROUP14_BITS, GROUP14_BITS)
            .expect("RngCore10's TryRng is infallible and bit_length == bits_precision here");

        let g_monty = BoxedMontyForm::new(generator(), &params);
        let e = g_monty.pow(&x).retrieve();
        let e_bytes = e.to_be_bytes().to_vec();

        Self { params, x, e_bytes }
    }

    /// `SSH_MSG_KEXDH_INIT`: `byte(30) || mpint e`.
    pub fn build_init_message(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(MSG_KEXDH_INIT);
        out.extend_from_slice(&encode_mpint(&self.e_bytes));
        out
    }

    pub fn e_bytes(&self) -> &[u8] {
        &self.e_bytes
    }

    /// Consume `self` to compute the shared secret `K = f^x mod p`, after validating `f` is in
    /// the required range `1 < f < p-1` (RFC 4253 SS 8: rejecting `0`, `1`, and `p-1` rules out
    /// the trivial/degenerate subgroup elements a malicious server could otherwise use to force
    /// a predictable shared secret).
    pub fn diffie_hellman(self, f_bytes: &[u8]) -> Result<Vec<u8>> {
        let f = BoxedUint::from_be_slice(f_bytes, GROUP14_BITS)
            .map_err(|_| SshError::Framing("f is too large for group14".into()))?;
        validate_public_value(&f, &self.params)?;

        let f_monty = BoxedMontyForm::new(f, &self.params);
        let shared = f_monty.pow(&self.x).retrieve();
        Ok(shared.to_be_bytes().to_vec())
    }
}

fn validate_public_value(value: &BoxedUint, params: &BoxedMontyParams) -> Result<()> {
    let prime = BoxedUint::from_be_hex(GROUP14_PRIME_HEX, GROUP14_BITS)
        .expect("GROUP14_PRIME_HEX is a valid, fixed-length hex constant");
    let one = BoxedUint::one_with_precision(GROUP14_BITS);
    let prime_minus_one = prime.wrapping_sub(&one);
    let _ = params; // params only needed by callers that already have it handy; kept for symmetry

    if value.is_zero().into() || *value == one || *value >= prime_minus_one {
        return Err(SshError::Negotiation("group14 public value out of valid range"));
    }
    Ok(())
}

pub struct KexDhReply {
    pub host_key_blob: Vec<u8>,
    pub f_bytes: Vec<u8>,
    pub signature_blob: Vec<u8>,
}

/// Parse `SSH_MSG_KEXDH_REPLY`: `byte(31) || string K_S || mpint f || string signature`.
pub fn parse_reply(payload: &[u8]) -> Result<KexDhReply> {
    let mut r = Reader::new(payload);
    let msg_type = r.read_u8()?;
    if msg_type != MSG_KEXDH_REPLY {
        return Err(SshError::UnexpectedMessage {
            expected_state: "KexDhReply",
            msg_type,
        });
    }
    let host_key_blob = r.read_string()?.to_vec();
    let f_bytes = r.read_string()?.to_vec(); // mpint is wire-compatible with `string` framing
    let signature_blob = r.read_string()?.to_vec();

    Ok(KexDhReply {
        host_key_blob,
        f_bytes,
        signature_blob,
    })
}

/// RFC 4253 SS 8 exchange hash: `H = SHA256(V_C || V_S || I_C || I_S || K_S || e || f || K)`,
/// with `e`, `f`, `K` all mpint-encoded (unlike curve25519-sha256's raw-bytes `Q_C`/`Q_S`).
pub fn exchange_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    e_bytes: &[u8],
    f_bytes: &[u8],
    shared_secret: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    write_string(&mut buf, v_c);
    write_string(&mut buf, v_s);
    write_string(&mut buf, i_c);
    write_string(&mut buf, i_s);
    write_string(&mut buf, k_s);
    buf.extend_from_slice(&encode_mpint(e_bytes));
    buf.extend_from_slice(&encode_mpint(f_bytes));
    buf.extend_from_slice(&encode_mpint(shared_secret));
    Sha256::digest(&buf).to_vec()
}

pub fn verify_reply_signature(reply: &KexDhReply, h: &[u8]) -> Result<HostKey> {
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
    fn group14_prime_constant_is_exactly_2048_bits_and_odd() {
        let prime = BoxedUint::from_be_hex(GROUP14_PRIME_HEX, GROUP14_BITS).unwrap();
        assert_eq!(prime.bits_precision(), GROUP14_BITS);
        let bytes = prime.to_be_bytes();
        assert_eq!(bytes.len(), 256);
        assert_eq!(bytes[0], 0xFF, "RFC 3526 group 14 prime starts with 0xFFFFFFFF");
        assert_eq!(bytes[255], 0xFF, "RFC 3526 group 14 prime ends with 0xFFFFFFFF");
        assert!(bool::from(prime.to_odd().is_some()));
    }

    #[test]
    fn both_sides_derive_the_same_shared_secret() {
        let client = ClientKeyExchange::generate(&mut FixedRng(3));
        let server = ClientKeyExchange::generate(&mut FixedRng(151));

        let client_e = client.e_bytes().to_vec();
        let server_e = server.e_bytes().to_vec();

        let client_shared = client.diffie_hellman(&server_e).unwrap();
        let server_shared = server.diffie_hellman(&client_e).unwrap();

        assert_eq!(client_shared, server_shared);
    }

    #[test]
    fn rejects_degenerate_public_values() {
        let client = ClientKeyExchange::generate(&mut FixedRng(9));
        assert!(client.diffie_hellman(&[0x00]).is_err());
        assert!(ClientKeyExchange::generate(&mut FixedRng(9)).diffie_hellman(&[0x01]).is_err());

        let prime_minus_one = {
            let prime = BoxedUint::from_be_hex(GROUP14_PRIME_HEX, GROUP14_BITS).unwrap();
            prime.wrapping_sub(&BoxedUint::one_with_precision(GROUP14_BITS)).to_be_bytes().to_vec()
        };
        assert!(ClientKeyExchange::generate(&mut FixedRng(9))
            .diffie_hellman(&prime_minus_one)
            .is_err());
    }

    #[test]
    fn parses_reply_message() {
        let mut payload = std::vec![MSG_KEXDH_REPLY];
        write_string(&mut payload, b"fake-host-key-blob");
        payload.extend_from_slice(&encode_mpint(&[0x01, 0x02, 0x03]));
        write_string(&mut payload, b"fake-signature-blob");

        let reply = parse_reply(&payload).unwrap();
        assert_eq!(reply.host_key_blob, b"fake-host-key-blob");
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

        let client = ClientKeyExchange::generate(&mut FixedRng(11));
        let server = ClientKeyExchange::generate(&mut FixedRng(222));
        let e_bytes = client.e_bytes().to_vec();
        let f_bytes = server.e_bytes().to_vec();

        let v_c = b"SSH-2.0-wasmssh_test";
        let v_s = b"SSH-2.0-OpenSSH_test";
        let i_c = b"fake-client-kexinit-payload";
        let i_s = b"fake-server-kexinit-payload";

        let shared = client.diffie_hellman(&f_bytes).unwrap();
        let h = exchange_hash(v_c, v_s, i_c, i_s, &host_key_blob, &e_bytes, &f_bytes, &shared);

        let signature = host_private.try_sign(&h).unwrap();
        let signature_blob: Vec<u8> = signature.try_into().unwrap();

        let reply = KexDhReply {
            host_key_blob,
            f_bytes,
            signature_blob,
        };

        let host_key = verify_reply_signature(&reply, &h).unwrap();
        assert_eq!(host_key.algorithm_name(), "ssh-ed25519");

        let mut bad_h = h.clone();
        bad_h[0] ^= 0xFF;
        assert!(verify_reply_signature(&reply, &bad_h).is_err());
    }
}
