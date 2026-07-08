//! RFC 4253 SS 7.2 key derivation.
//!
//! Six values are derived from the same `(K, H, session_id)` triple, distinguished only by a
//! single-letter tag: initial IV client->server (`A`)/server->client (`B`), encryption key
//! client->server (`C`)/server->client (`D`), integrity key client->server (`E`)/server->client
//! (`F`). `session_id` is the exchange hash `H` from the *first* key exchange of the connection;
//! since ssh-core doesn't implement rekeying in v1, `session_id` and the current `H` are always
//! the same value in practice, but they're kept as distinct parameters for correctness.

use sha2::{Digest, Sha256};
use std::vec::Vec;

pub const TAG_IV_CLIENT_TO_SERVER: u8 = b'A';
pub const TAG_IV_SERVER_TO_CLIENT: u8 = b'B';
pub const TAG_ENC_KEY_CLIENT_TO_SERVER: u8 = b'C';
pub const TAG_ENC_KEY_SERVER_TO_CLIENT: u8 = b'D';
pub const TAG_INTEGRITY_KEY_CLIENT_TO_SERVER: u8 = b'E';
pub const TAG_INTEGRITY_KEY_SERVER_TO_CLIENT: u8 = b'F';

/// Derive `needed_len` bytes of key material for the given tag.
///
/// `k_mpint` must be the *mpint-encoded* shared secret (the same bytes used when computing the
/// exchange hash `H`) - RFC 4253 SS 7.2 specifies `K` is used in this encoded form, not as a raw
/// big-endian integer.
pub fn derive(k_mpint: &[u8], h: &[u8], session_id: &[u8], tag: u8, needed_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(needed_len.max(Sha256::output_size()));

    let first_block = Sha256::new()
        .chain_update(k_mpint)
        .chain_update(h)
        .chain_update([tag])
        .chain_update(session_id)
        .finalize();
    out.extend_from_slice(&first_block);

    // Extension for ciphers needing more key material than one hash output (RFC 4253 SS 7.2):
    // K_n = HASH(K || H || K1 || K2 || ... || K_{n-1}), i.e. each new block is hashed over the
    // concatenation of *all* previously generated blocks, not just the last one.
    while out.len() < needed_len {
        let next_block = Sha256::new()
            .chain_update(k_mpint)
            .chain_update(h)
            .chain_update(&out)
            .finalize();
        out.extend_from_slice(&next_block);
    }

    out.truncate(needed_len);
    out
}

/// Encode a shared secret (as an unsigned big-endian integer) the way RFC 4253 requires it to
/// appear both in the exchange hash and as `K` in [`derive`] - as a wire-format `mpint`
/// (4-byte big-endian length prefix, plus a leading zero byte if the high bit of the first
/// significant byte would otherwise be set, since mpint is a *signed* representation).
pub fn encode_mpint(unsigned_be_bytes: &[u8]) -> Vec<u8> {
    let mpint = ssh_encoding::Mpint::from_positive_bytes(unsigned_be_bytes);
    let mut out = Vec::new();
    ssh_encoding::Encode::encode(&mpint, &mut out).expect("Vec<u8> writer is infallible");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_block_matches_single_hash() {
        let k = encode_mpint(&[0x01, 0x02, 0x03]);
        let h = b"exchange-hash-fixture";
        let session_id = b"session-id-fixture";
        let derived = derive(&k, h, session_id, TAG_ENC_KEY_CLIENT_TO_SERVER, 32);

        let expected = Sha256::new()
            .chain_update(&k)
            .chain_update(h)
            .chain_update([TAG_ENC_KEY_CLIENT_TO_SERVER])
            .chain_update(session_id)
            .finalize();
        assert_eq!(derived.as_slice(), expected.as_slice());
    }

    #[test]
    fn extension_blocks_use_cumulative_concatenation() {
        let k = encode_mpint(&[0xAA; 4]);
        let h = b"h";
        let session_id = b"sid";
        // 64 bytes needs a second block (chacha20-poly1305@openssh.com's real use case).
        let derived = derive(&k, h, session_id, TAG_ENC_KEY_CLIENT_TO_SERVER, 64);
        assert_eq!(derived.len(), 64);

        let k1 = Sha256::new()
            .chain_update(&k)
            .chain_update(h)
            .chain_update([TAG_ENC_KEY_CLIENT_TO_SERVER])
            .chain_update(session_id)
            .finalize();
        assert_eq!(&derived[..32], k1.as_slice());

        let k2 = Sha256::new().chain_update(&k).chain_update(h).chain_update(&k1).finalize();
        assert_eq!(&derived[32..64], k2.as_slice());
    }

    #[test]
    fn truncates_to_requested_length() {
        let k = encode_mpint(&[1]);
        let derived = derive(&k, b"h", b"sid", TAG_IV_CLIENT_TO_SERVER, 12);
        assert_eq!(derived.len(), 12);
    }

    #[test]
    fn mpint_encoding_adds_leading_zero_for_high_bit() {
        // 0x80... would look negative without a leading zero byte in the signed mpint format.
        let encoded = encode_mpint(&[0x80, 0x01]);
        // 4-byte big-endian length prefix + 1 padding zero byte + 2 payload bytes = 7.
        assert_eq!(encoded.len(), 7);
        assert_eq!(&encoded[0..4], &[0, 0, 0, 3]);
        assert_eq!(&encoded[4..], &[0x00, 0x80, 0x01]);
    }
}
