//! RFC 4253 SS 6 binary packet protocol, specialized to the two AEAD ciphers this client
//! supports (`chacha20-poly1305@openssh.com` and `aes256-gcm@openssh.com` - see module docs on
//! each `seal_*`/`open_*` pair for the wire-format details of each).
//!
//! A packet on the wire is `packet_length(4) || padding_length(1) || payload || padding || tag(16)`,
//! where `packet_length` covers everything after itself except the tag. Each direction
//! (client->server, server->client) has independent cipher state and its own monotonically
//! increasing 32-bit sequence number (RFC 4253 SS 6.4), used as part of both AEAD constructions'
//! nonces.

use std::vec::Vec;

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::Aes256Gcm;
use ssh_cipher::cipher::{KeyIvInit, StreamCipher};
use ssh_cipher::{ChaCha20, ChaCha20Poly1305, ChaChaKey, ChaChaNonce};

use crate::error::{Result, SshError};
use crate::rng::SecureRandom;

/// Hard upper bound on an (attempted) decrypted packet length, guarding against a
/// malicious/corrupted peer causing an oversized allocation before any authentication has
/// happened. Comfortably above anything a real server sends (OpenSSH's own limit is 256 KiB).
pub const MAX_PACKET_LENGTH: usize = 256 * 1024;

pub const TAG_LEN: usize = 16;
const MIN_PADDING: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    ChaCha20Poly1305OpenSsh,
    Aes256GcmOpenSsh,
}

impl CipherAlgorithm {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305OpenSsh => "chacha20-poly1305@openssh.com",
            Self::Aes256GcmOpenSsh => "aes256-gcm@openssh.com",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "chacha20-poly1305@openssh.com" => Some(Self::ChaCha20Poly1305OpenSsh),
            "aes256-gcm@openssh.com" => Some(Self::Aes256GcmOpenSsh),
            _ => None,
        }
    }

    /// `(encryption_key_bytes, iv_bytes)` to request from the RFC 4253 SS 7.2 KDF for one
    /// direction. `chacha20-poly1305@openssh.com` is unusual: it takes no IV at all (the nonce
    /// is derived purely from the sequence number) and instead needs 64 bytes of "encryption
    /// key" material, split into two 32-byte keys K1/K2.
    pub const fn kdf_material_len(self) -> (usize, usize) {
        match self {
            Self::ChaCha20Poly1305OpenSsh => (64, 0),
            Self::Aes256GcmOpenSsh => (32, 12),
        }
    }

    pub const fn block_size(self) -> usize {
        match self {
            Self::ChaCha20Poly1305OpenSsh => 8,
            Self::Aes256GcmOpenSsh => 16,
        }
    }
}

enum DirectionKeys {
    ChaCha20Poly1305 { k1: ChaChaKey, k2: ChaChaKey },
    Aes256Gcm { cipher: Aes256Gcm, nonce: [u8; 12] },
}

/// Per-direction cipher state (one instance for client->server, a separate one for
/// server->client - they have independent keys and sequence numbers).
pub struct PacketCipher {
    alg: CipherAlgorithm,
    keys: DirectionKeys,
    seq: u32,
}

impl PacketCipher {
    /// `enc_key`/`iv` must be exactly [`CipherAlgorithm::kdf_material_len`] bytes each (`iv` is
    /// empty for chacha20-poly1305@openssh.com).
    pub fn new(alg: CipherAlgorithm, enc_key: &[u8], iv: &[u8]) -> Self {
        let keys = match alg {
            CipherAlgorithm::ChaCha20Poly1305OpenSsh => {
                assert_eq!(enc_key.len(), 64, "chacha20-poly1305@openssh.com needs 64 key bytes");
                let k1 = ChaChaKey::try_from(&enc_key[0..32]).expect("32 bytes");
                let k2 = ChaChaKey::try_from(&enc_key[32..64]).expect("32 bytes");
                DirectionKeys::ChaCha20Poly1305 { k1, k2 }
            }
            CipherAlgorithm::Aes256GcmOpenSsh => {
                assert_eq!(enc_key.len(), 32, "aes256-gcm@openssh.com needs 32 key bytes");
                assert_eq!(iv.len(), 12, "aes256-gcm@openssh.com needs a 12-byte IV");
                let cipher = Aes256Gcm::new_from_slice(enc_key).expect("32-byte key");
                let nonce: [u8; 12] = iv.try_into().expect("12 bytes");
                DirectionKeys::Aes256Gcm { cipher, nonce }
            }
        };
        Self { alg, keys, seq: 0 }
    }

    pub fn algorithm(&self) -> CipherAlgorithm {
        self.alg
    }

    /// Frame and encrypt one packet carrying `payload`, advancing this direction's sequence
    /// number. Returns the complete wire-format packet.
    pub fn seal(&mut self, payload: &[u8], rng: &mut impl SecureRandom) -> Vec<u8> {
        let body = pad_payload(payload, self.alg.block_size(), rng);
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);

        match &mut self.keys {
            DirectionKeys::ChaCha20Poly1305 { k1, k2 } => seal_chacha20poly1305(k1, k2, seq, body),
            DirectionKeys::Aes256Gcm { cipher, nonce } => {
                // `nonce` here is the *current* per-direction IV state; compute this packet's
                // nonce from it, then advance the stored counter for the next packet - the
                // counter must advance in lockstep on both the sealing and opening side, exactly
                // once per packet, or the two sides' nonces desync after the first packet.
                let this_nonce = *nonce;
                let sealed = seal_aes256gcm(cipher, &this_nonce, body);
                increment_gcm_nonce(nonce);
                sealed
            }
        }
    }

    /// Given the first 4 bytes of a not-yet-fully-received wire packet, determine how many total
    /// bytes (including those 4) must be buffered before [`Self::open`] can be called. Does not
    /// mutate sequence-number state - only [`Self::open`] does, once a full packet is confirmed.
    pub fn peek_total_length(&self, first_4_bytes: &[u8; 4]) -> Result<usize> {
        let packet_length = match &self.keys {
            DirectionKeys::ChaCha20Poly1305 { k1, .. } => {
                decrypt_length_chacha20(k1, self.seq, first_4_bytes)
            }
            DirectionKeys::Aes256Gcm { .. } => u32::from_be_bytes(*first_4_bytes),
        } as usize;

        if packet_length == 0 || packet_length > MAX_PACKET_LENGTH {
            return Err(SshError::Framing(std::format!(
                "implausible packet length {packet_length}"
            )));
        }
        Ok(4 + packet_length + TAG_LEN)
    }

    /// Decrypt and authenticate one full wire packet (exactly [`Self::peek_total_length`] bytes),
    /// returning the plaintext payload with padding stripped. Advances the sequence number only
    /// on success - a failed MAC must be immediately fatal (RFC 4253 SS 6.3), so there's no
    /// meaningful "next packet" to advance into anyway.
    pub fn open(&mut self, wire_packet: &[u8]) -> Result<Vec<u8>> {
        let seq = self.seq;
        let enc_len: [u8; 4] = wire_packet[0..4]
            .try_into()
            .map_err(|_| SshError::Framing("packet shorter than length field".into()))?;

        let plaintext_body = match &mut self.keys {
            DirectionKeys::ChaCha20Poly1305 { k1, k2 } => {
                open_chacha20poly1305(k1, k2, seq, &enc_len, wire_packet)?
            }
            DirectionKeys::Aes256Gcm { cipher, nonce } => {
                let this_nonce = *nonce;
                let plaintext = open_aes256gcm(cipher, &this_nonce, &enc_len, wire_packet)?;
                increment_gcm_nonce(nonce);
                plaintext
            }
        };

        self.seq = self.seq.wrapping_add(1);
        strip_padding(plaintext_body)
    }
}

/// RFC 4253 SS 6 packet framing with cipher `none` and MAC `none` - used only for the initial
/// `SSH_MSG_KEXINIT` exchange, before either side has sent `SSH_MSG_NEWKEYS`. No sequence-number
/// state is needed since nothing here is keyed.
pub fn seal_plaintext(payload: &[u8], rng: &mut impl SecureRandom) -> Vec<u8> {
    let body = pad_payload(payload, 8, rng);
    let mut wire = Vec::with_capacity(4 + body.len());
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend_from_slice(&body);
    wire
}

pub fn peek_plaintext_length(first_4_bytes: &[u8; 4]) -> Result<usize> {
    let packet_length = u32::from_be_bytes(*first_4_bytes) as usize;
    if packet_length == 0 || packet_length > MAX_PACKET_LENGTH {
        return Err(SshError::Framing(std::format!(
            "implausible plaintext packet length {packet_length}"
        )));
    }
    Ok(4 + packet_length)
}

pub fn open_plaintext(wire_packet: &[u8]) -> Result<Vec<u8>> {
    let packet_length = u32::from_be_bytes(
        wire_packet[0..4]
            .try_into()
            .map_err(|_| SshError::Framing("packet shorter than length field".into()))?,
    ) as usize;
    if wire_packet.len() != 4 + packet_length {
        return Err(SshError::Framing("wire packet length mismatch".into()));
    }
    strip_padding(wire_packet[4..].to_vec())
}

/// Build `padding_length(1) || payload || padding` with random padding, sized so the whole body
/// is a multiple of `block_size` and padding is at least 4 bytes (RFC 4253 SS 6).
pub(crate) fn pad_payload(payload: &[u8], block_size: usize, rng: &mut impl SecureRandom) -> Vec<u8> {
    let unpadded_len = 1 + payload.len();
    let mut padding_len = block_size - (unpadded_len % block_size);
    if padding_len < MIN_PADDING {
        padding_len += block_size;
    }
    debug_assert!(padding_len <= u8::MAX as usize);

    let mut body = Vec::with_capacity(unpadded_len + padding_len);
    body.push(padding_len as u8);
    body.extend_from_slice(payload);
    let pad_start = body.len();
    body.resize(body.len() + padding_len, 0);
    rng.fill(&mut body[pad_start..]);
    body
}

pub(crate) fn strip_padding(mut body: Vec<u8>) -> Result<Vec<u8>> {
    if body.is_empty() {
        return Err(SshError::Framing("empty packet body".into()));
    }
    let padding_len = body[0] as usize;
    if 1 + padding_len > body.len() {
        return Err(SshError::Framing("padding length exceeds packet body".into()));
    }
    let payload_end = body.len() - padding_len;
    body.truncate(payload_end);
    body.drain(0..1);
    Ok(body)
}

fn chacha_nonce_for_seq(seq: u32) -> ChaChaNonce {
    let mut nonce = ChaChaNonce::default();
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn decrypt_length_chacha20(k1: &ChaChaKey, seq: u32, enc_len: &[u8; 4]) -> u32 {
    let nonce = chacha_nonce_for_seq(seq);
    let mut buf = *enc_len;
    let mut cipher = ChaCha20::new(k1, &nonce);
    cipher.apply_keystream(&mut buf);
    u32::from_be_bytes(buf)
}

/// `chacha20-poly1305@openssh.com` framing (see [PROTOCOL.chacha20poly1305]).
///
/// The 4-byte length field is separately encrypted (not authenticated on its own) using raw
/// ChaCha20 keyed with `K1`; the packet body is then encrypted and authenticated with
/// ChaCha20-Poly1305 keyed with `K2`, using the *encrypted* length bytes as associated data.
///
/// [PROTOCOL.chacha20poly1305]: https://web.mit.edu/freebsd/head/crypto/openssh/PROTOCOL.chacha20poly1305
fn seal_chacha20poly1305(k1: &ChaChaKey, k2: &ChaChaKey, seq: u32, mut body: Vec<u8>) -> Vec<u8> {
    let nonce = chacha_nonce_for_seq(seq);

    let packet_length = body.len() as u32;
    let mut len_bytes = packet_length.to_be_bytes();
    let mut len_cipher = ChaCha20::new(k1, &nonce);
    len_cipher.apply_keystream(&mut len_bytes);

    let body_cipher = ChaCha20Poly1305::new(k2);
    let tag = body_cipher
        .encrypt_inout_detached(&nonce, &len_bytes, body.as_mut_slice().into())
        .expect("chacha20-poly1305 encryption cannot fail for well-formed input");

    let mut wire = Vec::with_capacity(4 + body.len() + TAG_LEN);
    wire.extend_from_slice(&len_bytes);
    wire.extend_from_slice(&body);
    wire.extend_from_slice(tag.as_ref());
    wire
}

fn open_chacha20poly1305(
    k1: &ChaChaKey,
    k2: &ChaChaKey,
    seq: u32,
    enc_len: &[u8; 4],
    wire_packet: &[u8],
) -> Result<Vec<u8>> {
    let packet_length = decrypt_length_chacha20(k1, seq, enc_len) as usize;
    let expected_total = 4 + packet_length + TAG_LEN;
    if wire_packet.len() != expected_total {
        return Err(SshError::Framing("wire packet length mismatch".into()));
    }

    let mut body = wire_packet[4..4 + packet_length].to_vec();
    let tag_bytes = &wire_packet[4 + packet_length..expected_total];
    let tag = ssh_cipher::Tag::try_from(tag_bytes)
        .map_err(|_| SshError::Framing("bad tag length".into()))?;

    let nonce = chacha_nonce_for_seq(seq);
    let aead = ChaCha20Poly1305::new(k2);
    aead.decrypt_inout_detached(&nonce, enc_len, body.as_mut_slice().into(), &tag)
        .map_err(|_| SshError::Mac)?;

    Ok(body)
}

/// `aes256-gcm@openssh.com` framing (RFC 5647). Unlike chacha20-poly1305, the length field is
/// sent in the clear and used as AEAD associated data; the 12-byte nonce is the direction's KDF-
/// derived IV, with its last 8 bytes treated as a big-endian counter that increments by one for
/// every packet (RFC 5647 SS 7.1) - *not* the RFC 4253 sequence number, though the two happen to
/// increment in lockstep since both start together and step by 1 per packet.
fn seal_aes256gcm(cipher: &Aes256Gcm, nonce_bytes: &[u8; 12], mut body: Vec<u8>) -> Vec<u8> {
    let packet_length = body.len() as u32;
    let len_bytes = packet_length.to_be_bytes();
    let nonce = aes_gcm::Nonce::try_from(nonce_bytes.as_slice()).expect("12 bytes");

    let tag = cipher
        .encrypt_inout_detached(&nonce, &len_bytes, body.as_mut_slice().into())
        .expect("aes-gcm encryption cannot fail for well-formed input");

    let mut wire = Vec::with_capacity(4 + body.len() + TAG_LEN);
    wire.extend_from_slice(&len_bytes);
    wire.extend_from_slice(&body);
    wire.extend_from_slice(tag.as_ref());
    wire
}

fn open_aes256gcm(
    cipher: &Aes256Gcm,
    nonce_bytes: &[u8; 12],
    enc_len: &[u8; 4],
    wire_packet: &[u8],
) -> Result<Vec<u8>> {
    let packet_length = u32::from_be_bytes(*enc_len) as usize;
    let expected_total = 4 + packet_length + TAG_LEN;
    if wire_packet.len() != expected_total {
        return Err(SshError::Framing("wire packet length mismatch".into()));
    }

    let mut body = wire_packet[4..4 + packet_length].to_vec();
    let tag_bytes = &wire_packet[4 + packet_length..expected_total];
    let tag = aes_gcm::Tag::try_from(tag_bytes).map_err(|_| SshError::Framing("bad tag length".into()))?;

    let nonce = aes_gcm::Nonce::try_from(nonce_bytes.as_slice()).expect("12 bytes");
    cipher
        .decrypt_inout_detached(&nonce, enc_len, body.as_mut_slice().into(), &tag)
        .map_err(|_| SshError::Mac)?;

    Ok(body)
}

fn increment_gcm_nonce(nonce: &mut [u8; 12]) {
    let counter = u64::from_be_bytes(nonce[4..12].try_into().expect("8 bytes"));
    nonce[4..12].copy_from_slice(&counter.wrapping_add(1).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    struct FixedRng(u8);
    impl SecureRandom for FixedRng {
        fn fill(&mut self, buf: &mut [u8]) {
            buf.fill(self.0);
        }
    }

    /// Known-good test vector (OpenSSH's PROTOCOL.chacha20poly1305 reference values, also used
    /// by ssh-cipher's own test suite) for the *body* AEAD primitive in isolation: given nonce
    /// and AAD directly (rather than deriving them from a sequence number the way
    /// [`seal_chacha20poly1305`] does), confirms our use of `ssh_cipher::ChaCha20Poly1305` -
    /// key type, nonce type, and the `encrypt_inout_detached`/`decrypt_inout_detached` call
    /// shape - produces byte-exact, spec-correct output. Sequence-number-to-nonce derivation and
    /// K1-based length encryption are exercised separately by the round-trip tests below.
    #[test]
    fn chacha20poly1305_body_aead_matches_known_vector() {
        const KEY: [u8; 32] = hex!("379a8ca9e7e705763633213511e8d92eb148a46f1dd0045ec8164e5d23e456eb");
        const NONCE: [u8; 8] = hex!("0000000000000003");
        const AAD: [u8; 4] = hex!("5709db2d");
        const PT: [u8; 24] = hex!("06050000000c7373682d7573657261757468de5949ab061f");
        const CT: [u8; 24] = hex!("6dcfb03be8a55e7f0220465672edd921489ea0171198e8a7");
        const TAG: [u8; 16] = hex!("3e82fe0a2db7128d58ef8d9047963ca3");

        let cipher = ChaCha20Poly1305::new(&KEY.into());
        let mut buffer = PT;
        let tag = cipher
            .encrypt_inout_detached(&NONCE.into(), &AAD, buffer.as_mut_slice().into())
            .unwrap();
        assert_eq!(buffer, CT);
        assert_eq!(tag.as_slice(), TAG);

        cipher
            .decrypt_inout_detached(&NONCE.into(), &AAD, buffer.as_mut_slice().into(), &tag)
            .unwrap();
        assert_eq!(buffer, PT);
    }

    #[test]
    fn chacha20poly1305_round_trip() {
        // `sender` and `receiver` represent the two ends of the *same* direction (e.g. both
        // hold the client->server keys - one seals, the other opens), so they must share key
        // material; only their sequence-number progression is expected to stay in lockstep.
        let mut sender =
            PacketCipher::new(CipherAlgorithm::ChaCha20Poly1305OpenSsh, &[0x11; 64], &[]);
        let mut receiver =
            PacketCipher::new(CipherAlgorithm::ChaCha20Poly1305OpenSsh, &[0x11; 64], &[]);
        let mut rng = FixedRng(0x42);

        for i in 0..3u8 {
            let payload = std::vec![i; 10 + i as usize];
            let wire = sender.seal(&payload, &mut rng);

            let mut peek = [0u8; 4];
            peek.copy_from_slice(&wire[0..4]);
            let total = receiver.peek_total_length(&peek).unwrap();
            assert_eq!(total, wire.len());

            let opened = receiver.open(&wire).unwrap();
            assert_eq!(opened, payload);
        }

        // A receiver with the *wrong* keys entirely must reject the packet.
        let payload = b"wrong keys should fail".to_vec();
        let wire = sender.seal(&payload, &mut rng);
        let mut wrong_keys =
            PacketCipher::new(CipherAlgorithm::ChaCha20Poly1305OpenSsh, &[0x22; 64], &[]);
        assert!(wrong_keys.open(&wire).is_err());
    }

    #[test]
    fn aes256gcm_round_trip() {
        let mut cs_cipher =
            PacketCipher::new(CipherAlgorithm::Aes256GcmOpenSsh, &[0x33; 32], &[0x01; 12]);
        let mut sc_cipher =
            PacketCipher::new(CipherAlgorithm::Aes256GcmOpenSsh, &[0x33; 32], &[0x01; 12]);
        let mut rng = FixedRng(0x99);

        for i in 0..5u8 {
            let payload = std::vec![i; 5 + i as usize * 3];
            let wire = cs_cipher.seal(&payload, &mut rng);

            let mut peek = [0u8; 4];
            peek.copy_from_slice(&wire[0..4]);
            let total = sc_cipher.peek_total_length(&peek).unwrap();
            assert_eq!(total, wire.len());

            let opened = sc_cipher.open(&wire).unwrap();
            assert_eq!(opened, payload);
        }
    }

    #[test]
    fn aes256gcm_tampered_ciphertext_is_rejected() {
        let mut cs_cipher =
            PacketCipher::new(CipherAlgorithm::Aes256GcmOpenSsh, &[0x44; 32], &[0x02; 12]);
        let mut sc_cipher =
            PacketCipher::new(CipherAlgorithm::Aes256GcmOpenSsh, &[0x44; 32], &[0x02; 12]);
        let mut rng = FixedRng(0x01);

        let mut wire = cs_cipher.seal(b"hello", &mut rng);
        let last = wire.len() - 1;
        wire[last] ^= 0xFF; // flip a bit in the tag
        assert!(matches!(sc_cipher.open(&wire), Err(SshError::Mac)));
    }

    #[test]
    fn pad_payload_meets_min_padding_and_block_alignment() {
        let mut rng = FixedRng(0);
        for block_size in [8usize, 16] {
            for payload_len in 0..40 {
                let payload = std::vec![0u8; payload_len];
                let body = pad_payload(&payload, block_size, &mut rng);
                assert_eq!(body.len() % block_size, 0);
                let padding_len = body[0] as usize;
                assert!(padding_len >= MIN_PADDING);
                assert_eq!(body.len(), 1 + payload_len + padding_len);
            }
        }
    }

    #[test]
    fn plaintext_round_trip() {
        let mut rng = FixedRng(0x55);
        let payload = b"SSH_MSG_KEXINIT-shaped payload".to_vec();
        let wire = seal_plaintext(&payload, &mut rng);

        let mut peek = [0u8; 4];
        peek.copy_from_slice(&wire[0..4]);
        let total = peek_plaintext_length(&peek).unwrap();
        assert_eq!(total, wire.len());

        assert_eq!(open_plaintext(&wire).unwrap(), payload);
    }
}
