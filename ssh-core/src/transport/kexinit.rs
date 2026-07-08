//! `SSH_MSG_KEXINIT` (RFC 4253 SS 7.1) construction/parsing and algorithm negotiation.
//!
//! Name-lists are hand-rolled here (comma-joined ASCII inside a single length-prefixed `string`)
//! rather than using `ssh_encoding`'s `Vec<String>` (de)serialization: that impl reads/writes
//! *nested* length-prefixed strings, not a single comma-separated string, which doesn't match
//! RFC 4251 SS 5's name-list format - safer to hand-roll something this foundational (getting
//! negotiation wrong breaks every real server) than trust an API whose behavior doesn't match
//! its own doc comment.

use std::string::String;
use std::vec::Vec;

use ssh_encoding::{Decode, Encode, Reader};

use crate::error::{Result, SshError};
use crate::rng::SecureRandom;

pub const MSG_KEXINIT: u8 = 20;
pub const MSG_NEWKEYS: u8 = 21;

/// In preference order (first = most preferred). RFC 8731 curve25519-sha256 first; RFC 8268
/// diffie-hellman-group14-sha256 as the broader-compatibility fallback for older servers.
pub const KEX_ALGORITHMS: &[&str] = &["curve25519-sha256", "diffie-hellman-group14-sha256"];

/// ssh-ed25519 first (fast, small, modern default); rsa-sha2-512/256 (RFC 8332) as fallback for
/// servers/hosts without an Ed25519 host key. Legacy `ssh-rsa` (SHA-1) is intentionally excluded.
pub const SERVER_HOST_KEY_ALGORITHMS: &[&str] = &["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"];

/// chacha20-poly1305@openssh.com first (no separate MAC key schedule, single-pass AEAD);
/// aes256-gcm@openssh.com as fallback. No CBC ciphers, no `none`.
pub const ENCRYPTION_ALGORITHMS: &[&str] = &["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"];

/// Never actually used for integrity when the negotiated cipher is AEAD (both of ours always
/// are) - included only so negotiation has something to agree on for servers that expect a
/// non-empty MAC list regardless of cipher choice.
pub const MAC_ALGORITHMS: &[&str] = &["hmac-sha2-256"];

pub const COMPRESSION_ALGORITHMS: &[&str] = &["none"];

#[derive(Debug, Clone)]
pub struct KexInit {
    pub cookie: [u8; 16],
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_client_to_server: Vec<String>,
    pub encryption_server_to_client: Vec<String>,
    pub mac_client_to_server: Vec<String>,
    pub mac_server_to_client: Vec<String>,
    pub compression_client_to_server: Vec<String>,
    pub compression_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
}

impl KexInit {
    /// Build our own KEXINIT, offering exactly the algorithms this client supports.
    pub fn ours(rng: &mut impl SecureRandom) -> Self {
        let mut cookie = [0u8; 16];
        rng.fill(&mut cookie);
        let names = |list: &[&str]| list.iter().map(|s| String::from(*s)).collect();
        Self {
            cookie,
            kex_algorithms: names(KEX_ALGORITHMS),
            server_host_key_algorithms: names(SERVER_HOST_KEY_ALGORITHMS),
            encryption_client_to_server: names(ENCRYPTION_ALGORITHMS),
            encryption_server_to_client: names(ENCRYPTION_ALGORITHMS),
            mac_client_to_server: names(MAC_ALGORITHMS),
            mac_server_to_client: names(MAC_ALGORITHMS),
            compression_client_to_server: names(COMPRESSION_ALGORITHMS),
            compression_server_to_client: names(COMPRESSION_ALGORITHMS),
            languages_client_to_server: Vec::new(),
            languages_server_to_client: Vec::new(),
            first_kex_packet_follows: false,
        }
    }

    /// Serialize to a full SSH packet payload, starting with the `SSH_MSG_KEXINIT` message-type
    /// byte. This exact byte sequence is what must be used as `I_C`/`I_S` in the exchange hash.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(MSG_KEXINIT);
        out.extend_from_slice(&self.cookie);
        write_name_list(&mut out, &self.kex_algorithms);
        write_name_list(&mut out, &self.server_host_key_algorithms);
        write_name_list(&mut out, &self.encryption_client_to_server);
        write_name_list(&mut out, &self.encryption_server_to_client);
        write_name_list(&mut out, &self.mac_client_to_server);
        write_name_list(&mut out, &self.mac_server_to_client);
        write_name_list(&mut out, &self.compression_client_to_server);
        write_name_list(&mut out, &self.compression_server_to_client);
        write_name_list(&mut out, &self.languages_client_to_server);
        write_name_list(&mut out, &self.languages_server_to_client);
        Encode::encode(&self.first_kex_packet_follows, &mut out).expect("Vec<u8> writer is infallible");
        out.extend_from_slice(&0u32.to_be_bytes()); // reserved
        out
    }

    /// Parse a full `SSH_MSG_KEXINIT` packet payload (including the leading message-type byte).
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut reader = payload;
        let msg_type = u8::decode(&mut reader)?;
        if msg_type != MSG_KEXINIT {
            return Err(SshError::UnexpectedMessage {
                expected_state: "KexInit",
                msg_type,
            });
        }
        let mut cookie = [0u8; 16];
        reader.read(&mut cookie)?;

        let kex_algorithms = read_name_list(&mut reader)?;
        let server_host_key_algorithms = read_name_list(&mut reader)?;
        let encryption_client_to_server = read_name_list(&mut reader)?;
        let encryption_server_to_client = read_name_list(&mut reader)?;
        let mac_client_to_server = read_name_list(&mut reader)?;
        let mac_server_to_client = read_name_list(&mut reader)?;
        let compression_client_to_server = read_name_list(&mut reader)?;
        let compression_server_to_client = read_name_list(&mut reader)?;
        let languages_client_to_server = read_name_list(&mut reader)?;
        let languages_server_to_client = read_name_list(&mut reader)?;
        let first_kex_packet_follows = bool::decode(&mut reader)?;
        // trailing reserved uint32 intentionally not read/validated - RFC says it's reserved for
        // future extension and must be ignored by implementations that don't understand it.

        Ok(Self {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_client_to_server,
            encryption_server_to_client,
            mac_client_to_server,
            mac_server_to_client,
            compression_client_to_server,
            compression_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
        })
    }
}

fn write_name_list(out: &mut Vec<u8>, names: &[String]) {
    let joined = names.join(",");
    Encode::encode(joined.as_str(), out).expect("Vec<u8> writer is infallible");
}

fn read_name_list(reader: &mut impl Reader) -> Result<Vec<String>> {
    let joined = String::decode(reader)?;
    if joined.is_empty() {
        return Ok(Vec::new());
    }
    Ok(joined.split(',').map(String::from).collect())
}

/// Result of negotiating one KEXINIT category: the client's most-preferred name that the server
/// also offered (RFC 4253 SS 7.1: "the first algorithm on the client's list that is also
/// supported by the server").
pub fn negotiate(client: &[String], server: &[String], category: &'static str) -> Result<String> {
    client
        .iter()
        .find(|c| server.iter().any(|s| s == *c))
        .cloned()
        .ok_or(SshError::Negotiation(category))
}

#[derive(Debug, Clone)]
pub struct NegotiatedAlgorithms {
    pub kex: String,
    pub server_host_key: String,
    pub encryption_client_to_server: String,
    pub encryption_server_to_client: String,
}

pub fn negotiate_all(ours: &KexInit, theirs: &KexInit) -> Result<NegotiatedAlgorithms> {
    Ok(NegotiatedAlgorithms {
        kex: negotiate(&ours.kex_algorithms, &theirs.kex_algorithms, "key exchange algorithm")?,
        server_host_key: negotiate(
            &ours.server_host_key_algorithms,
            &theirs.server_host_key_algorithms,
            "server host key algorithm",
        )?,
        encryption_client_to_server: negotiate(
            &ours.encryption_client_to_server,
            &theirs.encryption_client_to_server,
            "client-to-server cipher",
        )?,
        encryption_server_to_client: negotiate(
            &ours.encryption_server_to_client,
            &theirs.encryption_server_to_client,
            "server-to-client cipher",
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng;
    impl SecureRandom for FixedRng {
        fn fill(&mut self, buf: &mut [u8]) {
            buf.fill(0x7A);
        }
    }

    #[test]
    fn round_trips_through_wire_format() {
        let kex = KexInit::ours(&mut FixedRng);
        let payload = kex.to_payload();
        let parsed = KexInit::parse(&payload).unwrap();

        assert_eq!(parsed.cookie, kex.cookie);
        assert_eq!(parsed.kex_algorithms, kex.kex_algorithms);
        assert_eq!(parsed.server_host_key_algorithms, kex.server_host_key_algorithms);
        assert_eq!(parsed.encryption_client_to_server, kex.encryption_client_to_server);
        assert_eq!(parsed.languages_client_to_server, Vec::<String>::new());
        assert!(!parsed.first_kex_packet_follows);
    }

    #[test]
    fn negotiate_picks_clients_first_preference_present_on_server() {
        let client = std::vec![String::from("a"), String::from("b"), String::from("c")];
        let server = std::vec![String::from("c"), String::from("b")];
        assert_eq!(negotiate(&client, &server, "test").unwrap(), "b");
    }

    #[test]
    fn negotiate_fails_with_no_overlap() {
        let client = std::vec![String::from("a")];
        let server = std::vec![String::from("b")];
        assert!(negotiate(&client, &server, "test").is_err());
    }

    #[test]
    fn negotiate_all_picks_our_preferred_algorithms_when_server_supports_everything() {
        let mut rng = FixedRng;
        let ours = KexInit::ours(&mut rng);
        let theirs = KexInit::ours(&mut rng); // pretend the server offers the same full list
        let picked = negotiate_all(&ours, &theirs).unwrap();
        assert_eq!(picked.kex, "curve25519-sha256");
        assert_eq!(picked.server_host_key, "ssh-ed25519");
        assert_eq!(picked.encryption_client_to_server, "chacha20-poly1305@openssh.com");
    }

    #[test]
    fn negotiate_all_falls_back_when_server_only_supports_secondary_choices() {
        let mut rng = FixedRng;
        let ours = KexInit::ours(&mut rng);
        let mut theirs = KexInit::ours(&mut rng);
        theirs.kex_algorithms = std::vec![String::from("diffie-hellman-group14-sha256")];
        theirs.encryption_client_to_server = std::vec![String::from("aes256-gcm@openssh.com")];
        theirs.encryption_server_to_client = std::vec![String::from("aes256-gcm@openssh.com")];

        let picked = negotiate_all(&ours, &theirs).unwrap();
        assert_eq!(picked.kex, "diffie-hellman-group14-sha256");
        assert_eq!(picked.encryption_client_to_server, "aes256-gcm@openssh.com");
    }

    #[test]
    fn empty_name_list_round_trips() {
        let mut out = Vec::new();
        write_name_list(&mut out, &[]);
        let mut reader: &[u8] = &out;
        let parsed = read_name_list(&mut reader).unwrap();
        assert!(parsed.is_empty());
    }
}
