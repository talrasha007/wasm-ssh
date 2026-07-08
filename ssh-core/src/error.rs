//! Error types for the SSH protocol engine.
//!
//! A hard split is drawn between fatal protocol errors ([`SshError`], returned as `Err`) and
//! normal negative protocol outcomes (e.g. a wrong password, a rejected host key) which are
//! surfaced as [`crate::event::Event`] values instead, since they aren't exceptional from the
//! caller's point of view and the connection can often continue (e.g. retry auth).

use std::fmt;
use std::string::String;

/// Standard SSH disconnect reason codes (RFC 4253 SS 11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisconnectReason {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 14,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 15,
    IllegalUserName = 16,
}

/// Fatal protocol errors. Receiving one of these always moves the [`crate::session::Session`]
/// to its terminal `Closed` state.
#[derive(Debug)]
#[non_exhaustive]
pub enum SshError {
    /// Malformed packet: bad length, truncated field, invalid message layout.
    Framing(String),
    /// AEAD/MAC verification failed. Per RFC 4253 SS 6.3 this is immediately fatal.
    Mac,
    /// No common algorithm across client/server KEXINIT lists.
    Negotiation(&'static str),
    /// Host key signature over the exchange hash did not verify.
    HostKeySignatureInvalid,
    /// The caller (JS host) explicitly rejected the host key via
    /// `provide_host_key_decision(false)`.
    HostKeyRejected,
    /// All configured authentication methods were exhausted without success.
    AuthExhausted,
    /// A message was received that is not valid in the engine's current state.
    UnexpectedMessage {
        expected_state: &'static str,
        msg_type: u8,
    },
    /// Channel-level protocol violation (unknown channel id, window exceeded, malformed request).
    Channel(String),
    /// The peer sent SSH_MSG_DISCONNECT.
    PeerDisconnected {
        reason: u32,
        description: String,
    },
    /// The underlying transport (JS socket) closed without a clean SSH disconnect.
    TransportClosed,
    /// Encoding/decoding failure surfaced from the `ssh-encoding` crate.
    Encoding(ssh_encoding::Error),
    /// Key parsing/signature failure surfaced from the `ssh-key` crate.
    Key(ssh_key::Error),
    /// Producing a client auth signature failed (malformed/unsupported key material).
    SigningFailed,
    /// All configured auth methods were tried and the server rejected every one
    /// (a normal, non-exhausted-by-us `SSH_MSG_USERAUTH_FAILURE` is `Event::AuthFailure`, not
    /// this - this variant is for method/key material we can't even attempt).
    UnsupportedAuthMethod(&'static str),
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(msg) => write!(f, "framing error: {msg}"),
            Self::Mac => write!(f, "MAC/AEAD verification failed"),
            Self::Negotiation(what) => write!(f, "algorithm negotiation failed: no common {what}"),
            Self::HostKeySignatureInvalid => write!(f, "host key signature verification failed"),
            Self::HostKeyRejected => write!(f, "host key rejected by caller"),
            Self::AuthExhausted => write!(f, "all authentication methods exhausted"),
            Self::UnexpectedMessage {
                expected_state,
                msg_type,
            } => write!(
                f,
                "unexpected message type {msg_type} in state {expected_state}"
            ),
            Self::Channel(msg) => write!(f, "channel error: {msg}"),
            Self::PeerDisconnected { reason, description } => {
                write!(f, "peer disconnected (reason {reason}): {description}")
            }
            Self::TransportClosed => write!(f, "transport closed unexpectedly"),
            Self::Encoding(e) => write!(f, "encoding error: {e}"),
            Self::Key(e) => write!(f, "key error: {e}"),
            Self::SigningFailed => write!(f, "failed to produce client auth signature"),
            Self::UnsupportedAuthMethod(what) => write!(f, "unsupported auth method or key type: {what}"),
        }
    }
}

impl From<ssh_encoding::Error> for SshError {
    fn from(e: ssh_encoding::Error) -> Self {
        Self::Encoding(e)
    }
}

impl From<ssh_key::Error> for SshError {
    fn from(e: ssh_key::Error) -> Self {
        Self::Key(e)
    }
}

pub type Result<T> = core::result::Result<T, SshError>;
