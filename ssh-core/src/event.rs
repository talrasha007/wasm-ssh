//! Events the [`crate::session::Session`] emits for the host (JS wrapper) to react to.
//!
//! These are drained one at a time via `Session::poll_event`. Some are terminal for a channel
//! or for the whole session; most are informational and don't require an immediate response.

use std::string::String;
use std::vec::Vec;

use crate::error::SshError;

/// Which stream a chunk of channel data belongs to (RFC 4254 SS 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// The host key's signature over the exchange hash has been verified; the session now
    /// pauses in `AwaitingHostKeyDecision` until the host calls
    /// `Session::provide_host_key_decision`. No further protocol progress (including
    /// `SSH_MSG_NEWKEYS`) happens until then.
    HostKeyVerify {
        algorithm: String,
        fingerprint_sha256: String,
        raw_blob: Vec<u8>,
    },

    /// The transport/service handshake is complete and the session is now ready for
    /// `authenticate_password`/`authenticate_publickey` to be called. Calling either before this
    /// fires is silently ignored (there's nothing to send it to yet).
    ReadyForAuth,

    /// `SSH_MSG_USERAUTH_FAILURE`: a normal, retryable outcome, not an error.
    AuthFailure { remaining_methods: Vec<String> },

    /// `SSH_MSG_USERAUTH_SUCCESS`.
    AuthSuccess,

    /// The server confirmed opening a channel this session requested.
    ChannelOpened { id: u32 },

    /// The server rejected opening a channel this session requested.
    ChannelOpenFailed {
        id: u32,
        reason_code: u32,
        description: String,
    },

    /// Data arrived on an open channel.
    ChannelData {
        id: u32,
        stream: DataStream,
        data: Vec<u8>,
    },

    /// The remote window closed; the host should stop calling `channel_send` for this channel
    /// until data has been consumed and window has re-opened (this event does not repeat -
    /// there's no corresponding "window open" event; the host learns the window re-opened only
    /// by `channel_send` succeeding again on a later call).
    ChannelWindowFull { id: u32 },

    /// The remote command/shell exited (RFC 4254 SS 6.10). `signal` is set instead of `code`
    /// when the process was killed by a signal.
    ChannelExitStatus {
        id: u32,
        code: Option<u32>,
        signal: Option<String>,
    },

    /// `SSH_MSG_CHANNEL_EOF`: the remote side will send no more data on this channel.
    ChannelEof { id: u32 },

    /// The channel is fully closed (both directions); the host may drop all state for it.
    ChannelClosed { id: u32 },

    /// The peer sent `SSH_MSG_DISCONNECT`, or the engine decided to send one locally.
    Disconnected { reason_code: u32, description: String },

    /// A fatal error occurred; the session has moved to `Closed` and will not process further
    /// input or produce further output.
    Unrecoverable(SshError),
}
