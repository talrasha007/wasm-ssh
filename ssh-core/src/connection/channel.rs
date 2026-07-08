//! Per-channel wire messages (RFC 4254) and RFC 4254 SS 5.2 flow-control bookkeeping.
//!
//! Terminology per RFC 4254: every message "about a channel" carries the channel id as known to
//! whoever is *receiving* that particular message. So outgoing messages we build address the
//! channel by `remote_id` (the server's id for it), while the `recipient_channel` field on
//! incoming messages is *our* id for the channel (what this module calls `local_id`) - callers
//! look channels up by that field's value.

use std::vec::Vec;

use crate::wire::{write_bool, write_string, write_u32};

pub const MSG_CHANNEL_OPEN: u8 = 90;
pub const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const MSG_CHANNEL_DATA: u8 = 94;
pub const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const MSG_CHANNEL_EOF: u8 = 96;
pub const MSG_CHANNEL_CLOSE: u8 = 97;
pub const MSG_CHANNEL_REQUEST: u8 = 98;
pub const MSG_CHANNEL_SUCCESS: u8 = 99;
pub const MSG_CHANNEL_FAILURE: u8 = 100;

pub const SSH_EXTENDED_DATA_STDERR: u32 = 1;

pub const INITIAL_WINDOW_SIZE: u32 = 2 * 1024 * 1024;
pub const MAX_PACKET_SIZE: u32 = 32 * 1024;
/// Replenish the local window once consumed-but-not-yet-advertised bytes cross this much, rather
/// than sending a `WINDOW_ADJUST` for every single byte consumed.
const WINDOW_ADJUST_THRESHOLD: u32 = INITIAL_WINDOW_SIZE / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    Exec,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLifecycle {
    OpenRequested,
    Open,
    EofSent,
    CloseSent,
    Closed,
}

pub struct Channel {
    pub local_id: u32,
    pub remote_id: Option<u32>,
    pub kind: ChannelKind,
    pub lifecycle: ChannelLifecycle,
    pub local_window: u32,
    local_window_unadvertised: u32,
    pub remote_window: u32,
    pub remote_max_packet: u32,
}

impl Channel {
    pub fn new(local_id: u32, kind: ChannelKind) -> Self {
        Self {
            local_id,
            remote_id: None,
            kind,
            lifecycle: ChannelLifecycle::OpenRequested,
            local_window: INITIAL_WINDOW_SIZE,
            local_window_unadvertised: 0,
            remote_window: 0,
            remote_max_packet: 0,
        }
    }

    /// `SSH_MSG_CHANNEL_OPEN "session"`.
    pub fn build_open_message(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(MSG_CHANNEL_OPEN);
        write_string(&mut out, b"session");
        write_u32(&mut out, self.local_id);
        write_u32(&mut out, INITIAL_WINDOW_SIZE);
        write_u32(&mut out, MAX_PACKET_SIZE);
        out
    }

    pub fn on_open_confirmation(&mut self, sender_channel: u32, initial_window: u32, max_packet: u32) {
        self.remote_id = Some(sender_channel);
        self.lifecycle = ChannelLifecycle::Open;
        self.remote_window = initial_window;
        self.remote_max_packet = max_packet.max(1);
    }

    fn remote_id_or_panic(&self) -> u32 {
        self.remote_id.expect("channel must be open (have a remote id) before sending on it")
    }

    /// Chunk and frame as much of `data` as the current remote window/max-packet-size allow.
    /// Returns how many bytes were consumed (possibly fewer than `data.len()` - the caller is
    /// expected to retry the remainder later, once a `WINDOW_ADJUST` arrives) plus the wire
    /// messages to send. Never buffers unsent bytes itself, by design: unbounded internal
    /// buffering here would just move the memory-growth problem from "the caller's queue" to
    /// "inside the wasm heap", where it's harder for the JS host to apply real backpressure
    /// against the underlying socket.
    pub fn build_data_messages(&mut self, data: &[u8]) -> (usize, Vec<Vec<u8>>) {
        let mut consumed = 0;
        let mut messages = Vec::new();
        while consumed < data.len() && self.remote_window > 0 {
            let chunk_len = (data.len() - consumed)
                .min(self.remote_max_packet as usize)
                .min(self.remote_window as usize);
            if chunk_len == 0 {
                break;
            }
            let chunk = &data[consumed..consumed + chunk_len];
            let mut msg = Vec::new();
            msg.push(MSG_CHANNEL_DATA);
            write_u32(&mut msg, self.remote_id_or_panic());
            write_string(&mut msg, chunk);
            messages.push(msg);
            self.remote_window -= chunk_len as u32;
            consumed += chunk_len;
        }
        (consumed, messages)
    }

    /// Call once received channel data (of length `len`) has been delivered to the consumer, to
    /// (maybe) emit a `WINDOW_ADJUST` replenishing our advertised local window. Returns `None`
    /// most of the time - only crosses the threshold occasionally.
    pub fn on_data_consumed(&mut self, len: u32) -> Option<Vec<u8>> {
        self.local_window = self.local_window.saturating_sub(len);
        self.local_window_unadvertised = self.local_window_unadvertised.saturating_add(len);
        if self.local_window_unadvertised < WINDOW_ADJUST_THRESHOLD {
            return None;
        }
        let add = self.local_window_unadvertised;
        self.local_window_unadvertised = 0;
        self.local_window = self.local_window.saturating_add(add);

        let mut msg = Vec::new();
        msg.push(MSG_CHANNEL_WINDOW_ADJUST);
        write_u32(&mut msg, self.remote_id_or_panic());
        write_u32(&mut msg, add);
        Some(msg)
    }

    pub fn on_window_adjust(&mut self, bytes_to_add: u32) {
        self.remote_window = self.remote_window.saturating_add(bytes_to_add);
    }

    pub fn build_eof_message(&self) -> Vec<u8> {
        channel_id_only_message(MSG_CHANNEL_EOF, self.remote_id_or_panic())
    }

    pub fn build_close_message(&self) -> Vec<u8> {
        channel_id_only_message(MSG_CHANNEL_CLOSE, self.remote_id_or_panic())
    }
}

fn channel_id_only_message(msg_type: u8, channel_id: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg_type);
    write_u32(&mut out, channel_id);
    out
}

pub fn build_channel_request(remote_id: u32, request_type: &str, want_reply: bool, type_specific: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(MSG_CHANNEL_REQUEST);
    write_u32(&mut out, remote_id);
    write_string(&mut out, request_type.as_bytes());
    write_bool(&mut out, want_reply);
    out.extend_from_slice(type_specific);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_messages_respect_remote_window_and_max_packet() {
        let mut ch = Channel::new(0, ChannelKind::Shell);
        ch.on_open_confirmation(7, 10, 4); // tiny window/max-packet to force multiple chunks

        let (consumed, messages) = ch.build_data_messages(b"0123456789ABCDEF");
        // window=10 caps total bytes sent this call regardless of how many more we have.
        assert_eq!(consumed, 10);
        // max_packet=4 caps each individual message's payload.
        assert_eq!(messages.len(), 3); // 4 + 4 + 2 = 10
        assert_eq!(ch.remote_window, 0);

        let (consumed2, messages2) = ch.build_data_messages(b"XYZ");
        assert_eq!(consumed2, 0);
        assert!(messages2.is_empty());

        ch.on_window_adjust(100);
        let (consumed3, _) = ch.build_data_messages(b"XYZ");
        assert_eq!(consumed3, 3);
    }

    #[test]
    fn window_adjust_only_emitted_past_threshold() {
        let mut ch = Channel::new(0, ChannelKind::Shell);
        ch.on_open_confirmation(7, INITIAL_WINDOW_SIZE, MAX_PACKET_SIZE);

        assert!(ch.on_data_consumed(100).is_none());
        assert!(ch.on_data_consumed(WINDOW_ADJUST_THRESHOLD).is_some());
    }

    #[test]
    fn open_message_has_expected_shape() {
        use crate::wire::Reader;
        let ch = Channel::new(3, ChannelKind::Exec);
        let msg = ch.build_open_message();
        let mut r = Reader::new(&msg);
        assert_eq!(r.read_u8().unwrap(), MSG_CHANNEL_OPEN);
        assert_eq!(r.read_string().unwrap(), b"session");
        assert_eq!(r.read_u32().unwrap(), 3);
        assert_eq!(r.read_u32().unwrap(), INITIAL_WINDOW_SIZE);
        assert_eq!(r.read_u32().unwrap(), MAX_PACKET_SIZE);
    }
}
