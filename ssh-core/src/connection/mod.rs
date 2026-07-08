//! RFC 4254 connection protocol: channel table and incoming-message dispatch. Outgoing requests
//! (open/exec/pty/shell/data/close) are built by [`channel`], [`exec`], and [`pty`]; this module
//! is where the results of those requests, and all channel-scoped traffic from the server, get
//! turned into [`crate::event::Event`]s for the host.

pub mod channel;
pub mod exec;
pub mod pty;

use std::collections::HashMap;
use std::vec::Vec;

pub use channel::{Channel, ChannelKind, ChannelLifecycle};

use crate::error::{Result, SshError};
use crate::event::{DataStream, Event};
use crate::wire::Reader;

pub struct ChannelTable {
    channels: HashMap<u32, Channel>,
    next_id: u32,
}

impl ChannelTable {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            next_id: 0,
        }
    }

    /// Allocate a new local channel id and build its `SSH_MSG_CHANNEL_OPEN`. The id is returned
    /// immediately so the caller can correlate it with whatever request (exec/shell) prompted the
    /// open, even though we won't know the *server's* id for it until the confirmation arrives.
    pub fn open(&mut self, kind: ChannelKind) -> (u32, Vec<u8>) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let channel = Channel::new(id, kind);
        let msg = channel.build_open_message();
        self.channels.insert(id, channel);
        (id, msg)
    }

    pub fn get(&self, id: u32) -> Option<&Channel> {
        self.channels.get(&id)
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Channel> {
        self.channels.get_mut(&id)
    }

    pub fn remove(&mut self, id: u32) {
        self.channels.remove(&id);
    }

    pub fn len(&self) -> usize {
        self.channels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Dispatch one connection-protocol message (already identified by `msg_type`, e.g. by
    /// `session.rs`'s top-level message-type switch). Returns host-facing events plus any wire
    /// messages ssh-core needs to send itself in reaction (window-adjust replenishment,
    /// `CHANNEL_FAILURE` for an unrecognized incoming request).
    pub fn handle_message(&mut self, msg_type: u8, payload: &[u8]) -> Result<(Vec<Event>, Vec<Vec<u8>>)> {
        let mut r = Reader::new(payload);
        r.read_u8()?; // msg_type already known to the caller; just advance past it

        match msg_type {
            channel::MSG_CHANNEL_OPEN_CONFIRMATION => {
                let recipient_channel = r.read_u32()?;
                let sender_channel = r.read_u32()?;
                let initial_window = r.read_u32()?;
                let max_packet = r.read_u32()?;
                let ch = self.channel_mut(recipient_channel)?;
                ch.on_open_confirmation(sender_channel, initial_window, max_packet);
                Ok((std::vec![Event::ChannelOpened { id: recipient_channel }], Vec::new()))
            }

            channel::MSG_CHANNEL_OPEN_FAILURE => {
                let recipient_channel = r.read_u32()?;
                let reason_code = r.read_u32()?;
                let description = r.read_utf8_string().unwrap_or_default();
                self.remove(recipient_channel);
                Ok((
                    std::vec![Event::ChannelOpenFailed {
                        id: recipient_channel,
                        reason_code,
                        description,
                    }],
                    Vec::new(),
                ))
            }

            channel::MSG_CHANNEL_WINDOW_ADJUST => {
                let recipient_channel = r.read_u32()?;
                let bytes_to_add = r.read_u32()?;
                self.channel_mut(recipient_channel)?.on_window_adjust(bytes_to_add);
                Ok((Vec::new(), Vec::new()))
            }

            channel::MSG_CHANNEL_DATA => {
                let recipient_channel = r.read_u32()?;
                let data = r.read_string()?.to_vec();
                let len = data.len() as u32;
                let ch = self.channel_mut(recipient_channel)?;
                let mut outgoing = Vec::new();
                if let Some(adjust) = ch.on_data_consumed(len) {
                    outgoing.push(adjust);
                }
                Ok((
                    std::vec![Event::ChannelData {
                        id: recipient_channel,
                        stream: DataStream::Stdout,
                        data,
                    }],
                    outgoing,
                ))
            }

            channel::MSG_CHANNEL_EXTENDED_DATA => {
                let recipient_channel = r.read_u32()?;
                let data_type = r.read_u32()?;
                let data = r.read_string()?.to_vec();
                let len = data.len() as u32;
                let ch = self.channel_mut(recipient_channel)?;
                let mut outgoing = Vec::new();
                if let Some(adjust) = ch.on_data_consumed(len) {
                    outgoing.push(adjust);
                }
                let stream = if data_type == channel::SSH_EXTENDED_DATA_STDERR {
                    DataStream::Stderr
                } else {
                    DataStream::Stdout
                };
                Ok((
                    std::vec![Event::ChannelData {
                        id: recipient_channel,
                        stream,
                        data,
                    }],
                    outgoing,
                ))
            }

            channel::MSG_CHANNEL_EOF => {
                let recipient_channel = r.read_u32()?;
                self.channel_mut(recipient_channel)?.lifecycle = ChannelLifecycle::EofSent;
                Ok((std::vec![Event::ChannelEof { id: recipient_channel }], Vec::new()))
            }

            channel::MSG_CHANNEL_CLOSE => {
                let recipient_channel = r.read_u32()?;
                self.remove(recipient_channel);
                Ok((std::vec![Event::ChannelClosed { id: recipient_channel }], Vec::new()))
            }

            channel::MSG_CHANNEL_REQUEST => self.handle_channel_request(&mut r),

            channel::MSG_CHANNEL_SUCCESS | channel::MSG_CHANNEL_FAILURE => {
                // Replies to our own pty-req/shell/exec requests. session.rs correlates these by
                // tracking which channel has an outstanding request; nothing for the channel
                // table itself to update.
                let recipient_channel = r.read_u32()?;
                let _ = self.channel_mut(recipient_channel)?; // validate the channel id is known
                Ok((Vec::new(), Vec::new()))
            }

            other => Err(SshError::UnexpectedMessage {
                expected_state: "Connection",
                msg_type: other,
            }),
        }
    }

    fn handle_channel_request(&mut self, r: &mut Reader) -> Result<(Vec<Event>, Vec<Vec<u8>>)> {
        let recipient_channel = r.read_u32()?;
        let request_type = r.read_utf8_string()?;
        let want_reply = r.read_bool()?;
        self.channel_mut(recipient_channel)?; // validate

        match request_type.as_str() {
            "exit-status" => {
                let code = r.read_u32()?;
                Ok((
                    std::vec![Event::ChannelExitStatus {
                        id: recipient_channel,
                        code: Some(code),
                        signal: None,
                    }],
                    Vec::new(),
                ))
            }
            "exit-signal" => {
                let signal_name = r.read_utf8_string()?;
                Ok((
                    std::vec![Event::ChannelExitStatus {
                        id: recipient_channel,
                        code: None,
                        signal: Some(signal_name),
                    }],
                    Vec::new(),
                ))
            }
            _ => {
                // Unknown/unsupported server-initiated request (we don't accept any - no reverse
                // forwarding, no agent forwarding). Politely decline if a reply was requested,
                // per RFC 4254 SS 5.4, rather than silently ignoring it.
                let mut outgoing = Vec::new();
                if want_reply {
                    let remote_id = self
                        .channel(recipient_channel)?
                        .remote_id
                        .expect("channel receiving requests must already be open");
                    let mut msg = Vec::new();
                    msg.push(channel::MSG_CHANNEL_FAILURE);
                    crate::wire::write_u32(&mut msg, remote_id);
                    outgoing.push(msg);
                }
                Ok((Vec::new(), outgoing))
            }
        }
    }

    fn channel(&self, id: u32) -> Result<&Channel> {
        self.channels
            .get(&id)
            .ok_or_else(|| SshError::Channel(std::format!("unknown channel id {id}")))
    }

    fn channel_mut(&mut self, id: u32) -> Result<&mut Channel> {
        self.channels
            .get_mut(&id)
            .ok_or_else(|| SshError::Channel(std::format!("unknown channel id {id}")))
    }
}

impl Default for ChannelTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{write_string, write_u32};

    fn confirm(table: &mut ChannelTable, local_id: u32, remote_id: u32) {
        let mut msg = std::vec![channel::MSG_CHANNEL_OPEN_CONFIRMATION];
        write_u32(&mut msg, local_id);
        write_u32(&mut msg, remote_id);
        write_u32(&mut msg, channel::INITIAL_WINDOW_SIZE);
        write_u32(&mut msg, channel::MAX_PACKET_SIZE);
        table.handle_message(channel::MSG_CHANNEL_OPEN_CONFIRMATION, &msg).unwrap();
    }

    #[test]
    fn open_then_confirm_transitions_to_open() {
        let mut table = ChannelTable::new();
        let (id, _open_msg) = table.open(ChannelKind::Exec);
        assert_eq!(table.get(id).unwrap().lifecycle, ChannelLifecycle::OpenRequested);

        confirm(&mut table, id, 42);
        let ch = table.get(id).unwrap();
        assert_eq!(ch.lifecycle, ChannelLifecycle::Open);
        assert_eq!(ch.remote_id, Some(42));
    }

    #[test]
    fn open_failure_removes_the_channel_and_emits_event() {
        let mut table = ChannelTable::new();
        let (id, _) = table.open(ChannelKind::Exec);

        let mut msg = std::vec![channel::MSG_CHANNEL_OPEN_FAILURE];
        write_u32(&mut msg, id);
        write_u32(&mut msg, 2);
        write_string(&mut msg, b"administratively prohibited");
        write_string(&mut msg, b"");

        let (events, _) = table.handle_message(channel::MSG_CHANNEL_OPEN_FAILURE, &msg).unwrap();
        assert!(matches!(events[0], Event::ChannelOpenFailed { id: eid, reason_code: 2, .. } if eid == id));
        assert!(table.get(id).is_none());
    }

    #[test]
    fn data_message_emits_event_and_may_trigger_window_adjust() {
        let mut table = ChannelTable::new();
        let (id, _) = table.open(ChannelKind::Shell);
        confirm(&mut table, id, 1);

        let mut msg = std::vec![channel::MSG_CHANNEL_DATA];
        write_u32(&mut msg, id);
        write_string(&mut msg, b"hello");
        let (events, outgoing) = table.handle_message(channel::MSG_CHANNEL_DATA, &msg).unwrap();

        assert!(matches!(&events[0], Event::ChannelData { id: eid, stream: DataStream::Stdout, data } if *eid == id && data == b"hello"));
        assert!(outgoing.is_empty(), "5 bytes is nowhere near the window-adjust threshold");
    }

    #[test]
    fn extended_data_is_reported_as_stderr() {
        let mut table = ChannelTable::new();
        let (id, _) = table.open(ChannelKind::Exec);
        confirm(&mut table, id, 1);

        let mut msg = std::vec![channel::MSG_CHANNEL_EXTENDED_DATA];
        write_u32(&mut msg, id);
        write_u32(&mut msg, channel::SSH_EXTENDED_DATA_STDERR);
        write_string(&mut msg, b"oh no");
        let (events, _) = table.handle_message(channel::MSG_CHANNEL_EXTENDED_DATA, &msg).unwrap();

        assert!(matches!(&events[0], Event::ChannelData { stream: DataStream::Stderr, data, .. } if data == b"oh no"));
    }

    #[test]
    fn exit_status_request_is_translated_to_event() {
        let mut table = ChannelTable::new();
        let (id, _) = table.open(ChannelKind::Exec);
        confirm(&mut table, id, 1);

        let mut msg = std::vec![channel::MSG_CHANNEL_REQUEST];
        write_u32(&mut msg, id);
        write_string(&mut msg, b"exit-status");
        crate::wire::write_bool(&mut msg, false);
        write_u32(&mut msg, 0);
        let (events, _) = table.handle_message(channel::MSG_CHANNEL_REQUEST, &msg).unwrap();

        assert!(matches!(events[0], Event::ChannelExitStatus { code: Some(0), signal: None, .. }));
    }

    #[test]
    fn unknown_channel_id_is_an_error_not_a_panic() {
        let mut table = ChannelTable::new();
        let mut msg = std::vec![channel::MSG_CHANNEL_EOF];
        write_u32(&mut msg, 999);
        assert!(table.handle_message(channel::MSG_CHANNEL_EOF, &msg).is_err());
    }

    #[test]
    fn close_message_removes_channel() {
        let mut table = ChannelTable::new();
        let (id, _) = table.open(ChannelKind::Shell);
        confirm(&mut table, id, 1);

        let mut msg = std::vec![channel::MSG_CHANNEL_CLOSE];
        write_u32(&mut msg, id);
        let (events, _) = table.handle_message(channel::MSG_CHANNEL_CLOSE, &msg).unwrap();
        assert!(matches!(events[0], Event::ChannelClosed { id: eid } if eid == id));
        assert!(table.get(id).is_none());
    }
}
