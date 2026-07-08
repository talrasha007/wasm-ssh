//! Thin wasm-bindgen shell around `ssh_core::session::Session`. Owns the `getrandom`/`wasm_js`
//! RNG backend and translates the Rust-native `Event` enum into small JSON envelopes (bulk byte
//! payloads - host key blobs, channel data - are handed over separately via
//! [`WasmSshSession::take_event_data`] rather than embedded in the JSON, to avoid encoding
//! arbitrary-length binary data as a JSON number array).

use ssh_core::connection::pty::PtyOptions;
use ssh_core::event::{DataStream, Event};
use ssh_core::rng::SecureRandom;
use ssh_core::session::Session;
use ssh_key::private::PrivateKey;
use wasm_bindgen::prelude::*;

struct WasmRng;

impl SecureRandom for WasmRng {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom() failed - is the wasm_js backend wired up?");
    }
}

#[wasm_bindgen]
pub struct WasmSshSession {
    inner: Session<WasmRng>,
    last_event_data: Vec<u8>,
}

#[wasm_bindgen]
impl WasmSshSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmSshSession {
        WasmSshSession {
            inner: Session::new(WasmRng),
            last_event_data: Vec::new(),
        }
    }

    /// Bytes read from the transport (e.g. a Cloudflare `Socket`'s `readable`).
    pub fn feed_incoming(&mut self, bytes: &[u8]) {
        self.inner.feed_incoming(bytes);
    }

    /// Bytes to write to the transport, draining the engine's internal outgoing buffer.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.inner.take_outgoing(&mut out);
        out
    }

    /// One JSON-encoded event, or `undefined` if none are queued. Events carrying bulk bytes
    /// (`HostKeyVerify.rawBlob`, `ChannelData`) stash them for [`Self::take_event_data`] instead
    /// of inlining them - call it immediately after `poll_event` if the JSON says data is
    /// present, before polling again (the buffer holds only the most recent event's payload).
    pub fn poll_event(&mut self) -> Option<String> {
        let event = self.inner.poll_event()?;
        Some(self.encode_event(event))
    }

    /// Drains the byte payload stashed by the most recent [`Self::poll_event`] call, if any.
    pub fn take_event_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.last_event_data)
    }

    pub fn provide_host_key_decision(&mut self, accept: bool) {
        self.inner.provide_host_key_decision(accept);
    }

    pub fn authenticate_password(&mut self, username: &str, password: &str) {
        self.inner.authenticate_password(username, password);
    }

    /// `private_key_openssh` is an OpenSSH-formatted private key (`-----BEGIN OPENSSH PRIVATE
    /// KEY-----...`), optionally passphrase-encrypted.
    pub fn authenticate_publickey(
        &mut self,
        username: &str,
        private_key_openssh: &str,
        passphrase: Option<String>,
    ) -> Result<(), JsValue> {
        let mut key = PrivateKey::from_openssh(private_key_openssh).map_err(to_js_error)?;
        if key.is_encrypted() {
            let passphrase = passphrase
                .ok_or_else(|| JsValue::from_str("private key is encrypted but no passphrase was provided"))?;
            key = key.decrypt(passphrase.as_bytes()).map_err(to_js_error)?;
        }
        self.inner.authenticate_publickey(username, key).map_err(to_js_error)
    }

    pub fn open_exec(&mut self, command: &str) -> u32 {
        self.inner.open_exec(command)
    }

    pub fn open_shell(&mut self, term: &str, cols: u32, rows: u32) -> u32 {
        self.inner.open_shell(PtyOptions {
            term: term.to_string(),
            cols,
            rows,
            pixel_width: 0,
            pixel_height: 0,
        })
    }

    /// Returns how many bytes of `data` were actually accepted (see
    /// `ssh_core::session::Session::channel_send` - less than `data.len()` means the channel's
    /// flow-control window is full; retry the remainder after a `ChannelWindowFull`-following
    /// event, once more window has opened up).
    pub fn channel_send(&mut self, id: u32, data: &[u8]) -> usize {
        self.inner.channel_send(id, data)
    }

    pub fn resize_pty(&mut self, id: u32, cols: u32, rows: u32) {
        self.inner.resize_pty(id, cols, rows);
    }

    pub fn close_channel(&mut self, id: u32) {
        self.inner.close_channel(id);
    }

    pub fn notify_transport_closed(&mut self) {
        self.inner.notify_transport_closed();
    }
}

impl Default for WasmSshSession {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmSshSession {
    fn encode_event(&mut self, event: Event) -> String {
        match event {
            Event::HostKeyVerify {
                algorithm,
                fingerprint_sha256,
                raw_blob,
            } => {
                self.last_event_data = raw_blob;
                std::format!(
                    r#"{{"type":"HostKeyVerify","algorithm":{},"fingerprintSha256":{},"dataAvailable":true}}"#,
                    json_str(&algorithm),
                    json_str(&fingerprint_sha256)
                )
            }
            Event::ReadyForAuth => r#"{"type":"ReadyForAuth"}"#.to_string(),
            Event::AuthFailure { remaining_methods } => {
                let methods = remaining_methods.iter().map(|m| json_str(m)).collect::<Vec<_>>().join(",");
                std::format!(r#"{{"type":"AuthFailure","remainingMethods":[{methods}]}}"#)
            }
            Event::AuthSuccess => r#"{"type":"AuthSuccess"}"#.to_string(),
            Event::ChannelOpened { id } => std::format!(r#"{{"type":"ChannelOpened","id":{id}}}"#),
            Event::ChannelOpenFailed {
                id,
                reason_code,
                description,
            } => std::format!(
                r#"{{"type":"ChannelOpenFailed","id":{id},"reasonCode":{reason_code},"description":{}}}"#,
                json_str(&description)
            ),
            Event::ChannelData { id, stream, data } => {
                self.last_event_data = data;
                let stream_str = match stream {
                    DataStream::Stdout => "stdout",
                    DataStream::Stderr => "stderr",
                };
                std::format!(r#"{{"type":"ChannelData","id":{id},"stream":"{stream_str}","dataAvailable":true}}"#)
            }
            Event::ChannelWindowFull { id } => std::format!(r#"{{"type":"ChannelWindowFull","id":{id}}}"#),
            Event::ChannelExitStatus { id, code, signal } => {
                let code_json = code.map(|c| c.to_string()).unwrap_or_else(|| "null".into());
                let signal_json = signal.map(|s| json_str(&s)).unwrap_or_else(|| "null".into());
                std::format!(r#"{{"type":"ChannelExitStatus","id":{id},"code":{code_json},"signal":{signal_json}}}"#)
            }
            Event::ChannelEof { id } => std::format!(r#"{{"type":"ChannelEof","id":{id}}}"#),
            Event::ChannelClosed { id } => std::format!(r#"{{"type":"ChannelClosed","id":{id}}}"#),
            Event::Disconnected { reason_code, description } => std::format!(
                r#"{{"type":"Disconnected","reasonCode":{reason_code},"description":{}}}"#,
                json_str(&description)
            ),
            Event::Unrecoverable(err) => {
                std::format!(r#"{{"type":"Unrecoverable","message":{}}}"#, json_str(&err.to_string()))
            }
            // `Event` is `#[non_exhaustive]` so new variants can be added without a semver break;
            // surface anything we don't yet know how to encode rather than silently dropping it.
            other => std::format!(r#"{{"type":"Unknown","debug":{}}}"#, json_str(&std::format!("{other:?}"))),
        }
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&std::format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn to_js_error<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}
