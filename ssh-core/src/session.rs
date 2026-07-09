//! Top-level sans-io session state machine: the public surface the wasm-bindgen crate (and,
//! for testing, plain Rust) drives. See the crate-level docs / project plan for the full phase
//! diagram; in short:
//!
//! `VersionExchange -> KexInit -> KexInProgress -> AwaitingHostKeyDecision -> (NewKeys) ->
//! ServiceRequest -> UserAuth -> Connected -> Closed`

use std::collections::{HashMap, VecDeque};
use std::string::String;
use std::vec::Vec;

use ssh_key::PrivateKey;

use crate::auth;
use crate::connection::pty::PtyOptions;
use crate::connection::{self, ChannelKind, ChannelTable};
use crate::error::{Result, SshError};
use crate::event::Event;
use crate::ident::{self, IdentExchange};
use crate::rng::SecureRandom;
use crate::transport::hostkey::HostKey;
use crate::transport::kdf;
use crate::transport::kexinit::{self, KexInit, NegotiatedAlgorithms};
use crate::transport::packet::{self, CipherAlgorithm, PacketCipher};
use crate::transport::{kex_curve25519, kex_dh_group14};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    VersionExchange,
    KexInProgress,
    AwaitingHostKeyDecision,
    ServiceRequest,
    UserAuth,
    Connected,
    Closed,
}

enum ActiveKex {
    Curve25519(kex_curve25519::EphemeralKeypair),
    DhGroup14(kex_dh_group14::ClientKeyExchange),
}

struct DerivedCiphers {
    cs: PacketCipher,
    sc: PacketCipher,
}

enum PendingAuth {
    Password,
    PublicKeyQuery { auth: auth::publickey::PublicKeyAuth, private_key: PrivateKey },
    PublicKeySigned,
}

enum ChannelSetupStep {
    AwaitingExecReply,
    AwaitingPtyReply,
    AwaitingShellReply,
}

pub struct Session<R: SecureRandom> {
    phase: Phase,
    rng: R,

    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    events: VecDeque<Event>,

    ident: IdentExchange,
    own_ident_line: Vec<u8>,
    peer_ident_line: Vec<u8>,

    own_kexinit_payload: Vec<u8>,
    peer_kexinit_payload: Vec<u8>,
    negotiated: Option<NegotiatedAlgorithms>,
    active_kex: Option<ActiveKex>,

    session_id: Option<Vec<u8>>,
    pending_host_key: Option<(HostKey, Vec<u8>, Vec<u8>)>, // (key, H, raw shared secret)
    pending_ciphers: Option<DerivedCiphers>,
    pending_sc_cipher: Option<PacketCipher>,

    cs_cipher: Option<PacketCipher>,
    sc_cipher: Option<PacketCipher>,

    username: Option<String>,
    pending_auth: Option<PendingAuth>,

    channels: ChannelTable,
    channel_setup: HashMap<u32, ChannelSetupStep>,
    pending_exec: HashMap<u32, String>,
    pending_pty: HashMap<u32, PtyOptions>,
}

impl<R: SecureRandom> Session<R> {
    pub fn new(rng: R) -> Self {
        let mut session = Self {
            phase: Phase::VersionExchange,
            rng,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            events: VecDeque::new(),
            ident: IdentExchange::new(),
            own_ident_line: Vec::new(),
            peer_ident_line: Vec::new(),
            own_kexinit_payload: Vec::new(),
            peer_kexinit_payload: Vec::new(),
            negotiated: None,
            active_kex: None,
            session_id: None,
            pending_host_key: None,
            pending_ciphers: None,
            pending_sc_cipher: None,
            cs_cipher: None,
            sc_cipher: None,
            username: None,
            pending_auth: None,
            channels: ChannelTable::new(),
            channel_setup: HashMap::new(),
            pending_exec: HashMap::new(),
            pending_pty: HashMap::new(),
        };

        let line = ident::client_ident_line();
        session.own_ident_line = line[..line.len() - 2].to_vec(); // strip CRLF for V_C
        session.outgoing.extend_from_slice(&line);
        session
    }

    // ---- host-facing drains -------------------------------------------------------------

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn take_outgoing(&mut self, out: &mut Vec<u8>) -> usize {
        let n = self.outgoing.len();
        out.extend_from_slice(&self.outgoing);
        self.outgoing.clear();
        n
    }

    // ---- byte input -----------------------------------------------------------------------

    pub fn feed_incoming(&mut self, bytes: &[u8]) {
        self.incoming.extend_from_slice(bytes);
        self.drive();
    }

    pub fn notify_transport_closed(&mut self) {
        if self.phase != Phase::Closed {
            self.fail(SshError::TransportClosed);
        }
    }

    /// Keep making forward progress (consuming buffered bytes, producing outgoing bytes/events)
    /// until either input is exhausted or the session pauses (host-key decision) or closes.
    fn drive(&mut self) {
        loop {
            if self.phase == Phase::Closed || self.phase == Phase::AwaitingHostKeyDecision {
                return;
            }

            let progressed = match self.phase {
                Phase::VersionExchange => self.drive_version_exchange(),
                _ => self.drive_packet_phase(),
            };

            match progressed {
                Ok(true) => continue,
                Ok(false) => return,
                Err(e) => {
                    self.fail(e);
                    return;
                }
            }
        }
    }

    fn drive_version_exchange(&mut self) -> Result<bool> {
        if self.ident.is_done() {
            return Ok(false);
        }
        let consumed = self.ident.feed(&self.incoming)?;
        self.incoming.drain(0..consumed);
        if !self.ident.is_done() {
            return Ok(false);
        }

        self.peer_ident_line = self.ident.server_ident().expect("just confirmed done").to_vec();
        self.phase = Phase::KexInProgress;
        self.send_own_kexinit();
        Ok(true)
    }

    fn send_own_kexinit(&mut self) {
        let kex = KexInit::ours(&mut self.rng);
        self.own_kexinit_payload = kex.to_payload();
        let wire = packet::seal_plaintext(&self.own_kexinit_payload, &mut self.rng);
        self.outgoing.extend_from_slice(&wire);
    }

    /// One iteration of the generic "peek length, buffer, decrypt, dispatch" loop shared by
    /// every phase from `KexInProgress` onward.
    fn drive_packet_phase(&mut self) -> Result<bool> {
        if self.incoming.len() < 4 {
            return Ok(false);
        }
        let first4: [u8; 4] = self.incoming[0..4].try_into().expect("checked len >= 4");

        let total_len = match &self.sc_cipher {
            None => packet::peek_plaintext_length(&first4)?,
            Some(cipher) => cipher.peek_total_length(&first4)?,
        };
        if self.incoming.len() < total_len {
            return Ok(false);
        }

        let wire_packet: Vec<u8> = self.incoming.drain(0..total_len).collect();
        let payload = match &mut self.sc_cipher {
            None => packet::open_plaintext(&wire_packet)?,
            Some(cipher) => cipher.open(&wire_packet)?,
        };
        if payload.is_empty() {
            return Err(SshError::Framing("empty packet payload".into()));
        }

        self.dispatch(payload[0], &payload)?;
        Ok(true)
    }

    fn dispatch(&mut self, msg_type: u8, payload: &[u8]) -> Result<()> {
        match msg_type {
            // SSH_MSG_DISCONNECT (RFC 4253 SS 11.1): `byte(1) || uint32 reason || string
            // description || string language-tag`.
            1 => {
                let mut r = crate::wire::Reader::new(payload);
                r.read_u8()?;
                let reason_code = r.read_u32()?;
                let description = r.read_utf8_string().unwrap_or_default();
                self.phase = Phase::Closed;
                self.events.push_back(Event::Disconnected { reason_code, description });
                Ok(())
            }
            // SSH_MSG_IGNORE / SSH_MSG_UNIMPLEMENTED / SSH_MSG_DEBUG (RFC 4253 SS 11.3/11.4):
            // tolerate and drop, per spec.
            2 | 3 | 4 => Ok(()),
            kexinit::MSG_KEXINIT => self.handle_peer_kexinit(payload),
            kex_curve25519::MSG_KEX_ECDH_REPLY if self.active_kex_is_curve25519() => {
                self.handle_curve25519_reply(payload)
            }
            kex_dh_group14::MSG_KEXDH_REPLY if self.active_kex_is_dh_group14() => {
                self.handle_dh_group14_reply(payload)
            }
            kexinit::MSG_NEWKEYS => self.handle_newkeys(),
            auth::MSG_SERVICE_ACCEPT => self.handle_service_accept(payload),
            auth::MSG_USERAUTH_FAILURE => self.handle_userauth_failure(payload),
            auth::MSG_USERAUTH_SUCCESS => self.handle_userauth_success(),
            auth::MSG_USERAUTH_PK_OK => self.handle_userauth_pk_ok(payload),
            connection::channel::MSG_CHANNEL_OPEN_CONFIRMATION
            | connection::channel::MSG_CHANNEL_OPEN_FAILURE
            | connection::channel::MSG_CHANNEL_WINDOW_ADJUST
            | connection::channel::MSG_CHANNEL_DATA
            | connection::channel::MSG_CHANNEL_EXTENDED_DATA
            | connection::channel::MSG_CHANNEL_EOF
            | connection::channel::MSG_CHANNEL_CLOSE
            | connection::channel::MSG_CHANNEL_REQUEST => self.handle_channel_message(msg_type, payload),
            connection::channel::MSG_CHANNEL_SUCCESS => self.handle_channel_success(payload),
            connection::channel::MSG_CHANNEL_FAILURE => self.handle_channel_failure(payload),
            connection::MSG_GLOBAL_REQUEST => self.handle_global_request(payload),
            other => Err(SshError::UnexpectedMessage {
                expected_state: "dispatch",
                msg_type: other,
            }),
        }
    }

    // ---- KEX ------------------------------------------------------------------------------

    fn handle_peer_kexinit(&mut self, payload: &[u8]) -> Result<()> {
        self.peer_kexinit_payload = payload.to_vec();
        let ours = KexInit::parse(&self.own_kexinit_payload)?;
        let theirs = KexInit::parse(payload)?;
        let negotiated = kexinit::negotiate_all(&ours, &theirs)?;

        match negotiated.kex.as_str() {
            "curve25519-sha256" => {
                let kp = kex_curve25519::EphemeralKeypair::generate(&mut self.rng);
                let msg = kp.build_init_message();
                self.active_kex = Some(ActiveKex::Curve25519(kp));
                self.send_plaintext_or_ciphered(&msg);
            }
            "diffie-hellman-group14-sha256" => {
                let kex = kex_dh_group14::ClientKeyExchange::generate(&mut self.rng);
                let msg = kex.build_init_message();
                self.active_kex = Some(ActiveKex::DhGroup14(kex));
                self.send_plaintext_or_ciphered(&msg);
            }
            // Unreachable in practice: `negotiate_all` only ever picks a name from our own
            // `KEX_ALGORITHMS` list, which currently has exactly the two arms above. Kept as a
            // defensive error (not a panic) in case that list and this match ever drift apart.
            _ => return Err(SshError::Negotiation("kex algorithm implementation missing for negotiated choice")),
        }

        self.negotiated = Some(negotiated);
        Ok(())
    }

    fn active_kex_is_curve25519(&self) -> bool {
        matches!(self.active_kex, Some(ActiveKex::Curve25519(_)))
    }

    fn active_kex_is_dh_group14(&self) -> bool {
        matches!(self.active_kex, Some(ActiveKex::DhGroup14(_)))
    }

    fn handle_curve25519_reply(&mut self, payload: &[u8]) -> Result<()> {
        let reply = kex_curve25519::parse_reply(payload)?;
        let kp = match self.active_kex.take() {
            Some(ActiveKex::Curve25519(kp)) => kp,
            _ => unreachable!("guarded by active_kex_is_curve25519"),
        };
        let q_c = kp.public_bytes();
        let shared_secret = kp.diffie_hellman(reply.server_public)?;
        let h = kex_curve25519::exchange_hash(
            &self.own_ident_line,
            &self.peer_ident_line,
            &self.own_kexinit_payload,
            &self.peer_kexinit_payload,
            &reply.host_key_blob,
            &q_c,
            &reply.server_public,
            &shared_secret,
        );
        let host_key = kex_curve25519::verify_reply_signature(&reply, &h)?;
        self.on_kex_result(host_key, h, shared_secret.to_vec())
    }

    fn handle_dh_group14_reply(&mut self, payload: &[u8]) -> Result<()> {
        let reply = kex_dh_group14::parse_reply(payload)?;
        let kex = match self.active_kex.take() {
            Some(ActiveKex::DhGroup14(kex)) => kex,
            _ => unreachable!("guarded by active_kex_is_dh_group14"),
        };
        let e_bytes = kex.e_bytes().to_vec();
        let shared_secret = kex.diffie_hellman(&reply.f_bytes)?;
        let h = kex_dh_group14::exchange_hash(
            &self.own_ident_line,
            &self.peer_ident_line,
            &self.own_kexinit_payload,
            &self.peer_kexinit_payload,
            &reply.host_key_blob,
            &e_bytes,
            &reply.f_bytes,
            &shared_secret,
        );
        let host_key = kex_dh_group14::verify_reply_signature(&reply, &h)?;
        self.on_kex_result(host_key, h, shared_secret)
    }

    fn on_kex_result(&mut self, host_key: HostKey, h: Vec<u8>, shared_secret: Vec<u8>) -> Result<()> {
        let algorithm = self
            .negotiated
            .as_ref()
            .expect("negotiated set before kex reply is possible")
            .encryption_client_to_server
            .clone();
        let alg = CipherAlgorithm::from_name(&algorithm).ok_or(SshError::Negotiation("cipher"))?;

        let k_mpint = kdf::encode_mpint(&shared_secret);
        let session_id = self.session_id.clone().unwrap_or_else(|| h.clone());

        let (cs_key_len, cs_iv_len) = alg.kdf_material_len();
        let cs_key = kdf::derive(&k_mpint, &h, &session_id, kdf::TAG_ENC_KEY_CLIENT_TO_SERVER, cs_key_len);
        let cs_iv = kdf::derive(&k_mpint, &h, &session_id, kdf::TAG_IV_CLIENT_TO_SERVER, cs_iv_len);
        let sc_key = kdf::derive(&k_mpint, &h, &session_id, kdf::TAG_ENC_KEY_SERVER_TO_CLIENT, cs_key_len);
        let sc_iv = kdf::derive(&k_mpint, &h, &session_id, kdf::TAG_IV_SERVER_TO_CLIENT, cs_iv_len);

        // Each direction has already sent exactly 3 plaintext packets by the time NEWKEYS
        // activates encryption (KEXINIT, KEX_ECDH_INIT/KEXDH_INIT, NEWKEYS itself) - RFC 4253 SS
        // 6.4's sequence number is one continuous per-direction counter for the whole connection,
        // so the newly-activated cipher must carry on from 3, not restart at 0. See
        // `PacketCipher::with_initial_seq`'s doc for why this matters (chacha20-poly1305's nonce
        // *is* the sequence number) and how this went uncaught until tested against a real `sshd`.
        const PLAINTEXT_PACKETS_BEFORE_NEWKEYS: u32 = 3;
        self.pending_ciphers = Some(DerivedCiphers {
            cs: PacketCipher::with_initial_seq(alg, &cs_key, &cs_iv, PLAINTEXT_PACKETS_BEFORE_NEWKEYS),
            sc: PacketCipher::with_initial_seq(alg, &sc_key, &sc_iv, PLAINTEXT_PACKETS_BEFORE_NEWKEYS),
        });
        self.session_id.get_or_insert(h.clone());

        let fingerprint_sha256 = host_key.fingerprint_sha256();
        let algorithm_name = host_key.algorithm_name();
        let raw_blob = host_key.raw_blob().to_vec();
        self.pending_host_key = Some((host_key, h, shared_secret));
        self.phase = Phase::AwaitingHostKeyDecision;
        self.events.push_back(Event::HostKeyVerify {
            algorithm: algorithm_name,
            fingerprint_sha256,
            raw_blob,
        });
        Ok(())
    }

    /// Resume after the host answers the [`Event::HostKeyVerify`] pause.
    pub fn provide_host_key_decision(&mut self, accept: bool) {
        if self.phase != Phase::AwaitingHostKeyDecision {
            return; // stale/duplicate call; nothing to do
        }
        if !accept {
            self.fail(SshError::HostKeyRejected);
            return;
        }
        self.pending_host_key = None;

        // Our own NEWKEYS is the last plaintext packet we send; only messages *after* it use the
        // new cipher (RFC 4253 SS 7.3), so queue it before promoting `cs_cipher`.
        let wire = packet::seal_plaintext(&[kexinit::MSG_NEWKEYS], &mut self.rng);
        self.outgoing.extend_from_slice(&wire);
        if let Some(ciphers) = self.pending_ciphers.take() {
            self.cs_cipher = Some(ciphers.cs);
            // `sc_cipher` (our *receive* side) must stay plaintext until we actually consume the
            // peer's own NEWKEYS - which may already be sitting in `self.incoming` at this point
            // (servers commonly send it immediately, without waiting for ours) but must still be
            // parsed as plaintext, since it genuinely was sent that way on the wire.
            self.pending_sc_cipher = Some(ciphers.sc);
        }
        self.phase = Phase::ServiceRequest;
        self.send_ciphered(&auth::build_service_request(auth::SERVICE_USERAUTH));

        self.drive();
    }

    fn handle_newkeys(&mut self) -> Result<()> {
        self.sc_cipher = self.pending_sc_cipher.take();
        if self.cs_cipher.is_none() || self.sc_cipher.is_none() {
            return Err(SshError::UnexpectedMessage {
                expected_state: "NewKeys",
                msg_type: kexinit::MSG_NEWKEYS,
            });
        }
        Ok(())
    }

    fn send_plaintext_or_ciphered(&mut self, payload: &[u8]) {
        match &mut self.cs_cipher {
            None => {
                let wire = packet::seal_plaintext(payload, &mut self.rng);
                self.outgoing.extend_from_slice(&wire);
            }
            Some(_) => self.send_ciphered(payload),
        }
    }

    fn send_ciphered(&mut self, payload: &[u8]) {
        let wire = self
            .cs_cipher
            .as_mut()
            .expect("send_ciphered called only once cs_cipher is active")
            .seal(payload, &mut self.rng);
        self.outgoing.extend_from_slice(&wire);
    }

    // ---- service request / auth ------------------------------------------------------------

    fn handle_service_accept(&mut self, payload: &[u8]) -> Result<()> {
        let service = auth::parse_service_accept(payload)?;
        if service != auth::SERVICE_USERAUTH {
            return Err(SshError::Negotiation("service"));
        }
        self.phase = Phase::UserAuth;
        self.events.push_back(Event::ReadyForAuth);
        Ok(())
    }

    pub fn authenticate_password(&mut self, username: &str, password: &str) {
        if self.phase != Phase::UserAuth {
            return;
        }
        self.username = Some(username.into());
        self.pending_auth = Some(PendingAuth::Password);
        self.send_ciphered(&auth::password::build_request(username, password));
    }

    pub fn authenticate_publickey(&mut self, username: &str, private_key: PrivateKey) -> Result<()> {
        if self.phase != Phase::UserAuth {
            return Ok(());
        }
        self.username = Some(username.into());
        let pk_auth = auth::publickey::PublicKeyAuth::new(username, &private_key)?;
        let query = pk_auth.build_query();
        self.pending_auth = Some(PendingAuth::PublicKeyQuery {
            auth: pk_auth,
            private_key,
        });
        self.send_ciphered(&query);
        Ok(())
    }

    fn handle_userauth_failure(&mut self, payload: &[u8]) -> Result<()> {
        let failure = auth::parse_userauth_failure(payload)?;
        self.pending_auth = None;
        self.events.push_back(Event::AuthFailure {
            remaining_methods: failure.remaining_methods,
        });
        Ok(())
    }

    fn handle_userauth_success(&mut self) -> Result<()> {
        self.pending_auth = None;
        self.phase = Phase::Connected;
        self.events.push_back(Event::AuthSuccess);
        Ok(())
    }

    fn handle_userauth_pk_ok(&mut self, payload: &[u8]) -> Result<()> {
        match self.pending_auth.take() {
            Some(PendingAuth::PublicKeyQuery { auth, private_key }) => {
                let _ = auth::publickey::parse_pk_ok(payload)?; // validated shape; fields unused
                let session_id = self
                    .session_id
                    .clone()
                    .expect("session_id set once kex completes, which precedes auth");
                let signed = auth.build_signed_request(&session_id, &private_key)?;
                self.pending_auth = Some(PendingAuth::PublicKeySigned);
                self.send_ciphered(&signed);
                Ok(())
            }
            other => {
                // Message code 60 with no outstanding publickey query means the server sent
                // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ (same wire number, disambiguated only by
                // context) - a password-change flow this client intentionally doesn't support.
                self.pending_auth = other;
                Err(SshError::UnsupportedAuthMethod("password change (PASSWD_CHANGEREQ)"))
            }
        }
    }

    // ---- connection protocol ----------------------------------------------------------------

    pub fn open_exec(&mut self, command: &str) -> u32 {
        let (id, open_msg) = self.channels.open(ChannelKind::Exec);
        self.channel_setup.insert(id, ChannelSetupStep::AwaitingExecReply);
        self.pending_exec.insert(id, command.into());
        self.send_ciphered(&open_msg);
        id
    }

    pub fn open_shell(&mut self, pty: PtyOptions) -> u32 {
        let (id, open_msg) = self.channels.open(ChannelKind::Shell);
        self.channel_setup
            .insert(id, ChannelSetupStep::AwaitingPtyReply);
        self.pending_pty.insert(id, pty);
        self.send_ciphered(&open_msg);
        id
    }

    /// Send as much of `data` as the channel's current flow-control window allows. Returns the
    /// number of bytes actually sent; if less than `data.len()`, an `Event::ChannelWindowFull`
    /// has been queued and the host should retry the remainder later.
    pub fn channel_send(&mut self, id: u32, data: &[u8]) -> usize {
        let Some(channel) = self.channels.get_mut(id) else {
            return 0;
        };
        let (consumed, messages) = channel.build_data_messages(data);
        for msg in messages {
            self.outgoing_via_cs(msg);
        }
        if consumed < data.len() {
            self.events.push_back(Event::ChannelWindowFull { id });
        }
        consumed
    }

    pub fn resize_pty(&mut self, id: u32, cols: u32, rows: u32) {
        if self.channels.get(id).is_none() {
            return;
        }
        let remote_id = self.channels.get(id).and_then(|c| c.remote_id);
        if let Some(remote_id) = remote_id {
            let msg = connection::pty::build_window_change_request(remote_id, cols, rows, 0, 0);
            self.send_ciphered(&msg);
        }
    }

    pub fn close_channel(&mut self, id: u32) {
        if let Some(channel) = self.channels.get(id) {
            if channel.remote_id.is_some() {
                let msg = channel.build_close_message();
                self.send_ciphered(&msg);
            }
        }
    }

    fn outgoing_via_cs(&mut self, msg: Vec<u8>) {
        self.send_ciphered(&msg);
    }

    fn handle_channel_message(&mut self, msg_type: u8, payload: &[u8]) -> Result<()> {
        let (events, outgoing) = self.channels.handle_message(msg_type, payload)?;

        // Freshly confirmed channels need their setup continued (exec/pty-req).
        for event in &events {
            if let Event::ChannelOpened { id } = event {
                self.continue_channel_setup(*id, None)?;
            }
        }

        for event in events {
            self.events.push_back(event);
        }
        for msg in outgoing {
            self.send_ciphered(&msg);
        }
        Ok(())
    }

    fn handle_channel_success(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = crate::wire::Reader::new(payload);
        r.read_u8()?;
        let id = r.read_u32()?;
        self.continue_channel_setup(id, Some(true))
    }

    fn handle_channel_failure(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = crate::wire::Reader::new(payload);
        r.read_u8()?;
        let id = r.read_u32()?;
        self.continue_channel_setup(id, Some(false))
    }

    /// `SSH_MSG_GLOBAL_REQUEST` (RFC 4254 SS 4): `byte(80) || string request_name || boolean
    /// want_reply || ...`. Real servers send these unprompted (e.g. OpenSSH's
    /// `hostkeys-00@openssh.com` host-key announcement right after auth succeeds); we don't
    /// implement any global request, so reply `MSG_REQUEST_FAILURE` when the peer wants a reply
    /// and otherwise just drop it, per spec, rather than treating it as a fatal protocol error.
    fn handle_global_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = crate::wire::Reader::new(payload);
        r.read_u8()?;
        r.read_string()?; // request name - ignored, we don't support any
        let want_reply = r.read_bool()?;
        if want_reply {
            self.send_ciphered(&[connection::MSG_REQUEST_FAILURE]);
        }
        Ok(())
    }

    /// Drives a channel through its post-open setup (exec request, or pty-req then shell).
    /// `reply` is `None` right after `CHANNEL_OPEN_CONFIRMATION` (kick off the first step) or
    /// `Some(success)` in response to a `CHANNEL_SUCCESS`/`CHANNEL_FAILURE` for the current step.
    fn continue_channel_setup(&mut self, id: u32, reply: Option<bool>) -> Result<()> {
        let Some(step) = self.channel_setup.get(&id) else {
            return Ok(());
        };
        if reply == Some(false) {
            self.channel_setup.remove(&id);
            let remote_id = self.channels.get(id).and_then(|c| c.remote_id);
            self.channels.remove(id);
            if let Some(remote_id) = remote_id {
                let mut msg = Vec::new();
                msg.push(connection::channel::MSG_CHANNEL_CLOSE);
                crate::wire::write_u32(&mut msg, remote_id);
                self.send_ciphered(&msg);
            }
            self.events.push_back(Event::ChannelOpenFailed {
                id,
                reason_code: 0,
                description: "channel setup request failed".into(),
            });
            return Ok(());
        }

        let remote_id = self
            .channels
            .get(id)
            .and_then(|c| c.remote_id)
            .expect("channel setup only proceeds once open-confirmed");

        match step {
            ChannelSetupStep::AwaitingExecReply => {
                if reply.is_none() {
                    let command = self.pending_exec.remove(&id).unwrap_or_default();
                    self.send_ciphered(&connection::exec::build_request(remote_id, &command));
                } else {
                    self.channel_setup.remove(&id);
                }
            }
            ChannelSetupStep::AwaitingPtyReply => {
                if reply.is_none() {
                    let pty = self.pending_pty.remove(&id).unwrap_or_default();
                    self.send_ciphered(&connection::pty::build_pty_request(remote_id, &pty));
                } else {
                    self.channel_setup.insert(id, ChannelSetupStep::AwaitingShellReply);
                    self.send_ciphered(&connection::pty::build_shell_request(remote_id));
                }
            }
            ChannelSetupStep::AwaitingShellReply => {
                self.channel_setup.remove(&id);
            }
        }
        Ok(())
    }

    fn fail(&mut self, err: SshError) {
        self.phase = Phase::Closed;
        self.events.push_back(Event::Unrecoverable(err));
    }
}
