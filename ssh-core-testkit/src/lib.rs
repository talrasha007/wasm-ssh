//! Native-only test support for `ssh-core`: a deterministic test RNG and an in-process "fake
//! server" that speaks just enough of the server side of the protocol (reusing `ssh-core`'s own
//! transport/auth/connection building blocks from the other side) to drive a real client
//! `Session` through a full handshake without needing an external `sshd`.
//!
//! This intentionally reuses `ssh-core`'s own crypto/framing code for the server role too
//! (`EphemeralKeypair`, `exchange_hash`, `PacketCipher`, the KDF): the goal is proving
//! `Session`'s *sequencing* is correct against a protocol-faithful peer, not re-implementing an
//! independent SSH stack. Actual crypto correctness is already covered by unit tests that check
//! against RFC/vendor test vectors and independent `ssh-key` signing/verification.

use ssh_core::connection::channel;
use ssh_core::rng::SecureRandom;
use ssh_core::transport::kdf;
use ssh_core::transport::kex_curve25519::{self, EphemeralKeypair};
use ssh_core::transport::kexinit::{self, KexInit};
use ssh_core::transport::packet::{self, CipherAlgorithm, PacketCipher};
use ssh_core::wire::{write_bool, write_string, write_u32, Reader};
use ssh_key::private::PrivateKey;

/// Deterministic, non-cryptographic PRNG (splitmix64) for reproducible tests. Never use outside
/// tests - there is no entropy here at all, just a fixed seed producing a fixed byte stream.
pub struct TestRng(u64);

impl TestRng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl SecureRandom for TestRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

impl rand_core_06::RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill(dest);
        Ok(())
    }
}
impl rand_core_06::CryptoRng for TestRng {}

enum ServerPhase {
    AwaitingIdent,
    AwaitingKexInit,
    AwaitingKexEcdhInit,
    AwaitingNewKeys,
    AwaitingUserAuth,
    Connected,
}

pub struct FakeServer {
    rng: TestRng,
    host_key: PrivateKey,
    username: String,
    password: String,
    default_exec_output: Vec<u8>,

    phase: ServerPhase,
    incoming: Vec<u8>,

    own_ident_line: Vec<u8>,  // without CRLF
    peer_ident_line: Vec<u8>, // without CRLF
    own_kexinit_payload: Vec<u8>,
    peer_kexinit_payload: Vec<u8>,
    session_id: Vec<u8>,

    cs_cipher: Option<PacketCipher>,
    cs_cipher_pending: Option<PacketCipher>,
    sc_cipher: Option<PacketCipher>,

    pub last_exec_command: Option<String>,
    send_global_request_after_auth: bool,
}

impl FakeServer {
    pub fn new(seed: u64, username: &str, password: &str) -> Self {
        let rng = TestRng::new(seed);
        let mut keygen_rng = TestRng::new(seed ^ 0xABCD_EF01_2345_6789);
        let host_key = PrivateKey::random(&mut keygen_rng, ssh_key::Algorithm::Ed25519).unwrap();

        Self {
            rng,
            host_key,
            username: username.into(),
            password: password.into(),
            default_exec_output: b"hello from fake server\n".to_vec(),
            phase: ServerPhase::AwaitingIdent,
            incoming: Vec::new(),
            own_ident_line: b"SSH-2.0-FakeTestServer_1.0".to_vec(),
            peer_ident_line: Vec::new(),
            own_kexinit_payload: Vec::new(),
            peer_kexinit_payload: Vec::new(),
            session_id: Vec::new(),
            cs_cipher: None,
            cs_cipher_pending: None,
            sc_cipher: None,
            last_exec_command: None,
            send_global_request_after_auth: false,
        }
    }

    /// Simulates a real server unpromptedly sending an `SSH_MSG_GLOBAL_REQUEST` right after auth
    /// succeeds (e.g. OpenSSH's `hostkeys-00@openssh.com`) - regression coverage for a client bug
    /// where any unhandled message type was treated as a fatal protocol error, killing every
    /// real-world connection at this exact point.
    pub fn send_global_request_after_auth(&mut self, enabled: bool) {
        self.send_global_request_after_auth = enabled;
    }

    pub fn set_exec_output(&mut self, output: &[u8]) {
        self.default_exec_output = output.to_vec();
    }

    /// The server's identification line, sent unconditionally as soon as it exists (RFC 4253
    /// SS 4.2 allows either side to send first).
    pub fn initial_outgoing(&self) -> Vec<u8> {
        let mut v = self.own_ident_line.clone();
        v.extend_from_slice(b"\r\n");
        v
    }

    /// Feed bytes from the client and return everything the server produces in response.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.incoming.extend_from_slice(bytes);
        let mut outgoing = Vec::new();
        while let Some(more) = self.step() {
            outgoing.extend_from_slice(&more);
        }
        outgoing
    }

    fn step(&mut self) -> Option<Vec<u8>> {
        if matches!(self.phase, ServerPhase::AwaitingIdent) {
            return self.step_ident();
        }
        self.step_packet()
    }

    fn step_ident(&mut self) -> Option<Vec<u8>> {
        let pos = self.incoming.iter().position(|&b| b == b'\n')?;
        let mut line: Vec<u8> = self.incoming.drain(0..=pos).collect();
        line.pop(); // '\n'
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        assert!(line.starts_with(b"SSH-"), "test client must send a valid ident line");
        self.peer_ident_line = line;
        self.phase = ServerPhase::AwaitingKexInit;
        Some(Vec::new())
    }

    fn step_packet(&mut self) -> Option<Vec<u8>> {
        if self.incoming.len() < 4 {
            return None;
        }
        let first4: [u8; 4] = self.incoming[0..4].try_into().unwrap();
        let total_len = match &self.cs_cipher {
            None => packet::peek_plaintext_length(&first4).ok()?,
            Some(c) => c.peek_total_length(&first4).ok()?,
        };
        if self.incoming.len() < total_len {
            return None;
        }
        let wire: Vec<u8> = self.incoming.drain(0..total_len).collect();
        let payload = match &mut self.cs_cipher {
            None => packet::open_plaintext(&wire).ok()?,
            Some(c) => c.open(&wire).ok()?,
        };

        Some(self.handle(&payload))
    }

    fn handle(&mut self, payload: &[u8]) -> Vec<u8> {
        match payload[0] {
            kexinit::MSG_KEXINIT => self.handle_kexinit(payload),
            kex_curve25519::MSG_KEX_ECDH_INIT => self.handle_kex_ecdh_init(payload),
            kexinit::MSG_NEWKEYS => {
                self.cs_cipher = self.cs_cipher_pending.take();
                Vec::new()
            }
            ssh_core::auth::MSG_SERVICE_REQUEST => self.handle_service_request(payload),
            ssh_core::auth::MSG_USERAUTH_REQUEST => self.handle_userauth_request(payload),
            channel::MSG_CHANNEL_OPEN => self.handle_channel_open(payload),
            channel::MSG_CHANNEL_REQUEST => self.handle_channel_request(payload),
            // The client's reply to `send_global_request_after_auth`'s injected global request.
            ssh_core::connection::MSG_REQUEST_FAILURE => Vec::new(),
            other => panic!("FakeServer received unexpected message type {other}"),
        }
    }

    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        match &mut self.sc_cipher {
            None => packet::seal_plaintext(payload, &mut self.rng),
            Some(c) => c.seal(payload, &mut self.rng),
        }
    }

    fn handle_kexinit(&mut self, payload: &[u8]) -> Vec<u8> {
        self.peer_kexinit_payload = payload.to_vec();
        let ours = KexInit::ours(&mut self.rng);
        self.own_kexinit_payload = ours.to_payload();
        self.phase = ServerPhase::AwaitingKexEcdhInit;
        let payload = self.own_kexinit_payload.clone();
        packet::seal_plaintext(&payload, &mut self.rng)
    }

    fn handle_kex_ecdh_init(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(payload);
        r.read_u8().unwrap();
        let q_c: [u8; 32] = r.read_string().unwrap().try_into().unwrap();

        let server_kp = EphemeralKeypair::generate(&mut self.rng);
        let q_s = server_kp.public_bytes();
        let shared_secret = server_kp.diffie_hellman(q_c).unwrap();

        let host_key_blob = self.host_key.public_key().to_bytes().unwrap();
        let h = kex_curve25519::exchange_hash(
            &self.peer_ident_line,
            &self.own_ident_line,
            &self.peer_kexinit_payload,
            &self.own_kexinit_payload,
            &host_key_blob,
            &q_c,
            &q_s,
            &shared_secret,
        );
        self.session_id = h.clone();

        use signature::Signer;
        let signature = self.host_key.try_sign(&h).unwrap();
        let signature_blob: Vec<u8> = signature.try_into().unwrap();

        let mut reply = std::vec![kex_curve25519::MSG_KEX_ECDH_REPLY];
        write_string(&mut reply, &host_key_blob);
        write_string(&mut reply, &q_s);
        write_string(&mut reply, &signature_blob);

        let alg = CipherAlgorithm::ChaCha20Poly1305OpenSsh;
        let k_mpint = kdf::encode_mpint(&shared_secret);
        let (key_len, iv_len) = alg.kdf_material_len();
        let cs_key = kdf::derive(&k_mpint, &h, &h, kdf::TAG_ENC_KEY_CLIENT_TO_SERVER, key_len);
        let cs_iv = kdf::derive(&k_mpint, &h, &h, kdf::TAG_IV_CLIENT_TO_SERVER, iv_len);
        let sc_key = kdf::derive(&k_mpint, &h, &h, kdf::TAG_ENC_KEY_SERVER_TO_CLIENT, key_len);
        let sc_iv = kdf::derive(&k_mpint, &h, &h, kdf::TAG_IV_SERVER_TO_CLIENT, iv_len);
        // Each direction has already sent exactly 3 plaintext packets (KEXINIT,
        // KEX_ECDH_INIT/REPLY, NEWKEYS) by the time its own NEWKEYS activates encryption - RFC
        // 4253 SS 6.4's sequence number is one continuous per-direction counter for the whole
        // connection, not reset per cipher. See `PacketCipher::with_initial_seq`'s doc.
        const PLAINTEXT_PACKETS_BEFORE_NEWKEYS: u32 = 3;
        self.cs_cipher_pending = Some(PacketCipher::with_initial_seq(alg, &cs_key, &cs_iv, PLAINTEXT_PACKETS_BEFORE_NEWKEYS));

        self.phase = ServerPhase::AwaitingNewKeys;

        let mut out = packet::seal_plaintext(&reply, &mut self.rng);
        // Real servers send their own NEWKEYS immediately, without waiting for the client's.
        out.extend_from_slice(&packet::seal_plaintext(&[kexinit::MSG_NEWKEYS], &mut self.rng));
        self.sc_cipher = Some(PacketCipher::with_initial_seq(alg, &sc_key, &sc_iv, PLAINTEXT_PACKETS_BEFORE_NEWKEYS));
        out
    }

    fn handle_service_request(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(payload);
        r.read_u8().unwrap();
        let service = r.read_utf8_string().unwrap();
        assert_eq!(service, "ssh-userauth");
        self.phase = ServerPhase::AwaitingUserAuth;

        let mut accept = std::vec![ssh_core::auth::MSG_SERVICE_ACCEPT];
        write_string(&mut accept, b"ssh-userauth");
        self.seal(&accept)
    }

    fn handle_userauth_request(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(payload);
        r.read_u8().unwrap();
        let username = r.read_utf8_string().unwrap();
        let _service = r.read_utf8_string().unwrap();
        let method = r.read_utf8_string().unwrap();

        let ok = match method.as_str() {
            "password" => {
                let _has_new_password = r.read_bool().unwrap();
                let password = r.read_utf8_string().unwrap();
                username == self.username && password == self.password
            }
            "publickey" => {
                let has_signature = r.read_bool().unwrap();
                let algo = r.read_utf8_string().unwrap();
                let key_blob = r.read_string().unwrap().to_vec();
                if !has_signature {
                    let mut pk_ok = std::vec![60u8];
                    write_string(&mut pk_ok, algo.as_bytes());
                    write_string(&mut pk_ok, &key_blob);
                    return self.seal(&pk_ok);
                }
                let signature_blob = r.read_string().unwrap();
                let host_key = ssh_core::transport::hostkey::HostKey::parse(&key_blob).unwrap();
                let mut signed_data = Vec::new();
                write_string(&mut signed_data, &self.session_id);
                signed_data.push(ssh_core::auth::MSG_USERAUTH_REQUEST);
                write_string(&mut signed_data, username.as_bytes());
                write_string(&mut signed_data, b"ssh-connection");
                write_string(&mut signed_data, b"publickey");
                signed_data.push(1); // has_signature = true
                write_string(&mut signed_data, algo.as_bytes());
                write_string(&mut signed_data, &key_blob);
                host_key.verify_signature(&signed_data, signature_blob).is_ok() && username == self.username
            }
            _ => false,
        };

        if ok {
            let mut out = self.seal(&[ssh_core::auth::MSG_USERAUTH_SUCCESS]);
            if self.send_global_request_after_auth {
                let mut req = std::vec![80u8]; // SSH_MSG_GLOBAL_REQUEST
                write_string(&mut req, b"test-global-request@example.com");
                write_bool(&mut req, true); // want_reply
                out.extend_from_slice(&self.seal(&req));
            }
            out
        } else {
            let mut failure = std::vec![ssh_core::auth::MSG_USERAUTH_FAILURE];
            write_string(&mut failure, b"password,publickey");
            write_bool(&mut failure, false);
            self.seal(&failure)
        }
    }

    fn handle_channel_open(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(payload);
        r.read_u8().unwrap();
        let _channel_type = r.read_string().unwrap();
        let sender_channel = r.read_u32().unwrap();
        let _initial_window = r.read_u32().unwrap();
        let _max_packet = r.read_u32().unwrap();

        self.phase = ServerPhase::Connected;

        let mut confirm = std::vec![channel::MSG_CHANNEL_OPEN_CONFIRMATION];
        write_u32(&mut confirm, sender_channel);
        write_u32(&mut confirm, 0);
        write_u32(&mut confirm, channel::INITIAL_WINDOW_SIZE);
        write_u32(&mut confirm, channel::MAX_PACKET_SIZE);
        self.seal(&confirm)
    }

    fn handle_channel_request(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(payload);
        r.read_u8().unwrap();
        let recipient_channel = r.read_u32().unwrap();
        let request_type = r.read_utf8_string().unwrap();
        let _want_reply = r.read_bool().unwrap();

        if request_type != "exec" {
            let mut failure = std::vec![channel::MSG_CHANNEL_FAILURE];
            write_u32(&mut failure, recipient_channel);
            return self.seal(&failure);
        }

        let command = r.read_utf8_string().unwrap();
        self.last_exec_command = Some(command);

        let mut out = Vec::new();
        let mut success = std::vec![channel::MSG_CHANNEL_SUCCESS];
        write_u32(&mut success, recipient_channel);
        out.extend_from_slice(&self.seal(&success));

        let mut data = std::vec![channel::MSG_CHANNEL_DATA];
        write_u32(&mut data, recipient_channel);
        write_string(&mut data, &self.default_exec_output.clone());
        out.extend_from_slice(&self.seal(&data));

        let mut exit_status = std::vec![channel::MSG_CHANNEL_REQUEST];
        write_u32(&mut exit_status, recipient_channel);
        write_string(&mut exit_status, b"exit-status");
        write_bool(&mut exit_status, false);
        write_u32(&mut exit_status, 0);
        out.extend_from_slice(&self.seal(&exit_status));

        let mut eof = std::vec![channel::MSG_CHANNEL_EOF];
        write_u32(&mut eof, recipient_channel);
        out.extend_from_slice(&self.seal(&eof));

        let mut close = std::vec![channel::MSG_CHANNEL_CLOSE];
        write_u32(&mut close, recipient_channel);
        out.extend_from_slice(&self.seal(&close));

        out
    }
}
