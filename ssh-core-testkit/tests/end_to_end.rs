//! Drives a real client `Session` through a complete handshake - version exchange, curve25519
//! KEX, host key verification, password auth, and an `exec` channel - against the in-process
//! `FakeServer`. This is the primary proof that `session.rs`'s orchestration (not just the
//! individual crypto/framing pieces, which have their own unit tests) is wired together
//! correctly.

use ssh_core::event::{DataStream, Event};
use ssh_core::session::Session;
use ssh_core_testkit::{FakeServer, TestRng};

fn pump(session: &mut Session<TestRng>, server: &mut FakeServer) {
    for _ in 0..1000 {
        let mut out = Vec::new();
        session.take_outgoing(&mut out);
        if out.is_empty() {
            return;
        }
        let server_out = server.feed(&out);
        if !server_out.is_empty() {
            session.feed_incoming(&server_out);
        }
    }
    panic!("pump did not settle after 1000 iterations - likely an infinite ping-pong bug");
}

#[test]
fn full_handshake_password_auth_and_exec() {
    let mut session = Session::new(TestRng::new(1));
    let mut server = FakeServer::new(2, "alice", "hunter2");
    server.set_exec_output(b"hello from fake server\n");

    // Bootstrap: exchange identification lines before the generic pump loop takes over (the
    // server's ident line isn't a response to anything the client sent, so it needs to be
    // delivered explicitly once).
    let mut client_ident = Vec::new();
    session.take_outgoing(&mut client_ident);
    session.feed_incoming(&server.initial_outgoing());
    let server_reply = server.feed(&client_ident);
    if !server_reply.is_empty() {
        session.feed_incoming(&server_reply);
    }

    pump(&mut session, &mut server);

    let mut exec_channel = None;
    let mut exec_output = Vec::new();
    let mut exit_code = None;
    let mut saw_channel_opened = false;
    let mut saw_eof = false;
    let mut closed = false;

    for _ in 0..1000 {
        match session.poll_event() {
            Some(Event::HostKeyVerify { algorithm, fingerprint_sha256, .. }) => {
                assert_eq!(algorithm, "ssh-ed25519");
                assert!(fingerprint_sha256.starts_with("SHA256:"));
                session.provide_host_key_decision(true);
                pump(&mut session, &mut server);
            }
            Some(Event::ReadyForAuth) => {
                session.authenticate_password("alice", "hunter2");
                pump(&mut session, &mut server);
            }
            Some(Event::AuthFailure { remaining_methods }) => {
                panic!("expected auth to succeed, got failure with methods {remaining_methods:?}")
            }
            Some(Event::AuthSuccess) => {
                let id = session.open_exec("echo hello");
                exec_channel = Some(id);
                pump(&mut session, &mut server);
            }
            Some(Event::ChannelOpened { id }) => {
                assert_eq!(Some(id), exec_channel);
                saw_channel_opened = true;
            }
            Some(Event::ChannelData { id, stream, data }) => {
                assert_eq!(Some(id), exec_channel);
                assert_eq!(stream, DataStream::Stdout);
                exec_output.extend_from_slice(&data);
            }
            Some(Event::ChannelExitStatus { id, code, signal }) => {
                assert_eq!(Some(id), exec_channel);
                assert_eq!(signal, None);
                exit_code = code;
            }
            Some(Event::ChannelEof { id }) => {
                assert_eq!(Some(id), exec_channel);
                saw_eof = true;
            }
            Some(Event::ChannelClosed { id }) => {
                assert_eq!(Some(id), exec_channel);
                closed = true;
                break;
            }
            Some(Event::Unrecoverable(e)) => panic!("session failed: {e}"),
            Some(other) => panic!("unexpected event in this flow: {other:?}"),
            None => {
                pump(&mut session, &mut server);
                if closed {
                    break;
                }
            }
        }
    }

    assert!(saw_channel_opened, "never saw ChannelOpened");
    assert_eq!(exec_output, b"hello from fake server\n");
    assert_eq!(exit_code, Some(0));
    assert!(saw_eof, "never saw ChannelEof");
    assert!(closed, "channel never closed");
    assert_eq!(server.last_exec_command.as_deref(), Some("echo hello"));
}

/// Regression test: a real server sending an unprompted `SSH_MSG_GLOBAL_REQUEST` right after
/// auth (e.g. OpenSSH's `hostkeys-00@openssh.com`) used to be treated as a fatal, unhandled
/// message type, killing the connection before it ever reached a channel. `FakeServer` never
/// sent one, so only a real `sshd` ever exercised this path.
#[test]
fn unsolicited_global_request_after_auth_does_not_break_the_session() {
    let mut session = Session::new(TestRng::new(3));
    let mut server = FakeServer::new(4, "alice", "hunter2");
    server.set_exec_output(b"hello from fake server\n");
    server.send_global_request_after_auth(true);

    let mut client_ident = Vec::new();
    session.take_outgoing(&mut client_ident);
    session.feed_incoming(&server.initial_outgoing());
    let server_reply = server.feed(&client_ident);
    if !server_reply.is_empty() {
        session.feed_incoming(&server_reply);
    }

    pump(&mut session, &mut server);

    let mut exec_channel = None;
    let mut exit_code = None;
    let mut closed = false;

    for _ in 0..1000 {
        match session.poll_event() {
            Some(Event::HostKeyVerify { .. }) => {
                session.provide_host_key_decision(true);
                pump(&mut session, &mut server);
            }
            Some(Event::ReadyForAuth) => {
                session.authenticate_password("alice", "hunter2");
                pump(&mut session, &mut server);
            }
            Some(Event::AuthSuccess) => {
                exec_channel = Some(session.open_exec("echo hello"));
                pump(&mut session, &mut server);
            }
            Some(Event::ChannelOpened { .. }) | Some(Event::ChannelData { .. }) | Some(Event::ChannelEof { .. }) => {}
            Some(Event::ChannelExitStatus { id, code, .. }) => {
                assert_eq!(Some(id), exec_channel);
                exit_code = code;
            }
            Some(Event::ChannelClosed { id }) => {
                assert_eq!(Some(id), exec_channel);
                closed = true;
                break;
            }
            Some(Event::Unrecoverable(e)) => panic!("session failed: {e}"),
            Some(other) => panic!("unexpected event in this flow (global request should be invisible): {other:?}"),
            None => {
                pump(&mut session, &mut server);
                if closed {
                    break;
                }
            }
        }
    }

    assert_eq!(exit_code, Some(0));
    assert!(closed, "channel never closed - global request likely broke the session");
}

#[test]
fn wrong_password_is_reported_as_auth_failure_not_a_fatal_error() {
    let mut session = Session::new(TestRng::new(10));
    let mut server = FakeServer::new(20, "alice", "hunter2");

    let mut client_ident = Vec::new();
    session.take_outgoing(&mut client_ident);
    session.feed_incoming(&server.initial_outgoing());
    let server_reply = server.feed(&client_ident);
    if !server_reply.is_empty() {
        session.feed_incoming(&server_reply);
    }
    pump(&mut session, &mut server);

    let mut saw_failure = false;
    for _ in 0..1000 {
        match session.poll_event() {
            Some(Event::HostKeyVerify { .. }) => {
                session.provide_host_key_decision(true);
                pump(&mut session, &mut server);
            }
            Some(Event::ReadyForAuth) => {
                session.authenticate_password("alice", "wrong-password");
                pump(&mut session, &mut server);
            }
            Some(Event::AuthFailure { remaining_methods }) => {
                assert!(remaining_methods.contains(&"password".to_string()));
                saw_failure = true;
                break;
            }
            Some(Event::AuthSuccess) => panic!("wrong password must not succeed"),
            Some(Event::Unrecoverable(e)) => panic!("session failed: {e}"),
            Some(_) => {}
            None => pump(&mut session, &mut server),
        }
    }

    assert!(saw_failure, "expected an AuthFailure event for the wrong password");
}

#[test]
fn publickey_auth_two_phase_flow_then_exec() {
    use ssh_key::private::PrivateKey;

    // The FakeServer only checks the *username* for publickey auth (any key whose signature
    // verifies is accepted) - so any freshly generated Ed25519 key exercises the real two-phase
    // query/sign flow end to end.
    let client_key = PrivateKey::random(&mut TestRng::new(999), ssh_key::Algorithm::Ed25519).unwrap();

    let mut session = Session::new(TestRng::new(3));
    let mut server = FakeServer::new(4, "bob", "unused-for-publickey");

    let mut client_ident = Vec::new();
    session.take_outgoing(&mut client_ident);
    session.feed_incoming(&server.initial_outgoing());
    let server_reply = server.feed(&client_ident);
    if !server_reply.is_empty() {
        session.feed_incoming(&server_reply);
    }
    pump(&mut session, &mut server);

    let mut authenticated = false;
    let mut exec_channel = None;
    let mut exit_code = None;
    let mut closed = false;

    for _ in 0..1000 {
        match session.poll_event() {
            Some(Event::HostKeyVerify { .. }) => {
                session.provide_host_key_decision(true);
                pump(&mut session, &mut server);
            }
            Some(Event::ReadyForAuth) => {
                session.authenticate_publickey("bob", client_key.clone()).unwrap();
                pump(&mut session, &mut server);
            }
            Some(Event::AuthFailure { remaining_methods }) => {
                panic!("expected publickey auth to succeed, got failure with methods {remaining_methods:?}")
            }
            Some(Event::AuthSuccess) => {
                authenticated = true;
                let id = session.open_exec("whoami");
                exec_channel = Some(id);
                pump(&mut session, &mut server);
            }
            Some(Event::ChannelExitStatus { id, code, .. }) => {
                assert_eq!(Some(id), exec_channel);
                exit_code = code;
            }
            Some(Event::ChannelClosed { id }) => {
                assert_eq!(Some(id), exec_channel);
                closed = true;
                break;
            }
            Some(Event::Unrecoverable(e)) => panic!("session failed: {e}"),
            Some(_) => {}
            None => pump(&mut session, &mut server),
        }
    }

    assert!(authenticated, "publickey auth did not succeed");
    assert_eq!(exit_code, Some(0));
    assert!(closed, "channel never closed");
    assert_eq!(server.last_exec_command.as_deref(), Some("whoami"));
}

#[test]
fn rejecting_the_host_key_disconnects_cleanly() {
    let mut session = Session::new(TestRng::new(100));
    let mut server = FakeServer::new(200, "alice", "hunter2");

    let mut client_ident = Vec::new();
    session.take_outgoing(&mut client_ident);
    session.feed_incoming(&server.initial_outgoing());
    let server_reply = server.feed(&client_ident);
    if !server_reply.is_empty() {
        session.feed_incoming(&server_reply);
    }
    pump(&mut session, &mut server);

    let mut saw_unrecoverable = false;
    for _ in 0..1000 {
        match session.poll_event() {
            Some(Event::HostKeyVerify { .. }) => {
                session.provide_host_key_decision(false);
            }
            Some(Event::Unrecoverable(e)) => {
                assert!(matches!(e, ssh_core::error::SshError::HostKeyRejected));
                saw_unrecoverable = true;
                break;
            }
            Some(other) => panic!("unexpected event after rejecting host key: {other:?}"),
            None => break,
        }
    }

    assert!(saw_unrecoverable, "expected Unrecoverable(HostKeyRejected) after rejecting the host key");
    // Session is closed: further byte input must not resurrect it or panic.
    session.feed_incoming(b"garbage");
    assert!(session.poll_event().is_none());
}
