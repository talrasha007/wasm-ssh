//! RFC 4252 user authentication protocol, plus the RFC 4253 SS 10 service request that precedes
//! it (both `ssh-userauth` and, once authenticated, `ssh-connection` are requested this way).
//!
//! Every `build_*` function here is a pure function: given inputs, produce wire bytes. All
//! sequencing/state (which method we're trying, whether we're mid publickey-query) lives in
//! `session.rs`, matching the sans-io design - this module has no memory of its own.

pub mod password;
pub mod publickey;

use std::string::String;
use std::vec::Vec;

use crate::error::{Result, SshError};
use crate::wire::{write_string, Reader};

pub const MSG_SERVICE_REQUEST: u8 = 5;
pub const MSG_SERVICE_ACCEPT: u8 = 6;
pub const MSG_USERAUTH_REQUEST: u8 = 50;
pub const MSG_USERAUTH_FAILURE: u8 = 51;
pub const MSG_USERAUTH_SUCCESS: u8 = 52;
pub const MSG_USERAUTH_BANNER: u8 = 53;
/// Shared with `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` (also 60) - which of the two a `60` means is
/// determined entirely by which method the client's most recent request used, per RFC 4252.
pub const MSG_USERAUTH_PK_OK: u8 = 60;

pub const SERVICE_USERAUTH: &str = "ssh-userauth";
pub const SERVICE_CONNECTION: &str = "ssh-connection";

pub fn build_service_request(service_name: &str) -> Vec<u8> {
    let mut out = std::vec![MSG_SERVICE_REQUEST];
    write_string(&mut out, service_name.as_bytes());
    out
}

/// Returns the accepted service name so the caller can confirm it matches what was requested.
pub fn parse_service_accept(payload: &[u8]) -> Result<String> {
    let mut r = Reader::new(payload);
    expect_msg_type(&mut r, MSG_SERVICE_ACCEPT, "ServiceAccept")?;
    r.read_utf8_string()
}

#[derive(Debug, Clone)]
pub struct AuthFailure {
    pub remaining_methods: Vec<String>,
    pub partial_success: bool,
}

pub fn parse_userauth_failure(payload: &[u8]) -> Result<AuthFailure> {
    let mut r = Reader::new(payload);
    expect_msg_type(&mut r, MSG_USERAUTH_FAILURE, "UserAuthFailure")?;
    let joined = r.read_utf8_string()?;
    let remaining_methods = if joined.is_empty() {
        Vec::new()
    } else {
        joined.split(',').map(String::from).collect()
    };
    let partial_success = r.read_bool()?;
    Ok(AuthFailure {
        remaining_methods,
        partial_success,
    })
}

pub fn is_userauth_success(payload: &[u8]) -> bool {
    payload.first() == Some(&MSG_USERAUTH_SUCCESS)
}

fn expect_msg_type(r: &mut Reader, expected: u8, state_name: &'static str) -> Result<()> {
    let msg_type = r.read_u8()?;
    if msg_type != expected {
        return Err(SshError::UnexpectedMessage {
            expected_state: state_name,
            msg_type,
        });
    }
    Ok(())
}

/// Common `SSH_MSG_USERAUTH_REQUEST` prefix shared by every method: `byte(50) || string user-name
/// || string service-name || string method-name`.
fn write_request_prefix(out: &mut Vec<u8>, username: &str, service_name: &str, method_name: &str) {
    out.push(MSG_USERAUTH_REQUEST);
    write_string(out, username.as_bytes());
    write_string(out, service_name.as_bytes());
    write_string(out, method_name.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::write_bool;

    #[test]
    fn builds_and_would_be_parsed_service_flow() {
        let req = build_service_request(SERVICE_USERAUTH);
        assert_eq!(req[0], MSG_SERVICE_REQUEST);

        let mut accept = std::vec![MSG_SERVICE_ACCEPT];
        write_string(&mut accept, SERVICE_USERAUTH.as_bytes());
        assert_eq!(parse_service_accept(&accept).unwrap(), SERVICE_USERAUTH);
    }

    #[test]
    fn parses_failure_with_remaining_methods() {
        let mut payload = std::vec![MSG_USERAUTH_FAILURE];
        write_string(&mut payload, b"publickey,password");
        write_bool(&mut payload, false);

        let failure = parse_userauth_failure(&payload).unwrap();
        assert_eq!(failure.remaining_methods, std::vec!["publickey", "password"]);
        assert!(!failure.partial_success);
    }

    #[test]
    fn recognizes_success() {
        assert!(is_userauth_success(&[MSG_USERAUTH_SUCCESS]));
        assert!(!is_userauth_success(&[MSG_USERAUTH_FAILURE]));
    }
}
