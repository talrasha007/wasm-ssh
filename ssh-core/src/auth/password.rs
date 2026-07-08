//! `password` authentication method (RFC 4252 SS 8). We never send the "change password" variant
//! (the `TRUE`/new-password form) - only the plain `FALSE` form.

use std::vec::Vec;

use crate::wire::write_bool;
use crate::wire::write_string;

use super::{write_request_prefix, SERVICE_CONNECTION};

pub fn build_request(username: &str, password: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_request_prefix(&mut out, username, SERVICE_CONNECTION, "password");
    write_bool(&mut out, false);
    write_string(&mut out, password.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;

    #[test]
    fn builds_expected_wire_shape() {
        let req = build_request("alice", "hunter2");
        let mut r = Reader::new(&req);
        assert_eq!(r.read_u8().unwrap(), super::super::MSG_USERAUTH_REQUEST);
        assert_eq!(r.read_string().unwrap(), b"alice");
        assert_eq!(r.read_string().unwrap(), b"ssh-connection");
        assert_eq!(r.read_string().unwrap(), b"password");
        assert!(!r.read_bool().unwrap());
        assert_eq!(r.read_string().unwrap(), b"hunter2");
        assert!(r.is_finished());
    }
}
