//! `exec` channel request (RFC 4254 SS 6.5): run a single command, non-interactively.

use std::vec::Vec;

use crate::wire::write_string;

use super::channel::build_channel_request;

pub fn build_request(remote_id: u32, command: &str) -> Vec<u8> {
    let mut type_specific = Vec::new();
    write_string(&mut type_specific, command.as_bytes());
    build_channel_request(remote_id, "exec", true, &type_specific)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;

    #[test]
    fn builds_expected_wire_shape() {
        let msg = build_request(9, "echo hello");
        let mut r = Reader::new(&msg);
        assert_eq!(r.read_u8().unwrap(), super::super::channel::MSG_CHANNEL_REQUEST);
        assert_eq!(r.read_u32().unwrap(), 9);
        assert_eq!(r.read_string().unwrap(), b"exec");
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_string().unwrap(), b"echo hello");
        assert!(r.is_finished());
    }
}
