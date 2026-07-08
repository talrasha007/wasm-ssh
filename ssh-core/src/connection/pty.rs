//! `pty-req` / `shell` / `window-change` channel requests (RFC 4254 SS 6.2, 6.5, 6.7) for
//! interactive sessions.

use std::string::String;
use std::vec::Vec;

use crate::wire::{write_string, write_u32};

use super::channel::build_channel_request;

#[derive(Debug, Clone)]
pub struct PtyOptions {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

impl Default for PtyOptions {
    fn default() -> Self {
        Self {
            term: String::from("xterm-256color"),
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

pub fn build_pty_request(remote_id: u32, opts: &PtyOptions) -> Vec<u8> {
    let mut type_specific = Vec::new();
    write_string(&mut type_specific, opts.term.as_bytes());
    write_u32(&mut type_specific, opts.cols);
    write_u32(&mut type_specific, opts.rows);
    write_u32(&mut type_specific, opts.pixel_width);
    write_u32(&mut type_specific, opts.pixel_height);
    write_string(&mut type_specific, &[]); // encoded terminal modes: none
    build_channel_request(remote_id, "pty-req", true, &type_specific)
}

pub fn build_shell_request(remote_id: u32) -> Vec<u8> {
    build_channel_request(remote_id, "shell", true, &[])
}

/// Per RFC 4254 SS 6.7, `window-change` never sets `want_reply`.
pub fn build_window_change_request(remote_id: u32, cols: u32, rows: u32, pixel_width: u32, pixel_height: u32) -> Vec<u8> {
    let mut type_specific = Vec::new();
    write_u32(&mut type_specific, cols);
    write_u32(&mut type_specific, rows);
    write_u32(&mut type_specific, pixel_width);
    write_u32(&mut type_specific, pixel_height);
    build_channel_request(remote_id, "window-change", false, &type_specific)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;

    #[test]
    fn pty_request_has_expected_shape() {
        let opts = PtyOptions::default();
        let msg = build_pty_request(5, &opts);
        let mut r = Reader::new(&msg);
        assert_eq!(r.read_u8().unwrap(), super::super::channel::MSG_CHANNEL_REQUEST);
        assert_eq!(r.read_u32().unwrap(), 5);
        assert_eq!(r.read_string().unwrap(), b"pty-req");
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_string().unwrap(), b"xterm-256color");
        assert_eq!(r.read_u32().unwrap(), 80);
        assert_eq!(r.read_u32().unwrap(), 24);
        assert_eq!(r.read_u32().unwrap(), 0);
        assert_eq!(r.read_u32().unwrap(), 0);
        assert_eq!(r.read_string().unwrap(), b"");
        assert!(r.is_finished());
    }

    #[test]
    fn shell_request_has_no_type_specific_data() {
        let msg = build_shell_request(5);
        let mut r = Reader::new(&msg);
        r.read_u8().unwrap();
        r.read_u32().unwrap();
        assert_eq!(r.read_string().unwrap(), b"shell");
        assert!(r.read_bool().unwrap());
        assert!(r.is_finished());
    }

    #[test]
    fn window_change_never_wants_a_reply() {
        let msg = build_window_change_request(5, 100, 40, 0, 0);
        let mut r = Reader::new(&msg);
        r.read_u8().unwrap();
        r.read_u32().unwrap();
        assert_eq!(r.read_string().unwrap(), b"window-change");
        assert!(!r.read_bool().unwrap());
    }
}
