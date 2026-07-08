//! Minimal, dependency-free helpers for reading/writing the two RFC 4251 SS 5 primitives used
//! constantly across message parsing: `uint32` and `string` (length-prefixed byte blob).
//!
//! Hand-rolled deliberately: `ssh-key`'s bundled `ssh-encoding` is a different major version
//! (0.2) than the one `ssh-core` depends on directly (0.3), so mixing trait-based decode calls
//! across the two would be a type error, not just a style choice. These two primitives are
//! trivial enough that a tiny local implementation avoids the whole issue for message bodies
//! that don't otherwise touch `ssh-key` types.

use std::vec::Vec;

use crate::error::{Result, SshError};

pub fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn write_string(out: &mut Vec<u8>, data: &[u8]) {
    write_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(if value { 1 } else { 0 });
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or_else(too_short)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let end = self.pos.checked_add(4).ok_or_else(too_short)?;
        let bytes = self.buf.get(self.pos..end).ok_or_else(too_short)?;
        self.pos = end;
        Ok(u32::from_be_bytes(bytes.try_into().expect("4 bytes")))
    }

    /// Read a length-prefixed `string` and return a borrowed slice of its contents.
    pub fn read_string(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        let end = self.pos.checked_add(len).ok_or_else(too_short)?;
        let s = self.buf.get(self.pos..end).ok_or_else(too_short)?;
        self.pos = end;
        Ok(s)
    }

    /// Read a length-prefixed `string` and interpret it as UTF-8 (e.g. an algorithm name).
    pub fn read_utf8_string(&mut self) -> Result<std::string::String> {
        let bytes = self.read_string()?;
        core::str::from_utf8(bytes)
            .map(std::string::String::from)
            .map_err(|_| SshError::Framing("expected UTF-8 string".into()))
    }

    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(too_short)?;
        let s = self.buf.get(self.pos..end).ok_or_else(too_short)?;
        self.pos = end;
        Ok(s)
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn is_finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn too_short() -> SshError {
    SshError::Framing("message ended before expected field".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_mixed_fields() {
        let mut out = Vec::new();
        write_u32(&mut out, 42);
        write_string(&mut out, b"hello");
        write_bool(&mut out, true);
        out.push(0x99);

        let mut r = Reader::new(&out);
        assert_eq!(r.read_u32().unwrap(), 42);
        assert_eq!(r.read_string().unwrap(), b"hello");
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_u8().unwrap(), 0x99);
        assert!(r.is_finished());
    }

    #[test]
    fn truncated_input_errors_instead_of_panicking() {
        let mut r = Reader::new(&[0, 0, 0, 5, b'h', b'i']);
        assert!(r.read_string().is_err());
    }

    #[test]
    fn oversized_length_does_not_panic_via_overflow() {
        let mut r = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(r.read_string().is_err());
    }
}
