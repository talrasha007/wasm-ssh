//! RFC 4253 SS 4.2 protocol version exchange.
//!
//! The client sends its identification line immediately; the server's identification line may
//! be preceded by arbitrary banner lines not starting with `SSH-`, which must be skipped. The
//! server's ident line (and any bytes after its trailing CRLF) may arrive in the same read as
//! the start of the binary packet protocol, so [`IdentExchange::feed`] reports how many bytes of
//! the input it actually consumed - any remainder belongs to the packet layer.

use std::vec::Vec;

use crate::error::{Result, SshError};

/// Our own identification string. Kept short and RFC-boring on purpose: some servers pattern-
/// match on the software name field for compatibility quirks, and we don't want to trigger any.
pub fn client_ident_line() -> Vec<u8> {
    let mut v = std::format!("SSH-2.0-wasmssh_{}", env!("CARGO_PKG_VERSION")).into_bytes();
    v.extend_from_slice(b"\r\n");
    v
}

pub struct IdentExchange {
    scan_buf: Vec<u8>,
    total_scanned: usize,
    server_ident: Option<Vec<u8>>,
}

impl IdentExchange {
    /// Bound on total bytes scanned (across all banner lines + the ident line itself) before
    /// giving up. Generous relative to real-world banners, but prevents a hostile/broken peer
    /// from making us buffer unbounded data before transport encryption is even established.
    const MAX_SCAN_BYTES: usize = 64 * 1024;

    pub fn new() -> Self {
        Self {
            scan_buf: Vec::new(),
            total_scanned: 0,
            server_ident: None,
        }
    }

    pub fn is_done(&self) -> bool {
        self.server_ident.is_some()
    }

    /// The server's raw identification line (e.g. `SSH-2.0-OpenSSH_9.7`), without the trailing
    /// CR/LF. Only `Some` once [`Self::is_done`].
    pub fn server_ident(&self) -> Option<&[u8]> {
        self.server_ident.as_deref()
    }

    /// Feed newly-received bytes. Returns the number of bytes consumed from the front of `data`.
    /// Once this returns with [`Self::is_done`] true, `data[consumed..]` was not touched and must
    /// be handed to the binary packet layer instead.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize> {
        if self.is_done() {
            return Ok(0);
        }

        let mut consumed = 0;
        for &byte in data {
            consumed += 1;
            self.total_scanned += 1;
            if self.total_scanned > Self::MAX_SCAN_BYTES {
                return Err(SshError::Framing(
                    "server identification exchange exceeded size limit".into(),
                ));
            }

            if byte == b'\n' {
                let mut line_end = self.scan_buf.len();
                if line_end > 0 && self.scan_buf[line_end - 1] == b'\r' {
                    line_end -= 1;
                }
                let line = self.scan_buf[..line_end].to_vec();
                self.scan_buf.clear();

                if line.starts_with(b"SSH-") {
                    validate_version(&line)?;
                    self.server_ident = Some(line);
                    return Ok(consumed);
                }
                // Otherwise it's a pre-ident banner line (RFC 4253 SS 4.2); keep scanning.
                continue;
            }

            self.scan_buf.push(byte);
        }

        Ok(consumed)
    }
}

impl Default for IdentExchange {
    fn default() -> Self {
        Self::new()
    }
}

/// Reject anything that isn't SSH-2.0 (or the SSH-1.99 back-compat marker some old servers use
/// to mean "I speak both 1.x and 2.0").
fn validate_version(line: &[u8]) -> Result<()> {
    let text = core::str::from_utf8(line)
        .map_err(|_| SshError::Framing("server ident line is not valid UTF-8".into()))?;
    let rest = text.strip_prefix("SSH-").unwrap_or(text);
    let proto_version = rest.split('-').next().unwrap_or("");
    match proto_version {
        "2.0" | "1.99" => Ok(()),
        other => Err(SshError::Framing(std::format!(
            "unsupported SSH protocol version: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ident_line_with_no_banner() {
        let mut ex = IdentExchange::new();
        let consumed = ex.feed(b"SSH-2.0-OpenSSH_9.7\r\n").unwrap();
        assert_eq!(consumed, "SSH-2.0-OpenSSH_9.7\r\n".len());
        assert!(ex.is_done());
        assert_eq!(ex.server_ident().unwrap(), b"SSH-2.0-OpenSSH_9.7");
    }

    #[test]
    fn skips_banner_lines_before_ident() {
        let mut ex = IdentExchange::new();
        let input = b"Welcome to our server!\r\nAuthorized use only.\r\nSSH-2.0-OpenSSH_9.7\r\n";
        let consumed = ex.feed(input).unwrap();
        assert_eq!(consumed, input.len());
        assert_eq!(ex.server_ident().unwrap(), b"SSH-2.0-OpenSSH_9.7");
    }

    #[test]
    fn leaves_trailing_bytes_unconsumed_for_packet_layer() {
        let mut ex = IdentExchange::new();
        let mut input = b"SSH-2.0-OpenSSH_9.7\r\n".to_vec();
        let trailer = [0xAAu8, 0xBB, 0xCC];
        input.extend_from_slice(&trailer);
        let consumed = ex.feed(&input).unwrap();
        assert_eq!(consumed, input.len() - trailer.len());
        assert_eq!(&input[consumed..], &trailer);
    }

    #[test]
    fn handles_ident_line_split_across_feeds() {
        let mut ex = IdentExchange::new();
        assert_eq!(ex.feed(b"SSH-2.0-Open").unwrap(), 12);
        assert!(!ex.is_done());
        assert_eq!(ex.feed(b"SSH_9.7\r\n").unwrap(), 9);
        assert!(ex.is_done());
        assert_eq!(ex.server_ident().unwrap(), b"SSH-2.0-OpenSSH_9.7");
    }

    #[test]
    fn rejects_ssh_1_only_server() {
        let mut ex = IdentExchange::new();
        let err = ex.feed(b"SSH-1.5-OldServer\r\n").unwrap_err();
        assert!(matches!(err, SshError::Framing(_)));
    }

    #[test]
    fn accepts_ssh_1_99_backcompat_marker() {
        let mut ex = IdentExchange::new();
        ex.feed(b"SSH-1.99-OpenSSH_3.0\r\n").unwrap();
        assert!(ex.is_done());
    }

    #[test]
    fn client_ident_line_is_well_formed() {
        let line = client_ident_line();
        assert!(line.starts_with(b"SSH-2.0-"));
        assert!(line.ends_with(b"\r\n"));
    }
}
