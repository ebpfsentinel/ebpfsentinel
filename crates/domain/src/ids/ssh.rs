//! The identification strings an SSH connection opens with (RFC 4253
//! section 4.2), read as Suricata 8 reads them: `ssh.proto` is the protocol
//! version between the first two hyphens, `ssh.software` what follows up to
//! the first space, the comments and the line end left out. Each side's
//! first line is its identification; a side whose first line does not start
//! with `SSH-` has none.
//!
//! These rules are held to Suricata by
//! `tests/fixtures/suricata/ssh-verdicts.txt`.

use std::sync::Arc;

use super::tx::{Fields, Ready};

/// The longest first line a side is waited on for: the 255 bytes RFC 4253
/// allows an identification string, its line end included.
const LINE_LIMIT: usize = 255;

/// The identification strings of one connection, as far as they arrived.
#[derive(Debug, Clone, Default)]
pub struct Ssh {
    pending: [Vec<u8>; 2],
    /// Whether the side's first line was read, or given up on.
    done: [bool; 2],
}

impl Ssh {
    /// Take the bytes `side` sent, in order, and hand back the side's
    /// identification once its line is whole.
    pub fn feed(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        if self.done[side] {
            return Vec::new();
        }
        let pending = &mut self.pending[side];
        let room = (LINE_LIMIT + 1).saturating_sub(pending.len());
        pending.extend_from_slice(&bytes[..bytes.len().min(room)]);
        let Some(end) = pending.iter().position(|&b| b == b'\n') else {
            if pending.len() > LINE_LIMIT {
                self.done[side] = true;
                *pending = Vec::new();
            }
            return Vec::new();
        };
        self.done[side] = true;
        let line = std::mem::take(pending);
        let line = &line[..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(fields) = identification(line) else {
            return Vec::new();
        };
        vec![Ready {
            id: 0,
            side,
            fields: Arc::new(fields),
            payload: Arc::from(&[][..]),
            whole: false,
            latest: true,
            last: true,
        }]
    }
}

/// The protocol and software versions of an identification line, its line
/// end removed.
fn identification(line: &[u8]) -> Option<Fields> {
    let rest = line.strip_prefix(b"SSH-")?;
    let dash = rest.iter().position(|&b| b == b'-')?;
    let (proto, rest) = (&rest[..dash], &rest[dash + 1..]);
    let software = rest.split(|&b| b == b' ').next().unwrap_or_default();
    let mut fields = Fields::default();
    fields.put("ssh.proto", proto.to_vec());
    fields.put("ssh.software", software.to_vec());
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(ready: &[Ready], name: &str) -> Option<Vec<u8>> {
        ready.first()?.fields.get(name, 0).map(<[u8]>::to_vec)
    }

    #[test]
    fn the_software_version_stops_before_the_comments() {
        let mut ssh = Ssh::default();
        let ready = ssh.feed(1, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n");
        assert_eq!(field(&ready, "ssh.proto").as_deref(), Some(&b"2.0"[..]));
        assert_eq!(
            field(&ready, "ssh.software").as_deref(),
            Some(&b"OpenSSH_8.9p1"[..])
        );
        assert_eq!(ready[0].side, 1);
    }

    #[test]
    fn a_line_split_across_segments_is_read_once_whole() {
        let mut ssh = Ssh::default();
        assert!(ssh.feed(0, b"SSH-1.99-Erl").is_empty());
        let ready = ssh.feed(0, b"ang/5.1\n\x00\x00");
        assert_eq!(
            field(&ready, "ssh.software").as_deref(),
            Some(&b"Erlang/5.1"[..])
        );
        assert!(ssh.feed(0, b"SSH-2.0-again\r\n").is_empty());
    }

    #[test]
    fn only_the_first_line_identifies_a_side() {
        let mut ssh = Ssh::default();
        assert!(
            ssh.feed(1, b"Welcome\r\nSSH-2.0-OpenSSH_9.0\r\n")
                .is_empty()
        );
        assert!(ssh.feed(1, b"SSH-2.0-OpenSSH_9.0\r\n").is_empty());
    }

    #[test]
    fn a_line_longer_than_the_limit_is_given_up_on() {
        let mut ssh = Ssh::default();
        assert!(ssh.feed(0, &[b'A'; 300]).is_empty());
        assert!(ssh.feed(0, b"\n").is_empty());
    }
}
