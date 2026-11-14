//! A netlink socket, the messages the warden writes to it and the attributes
//! it reads back.
//!
//! The warden image carries no shell and no tool, so the conntrack table and
//! the routing table are spoken to directly rather than through `conntrack`
//! and `ip`. Every read is bounded by a receive timeout: the warden serves one
//! connection per thread, and a socket the kernel never answers must not park
//! that thread past the agent's own wait.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

pub const NLMSG_HDRLEN: usize = 16;
const NLA_HDRLEN: usize = 4;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

/// How long one receive may wait for the kernel.
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// Large enough for any one datagram the kernel sends on a dump.
const RECV_BUFFER: usize = 64 * 1024;

fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// One netlink request being written: the header, the family header and the
/// attributes, nested ones included.
pub struct Message {
    buf: Vec<u8>,
    open: Vec<usize>,
}

impl Message {
    pub fn new(kind: u16, flags: u16, family_header: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&1u32.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(family_header);
        buf.resize(align(buf.len()), 0);
        Self {
            buf,
            open: Vec::new(),
        }
    }

    pub fn attr(&mut self, kind: u16, data: &[u8]) -> &mut Self {
        let len = NLA_HDRLEN + data.len();
        self.buf
            .extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(align(self.buf.len()), 0);
        self
    }

    /// A nested attribute whose contents are already encoded.
    pub fn nested(&mut self, kind: u16, encoded: &[u8]) -> &mut Self {
        self.attr(kind | NLA_F_NESTED, encoded)
    }

    /// Opens a nested attribute, closed by the matching [`Message::end`].
    pub fn begin(&mut self, kind: u16) -> &mut Self {
        self.open.push(self.buf.len());
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        self
    }

    pub fn end(&mut self) -> &mut Self {
        if let Some(at) = self.open.pop() {
            let len = u16::try_from(self.buf.len() - at).unwrap_or(u16::MAX);
            self.buf[at..at + 2].copy_from_slice(&len.to_ne_bytes());
        }
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        while !self.open.is_empty() {
            self.end();
        }
        let len = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

/// The attributes laid end to end in `buf`, as (type, payload), the nested
/// and byte-order flags masked off the type.
pub fn attributes(buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut at = 0;
    std::iter::from_fn(move || {
        let len = usize::from(u16_at(buf, at)?);
        let kind = u16_at(buf, at + 2)?;
        if len < NLA_HDRLEN || at + len > buf.len() {
            return None;
        }
        let payload = &buf[at + NLA_HDRLEN..at + len];
        at += align(len);
        Some((kind & NLA_TYPE_MASK, payload))
    })
}

/// The first attribute of type `kind` in `buf`.
pub fn attribute(buf: &[u8], kind: u16) -> Option<&[u8]> {
    attributes(buf).find(|(k, _)| *k == kind).map(|(_, p)| p)
}

pub fn be16(payload: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(payload.get(..2)?.try_into().ok()?))
}

pub fn be32(payload: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(payload.get(..4)?.try_into().ok()?))
}

pub fn be64(payload: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(payload.get(..8)?.try_into().ok()?))
}

/// What one datagram said: the payloads of the messages it carried, and
/// whether it ended the exchange.
#[derive(Debug, PartialEq, Eq)]
pub struct Batch {
    pub messages: Vec<Vec<u8>>,
    pub done: bool,
}

/// Splits one datagram. An acknowledgement and the end of a dump both end the
/// exchange; an error reply is the error the kernel gave.
pub fn split(buf: &[u8]) -> io::Result<Batch> {
    let mut batch = Batch {
        messages: Vec::new(),
        done: false,
    };
    let mut at = 0;
    while let (Some(len), Some(kind)) = (u32_at(buf, at), u16_at(buf, at + 4)) {
        let len = len as usize;
        if len < NLMSG_HDRLEN || at + len > buf.len() {
            break;
        }
        let body = &buf[at + NLMSG_HDRLEN..at + len];
        match kind {
            NLMSG_ERROR => {
                let errno = u32_at(body, 0).map_or(0, u32::cast_signed);
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(-errno));
                }
                batch.done = true;
            }
            NLMSG_DONE => batch.done = true,
            _ => batch.messages.push(body.to_vec()),
        }
        at += align(len);
    }
    Ok(batch)
}

/// A netlink socket of one protocol, bound by the kernel on first send.
pub struct Socket(OwnedFd);

impl Socket {
    pub fn open(protocol: libc::c_int) -> io::Result<Self> {
        // SAFETY: plain socket(2) call; the result is checked before use.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a descriptor this call just opened and owns alone.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let timeout = libc::timeval {
            tv_sec: libc::time_t::try_from(RECV_TIMEOUT.as_secs()).unwrap_or(5),
            tv_usec: 0,
        };
        // SAFETY: `timeout` is a live timeval and its exact size is passed.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(timeout).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::timeval>()).unwrap_or(16),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    /// Sends `request` and collects every message the kernel answers with
    /// until it acknowledges the request or ends the dump.
    pub fn exchange(&self, request: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        // SAFETY: `request` is a live buffer of the length passed.
        let sent = unsafe {
            libc::send(
                self.0.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; RECV_BUFFER];
        let mut out = Vec::new();
        loop {
            // SAFETY: `buf` is a live buffer of the length passed.
            let got =
                unsafe { libc::recv(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if got < 0 {
                return Err(io::Error::last_os_error());
            }
            let batch = split(&buf[..usize::try_from(got).unwrap_or(0)])?;
            out.extend(batch.messages);
            if batch.done || got == 0 {
                return Ok(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(kind: u16, body: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDRLEN + body.len();
        let mut msg = Vec::new();
        msg.extend_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&[0u8; 10]);
        msg.extend_from_slice(body);
        msg.resize(align(msg.len()), 0);
        msg
    }

    #[test]
    fn a_message_carries_its_length_and_nested_attributes() {
        let mut msg = Message::new(0x101, NLM_F_REQUEST, &[2, 0, 0, 0]);
        msg.begin(1).attr(2, &[1, 2, 3]).end();
        msg.attr(3, &7u32.to_be_bytes());
        let bytes = msg.finish();
        assert_eq!(u32_at(&bytes, 0).unwrap() as usize, bytes.len());
        assert_eq!(u16_at(&bytes, 4), Some(0x101));
        let body = &bytes[NLMSG_HDRLEN + 4..];
        let found: Vec<_> = attributes(body).collect();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, 1);
        assert_eq!(attribute(found[0].1, 2), Some(&[1u8, 2, 3][..]));
        assert_eq!(be32(found[1].1), Some(7));
    }

    #[test]
    fn a_dump_ends_at_done() {
        let mut buf = datagram(0x100, &[9, 9, 9, 9]);
        buf.extend(datagram(NLMSG_DONE, &0u32.to_ne_bytes()));
        let batch = split(&buf).unwrap();
        assert_eq!(batch.messages, vec![vec![9, 9, 9, 9]]);
        assert!(batch.done);
    }

    #[test]
    fn an_acknowledgement_ends_a_request() {
        let batch = split(&datagram(NLMSG_ERROR, &[0u8; 20])).unwrap();
        assert!(batch.messages.is_empty());
        assert!(batch.done);
    }

    #[test]
    fn an_error_reply_is_the_kernel_error() {
        let mut body = (-libc::ENOENT).to_ne_bytes().to_vec();
        body.extend_from_slice(&[0u8; 16]);
        let err = split(&datagram(NLMSG_ERROR, &body)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn a_truncated_attribute_ends_the_walk() {
        let buf = [8u8, 0, 1, 0, 1, 2];
        assert_eq!(attributes(&buf).count(), 0);
    }
}
