//! The DCE/RPC carried in the named pipes of an SMB conversation, handed to
//! [`Dcerpc`] as Suricata 8 hands it.
//!
//! What a client writes to a tree and what it reads back from it is read as
//! DCE/RPC unless the tree's connect response named a disk share: SMB2's
//! share type 1, SMB1's service `A:`. A tree whose connect was not seen
//! counts as a pipe. A pipe transaction, SMB2's `FSCTL_PIPE_TRANSCEIVE`
//! control and SMB1's `TransactNmPipe`, is read as DCE/RPC on whatever tree
//! it names, its request and its response alike.
//!
//! These rules are held to Suricata by
//! `tests/fixtures/suricata/dcerpc-verdicts.txt`.

use super::dcerpc::Dcerpc;
use super::tx::Ready;

/// The most bytes a direction holds while a session message is incomplete.
const PENDING_LIMIT: usize = 1024 * 1024;

/// The most trees and pending pipe transactions a connection remembers.
const REMEMBERED: usize = 64;

const SMB2_HEADER: usize = 64;
const SMB1_HEADER: usize = 32;

const SMB2_TREE_CONNECT: u16 = 3;
const SMB2_READ: u16 = 8;
const SMB2_WRITE: u16 = 9;
const SMB2_IOCTL: u16 = 11;
const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

const SMB1_TREE_CONNECT_ANDX: u8 = 0x75;
const SMB1_READ_ANDX: u8 = 0x2E;
const SMB1_WRITE_ANDX: u8 = 0x2F;
const SMB1_TRANS: u8 = 0x25;
const TRANSACT_NM_PIPE: u16 = 0x26;

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// `len` bytes at `offset` of a message, when they are all there.
fn slice(message: &[u8], offset: Option<usize>, len: Option<usize>) -> Option<&[u8]> {
    let (offset, len) = (offset?, len?);
    message.get(offset..offset.checked_add(len)?)
}

/// What a connection said in SMB, as far as its pipes go.
#[derive(Debug, Clone, Default)]
pub struct Smb {
    pending: [Vec<u8>; 2],
    lost: [bool; 2],
    /// Each tree whose connect response was seen, and whether it is a disk.
    trees: Vec<(u32, bool)>,
    /// The SMB1 pipe transactions waiting for their response, by mid.
    transactions: Vec<u16>,
    rpc: Dcerpc,
}

impl Smb {
    /// Take the bytes `side` sent, in order, and hand back the DCE/RPC
    /// transaction sides they changed.
    pub fn feed(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        let mut out = Vec::new();
        if self.lost[side] {
            return out;
        }
        self.pending[side].extend_from_slice(bytes);
        let mut at = 0;
        while let Some(head) = self.pending[side].get(at..at + 4) {
            let len =
                usize::from(head[1] & 1) << 16 | usize::from(head[2]) << 8 | usize::from(head[3]);
            let kind = head[0];
            let Some(message) = self.pending[side].get(at + 4..at + 4 + len) else {
                break;
            };
            let message = message.to_vec();
            at += 4 + len;
            if kind == 0 {
                self.message(side, &message, &mut out);
            }
        }
        self.pending[side].drain(..at);
        if self.pending[side].len() > PENDING_LIMIT {
            self.pending[side] = Vec::new();
            self.lost[side] = true;
        }
        out
    }

    fn message(&mut self, side: usize, message: &[u8], out: &mut Vec<Ready>) {
        match message.get(..4) {
            Some(b"\xfeSMB") => {
                let mut at = 0;
                while let Some(rest) = message.get(at..) {
                    self.smb2(side, rest, out);
                    match u32_at(rest, 20).map(|n| n as usize) {
                        Some(next) if next >= SMB2_HEADER => at += next,
                        _ => break,
                    }
                }
            }
            Some(b"\xffSMB") => self.smb1(side, message, out),
            _ => {}
        }
    }

    fn disk(&self, tree: u32) -> bool {
        self.trees.iter().any(|&(t, disk)| t == tree && disk)
    }

    fn tree(&mut self, tree: u32, disk: bool) {
        self.trees.retain(|&(t, _)| t != tree);
        if self.trees.len() >= REMEMBERED {
            self.trees.remove(0);
        }
        self.trees.push((tree, disk));
    }

    /// One SMB2 message, its header first.
    fn smb2(&mut self, side: usize, m: &[u8], out: &mut Vec<Ready>) {
        let (Some(command), Some(flags), Some(status)) =
            (u16_at(m, 12), u32_at(m, 16), u32_at(m, 8))
        else {
            return;
        };
        let reply = flags & 1 != 0;
        if reply != (side == 1) || (reply && status != 0) {
            return;
        }
        let tree = if flags & 2 == 0 { u32_at(m, 36) } else { None };
        let body = SMB2_HEADER;
        let pipe = |s: &Self| tree.is_none_or(|t| !s.disk(t));
        let data = match (command, reply) {
            (SMB2_TREE_CONNECT, true) => {
                if let (Some(tree), Some(&kind)) = (tree, m.get(body + 2)) {
                    self.tree(tree, kind == 1);
                }
                None
            }
            (SMB2_WRITE, false) if pipe(self) => slice(
                m,
                u16_at(m, body + 2).map(usize::from),
                u32_at(m, body + 4).map(|n| n as usize),
            ),
            (SMB2_READ, true) if pipe(self) => slice(
                m,
                m.get(body + 2).copied().map(usize::from),
                u32_at(m, body + 4).map(|n| n as usize),
            ),
            (SMB2_IOCTL, false) if u32_at(m, body + 4) == Some(FSCTL_PIPE_TRANSCEIVE) => slice(
                m,
                u32_at(m, body + 24).map(|n| n as usize),
                u32_at(m, body + 28).map(|n| n as usize),
            ),
            (SMB2_IOCTL, true) if u32_at(m, body + 4) == Some(FSCTL_PIPE_TRANSCEIVE) => slice(
                m,
                u32_at(m, body + 32).map(|n| n as usize),
                u32_at(m, body + 36).map(|n| n as usize),
            ),
            _ => None,
        };
        if let Some(data) = data {
            out.extend(self.rpc.feed(side, data));
        }
    }

    /// One SMB1 message: its first command, the others of a chain left.
    fn smb1(&mut self, side: usize, m: &[u8], out: &mut Vec<Ready>) {
        let (Some(&command), Some(&flags), Some(status), Some(tid), Some(mid)) = (
            m.get(4),
            m.get(9),
            u32_at(m, 5),
            u16_at(m, 24),
            u16_at(m, 30),
        ) else {
            return;
        };
        let reply = flags & 0x80 != 0;
        if reply != (side == 1) || (reply && status != 0) {
            return;
        }
        let Some(&count) = m.get(SMB1_HEADER) else {
            return;
        };
        let words = SMB1_HEADER + 1;
        let bytes = words + 2 * usize::from(count) + 2;
        let tree = u32::from(tid);
        let pipe = !self.disk(tree);
        let word = |at: usize| u16_at(m, words + at).map(usize::from);
        let data = match (command, reply) {
            (SMB1_TREE_CONNECT_ANDX, true) => {
                let service = m.get(bytes..).unwrap_or_default();
                self.tree(tree, service.starts_with(b"A:\0"));
                None
            }
            (SMB1_WRITE_ANDX, false) if pipe => slice(m, word(22), word(20)),
            (SMB1_READ_ANDX, true) if pipe => slice(m, word(12), word(10)),
            (SMB1_TRANS, false)
                if count >= 16 && word(28) == Some(usize::from(TRANSACT_NM_PIPE)) =>
            {
                if self.transactions.len() >= REMEMBERED {
                    self.transactions.remove(0);
                }
                self.transactions.push(mid);
                slice(m, word(24), word(22))
            }
            (SMB1_TRANS, true) if self.transactions.contains(&mid) => {
                self.transactions.retain(|&t| t != mid);
                slice(m, word(14), word(12))
            }
            _ => None,
        };
        if let Some(data) = data {
            out.extend(self.rpc.feed(side, data));
        }
    }
}
