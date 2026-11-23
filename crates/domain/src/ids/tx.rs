//! A side of an application transaction, ready for inspection: the buffers
//! the protocol's parser filled, as Suricata fills them.

use std::sync::Arc;

/// The buffers of one side of a transaction: each name once, or once per
/// instance for a buffer holding several (`http.request_header`,
/// `dns.query`). An integer field (`dns.opcode`) is held as its eight
/// big-endian bytes, once per value.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Fields {
    entries: Vec<(&'static str, Vec<u8>)>,
}

impl Fields {
    /// Add an instance of a buffer, unless it is empty: Suricata inspects
    /// no empty buffer.
    pub(crate) fn put(&mut self, name: &'static str, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.entries.push((name, bytes));
        }
    }

    /// Add a value of an integer field.
    pub(crate) fn put_int(&mut self, name: &'static str, value: u64) {
        self.entries.push((name, value.to_be_bytes().to_vec()));
    }

    /// The `index`th instance of a buffer.
    #[must_use]
    pub fn get(&self, name: &str, index: usize) -> Option<&[u8]> {
        self.entries
            .iter()
            .filter(|(n, _)| *n == name)
            .nth(index)
            .map(|(_, b)| b.as_slice())
    }

    /// Whether the side holds this buffer.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| *n == name)
    }
}

/// Read back a value [`Fields::put_int`] stored.
#[must_use]
pub fn int_of(bytes: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_be_bytes)
}

/// A transaction side ready for inspection.
#[derive(Debug, Clone)]
pub struct Ready {
    /// The transaction's number on its connection, from 0.
    pub id: u64,
    /// 0 for the request, 1 for the response.
    pub side: usize,
    pub fields: Arc<Fields>,
    /// The message's bytes as they travelled, for a rule that reads the
    /// payload beside the transaction's buffers; empty where the protocol
    /// offers no such reading.
    pub payload: Arc<[u8]>,
    /// Whether the message is whole, its body read to the end: an HTTP
    /// message then has its sender's stream inspected.
    pub whole: bool,
    /// Whether this side holds everything an earlier one of the same
    /// transaction held, so that it takes that one's place while both wait
    /// for inspection: the state of a protocol inspected as it stands
    /// rather than message by message.
    pub latest: bool,
    /// Whether this side will hold nothing more: once inspected, a later
    /// one of the same transaction is not, as an engine that stops
    /// inspecting a side once its part of the exchange is over.
    pub last: bool,
}
