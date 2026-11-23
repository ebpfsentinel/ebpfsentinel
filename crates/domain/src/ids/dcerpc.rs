//! DCE/RPC read as Suricata 8 reads it, into what `dcerpc.iface`,
//! `dcerpc.opnum` and `dcerpc.stub_data` compare.
//!
//! Over a connection (straight over TCP, or in a named pipe of SMB) the
//! client binds presentation contexts to interfaces, the server accepts or
//! refuses each in its acknowledgement, an alter context adds more, and each
//! request names a context and an operation. Every request PDU is a
//! transaction, a fragment as much as a whole call; its response is the
//! next response PDU with the same call id. The transaction's interface is
//! the one its context was bound to, once the server accepted the binding,
//! and its version is the interface's major version. The stub data is what
//! follows the request or response header to the end of the PDU, an
//! authentication verifier included.
//!
//! Both sides of a transaction carry its interface and operation number;
//! the request side carries the request's stub, the response side the
//! response's once it arrived. Each is offered again whenever it changes,
//! and whenever an acknowledgement binds a context, so that a rule whose
//! interface did not hold yet is tried again.
//!
//! Over UDP a datagram of version 4 is a request or a response, its stub
//! after the 80-byte header; Suricata compares neither interface nor
//! operation number there, only the stub.
//!
//! Every PDU of a segment is read, where Suricata 8.0.8 reads one after the
//! first only when the bytes left fit within the first one's body.
//!
//! These rules are held to Suricata by
//! `tests/fixtures/suricata/dcerpc-verdicts.txt`.

use std::sync::Arc;

use super::tx::{Fields, Ready};

/// The 16 bytes every connection-oriented PDU opens with.
const HEADER: usize = 16;

/// The bytes a request or response header holds after the common one.
const CALL_HEADER: usize = 8;

/// The most bytes a direction holds while a PDU is incomplete.
const PENDING_LIMIT: usize = 256 * 1024;

/// The most transactions a connection keeps open for their responses and
/// for a later binding.
const OPEN_CALLS: usize = 32;

/// The most contexts a connection remembers.
const CONTEXTS: usize = 64;

/// The header of a connectionless PDU.
const DATAGRAM_HEADER: usize = 80;

const REQUEST: u8 = 0;
const RESPONSE: u8 = 2;
const BIND: u8 = 11;
const BIND_ACK: u8 = 12;
const ALTER_CONTEXT: u8 = 14;
const ALTER_CONTEXT_RESP: u8 = 15;

/// The header flag saying an object UUID follows a request's header.
const OBJECT_UUID: u8 = 0x80;

/// A presentation context the client proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Context {
    id: u16,
    /// The interface UUID, in the order its text is written.
    uuid: [u8; 16],
    major: u16,
    minor: u16,
    accepted: bool,
}

/// A request PDU and what answered it.
#[derive(Debug, Clone)]
struct Call {
    id: u64,
    wire_id: u32,
    context: u16,
    opnum: u16,
    request: Arc<[u8]>,
    stub: Vec<u8>,
    response: Option<(Arc<[u8]>, Vec<u8>)>,
}

/// One direction's bytes not yet making a whole PDU.
#[derive(Debug, Clone, Default)]
struct Stream {
    pending: Vec<u8>,
    /// The bytes stopped being PDUs.
    lost: bool,
}

/// What a connection said in DCE/RPC.
#[derive(Debug, Clone, Default)]
pub struct Dcerpc {
    streams: [Stream; 2],
    contexts: Vec<Context>,
    /// The contexts of the last bind or alter context, waiting for their
    /// acknowledgement.
    proposed: Vec<Context>,
    calls: Vec<Call>,
    next_id: u64,
}

/// A 16-bit integer in the PDU's byte order.
fn u16_at(bytes: &[u8], at: usize, little: bool) -> Option<u16> {
    let pair: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(pair)
    } else {
        u16::from_be_bytes(pair)
    })
}

/// A 32-bit integer in the PDU's byte order.
fn u32_at(bytes: &[u8], at: usize, little: bool) -> Option<u32> {
    let quad: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(quad)
    } else {
        u32::from_be_bytes(quad)
    })
}

/// A UUID as it travels, its first three fields in the PDU's byte order,
/// put in the order its text is written.
fn uuid_at(bytes: &[u8], at: usize, little: bool) -> Option<[u8; 16]> {
    let mut uuid: [u8; 16] = bytes.get(at..at + 16)?.try_into().ok()?;
    if little {
        uuid[..4].reverse();
        uuid[4..6].reverse();
        uuid[6..8].reverse();
    }
    Some(uuid)
}

/// The value `dcerpc.iface` compares: the UUID then the major and minor
/// versions, big-endian.
fn iface_value(context: &Context) -> Vec<u8> {
    let mut value = context.uuid.to_vec();
    value.extend_from_slice(&context.major.to_be_bytes());
    value.extend_from_slice(&context.minor.to_be_bytes());
    value
}

impl Dcerpc {
    /// Take the bytes `side` sent, in order, and hand back the transaction
    /// sides they changed.
    pub fn feed(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        let mut out = Vec::new();
        if self.streams[side].lost {
            return out;
        }
        self.streams[side].pending.extend_from_slice(bytes);
        let mut at = 0;
        loop {
            let rest = &self.streams[side].pending[at..];
            let Some(header) = rest.get(..HEADER) else {
                break;
            };
            let little = header[4] & 0x10 != 0;
            let len = usize::from(u16_at(header, 8, little).unwrap_or(0));
            if header[..2] != [5, 0] || len < HEADER {
                self.streams[side] = Stream {
                    pending: Vec::new(),
                    lost: true,
                };
                return out;
            }
            if rest.len() < len {
                break;
            }
            let pdu = rest[..len].to_vec();
            at += len;
            self.pdu(side, &pdu, &mut out);
        }
        let stream = &mut self.streams[side];
        stream.pending.drain(..at);
        if stream.pending.len() > PENDING_LIMIT {
            *stream = Stream {
                pending: Vec::new(),
                lost: true,
            };
        }
        out
    }

    /// Read one whole PDU.
    fn pdu(&mut self, side: usize, pdu: &[u8], out: &mut Vec<Ready>) {
        let little = pdu[4] & 0x10 != 0;
        let call_id = u32_at(pdu, 12, little).unwrap_or(0);
        match (pdu[2], side) {
            (REQUEST, 0) => self.request(pdu, little, call_id, out),
            (RESPONSE, 1) => self.response(pdu, little, call_id, out),
            (BIND | ALTER_CONTEXT, 0) => self.bind(pdu, little, pdu[2] == BIND),
            (BIND_ACK | ALTER_CONTEXT_RESP, 1) => self.bind_ack(pdu, little, out),
            _ => {}
        }
    }

    fn request(&mut self, pdu: &[u8], little: bool, call_id: u32, out: &mut Vec<Ready>) {
        let (Some(context), Some(opnum)) = (u16_at(pdu, 20, little), u16_at(pdu, 22, little))
        else {
            return;
        };
        let mut start = HEADER + CALL_HEADER;
        if pdu[3] & OBJECT_UUID != 0 {
            start += 16;
        }
        let stub = pdu.get(start..).unwrap_or_default().to_vec();
        let call = Call {
            id: self.next_id,
            wire_id: call_id,
            context,
            opnum,
            request: Arc::from(pdu),
            stub,
            response: None,
        };
        self.next_id += 1;
        if self.calls.len() >= OPEN_CALLS {
            self.calls.remove(0);
        }
        self.calls.push(call);
        let index = self.calls.len() - 1;
        self.offer(index, out);
    }

    fn response(&mut self, pdu: &[u8], _little: bool, call_id: u32, out: &mut Vec<Ready>) {
        let Some(index) = self
            .calls
            .iter()
            .rposition(|c| c.wire_id == call_id && c.response.is_none())
        else {
            return;
        };
        let stub = pdu.get(HEADER + CALL_HEADER..).unwrap_or_default().to_vec();
        self.calls[index].response = Some((Arc::from(pdu), stub));
        self.offer(index, out);
    }

    /// A bind or an alter context: the contexts it proposes wait for the
    /// server's answer. A bind starts the association over.
    fn bind(&mut self, pdu: &[u8], little: bool, fresh: bool) {
        let Some(&count) = pdu.get(HEADER + 8) else {
            return;
        };
        let mut at = HEADER + 12;
        let mut proposed = Vec::new();
        for _ in 0..count {
            let (Some(id), Some(&syntaxes), Some(uuid), Some(major), Some(minor)) = (
                u16_at(pdu, at, little),
                pdu.get(at + 2),
                uuid_at(pdu, at + 4, little),
                u16_at(pdu, at + 20, little),
                u16_at(pdu, at + 22, little),
            ) else {
                break;
            };
            proposed.push(Context {
                id,
                uuid,
                major,
                minor,
                accepted: false,
            });
            at += 24 + 20 * usize::from(syntaxes);
        }
        if fresh {
            self.contexts.clear();
        }
        self.proposed = proposed;
    }

    /// The server's answer to the contexts proposed last, one result each in
    /// order: the accepted ones bind, and every open transaction is offered
    /// again.
    fn bind_ack(&mut self, pdu: &[u8], little: bool, out: &mut Vec<Ready>) {
        let Some(address) = u16_at(pdu, HEADER + 8, little) else {
            return;
        };
        let mut at = HEADER + 10 + usize::from(address);
        at = at.next_multiple_of(4);
        let Some(&count) = pdu.get(at) else {
            return;
        };
        at += 4;
        let proposed = std::mem::take(&mut self.proposed);
        let mut bound = false;
        for (n, context) in proposed.into_iter().enumerate() {
            if n >= usize::from(count) {
                break;
            }
            let Some(result) = u16_at(pdu, at + 24 * n, little) else {
                break;
            };
            self.contexts.retain(|c| c.id != context.id);
            if self.contexts.len() >= CONTEXTS {
                self.contexts.remove(0);
            }
            self.contexts.push(Context {
                accepted: result == 0,
                ..context
            });
            bound |= result == 0;
        }
        if bound {
            for index in 0..self.calls.len() {
                self.offer(index, out);
            }
        }
    }

    /// Both sides of a transaction as they now stand.
    fn offer(&self, index: usize, out: &mut Vec<Ready>) {
        let call = &self.calls[index];
        let iface = self
            .contexts
            .iter()
            .find(|c| c.id == call.context && c.accepted)
            .map(iface_value);
        for side in 0..2 {
            let mut fields = Fields::default();
            fields.put_int("dcerpc.opnum", u64::from(call.opnum));
            if let Some(iface) = &iface {
                fields.put("dcerpc.iface", iface.clone());
            }
            let payload = if side == 0 {
                fields.put("dcerpc.stub_data", call.stub.clone());
                Arc::clone(&call.request)
            } else if let Some((pdu, stub)) = &call.response {
                fields.put("dcerpc.stub_data", stub.clone());
                Arc::clone(pdu)
            } else {
                Arc::from(&[][..])
            };
            out.push(Ready {
                id: call.id,
                side,
                fields: Arc::new(fields),
                payload,
                whole: false,
                latest: true,
                last: false,
            });
        }
    }

    /// A connectionless datagram `side` sent: a request or a response of
    /// version 4, its stub after the header.
    pub fn datagram(&mut self, side: usize, datagram: &[u8]) -> Vec<Ready> {
        let Some(header) = datagram.get(..DATAGRAM_HEADER) else {
            return Vec::new();
        };
        if header[0] != 4 || !matches!(header[1], REQUEST | RESPONSE) {
            return Vec::new();
        }
        let little = header[4] & 0x10 != 0;
        let len = usize::from(u16_at(header, 74, little).unwrap_or(0));
        let stub = datagram
            .get(DATAGRAM_HEADER..DATAGRAM_HEADER + len)
            .unwrap_or(&datagram[DATAGRAM_HEADER..]);
        let mut fields = Fields::default();
        fields.put("dcerpc.stub_data", stub.to_vec());
        let id = self.next_id;
        self.next_id += 1;
        vec![Ready {
            id,
            side,
            fields: Arc::new(fields),
            payload: Arc::from(datagram),
            whole: false,
            latest: true,
            last: false,
        }]
    }
}

/// A UUID written as text, in the order [`Dcerpc`] holds it.
#[must_use]
pub fn uuid_of(text: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0; 16];
    for (n, pair) in hex.chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        out[n] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRVSVC: &str = "4b324fc8-1670-01d3-1278-5a47bf6ee188";

    fn co(ptype: u8, body: &[u8], call: u32) -> Vec<u8> {
        let len = u16::try_from(HEADER + body.len()).unwrap();
        let mut pdu = vec![5, 0, ptype, 3, 0x10, 0, 0, 0];
        pdu.extend_from_slice(&len.to_le_bytes());
        pdu.extend_from_slice(&[0, 0]);
        pdu.extend_from_slice(&call.to_le_bytes());
        pdu.extend_from_slice(body);
        pdu
    }

    fn bind(uuid: &str) -> Vec<u8> {
        let mut body = vec![0x10, 0x10, 0x10, 0x10, 0, 0, 0, 0, 1, 0, 0, 0];
        body.extend_from_slice(&[0, 0, 1, 0]);
        let mut wire = uuid_of(uuid).unwrap();
        wire[..4].reverse();
        wire[4..6].reverse();
        wire[6..8].reverse();
        body.extend_from_slice(&wire);
        body.extend_from_slice(&[3, 0, 0, 0]);
        body.extend_from_slice(&[0; 20]);
        co(BIND, &body, 1)
    }

    fn bind_ack(result: u16) -> Vec<u8> {
        let mut body = vec![0x10, 0x10, 0x10, 0x10, 0, 0, 0, 0, 2, 0, b'x', 0];
        body.extend_from_slice(&[1, 0, 0, 0]);
        body.extend_from_slice(&result.to_le_bytes());
        body.extend_from_slice(&[0; 22]);
        co(BIND_ACK, &body, 1)
    }

    fn request(opnum: u16, stub: &[u8], call: u32) -> Vec<u8> {
        let mut body = vec![0; 4];
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&opnum.to_le_bytes());
        body.extend_from_slice(stub);
        co(REQUEST, &body, call)
    }

    #[test]
    fn a_call_carries_the_interface_once_the_server_accepted_it() {
        let mut d = Dcerpc::default();
        assert_eq!(
            d.feed(0, &[bind(SRVSVC), request(31, b"STUB", 2)].concat())
                .len(),
            2
        );
        let before = d.feed(0, &[]);
        assert!(before.is_empty());
        let after = d.feed(1, &bind_ack(0));
        assert_eq!(after.len(), 2);
        let iface = after[0].fields.get("dcerpc.iface", 0).unwrap();
        assert_eq!(&iface[..16], &uuid_of(SRVSVC).unwrap());
        assert_eq!(&iface[16..18], &[0, 3]);
        assert_eq!(
            after[0].fields.get("dcerpc.stub_data", 0),
            Some(&b"STUB"[..])
        );
        assert!(!after[1].fields.has("dcerpc.stub_data"));
    }

    #[test]
    fn a_refused_binding_names_no_interface() {
        let mut d = Dcerpc::default();
        d.feed(0, &bind(SRVSVC));
        assert!(d.feed(1, &bind_ack(2)).is_empty());
        let call = d.feed(0, &request(31, b"STUB", 2));
        assert!(!call[0].fields.has("dcerpc.iface"));
        assert!(call[0].fields.has("dcerpc.opnum"));
    }

    #[test]
    fn every_pdu_of_a_segment_is_read() {
        let mut d = Dcerpc::default();
        let three = [
            request(31, b"ONE", 2),
            request(7, b"TWO", 3),
            request(8, b"THREE", 4),
        ]
        .concat();
        assert_eq!(d.feed(0, &three).len(), 6);
    }

    #[test]
    fn a_response_answers_the_latest_call_of_its_id() {
        let mut d = Dcerpc::default();
        d.feed(
            0,
            &[request(31, b"..AB", 2), request(31, b"CD", 2)].concat(),
        );
        let body = [&[0u8; 8][..], b"RESP"].concat();
        let answered = d.feed(1, &co(RESPONSE, &body, 2));
        assert_eq!(answered.len(), 2);
        assert_eq!(answered[0].id, 1);
        assert_eq!(
            answered[1].fields.get("dcerpc.stub_data", 0),
            Some(&b"RESP"[..])
        );
    }

    #[test]
    fn bytes_that_are_no_pdu_stop_the_direction() {
        let mut d = Dcerpc::default();
        assert!(d.feed(0, b"GET / HTTP/1.1\r\n\r\n").is_empty());
        assert!(d.feed(0, &request(31, b"STUB", 2)).is_empty());
    }

    #[test]
    fn a_datagram_carries_its_stub_alone() {
        let mut d = Dcerpc::default();
        let mut datagram = vec![0u8; DATAGRAM_HEADER];
        datagram[0] = 4;
        datagram[4] = 0x10;
        datagram[74] = 5;
        datagram.extend_from_slice(b"STUBXtrailing");
        let ready = d.datagram(0, &datagram);
        assert_eq!(
            ready[0].fields.get("dcerpc.stub_data", 0),
            Some(&b"STUBX"[..])
        );
        assert!(!ready[0].fields.has("dcerpc.opnum"));
    }
}
