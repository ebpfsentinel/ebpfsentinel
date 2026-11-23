//! The signature engine: a Suricata 8 rule read into a typed model, every
//! option checked the way the Suricata documentation writes it.

pub mod buffers;
pub mod field;
pub mod inspect;
pub mod int;
pub mod model;
pub(crate) mod parse;

pub use parse::parse_signature;
