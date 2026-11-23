//! Turning an L7 `deny` or `reject` verdict into a refused connection.
//!
//! The rule engine judges a request after the classifier captured it, so the
//! request itself has already been forwarded by the time a verdict exists.
//! What the verdict can still stop is everything after it: the reply, and
//! every later segment either way. This service writes the connection into
//! the table the classifier reads, and the classifier shoots those packets.
//!
//! The table belongs to whichever `tc-ids` object is loaded, so it is handed
//! over on every load and taken back on every detach. Between the two there
//! is no table, and a verdict reached then is reported as not enforced
//! rather than counted as a drop.

use std::sync::{Mutex, PoisonError};

use domain::common::error::DomainError;
use ports::secondary::l7_flow_refusal_port::{L7FlowRefusalMapPort, RefusedL7Flow};

/// Holds the loaded classifier's table of refused connections, if any.
#[derive(Default)]
pub struct L7FlowRefusalService {
    map: Mutex<Option<Box<dyn L7FlowRefusalMapPort>>>,
}

impl std::fmt::Debug for L7FlowRefusalService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L7FlowRefusalService")
            .field("installed", &self.installed())
            .finish()
    }
}

impl L7FlowRefusalService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hand over the table of a freshly loaded classifier.
    pub fn set_map(&self, map: Box<dyn L7FlowRefusalMapPort>) {
        // A poisoned lock holds an `Option` written whole, still valid.
        *self.map.lock().unwrap_or_else(PoisonError::into_inner) = Some(map);
    }

    /// Forget the table: the classifier that owned it is gone.
    pub fn clear_map(&self) {
        *self.map.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Whether a classifier's table is held, so a refusal can be enforced.
    pub fn installed(&self) -> bool {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Refuse the connection the request travelled on, in both directions.
    ///
    /// Fails when no classifier is loaded, or when the kernel refused the
    /// write; either way nothing will stop the connection.
    pub fn refuse(&self, flow: &RefusedL7Flow) -> Result<(), DomainError> {
        let mut guard = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        match guard.as_mut() {
            Some(map) => map.refuse(flow),
            None => Err(DomainError::EngineError(
                "no tc-ids classifier is loaded to hold the refused connection".to_string(),
            )),
        }
    }
}

/// FNV-1a over the rule id: a stable 32-bit name for the rule in a kernel
/// table, where a string does not fit.
pub fn rule_hash(rule_id: &str) -> u32 {
    rule_id.bytes().fold(0x811c_9dc5_u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Default)]
    struct Recorded(Arc<Mutex<Vec<RefusedL7Flow>>>);

    impl L7FlowRefusalMapPort for Recorded {
        fn refuse(&mut self, flow: &RefusedL7Flow) -> Result<(), DomainError> {
            self.0.lock().unwrap().push(*flow);
            Ok(())
        }
    }

    fn flow() -> RefusedL7Flow {
        RefusedL7Flow {
            src_addr: [0x0a00_0001, 0, 0, 0],
            dst_addr: [0x0a00_0002, 0, 0, 0],
            src_port: 40_000,
            dst_port: 8888,
            ipv6: false,
            rule_hash: rule_hash("l7-deny-admin"),
        }
    }

    #[test]
    fn a_refusal_without_a_loaded_classifier_is_an_error_not_a_drop() {
        let svc = L7FlowRefusalService::new();
        assert!(!svc.installed());
        assert!(svc.refuse(&flow()).is_err());
    }

    #[test]
    fn a_refusal_reaches_the_table_and_stops_once_it_is_taken_back() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let svc = L7FlowRefusalService::new();
        svc.set_map(Box::new(Recorded(Arc::clone(&seen))));
        svc.refuse(&flow()).unwrap();
        assert_eq!(seen.lock().unwrap().as_slice(), &[flow()]);
        svc.clear_map();
        assert!(svc.refuse(&flow()).is_err());
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_rule_hash_is_fnv1a() {
        // Reference values of 32-bit FNV-1a.
        assert_eq!(rule_hash(""), 0x811c_9dc5);
        assert_eq!(rule_hash("a"), 0xe40c_292c);
        assert_eq!(rule_hash("foobar"), 0xbf9c_f968);
    }
}
