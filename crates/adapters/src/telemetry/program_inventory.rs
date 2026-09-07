//! Reading which eBPF programs are loaded.
//!
//! The agent already keeps this: one map, written once at startup, served to
//! the operator on `/api/v1/ebpf/programs`. This adapter reads that map rather
//! than walking the loaders a second time, because a second inventory would
//! drift from the one the operator can see, and the first time those two
//! disagree is the last time either is believed.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use domain::telemetry::entity::{ProgramReport, ProgramState};
use ports::secondary::telemetry_port::ProgramInventory;
use tokio::sync::RwLock;

/// Reads the agent's own program status map.
#[derive(Debug, Clone)]
pub struct SharedProgramInventory {
    status: Arc<RwLock<HashMap<String, bool>>>,
}

impl SharedProgramInventory {
    /// Wraps the map the agent already fills at startup.
    #[must_use]
    pub fn new(status: Arc<RwLock<HashMap<String, bool>>>) -> Self {
        Self { status }
    }
}

impl ProgramInventory for SharedProgramInventory {
    fn programs<'a>(&'a self) -> Pin<Box<dyn Future<Output = Vec<ProgramReport>> + Send + 'a>> {
        Box::pin(async move {
            self.status
                .read()
                .await
                .iter()
                .map(|(program, loaded)| ProgramReport {
                    program: program.clone(),
                    state: ProgramState::from(*loaded),
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_program_the_agent_knows_about_is_reported_with_its_state() {
        // The map is filled with the published names, which is what makes the
        // beacon's programs the ones an operator reads off `/metrics` and off
        // the ops endpoint rather than a third spelling nobody sees anywhere.
        let status = Arc::new(RwLock::new(HashMap::from([
            ("xdp-firewall".to_string(), true),
            ("tc-dns".to_string(), false),
        ])));

        let mut reported = SharedProgramInventory::new(status).programs().await;
        reported.sort_by(|a, b| a.program.cmp(&b.program));

        assert_eq!(reported.len(), 2);
        assert_eq!(reported[0].program, "tc-dns");
        assert_eq!(reported[0].state, ProgramState::NotLoaded);
        assert_eq!(reported[1].program, "xdp-firewall");
        assert_eq!(reported[1].state, ProgramState::Loaded);
    }

    #[tokio::test]
    async fn an_agent_that_loaded_nothing_reports_an_empty_list_rather_than_failing() {
        let status = Arc::new(RwLock::new(HashMap::new()));
        assert!(
            SharedProgramInventory::new(status)
                .programs()
                .await
                .is_empty()
        );
    }
}
