//! Putting the containment decisions back in force after a restart.
//!
//! A blocked source and a response action are written down when they are
//! taken, which leaves this with one question per record: how much of the TTL
//! is left. What elapsed while the agent was down is dropped on the way in,
//! and what is left is installed for its remaining time rather than for its
//! original TTL, so a restart never extends containment and a restart loop
//! never turns an hour into forever.
//!
//! Every restored decision is audited under `ChangeActor::Restore`, or, for a
//! response action, with a detail line naming the restart: a reader who cannot
//! tell a restored block from a fresh one reads the same address being blocked
//! twice.
//!
//! What is deliberately not restored is the rate limiter's token state. A
//! throttle's rate comes back, the credit the source had spent against its
//! bucket does not: the buckets live in a kernel map that went with the old
//! process, and a source therefore gets one bucket's worth of burst across a
//! restart.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use application::audit_service_impl::AuditAppService;
use application::ips_service_impl::IpsAppService;
use application::ratelimit_service_impl::RateLimitAppService;
use arc_swap::ArcSwap;
use domain::audit::entity::{AuditAction, AuditComponent};
use domain::audit::rule_change::ChangeActor;
use domain::response::engine::ResponseEngine;
use ports::secondary::mitigation_store::MitigationStore;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// What came back, and what did not.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Restored {
    /// Blocked sources put back in force.
    pub blocks: usize,
    /// Blocked sources whose TTL elapsed while the agent was down.
    pub blocks_elapsed: usize,
    /// Response actions put back in force.
    pub actions: usize,
    /// Response actions that elapsed, were revoked, or no longer fit the
    /// configured TTL ceiling.
    pub actions_elapsed: usize,
    /// Decisions the data plane refused to take back.
    pub failed: usize,
}

impl Restored {
    /// Whether the store held nothing worth reporting.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self == Self::default()
    }
}

fn now_ns(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Read the store back and re-install what is still in force.
///
/// Called once, after the eBPF programs are loaded and the services hold their
/// map ports, because a block installed before that would be in a service's
/// memory and not in the datapath.
pub async fn restore_mitigations(
    store: &Arc<dyn MitigationStore>,
    ips_svc: &ArcSwap<IpsAppService>,
    rl_svc: &RwLock<RateLimitAppService>,
    response_engine: &RwLock<ResponseEngine>,
    audit_svc: &AuditAppService,
    now: SystemTime,
) -> Restored {
    let mut restored = restore_blocks(store, ips_svc, audit_svc, now);
    restore_actions(
        store,
        ips_svc,
        rl_svc,
        response_engine,
        audit_svc,
        now_ns(now),
        &mut restored,
    )
    .await;

    if !restored.is_empty() {
        info!(
            blocks = restored.blocks,
            blocks_elapsed = restored.blocks_elapsed,
            actions = restored.actions,
            actions_elapsed = restored.actions_elapsed,
            failed = restored.failed,
            "mitigations in force before the restart put back"
        );
    }

    restored
}

/// Re-install the blocked sources, each for what is left of its TTL.
fn restore_blocks(
    store: &Arc<dyn MitigationStore>,
    ips_svc: &ArcSwap<IpsAppService>,
    audit_svc: &AuditAppService,
    now: SystemTime,
) -> Restored {
    let mut restored = Restored::default();
    let blocks = match store.load_blocks() {
        Ok(blocks) => blocks,
        Err(e) => {
            warn!(error = %e, "the written-down blocks could not be read back");
            return restored;
        }
    };

    for block in blocks {
        let Some(remaining) = block.remaining(now) else {
            forget_block(store, block.ip);
            restored.blocks_elapsed += 1;
            continue;
        };
        match ips_svc.load().restore_block(&block, remaining) {
            Ok(()) => {
                restored.blocks += 1;
                audit_svc.record_rule_change(
                    AuditComponent::Ips,
                    AuditAction::RuleAdded,
                    ChangeActor::Restore,
                    &block.ip.to_string(),
                    None,
                    serde_json::to_string(&serde_json::json!({
                        "ip": block.ip.to_string(),
                        "reason": block.reason,
                        "auto_generated": block.auto_generated,
                        "taken_at_ns": block.added_at_ns,
                        "original_ttl_secs": block.ttl_secs,
                        "remaining_secs": remaining.as_secs(),
                    }))
                    .ok(),
                );
            }
            Err(e) => {
                restored.failed += 1;
                warn!(
                    ip = %block.ip,
                    error = %e,
                    "a block written down before the restart could not be put back"
                );
            }
        }
    }

    restored
}

/// Re-install the response actions, each for what is left of its TTL and only
/// within the TTL ceiling in force now.
async fn restore_actions(
    store: &Arc<dyn MitigationStore>,
    ips_svc: &ArcSwap<IpsAppService>,
    rl_svc: &RwLock<RateLimitAppService>,
    response_engine: &RwLock<ResponseEngine>,
    audit_svc: &AuditAppService,
    at: u64,
    restored: &mut Restored,
) {
    let actions = match store.load_actions() {
        Ok(actions) => actions,
        Err(e) => {
            warn!(error = %e, "the written-down response actions could not be read back");
            return;
        }
    };

    for action in actions {
        if action.is_expired(at) {
            forget_action(store, &action.id);
            restored.actions_elapsed += 1;
            continue;
        }
        // The engine takes the action first, so a TTL ceiling lowered in the
        // configuration while the agent was down is honoured before anything
        // reaches the data plane.
        if let Err(e) = response_engine.write().await.add(action.clone()) {
            forget_action(store, &action.id);
            restored.actions_elapsed += 1;
            info!(
                id = %action.id,
                reason = %e,
                "a response action written down before the restart no longer fits the configuration and was dropped"
            );
            continue;
        }
        let remaining = Duration::from_secs(action.remaining_secs(at));
        match crate::http::response_handler::restore(ips_svc, rl_svc, &action, remaining).await {
            Ok(()) => {
                restored.actions += 1;
                audit_svc.record_response_action(
                    AuditAction::RuleAdded,
                    &action.target,
                    &action.rule_id,
                    &format!(
                        "restored {} response on {} after a restart ({}s of {}s left)",
                        action.action_type.as_str(),
                        action.target,
                        remaining.as_secs(),
                        action.ttl_secs
                    ),
                );
            }
            Err(e) => {
                // Not in force, so it must not be claimed to be: the engine
                // gives it up and the record goes with it.
                response_engine.write().await.revoke(&action.id);
                forget_action(store, &action.id);
                restored.failed += 1;
                warn!(
                    id = %action.id,
                    target = %action.target,
                    error = %e,
                    "a response action written down before the restart could not be put back"
                );
            }
        }
    }
}

fn forget_block(store: &Arc<dyn MitigationStore>, ip: std::net::IpAddr) {
    if let Err(e) = store.remove_block(ip) {
        warn!(%ip, error = %e, "an elapsed block could not be forgotten");
    }
}

fn forget_action(store: &Arc<dyn MitigationStore>, id: &str) {
    if let Err(e) = store.remove_action(id) {
        warn!(%id, error = %e, "an elapsed response action could not be forgotten");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;

    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use domain::common::error::DomainError;
    use domain::ips::engine::IpsEngine;
    use domain::ips::entity::{IpsPolicy, PersistedBlock};
    use domain::ratelimit::engine::RateLimitEngine;
    use domain::response::entity::{ResponseAction, ResponseActionType};
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::MetricsPort;
    use ports::test_utils::NoopMetrics;

    #[derive(Default)]
    struct TestStore {
        blocks: Mutex<HashMap<IpAddr, PersistedBlock>>,
        actions: Mutex<HashMap<String, ResponseAction>>,
    }

    impl MitigationStore for TestStore {
        fn save_block(&self, block: &PersistedBlock) -> Result<(), DomainError> {
            self.blocks.lock().unwrap().insert(block.ip, block.clone());
            Ok(())
        }
        fn remove_block(&self, ip: IpAddr) -> Result<(), DomainError> {
            self.blocks.lock().unwrap().remove(&ip);
            Ok(())
        }
        fn clear_blocks(&self) -> Result<(), DomainError> {
            self.blocks.lock().unwrap().clear();
            Ok(())
        }
        fn load_blocks(&self) -> Result<Vec<PersistedBlock>, DomainError> {
            Ok(self.blocks.lock().unwrap().values().cloned().collect())
        }
        fn save_action(&self, action: &ResponseAction) -> Result<(), DomainError> {
            self.actions
                .lock()
                .unwrap()
                .insert(action.id.clone(), action.clone());
            Ok(())
        }
        fn remove_action(&self, id: &str) -> Result<(), DomainError> {
            self.actions.lock().unwrap().remove(id);
            Ok(())
        }
        fn load_actions(&self) -> Result<Vec<ResponseAction>, DomainError> {
            Ok(self.actions.lock().unwrap().values().cloned().collect())
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        details: Mutex<Vec<String>>,
    }

    impl AuditSink for RecordingSink {
        fn write_entry(&self, entry: &AuditEntry) -> Result<(), AuditError> {
            self.details.lock().unwrap().push(entry.detail.clone());
            Ok(())
        }
    }

    struct Fixture {
        store: Arc<dyn MitigationStore>,
        records: Arc<TestStore>,
        ips: Arc<ArcSwap<IpsAppService>>,
        rl: Arc<RwLock<RateLimitAppService>>,
        engine: Arc<RwLock<ResponseEngine>>,
        audit: Arc<AuditAppService>,
        sink: Arc<RecordingSink>,
    }

    fn fixture(max_ttl_secs: u64) -> Fixture {
        let records = Arc::new(TestStore::default());
        let metrics = Arc::new(NoopMetrics) as Arc<dyn MetricsPort>;
        let sink = Arc::new(RecordingSink::default());
        let mut audit = AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>);
        audit.set_enabled(true);
        Fixture {
            store: Arc::clone(&records) as Arc<dyn MitigationStore>,
            records,
            ips: Arc::new(ArcSwap::from_pointee(IpsAppService::new(
                IpsEngine::new(IpsPolicy::default()),
                Arc::clone(&metrics),
            ))),
            rl: Arc::new(RwLock::new(RateLimitAppService::new(
                RateLimitEngine::new(),
                metrics,
            ))),
            engine: Arc::new(RwLock::new(ResponseEngine::new(max_ttl_secs))),
            audit: Arc::new(audit),
            sink,
        }
    }

    impl Fixture {
        async fn run(&self, now: SystemTime) -> Restored {
            restore_mitigations(
                &self.store,
                &self.ips,
                &self.rl,
                &self.engine,
                &self.audit,
                now,
            )
            .await
        }

        fn audited(&self) -> Vec<String> {
            self.sink.details.lock().unwrap().clone()
        }
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn block_taken(secs_ago: u64, ttl_secs: u64, ip: &str) -> PersistedBlock {
        PersistedBlock {
            ip: ip.parse().expect("an address"),
            reason: "ids threshold reached".to_string(),
            auto_generated: true,
            added_at_ns: u128::from(1_700_000_000 - secs_ago) * 1_000_000_000,
            ttl_secs,
            detection_count: 4,
        }
    }

    fn action_expiring_in(secs: u64, kind: ResponseActionType, id: &str) -> ResponseAction {
        let created_at_ns: u64 = 1_700_000_000 * 1_000_000_000;
        ResponseAction {
            id: id.to_string(),
            action_type: kind,
            target: "203.0.113.20".to_string(),
            ttl_secs: 600,
            created_at_ns,
            expires_at_ns: created_at_ns + secs * 1_000_000_000,
            rule_id: format!("response-{id}"),
            rate_pps: matches!(kind, ResponseActionType::ThrottleIp).then_some(100),
            revoked: false,
        }
    }

    #[tokio::test]
    async fn a_block_still_in_force_comes_back_for_what_is_left_of_it() {
        let f = fixture(86_400);
        let block = block_taken(600, 3600, "203.0.113.11");
        f.store.save_block(&block).expect("the record");

        let outcome = f.run(now()).await;
        assert_eq!(outcome.blocks, 1);
        assert_eq!(outcome.blocks_elapsed, 0);
        assert_eq!(outcome.failed, 0);

        let ips = f.ips.load();
        assert!(ips.is_blacklisted(block.ip), "the address is blocked again");
        let entries = ips.list_blacklist();
        assert_eq!(
            entries[0].ttl,
            Duration::from_mins(50),
            "it is blocked for the fifty minutes left, not for a fresh hour"
        );
        assert_eq!(entries[0].reason, "ids threshold reached");
    }

    #[tokio::test]
    async fn a_restored_block_is_audited_as_restored() {
        let f = fixture(86_400);
        f.store
            .save_block(&block_taken(60, 3600, "203.0.113.12"))
            .expect("the record");

        f.run(now()).await;
        let audited = f.audited();
        assert_eq!(audited.len(), 1, "one line per restored decision");
        assert!(
            audited[0].contains("203.0.113.12") && audited[0].contains("by restore"),
            "a reader must be able to tell this from a block taken now: {:?}",
            audited[0]
        );
    }

    #[tokio::test]
    async fn a_block_that_elapsed_while_the_agent_was_down_is_not_restored() {
        let f = fixture(86_400);
        let block = block_taken(7200, 3600, "203.0.113.13");
        f.store.save_block(&block).expect("the record");

        let outcome = f.run(now()).await;
        assert_eq!(outcome.blocks, 0);
        assert_eq!(outcome.blocks_elapsed, 1);
        assert!(!f.ips.load().is_blacklisted(block.ip));
        assert!(
            f.records.load_blocks().unwrap().is_empty(),
            "the elapsed record is swept on the way in"
        );
        assert!(f.audited().is_empty(), "nothing was restored to audit");
    }

    #[tokio::test]
    async fn a_response_action_comes_back_and_names_the_restart() {
        let f = fixture(86_400);
        let action = action_expiring_in(300, ResponseActionType::BlockIp, "resp-a");
        f.store.save_action(&action).expect("the record");

        let outcome = f.run(now()).await;
        assert_eq!(outcome.actions, 1);
        assert_eq!(outcome.failed, 0);

        let at = 1_700_000_000u64 * 1_000_000_000;
        assert_eq!(f.engine.read().await.list_active(at).len(), 1);
        assert!(
            f.ips.load().is_blacklisted("203.0.113.20".parse().unwrap()),
            "the block the action stands for is back on the data plane"
        );
        let audited = f.audited();
        assert!(
            audited.iter().any(|d| d.contains("restored")
                && d.contains("after a restart")
                && d.contains("300s of 600s left")),
            "the audit line says what came back and how much of it: {audited:?}"
        );
    }

    #[tokio::test]
    async fn a_throttle_comes_back_as_a_policy() {
        let f = fixture(86_400);
        f.store
            .save_action(&action_expiring_in(
                300,
                ResponseActionType::ThrottleIp,
                "resp-b",
            ))
            .expect("the record");

        let outcome = f.run(now()).await;
        assert_eq!(outcome.actions, 1);
        assert_eq!(
            f.rl.read().await.policies().len(),
            1,
            "the bucket's rate is reinstalled, its spent credit is not"
        );
    }

    #[tokio::test]
    async fn an_elapsed_action_is_dropped_rather_than_reinstated() {
        let f = fixture(86_400);
        f.store
            .save_action(&action_expiring_in(
                0,
                ResponseActionType::BlockIp,
                "resp-c",
            ))
            .expect("the record");

        let outcome = f.run(now()).await;
        assert_eq!(outcome.actions, 0);
        assert_eq!(outcome.actions_elapsed, 1);
        assert!(f.records.load_actions().unwrap().is_empty());
        assert!(f.engine.read().await.list().is_empty());
    }

    #[tokio::test]
    async fn a_revoked_action_is_dropped() {
        let f = fixture(86_400);
        let mut action = action_expiring_in(300, ResponseActionType::BlockIp, "resp-d");
        action.revoked = true;
        f.store.save_action(&action).expect("the record");

        let outcome = f.run(now()).await;
        assert_eq!(outcome.actions, 0);
        assert_eq!(outcome.actions_elapsed, 1);
        assert!(
            !f.ips.load().is_blacklisted("203.0.113.20".parse().unwrap()),
            "a revoked action must not come back as a block"
        );
    }

    #[tokio::test]
    async fn an_action_above_a_lowered_ceiling_is_dropped_before_the_data_plane() {
        // The ceiling was 600s when the action was taken and is 60s now.
        let f = fixture(60);
        f.store
            .save_action(&action_expiring_in(
                300,
                ResponseActionType::BlockIp,
                "resp-e",
            ))
            .expect("the record");

        let outcome = f.run(now()).await;
        assert_eq!(outcome.actions, 0);
        assert_eq!(outcome.actions_elapsed, 1);
        assert!(
            !f.ips.load().is_blacklisted("203.0.113.20".parse().unwrap()),
            "the configuration in force now is what decides, so nothing is installed"
        );
        assert!(f.records.load_actions().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_empty_store_restores_nothing_and_says_so() {
        let f = fixture(86_400);
        assert!(f.run(now()).await.is_empty());
        assert!(f.audited().is_empty());
    }
}
