//! The heartbeat loop.
//!
//! One beat every [`HEARTBEAT_INTERVAL`], carrying the installation identifier,
//! the agent version and which eBPF programs are loaded. A failed beat is
//! logged and forgotten: there is no retry, because the next one is half an
//! hour away and a fleet retrying a dead endpoint is worse than a fleet that
//! misses a window.

use std::sync::Arc;

use domain::telemetry::engine::{HEARTBEAT_INTERVAL, startup_delay};
use domain::telemetry::entity::{Heartbeat, InstallationId};
use domain::telemetry::error::TelemetryError;
use ports::secondary::telemetry_port::{InstallationStore, ProgramInventory, TelemetryTransport};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Sends one beat every half hour for as long as the agent runs.
pub struct TelemetryService {
    transport: Arc<dyn TelemetryTransport>,
    store: Arc<dyn InstallationStore>,
    inventory: Arc<dyn ProgramInventory>,
    version: String,
}

impl TelemetryService {
    /// Wires the loop to its three ports.
    #[must_use]
    pub fn new(
        transport: Arc<dyn TelemetryTransport>,
        store: Arc<dyn InstallationStore>,
        inventory: Arc<dyn ProgramInventory>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            store,
            inventory,
            version: version.into(),
        }
    }

    /// The identifier this installation answers to.
    ///
    /// The machine's own identifier decides it whenever there is one, ahead of
    /// whatever the file holds, so a machine reinstalled, or one that lost its
    /// state directory, comes back under the name it was counted under. The
    /// derived name is written down too, so that a mount of the identifier
    /// removed later does not turn into a second installation. Only a machine
    /// with no identifier of its own keeps a random name, minted on first boot.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Persistence`] when the file can be neither
    /// read nor written, and [`TelemetryError::Malformed`] when the one on disk
    /// is not an identifier this agent wrote.
    pub fn installation_id(&self) -> Result<InstallationId, TelemetryError> {
        let stored = self.store.load();

        if let Some(derived) = self
            .store
            .machine_identity()
            .as_deref()
            .and_then(InstallationId::for_machine)
        {
            if !matches!(&stored, Ok(Some(held)) if *held == derived) {
                self.store.save(&derived)?;
            }
            return Ok(derived);
        }

        if let Some(existing) = stored? {
            return Ok(existing);
        }

        let minted = InstallationId::from_bytes(self.store.random_bytes()?);
        self.store.save(&minted)?;
        Ok(minted)
    }

    /// Assembles and sends one beat.
    ///
    /// # Errors
    ///
    /// Returns whatever the transport or the domain refused it with.
    pub async fn beat_once(&self, id: &InstallationId) -> Result<(), TelemetryError> {
        let programs = self.inventory.programs().await;
        let beat = Heartbeat::new(id.clone(), &self.version, programs)?;

        debug!(
            programs = beat.programs.len(),
            loaded = beat.loaded_count(),
            "sending telemetry heartbeat"
        );

        self.transport.send(beat).await
    }

    /// Runs until the agent shuts down.
    ///
    /// Says what it is doing once, on the way in, naming the destination and
    /// how to switch it off. An installation whose identifier cannot be settled
    /// gives up rather than beating anonymously: a beat with a fresh identifier
    /// every restart would count restarts rather than installations.
    pub async fn run(self, cancel: CancellationToken) {
        let id = match self.installation_id() {
            Ok(id) => id,
            Err(e) => {
                warn!("telemetry disabled: {e}");
                return;
            }
        };

        info!(
            endpoint = self.transport.endpoint(),
            installation_id = id.as_str(),
            interval_minutes = HEARTBEAT_INTERVAL.as_secs() / 60,
            "telemetry on: this agent reports its installation id, its version and which eBPF \
             programs are loaded. It never reports configuration, rules, addresses, interfaces or \
             host names. Switch it off with telemetry.enabled=false or \
             EBPFSENTINEL_TELEMETRY_DISABLE=1"
        );

        let first = startup_delay(&id);
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(first) => {}
        }

        loop {
            if let Err(e) = self.beat_once(&id).await {
                // Debug rather than warn: an endpoint we cannot reach is our
                // problem, and an agent that fills a customer's logs with it
                // has turned our outage into their alert.
                debug!("telemetry heartbeat failed: {e}");
            }

            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(HEARTBEAT_INTERVAL) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use domain::telemetry::entity::{ProgramReport, ProgramState};

    use super::*;

    #[derive(Default)]
    struct RecordingTransport {
        sent: Mutex<Vec<Heartbeat>>,
        refuse: bool,
    }

    impl TelemetryTransport for RecordingTransport {
        fn send<'a>(
            &'a self,
            beat: Heartbeat,
        ) -> Pin<Box<dyn Future<Output = Result<(), TelemetryError>> + Send + 'a>> {
            Box::pin(async move {
                if self.refuse {
                    return Err(TelemetryError::Transport("refused".into()));
                }
                self.sent.lock().expect("not poisoned").push(beat);
                Ok(())
            })
        }

        fn endpoint(&self) -> &'static str {
            "https://telemetry.test/v1/heartbeat"
        }
    }

    #[derive(Default)]
    struct MemoryStore {
        held: Mutex<Option<InstallationId>>,
        machine: Option<String>,
        draws: AtomicUsize,
    }

    impl InstallationStore for MemoryStore {
        fn load(&self) -> Result<Option<InstallationId>, TelemetryError> {
            Ok(self.held.lock().expect("not poisoned").clone())
        }

        fn save(&self, id: &InstallationId) -> Result<(), TelemetryError> {
            *self.held.lock().expect("not poisoned") = Some(id.clone());
            Ok(())
        }

        fn machine_identity(&self) -> Option<String> {
            self.machine.clone()
        }

        fn random_bytes(&self) -> Result<[u8; 16], TelemetryError> {
            let n = self.draws.fetch_add(1, Ordering::Relaxed);
            Ok([u8::try_from(n % 256).unwrap_or(0); 16])
        }
    }

    struct FixedInventory(Vec<ProgramReport>);

    impl ProgramInventory for FixedInventory {
        fn programs<'a>(&'a self) -> Pin<Box<dyn Future<Output = Vec<ProgramReport>> + Send + 'a>> {
            Box::pin(async move { self.0.clone() })
        }
    }

    fn a_service(transport: Arc<RecordingTransport>, store: Arc<MemoryStore>) -> TelemetryService {
        TelemetryService::new(
            transport,
            store,
            Arc::new(FixedInventory(vec![
                ProgramReport {
                    program: "xdp_firewall".into(),
                    state: ProgramState::Loaded,
                },
                ProgramReport {
                    program: "tc_dns".into(),
                    state: ProgramState::NotLoaded,
                },
            ])),
            "1.2.3",
        )
    }

    #[test]
    fn an_installation_keeps_the_same_identifier_across_restarts() {
        let store = Arc::new(MemoryStore::default());

        let first = a_service(Arc::new(RecordingTransport::default()), Arc::clone(&store))
            .installation_id()
            .expect("minted");
        let second = a_service(Arc::new(RecordingTransport::default()), Arc::clone(&store))
            .installation_id()
            .expect("loaded");

        assert_eq!(first, second);
        assert_eq!(
            store.draws.load(Ordering::Relaxed),
            1,
            "a second boot drew fresh randomness and would have been counted twice"
        );
    }

    const A_MACHINE: &str = "4c4c4544003958108052b4c04f4e3732";

    fn a_machine() -> MemoryStore {
        MemoryStore {
            machine: Some(A_MACHINE.to_owned()),
            ..MemoryStore::default()
        }
    }

    #[test]
    fn a_machine_that_lost_its_state_comes_back_under_the_same_name() {
        let before = a_service(
            Arc::new(RecordingTransport::default()),
            Arc::new(a_machine()),
        )
        .installation_id()
        .expect("derived");
        let after_wipe = a_service(
            Arc::new(RecordingTransport::default()),
            Arc::new(a_machine()),
        )
        .installation_id()
        .expect("derived");

        assert_eq!(before, after_wipe);
    }

    #[test]
    fn the_machine_decides_over_a_random_name_kept_from_before() {
        let store = Arc::new(a_machine());
        *store.held.lock().expect("not poisoned") = Some(InstallationId::from_bytes([0x01; 16]));

        let id = a_service(Arc::new(RecordingTransport::default()), Arc::clone(&store))
            .installation_id()
            .expect("derived");

        assert_eq!(Some(id.clone()), InstallationId::for_machine(A_MACHINE));
        assert_eq!(*store.held.lock().expect("not poisoned"), Some(id));
        assert_eq!(store.draws.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_derived_name_survives_the_machine_identifier_going_away() {
        let store = Arc::new(a_machine());
        let derived = a_service(Arc::new(RecordingTransport::default()), Arc::clone(&store))
            .installation_id()
            .expect("derived");

        let unmounted = Arc::new(MemoryStore {
            held: Mutex::new(store.held.lock().expect("not poisoned").clone()),
            ..MemoryStore::default()
        });
        let later = a_service(Arc::new(RecordingTransport::default()), unmounted)
            .installation_id()
            .expect("loaded");

        assert_eq!(derived, later);
    }

    #[test]
    fn an_image_placeholder_falls_back_to_a_random_name() {
        let store = Arc::new(MemoryStore {
            machine: Some("uninitialized\n".to_owned()),
            ..MemoryStore::default()
        });

        a_service(Arc::new(RecordingTransport::default()), Arc::clone(&store))
            .installation_id()
            .expect("minted");

        assert_eq!(store.draws.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn one_beat_carries_the_version_and_every_program() {
        let transport = Arc::new(RecordingTransport::default());
        let service = a_service(Arc::clone(&transport), Arc::new(MemoryStore::default()));
        let id = service.installation_id().expect("minted");

        service.beat_once(&id).await.expect("sent");

        let sent = transport.sent.lock().expect("not poisoned");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].version, "1.2.3");
        assert_eq!(sent[0].installation_id, id);
        assert_eq!(sent[0].programs.len(), 2);
        assert_eq!(sent[0].loaded_count(), 1);
    }

    #[tokio::test]
    async fn an_endpoint_that_refuses_costs_the_beat_and_nothing_else() {
        let transport = Arc::new(RecordingTransport {
            sent: Mutex::default(),
            refuse: true,
        });
        let service = a_service(Arc::clone(&transport), Arc::new(MemoryStore::default()));
        let id = service.installation_id().expect("minted");

        assert!(service.beat_once(&id).await.is_err());
        assert!(transport.sent.lock().expect("not poisoned").is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_agent_stops_before_its_first_beat() {
        let transport = Arc::new(RecordingTransport::default());
        let service = a_service(Arc::clone(&transport), Arc::new(MemoryStore::default()));
        let cancel = CancellationToken::new();
        cancel.cancel();

        service.run(cancel).await;

        assert!(transport.sent.lock().expect("not poisoned").is_empty());
    }
}
