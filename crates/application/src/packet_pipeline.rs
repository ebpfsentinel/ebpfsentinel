use std::sync::{Arc, Mutex};

use domain::audit::entity::{AuditAction, AuditComponent};
use domain::common::entity::DomainMode;
use domain::ddos::entity::{DdosAttackType, DdosEvent};
use domain::dlp::entity::DlpAlert;
use domain::firewall::entity::FirewallAction;
use domain::ids::entity::IdsAlert;

use crate::alert_event::AlertEvent;
use arc_swap::ArcSwap;
use domain::dns::encrypted_dns::EncryptedDnsDetector;
use domain::l7::entity::{DetectedProtocol, ParsedProtocol};
use domain::l7::ja4::{self, FingerprintCache, FlowKey, Ja4sFingerprintCache};
use domain::l7::parser::{detect_protocol, parse_payload_with};
use domain::threatintel::entity::ThreatIntelAlert;
use ebpf_common::ddos::{
    EVENT_TYPE_DDOS_AMP, EVENT_TYPE_DDOS_CONNTRACK, EVENT_TYPE_DDOS_ICMP, EVENT_TYPE_DDOS_SYN,
};
use ebpf_common::dlp::DlpEvent;
use ebpf_common::dns::DnsEvent;
use ebpf_common::event::{
    EVENT_TYPE_FIREWALL, EVENT_TYPE_IDS, EVENT_TYPE_RATELIMIT, EVENT_TYPE_THREATINTEL, PacketEvent,
};
use ebpf_common::loadbalancer::{EVENT_TYPE_LB, LB_ACTION_FORWARD, LB_ACTION_NO_BACKEND};
use ebpf_common::threatintel::THREATINTEL_ACTION_DROP;
use ports::secondary::dns_cache_port::DnsCachePort;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::audit_service_impl::AuditAppService;
use crate::ddos_service_impl::DdosAppService;
use crate::dlp_service_impl::DlpAppService;
use crate::dns_blocklist_service_impl::DnsBlocklistAppService;
use crate::dns_cache_service_impl::DnsCacheAppService;
use crate::ids_service_impl::IdsAppService;
use crate::ips_service_impl::IpsAppService;
use crate::l7_service_impl::L7AppService;
use crate::threatintel_service_impl::ThreatIntelAppService;

/// Event wrapper flowing from the eBPF event reader to the dispatcher.
/// Defined in the domain layer; re-exported here for existing call sites.
pub use domain::common::agent_event::AgentEvent;

/// How many handshakes the log keeps before dropping the oldest.
pub const HANDSHAKE_LOG_CAPACITY: usize = 4096;

/// What a match against a prevention (IPS) rule carries into the alert and
/// escalation decisions that follow it.
#[derive(Debug, Clone, Copy)]
struct PreventionMatch {
    mode: DomainMode,
    severity: domain::common::entity::Severity,
    /// The rule blocks and asks for the process behind the flow too.
    kill_process: bool,
}

/// Routes eBPF events by `event_type` to the correct domain engine.
///
/// Consumes `PacketEvent`s from the event channel, dispatches IDS events
/// to the IDS engine for evaluation, and forwards resulting alerts to the
/// alert channel. Uses `tokio::select!` for cancellation awareness.
///
/// Supports parallel dispatch via [`run_parallel`](Self::run_parallel):
/// a distributor task hashes each event's source address and routes it to
/// one of N worker tasks, preserving per-source ordering while scaling
/// across cores.
#[derive(Clone)]
pub struct EventDispatcher {
    ids_service: Arc<ArcSwap<IdsAppService>>,
    l7_service: Arc<ArcSwap<L7AppService>>,
    threatintel_service: Arc<ArcSwap<ThreatIntelAppService>>,
    audit_service: Arc<AuditAppService>,
    metrics: Arc<dyn MetricsPort>,
    alert_tx: mpsc::Sender<AlertEvent>,
    dns_cache: Option<Arc<dyn DnsCachePort>>,
    dns_cache_svc: Option<Arc<DnsCacheAppService>>,
    ips_service: Option<Arc<ArcSwap<IpsAppService>>>,
    dlp_service: Option<Arc<ArcSwap<DlpAppService>>>,
    ddos_service: Option<Arc<ArcSwap<DdosAppService>>>,
    dns_blocklist_svc: Option<Arc<DnsBlocklistAppService>>,
    fingerprint_cache: Arc<FingerprintCache>,
    ja4s_fingerprint_cache: Arc<Ja4sFingerprintCache>,
    /// What the most recent TLS handshakes negotiated.
    handshake_log: Arc<domain::l7::handshake::HandshakeLog>,
    encrypted_dns_detector: EncryptedDnsDetector,
    container_resolver: Option<Arc<domain::container::engine::ContainerResolverEngine>>,
    /// Reads the executable behind a DLP event's pid. Optional, because an
    /// agent with no procfs view of the offending process can still raise the
    /// alert - it just cannot name the program.
    executable_reader:
        Option<Arc<dyn ports::secondary::process_executable_port::ProcessExecutableReader>>,
    /// Optional TCP stream reassembler. When present, L7 events are
    /// merged per flow before being handed to `parse_payload`.
    stream_reassembler: Option<Arc<domain::l7::reassembler::StreamReassembler>>,
    /// Optional extended L7 parser registered by the enterprise edition
    /// (MQTT / AMQP / NATS / Cassandra). Consulted only when the OSS
    /// detector returned [`DetectedProtocol::Unknown`].
    extended_l7_parser:
        Option<Arc<dyn ports::secondary::l7_extended_parser_port::L7ExtendedParser>>,
    /// Rate, errors and duration per service, measured on every L7 payload.
    red_meter: Arc<crate::l7_red_meter::L7RedMeter>,
    /// The cryptographic posture of each edge, counted per connection.
    crypto_posture: Arc<crate::crypto_posture_meter::CryptoPostureMeter>,
    /// Connections already compared with the protocol their port promises.
    /// `None` when the check is off.
    port_promise: Option<Arc<Mutex<domain::l7::port_promise::PortPromiseTracker>>>,
    /// Names the workload behind a flow for the L7 observers. The same
    /// resolver the meter reads, empty until the socket tables are wired.
    workloads: crate::workload_resolver::WorkloadResolver,
    /// Extensions handed every parsed L7 payload after the rules have run.
    l7_observers: Vec<Arc<dyn ports::secondary::l7_observer_port::L7Observer>>,
    /// Extensions handed every DNS query with the workload that sent it.
    dns_query_observers: Vec<Arc<dyn ports::secondary::dns_query_observer_port::DnsQueryObserver>>,
    /// Extensions handed every TLS plaintext buffer the library probes read.
    tls_plaintext_observers:
        Vec<Arc<dyn ports::secondary::tls_plaintext_observer_port::TlsPlaintextObserver>>,
}

/// What one DLP event's process resolves to, read once per event.
struct DlpEventContext {
    container: Option<domain::container::entity::ContainerInfo>,
    executable: Option<domain::dlp::entity::DlpExecutable>,
}

impl EventDispatcher {
    pub fn new(
        ids_service: Arc<ArcSwap<IdsAppService>>,
        l7_service: Arc<ArcSwap<L7AppService>>,
        threatintel_service: Arc<ArcSwap<ThreatIntelAppService>>,
        audit_service: Arc<AuditAppService>,
        metrics: Arc<dyn MetricsPort>,
        alert_tx: mpsc::Sender<AlertEvent>,
        dns_cache: Option<Arc<dyn DnsCachePort>>,
    ) -> Self {
        Self {
            ids_service,
            l7_service,
            threatintel_service,
            audit_service,
            alert_tx,
            dns_cache,
            dns_cache_svc: None,
            ips_service: None,
            dlp_service: None,
            ddos_service: None,
            dns_blocklist_svc: None,
            fingerprint_cache: Arc::new(FingerprintCache::new(
                10_000,
                std::time::Duration::from_mins(5),
            )),
            ja4s_fingerprint_cache: Arc::new(Ja4sFingerprintCache::new(
                10_000,
                std::time::Duration::from_mins(5),
            )),
            handshake_log: Arc::new(domain::l7::handshake::HandshakeLog::new(
                HANDSHAKE_LOG_CAPACITY,
            )),
            encrypted_dns_detector: EncryptedDnsDetector::default(),
            container_resolver: None,
            executable_reader: None,
            stream_reassembler: None,
            extended_l7_parser: None,
            red_meter: Arc::new(crate::l7_red_meter::L7RedMeter::new(
                domain::l7::red::RedConfig::default(),
                domain::l7::red::ServiceNames::default(),
                crate::workload_resolver::WorkloadResolver::new(),
                Arc::clone(&metrics),
            )),
            crypto_posture: Arc::new(crate::crypto_posture_meter::CryptoPostureMeter::new(
                crate::workload_resolver::WorkloadResolver::new(),
            )),
            port_promise: Some(Arc::new(Mutex::new(
                domain::l7::port_promise::PortPromiseTracker::new(
                    domain::l7::port_promise::PortPromiseConfig::default(),
                ),
            ))),
            workloads: crate::workload_resolver::WorkloadResolver::new(),
            l7_observers: Vec::new(),
            dns_query_observers: Vec::new(),
            tls_plaintext_observers: Vec::new(),
            metrics,
        }
    }

    /// The meter counting requests per service, which the service map reads.
    #[must_use]
    pub fn red_meter(&self) -> Arc<crate::l7_red_meter::L7RedMeter> {
        Arc::clone(&self.red_meter)
    }

    /// The meter counting each edge's cryptographic posture.
    #[must_use]
    pub fn crypto_posture(&self) -> Arc<crate::crypto_posture_meter::CryptoPostureMeter> {
        Arc::clone(&self.crypto_posture)
    }

    /// Compare each connection's first payload with the protocol its port
    /// promises under `config`, or not at all when it is `None`.
    #[must_use]
    pub fn with_port_promise(
        mut self,
        config: Option<domain::l7::port_promise::PortPromiseConfig>,
    ) -> Self {
        self.port_promise = config.map(|config| {
            Arc::new(Mutex::new(
                domain::l7::port_promise::PortPromiseTracker::new(config),
            ))
        });
        self
    }

    /// Name the services behind L7 requests from the agent's socket and
    /// process tables. Without it every request is counted against the
    /// `unattributed` service.
    #[must_use]
    pub fn with_workload_resolver(
        mut self,
        workloads: crate::workload_resolver::WorkloadResolver,
    ) -> Self {
        self.red_meter = Arc::new(crate::l7_red_meter::L7RedMeter::new(
            domain::l7::red::RedConfig::default(),
            domain::l7::red::ServiceNames::default(),
            workloads.clone(),
            Arc::clone(&self.metrics),
        ));
        self.crypto_posture = Arc::new(crate::crypto_posture_meter::CryptoPostureMeter::new(
            workloads.clone(),
        ));
        self.workloads = workloads;
        self
    }

    /// Hand every parsed L7 payload to `observer` once the rules have run,
    /// with the workload that opened the connection when it can be named.
    #[must_use]
    pub fn with_l7_observer(
        mut self,
        observer: Arc<dyn ports::secondary::l7_observer_port::L7Observer>,
    ) -> Self {
        tracing::info!(observer = observer.name(), "L7 observer registered");
        self.l7_observers.push(observer);
        self
    }

    /// Hand every DNS query to `observer`, with the workload whose socket
    /// sent it. An alert the observer returns is completed with the flow,
    /// the workload and the container, and raised like any other.
    #[must_use]
    pub fn with_dns_query_observer(
        mut self,
        observer: Arc<dyn ports::secondary::dns_query_observer_port::DnsQueryObserver>,
    ) -> Self {
        tracing::info!(observer = observer.name(), "DNS query observer registered");
        self.dns_query_observers.push(observer);
        self
    }

    /// Hand every TLS plaintext buffer the library probes capture to
    /// `observer`, in both directions, whether or not DLP itself is scanning.
    /// An alert the observer returns is completed with the flow, the process,
    /// the executable and the container, and raised like any other.
    #[must_use]
    pub fn with_tls_plaintext_observer(
        mut self,
        observer: Arc<dyn ports::secondary::tls_plaintext_observer_port::TlsPlaintextObserver>,
    ) -> Self {
        tracing::info!(
            observer = observer.name(),
            "TLS plaintext observer registered"
        );
        self.tls_plaintext_observers.push(observer);
        self
    }

    /// Inject an extended L7 parser. The dispatcher consults it whenever
    /// the built-in detector returns `DetectedProtocol::Unknown`.
    #[must_use]
    pub fn with_extended_l7_parser(
        mut self,
        parser: Arc<dyn ports::secondary::l7_extended_parser_port::L7ExtendedParser>,
    ) -> Self {
        tracing::info!(extension = parser.name(), "extended L7 parser registered");
        self.extended_l7_parser = Some(parser);
        self
    }

    /// Inject a TCP stream reassembler. When present, L7 events from
    /// the same flow are accumulated until a protocol boundary is
    /// detected (HTTP Content-Length) or the idle timeout fires.
    #[must_use]
    pub fn with_stream_reassembler(
        mut self,
        reassembler: Arc<domain::l7::reassembler::StreamReassembler>,
    ) -> Self {
        self.stream_reassembler = Some(reassembler);
        self
    }

    /// Return the shared reassembler handle so startup can wire the
    /// periodic flush sweep.
    pub fn stream_reassembler(&self) -> Option<Arc<domain::l7::reassembler::StreamReassembler>> {
        self.stream_reassembler.as_ref().map(Arc::clone)
    }

    /// Inject the container resolver engine. When present, alerts carry
    /// container context derived from their `cgroup_id`.
    #[must_use]
    pub fn with_container_resolver(
        mut self,
        resolver: Arc<domain::container::engine::ContainerResolverEngine>,
    ) -> Self {
        self.container_resolver = Some(resolver);
        self
    }

    /// Inject the executable reader. When present, a DLP alert names the
    /// binary the offending process was running.
    #[must_use]
    pub fn with_executable_reader(
        mut self,
        reader: Arc<dyn ports::secondary::process_executable_port::ProcessExecutableReader>,
    ) -> Self {
        self.executable_reader = Some(reader);
        self
    }

    /// Record a container resolution outcome on the resolver hit/miss/error
    /// counters.
    fn record_resolve_outcome(&self, outcome: domain::container::engine::ResolveOutcome) {
        use domain::container::engine::ResolveOutcome;
        match outcome {
            ResolveOutcome::CacheHit => self.metrics.record_container_cache_hit(),
            ResolveOutcome::CacheMiss => self.metrics.record_container_cache_miss(),
            ResolveOutcome::ReadError => self.metrics.record_container_resolver_error(),
        }
    }

    /// Resolve container provenance for a DLP uprobe event. Prefers the event's
    /// `cgroup_id` - reliably populated by the uprobe and resolvable from the
    /// host cgroupfs without host-PID visibility - so a neighbouring container's
    /// TLS is attributed to that container, mirroring the cgroup-id attribution
    /// on the TC datapath. Falls back to the pid cgroup read for cgroup v1 hosts
    /// where the kernel reports `cgroup_id == 0`.
    fn resolve_container_dlp(
        &self,
        pid: u32,
        cgroup_id: u64,
    ) -> Option<domain::container::entity::ContainerInfo> {
        let resolver = self.container_resolver.as_ref()?;
        let (info, outcome) = resolver.resolve_dlp(pid, cgroup_id);
        self.record_resolve_outcome(outcome);
        Some(info)
    }

    /// Resolve container provenance from a `cgroup_id` alone (no pid), used
    /// by the TC datapath alert path. Returns `None` when no resolver is
    /// wired or the id maps to the host namespace, so host traffic is not
    /// tagged with an empty container surface.
    fn resolve_container_by_id(
        &self,
        cgroup_id: u64,
    ) -> Option<domain::container::entity::ContainerInfo> {
        // cgroup_id 0 = the datapath captured no cgroup (softirq ingress on
        // a real NIC before demux). Not an error - skip silently so routine
        // host traffic does not churn the resolver error counter.
        if cgroup_id == 0 {
            return None;
        }
        let resolver = self.container_resolver.as_ref()?;
        let (info, outcome) = resolver.resolve_by_id(cgroup_id);
        self.record_resolve_outcome(outcome);
        if info.is_host() { None } else { Some(info) }
    }

    /// Return a shared reference to the JA4 fingerprint cache.
    pub fn fingerprint_cache(&self) -> Arc<FingerprintCache> {
        Arc::clone(&self.fingerprint_cache)
    }

    /// Return a shared reference to the JA4S fingerprint cache.
    pub fn ja4s_fingerprint_cache(&self) -> Arc<Ja4sFingerprintCache> {
        Arc::clone(&self.ja4s_fingerprint_cache)
    }

    /// Return a shared reference to the log of recent TLS handshakes.
    pub fn handshake_log(&self) -> Arc<domain::l7::handshake::HandshakeLog> {
        Arc::clone(&self.handshake_log)
    }

    /// Replace the dispatcher's handshake log with one the API also reads.
    #[must_use]
    pub fn with_handshake_log(mut self, log: Arc<domain::l7::handshake::HandshakeLog>) -> Self {
        self.handshake_log = log;
        self
    }

    /// Count into a posture meter that outlives this dispatcher, so the
    /// counts survive a datapath reloaded under a new dispatcher. Call it
    /// after [`Self::with_workload_resolver`], which installs a fresh one.
    #[must_use]
    pub fn with_crypto_posture(
        mut self,
        meter: Arc<crate::crypto_posture_meter::CryptoPostureMeter>,
    ) -> Self {
        self.crypto_posture = meter;
        self
    }

    /// Replace the dispatcher's JA4 fingerprint cache with an externally
    /// supplied one. Used when the agent wires a redb-backed cache so it
    /// survives restarts (the same `Arc` is also handed to `AppState`).
    #[must_use]
    pub fn with_fingerprint_cache(mut self, cache: Arc<FingerprintCache>) -> Self {
        self.fingerprint_cache = cache;
        self
    }

    /// Replace the dispatcher's JA4S fingerprint cache with an externally
    /// supplied one.
    #[must_use]
    pub fn with_ja4s_fingerprint_cache(mut self, cache: Arc<Ja4sFingerprintCache>) -> Self {
        self.ja4s_fingerprint_cache = cache;
        self
    }

    /// Set the DNS cache service for processing DNS events.
    #[must_use]
    pub fn with_dns_cache_svc(mut self, svc: Arc<DnsCacheAppService>) -> Self {
        self.dns_cache_svc = Some(svc);
        self
    }

    /// Set the IPS service for auto-blacklisting on IDS detections.
    #[must_use]
    pub fn with_ips_service(mut self, svc: Arc<ArcSwap<IpsAppService>>) -> Self {
        self.ips_service = Some(svc);
        self
    }

    /// Add custom `DoH` resolver domains for encrypted DNS detection.
    #[must_use]
    pub fn with_doh_resolvers(mut self, resolvers: &[String]) -> Self {
        self.encrypted_dns_detector.add_custom_resolvers(resolvers);
        self
    }

    /// Set the DLP service for processing DLP events.
    #[must_use]
    pub fn with_dlp_service(mut self, svc: Arc<ArcSwap<DlpAppService>>) -> Self {
        self.dlp_service = Some(svc);
        self
    }

    /// Set the `DDoS` service for processing `DDoS` events.
    #[must_use]
    pub fn with_ddos_service(mut self, svc: Arc<ArcSwap<DdosAppService>>) -> Self {
        self.ddos_service = Some(svc);
        self
    }

    /// Set the DNS blocklist service for evaluating DNS responses.
    #[must_use]
    pub fn with_dns_blocklist_svc(mut self, svc: Arc<DnsBlocklistAppService>) -> Self {
        self.dns_blocklist_svc = Some(svc);
        self
    }

    /// Main event loop. Receives events from the event channel, dispatches
    /// by type, and drains remaining events on cancellation.
    pub async fn run(self, mut rx: mpsc::Receiver<AgentEvent>, cancel_token: CancellationToken) {
        let mut count: u64 = 0;

        loop {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    // Drain remaining events before exiting
                    while let Ok(event) = rx.try_recv() {
                        count += 1;
                        self.dispatch_agent_event(event);
                    }
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(event) => {
                            count += 1;
                            self.dispatch_agent_event(event);
                        }
                        None => break, // channel closed
                    }
                }
            }
        }

        tracing::info!(total_events = count, "event dispatcher stopped");
    }

    /// Parallel event loop. Spawns `num_workers` worker tasks and a
    /// distributor that hashes each event's source address to a worker
    /// channel, preserving per-source ordering.
    ///
    /// Falls back to single-threaded [`run`](Self::run) when `num_workers <= 1`.
    pub async fn run_parallel(
        self,
        num_workers: usize,
        rx: mpsc::Receiver<AgentEvent>,
        cancel_token: CancellationToken,
    ) {
        if num_workers <= 1 {
            return self.run(rx, cancel_token).await;
        }

        let channel_size = 4096;
        let mut worker_txs = Vec::with_capacity(num_workers);
        let mut handles = Vec::with_capacity(num_workers);

        for id in 0..num_workers {
            let (tx, worker_rx) = mpsc::channel::<AgentEvent>(channel_size);
            worker_txs.push(tx);

            let worker = self.clone();
            let token = cancel_token.clone();
            handles.push(tokio::spawn(async move {
                worker.run_worker(id, worker_rx, token).await;
            }));
        }

        // Distributor: read from main channel, hash src_addr, send to worker
        Self::distribute(rx, worker_txs, num_workers, cancel_token.clone()).await;

        // Wait for all workers to finish draining
        for handle in handles {
            let _ = handle.await;
        }

        tracing::info!(num_workers, "parallel event dispatcher stopped");
    }

    async fn distribute(
        mut rx: mpsc::Receiver<AgentEvent>,
        worker_txs: Vec<mpsc::Sender<AgentEvent>>,
        num_workers: usize,
        cancel_token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    // Drain remaining events
                    while let Ok(event) = rx.try_recv() {
                        let idx = Self::worker_index(&event, num_workers);
                        let _ = worker_txs[idx].send(event).await;
                    }
                    // Drop senders to signal workers to finish
                    drop(worker_txs);
                    break;
                }
                msg = rx.recv() => {
                    if let Some(event) = msg {
                        let idx = Self::worker_index(&event, num_workers);
                        if worker_txs[idx].send(event).await.is_err() {
                            break; // worker gone
                        }
                    } else {
                        drop(worker_txs);
                        break;
                    }
                }
            }
        }
    }

    async fn run_worker(
        self,
        id: usize,
        mut rx: mpsc::Receiver<AgentEvent>,
        cancel_token: CancellationToken,
    ) {
        let mut count: u64 = 0;

        loop {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    while let Ok(event) = rx.try_recv() {
                        count += 1;
                        self.dispatch_worker_event(id, event);
                    }
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(event) => {
                            count += 1;
                            self.dispatch_worker_event(id, event);
                        }
                        None => break,
                    }
                }
            }
        }

        tracing::debug!(worker_id = id, total_events = count, "event worker stopped");
    }

    /// Dispatch with per-worker metrics instrumentation.
    fn dispatch_worker_event(&self, worker_id: usize, event: AgentEvent) {
        let start = std::time::Instant::now();
        self.dispatch_agent_event(event);
        self.metrics.record_worker_event(worker_id);
        self.metrics
            .observe_worker_duration(worker_id, start.elapsed().as_secs_f64());
    }

    /// Deterministic worker selection based on source address.
    /// Events from the same source always go to the same worker,
    /// preserving per-source ordering. XOR-folds all 4 address words
    /// for good distribution across both IPv4 and IPv6.
    ///
    /// L7 payloads are the exception: they are keyed on the connection,
    /// both directions folded together, because an answer is only read as
    /// one when the request it answers was seen first. Keyed on the source,
    /// a request and its answer land on two workers and the answer can be
    /// processed before the request it belongs to.
    fn worker_index(event: &AgentEvent, num_workers: usize) -> usize {
        let hash = match event {
            AgentEvent::L4(pkt) => {
                pkt.src_addr[0] ^ pkt.src_addr[1] ^ pkt.src_addr[2] ^ pkt.src_addr[3]
            }
            AgentEvent::L7 { header, .. } => {
                let fold = |addr: &[u32; 4]| addr[0] ^ addr[1] ^ addr[2] ^ addr[3];
                fold(&header.src_addr)
                    ^ fold(&header.dst_addr)
                    ^ u32::from(header.src_port ^ header.dst_port)
            }
            AgentEvent::Dns { header, .. } => {
                header.src_addr[0] ^ header.src_addr[1] ^ header.src_addr[2] ^ header.src_addr[3]
            }
            AgentEvent::Dlp(ev) => ev.pid ^ ev.tgid,
        };
        hash as usize % num_workers
    }

    fn dispatch_agent_event(&self, event: AgentEvent) {
        let start = std::time::Instant::now();
        let program = match &event {
            AgentEvent::L4(pkt) => event_type_label(pkt.event_type),
            AgentEvent::L7 { .. } => "l7",
            AgentEvent::Dns { .. } => "dns",
            AgentEvent::Dlp(_) => "dlp",
        };
        match event {
            AgentEvent::L4(pkt) => self.dispatch_event(pkt),
            AgentEvent::L7 { header, payload } => self.process_l7_event(header, &payload),
            AgentEvent::Dns { header, payload } => self.process_dns_event(header, &payload),
            AgentEvent::Dlp(event) => self.process_dlp_event(&event),
        }
        self.metrics
            .observe_processing_duration(program, start.elapsed().as_secs_f64());
    }

    fn dispatch_event(&self, event: PacketEvent) {
        match event.event_type {
            EVENT_TYPE_FIREWALL => self.process_firewall_event(event),
            EVENT_TYPE_IDS => self.process_ids_event(event),
            EVENT_TYPE_RATELIMIT => self.process_ratelimit_event(event),
            EVENT_TYPE_THREATINTEL => {
                self.process_threatintel_event(event);
            }
            EVENT_TYPE_DDOS_SYN
            | EVENT_TYPE_DDOS_ICMP
            | EVENT_TYPE_DDOS_AMP
            | EVENT_TYPE_DDOS_CONNTRACK => {
                self.process_ddos_event(event);
            }
            EVENT_TYPE_LB => {
                self.process_lb_event(&event);
            }
            other => {
                tracing::debug!(event_type = other, "unhandled event type");
                self.metrics.record_packet("unknown", "unknown");
            }
        }
    }

    fn process_firewall_event(&self, event: PacketEvent) {
        let action = action_label(event.action);
        self.metrics.record_packet("firewall", action);
        tracing::debug!(
            src_ip = %event.src_ip(),
            dst_ip = %event.dst_ip(),
            src_port = event.src_port,
            dst_port = event.dst_port,
            protocol = event.protocol,
            action = event.action,
            rule_id = event.rule_id,
            "firewall event"
        );

        let audit_action = if event.action == 1 {
            AuditAction::Drop
        } else {
            AuditAction::Pass
        };
        let detail = format!("firewall {action} rule_id={}", event.rule_id);
        self.audit_service.record_security_decision(
            AuditComponent::Firewall,
            audit_action,
            event.timestamp_ns,
            event.src_addr,
            event.dst_addr,
            event.is_ipv6(),
            event.src_port,
            event.dst_port,
            event.protocol,
            &event.rule_id.to_string(),
            &detail,
        );

        if event.action == 1 {
            self.emit_packet_security_alert(
                domain::alert::entity::PacketAlertComponent::Firewall,
                &event,
                &event.rule_id.to_string(),
                action,
                &detail,
            );
        }
    }

    fn process_ratelimit_event(&self, event: PacketEvent) {
        let action = action_label(event.action);
        self.metrics.record_packet("ratelimit", action);
        tracing::debug!(
            src_ip = %event.src_ip(),
            dst_ip = %event.dst_ip(),
            src_port = event.src_port,
            dst_port = event.dst_port,
            protocol = event.protocol,
            action = event.action,
            "ratelimit event"
        );

        // The kernel emits a rate limit event only once a bucket is empty, so
        // every one of them is an exceeded limit whatever verdict followed: a
        // rule configured to pass forwards the excess and is still reporting
        // that the source went over. Recording the pass as a pass would have
        // left the audit trail unable to say a limit was reached at all.
        let detail = format!("ratelimit {action}");
        self.audit_service.record_security_decision(
            AuditComponent::Ratelimit,
            AuditAction::RateExceeded,
            event.timestamp_ns,
            event.src_addr,
            event.dst_addr,
            event.is_ipv6(),
            event.src_port,
            event.dst_port,
            event.protocol,
            "",
            &detail,
        );

        // A `pass` rule is how a limit is sized against real traffic, so the
        // excess it forwards is alerted on as well, carrying the verdict word
        // that says nothing was dropped.
        self.emit_packet_security_alert(
            domain::alert::entity::PacketAlertComponent::Ratelimit,
            &event,
            "",
            action,
            &detail,
        );
    }

    fn process_ids_event(&self, event: PacketEvent) {
        let action = action_label(event.action);
        self.metrics.record_packet("ids", action);

        // Evaluate and threshold check (all methods are now &self via interior mutability)
        let svc = self.ids_service.load();

        // Reverse DNS lookup only when a domain-aware rule is loaded; otherwise
        // skip the cache RwLock read + Vec<String> allocation on the hot path.
        let dst_domains = if svc.has_domain_rules() {
            self.dns_cache
                .as_ref()
                .map(|cache| {
                    let dst_ip = addr_to_ip(event.dst_addr, event.is_ipv6());
                    cache.lookup_ip(&dst_ip)
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Resolve source country for country-aware sampling and thresholds
        let src_country = svc.resolve_country(event.src_addr, event.is_ipv6());

        let Some((idx, rule, matched_domain)) =
            svc.evaluate_event_with_context(&event, &dst_domains, src_country.as_deref())
        else {
            return;
        };

        self.report_ids_match(
            &event,
            &svc,
            idx,
            rule,
            matched_domain,
            src_country.as_deref(),
            true,
        );

        // A kernel map slot holds one rule, so a rule watching a port another
        // rule already claims is never named by the classifier. Replay those
        // rules here: which of two rules wins a map slot is a kernel storage
        // detail, and letting it decide whether a loaded rule ever fires would
        // silently drop the operator's policy.
        for peer in svc.shadowed_peers(&event, idx) {
            if let Some((peer_idx, peer_rule, peer_domain)) =
                svc.evaluate_index_with_context(peer, &event, &dst_domains, src_country.as_deref())
            {
                // The IPS detection counter answers to the packet, not to the
                // number of rules that matched it, so only the kernel match
                // feeds it.
                self.report_ids_match(
                    &event,
                    &svc,
                    peer_idx,
                    peer_rule,
                    peer_domain,
                    src_country.as_deref(),
                    false,
                );
            }
        }
    }

    /// Turn a rule match into an audit record and an alert, applying the
    /// service toggles and the rule threshold on the way.
    ///
    /// Shared by the two ways a rule can match: the kernel classifier event,
    /// which decides on port and protocol, and the captured payload, which
    /// the content rules match in userspace.
    ///
    /// `counts_toward_ips` is false when the match is a userspace replay of a
    /// rule the kernel could not name: the packet has already been counted
    /// once toward the IPS auto-blacklist, and counting it again per matching
    /// rule would trip the threshold early.
    #[allow(clippy::too_many_arguments)] // one match, described in full
    fn report_ids_match(
        &self,
        event: &PacketEvent,
        svc: &IdsAppService,
        idx: usize,
        rule: &domain::ids::entity::IdsRule,
        matched_domain: Option<String>,
        src_country: Option<&str>,
        counts_toward_ips: bool,
    ) {
        let (alert, detail, prevention) = {
            // Both rule sets are matched by the same kernel program, so the
            // IDS toggle gates detection rules only: a prevention rule keeps
            // firing while detection is muted, and answers to `ips.enabled`.
            let prevention = svc.is_prevention_index(idx).then_some(PreventionMatch {
                mode: rule.mode,
                severity: rule.severity,
                kill_process: rule.kill_process && rule.mode == DomainMode::Block,
            });
            if prevention.is_none() && !svc.enabled() {
                return;
            }
            if prevention.is_some()
                && !self
                    .ips_service
                    .as_ref()
                    .is_some_and(|ips| ips.load().enabled())
            {
                return;
            }

            let detail = if prevention.is_some() {
                format!("IPS rule {} matched", rule.id)
            } else {
                format!("IDS rule {} matched", rule.id)
            };
            let mut alert = IdsAlert::from_event(event, rule);
            if matched_domain.is_some() {
                self.metrics.record_ids_domain_match(&rule.id.0);
            }
            alert.matched_domain = matched_domain;

            // Threshold check with country-aware overrides (now &self, no write lock
            // needed). `rule` is borrowed for the duration of this block, so the
            // check borrows it directly - no per-match deep clone of the rule.
            if rule.threshold.is_some()
                && !svc.check_threshold_with_country(
                    rule,
                    event.src_addr[0],
                    event.dst_addr[0],
                    src_country,
                )
            {
                return; // Suppressed by threshold
            }

            // The classifier already resolved the sending cgroup, so a match
            // coming out of a container can name it. Resolve after the
            // threshold check: a suppressed match never reaches an operator,
            // and the lookup is a cgroupfs walk on a cache miss.
            alert.container = self.resolve_container_by_id(event.cgroup_id);

            // Block-mode IDS verdicts collapse the matching conntrack
            // entry's timeout via `bpf_ct_change_timeout` on the
            // kernel side (tc-ids program). Record the verdict on
            // the userspace counter so the enforcement rate is
            // observable alongside the alert-mode rate.
            if svc.mode() == DomainMode::Block {
                svc.record_flow_killed_via_ct();
            }

            (alert, detail, prevention)
        };

        self.audit_service.record_security_decision(
            if prevention.is_some() {
                AuditComponent::Ips
            } else {
                AuditComponent::Ids
            },
            AuditAction::Alert,
            event.timestamp_ns,
            event.src_addr,
            event.dst_addr,
            event.is_ipv6(),
            event.src_port,
            event.dst_port,
            event.protocol,
            &alert.rule_id.0,
            &detail,
        );

        // A prevention rule is reported under the IPS component, carrying its
        // own severity rather than the component default.
        if let Some(ref prevention) = prevention {
            let mut psa = self.packet_security_alert(
                domain::alert::entity::PacketAlertComponent::Ips,
                event,
                &alert.rule_id.0,
                prevention.mode.as_str(),
                &detail,
                prevention.severity,
            );
            psa.kill_process = prevention.kill_process;
            let _ = self.alert_tx.try_send(AlertEvent::PacketSecurity(psa));
        } else if self.alert_tx.try_send(AlertEvent::Ids(alert)).is_err() {
            self.metrics.record_event_dropped("alert_channel_full");
        }

        if counts_toward_ips {
            self.feed_ips_counter(event, prevention);
        }
    }

    /// Match a captured TCP payload against the IDS and IPS content rules.
    ///
    /// A rule that carries a pattern is decided here rather than on the
    /// kernel classifier event, which knows only the port and the protocol.
    /// The capture itself is arranged at load time: the ports such rules
    /// name are added to the set the kernel program copies payload for.
    fn process_ids_content(&self, header: &PacketEvent, payload: &[u8]) {
        let svc = self.ids_service.load();
        if !svc.has_content_rules() {
            return;
        }

        let src_country = svc.resolve_country(header.src_addr, header.is_ipv6());
        let Some((idx, rule)) =
            svc.evaluate_payload_with_context(header, payload, src_country.as_deref())
        else {
            return;
        };

        // The header the capture carries describes an L7 event: its
        // `rule_id` holds the captured length, and its type says L7. The
        // alert names an IDS rule, so it travels on an event that says so.
        let event = PacketEvent {
            event_type: EVENT_TYPE_IDS,
            rule_id: idx as u32,
            ..*header
        };
        self.metrics
            .record_packet("ids", action_label(event.action));
        self.report_ids_match(&event, &svc, idx, rule, None, src_country.as_deref(), true);
    }

    /// Feed a rule match into the IPS auto-blacklist counter.
    ///
    /// A prevention rule in alert mode is observation only, so it never
    /// counts; sampling and the IPS toggle gate both rule sets alike.
    fn feed_ips_counter(&self, event: &PacketEvent, prevention: Option<PreventionMatch>) {
        let Some(ref ips_svc) = self.ips_service else {
            return;
        };
        let svc = ips_svc.load();
        let counts = svc.enabled()
            && prevention.is_none_or(|p| p.mode == DomainMode::Block)
            && svc.should_process(event.src_addr[0], event.dst_addr[0]);
        if !counts {
            return;
        }
        let src_ip = addr_to_ip(event.src_addr, event.is_ipv6());
        let actions = svc.record_detection(src_ip);

        // Emit alert when IPS auto-blacklists an IP
        if !actions.is_empty() {
            let detail = format!("IPS auto-blacklist: {src_ip}");
            self.emit_packet_security_alert(
                domain::alert::entity::PacketAlertComponent::Ips,
                event,
                &format!("ips-blacklist:{src_ip}"),
                "blacklist",
                &detail,
            );
        }
    }

    fn process_threatintel_event(&self, event: PacketEvent) {
        let action = action_label(event.action);
        self.metrics.record_packet("threatintel", action);

        let svc = self.threatintel_service.load();

        if !svc.enabled() {
            return;
        }

        // The eBPF program already matched the IP - look up the IOC for context.
        // Try both src and dst IPs (the kernel fires one event per match direction).
        let src_ip = addr_to_ip(event.src_addr, event.is_ipv6());
        let dst_ip = addr_to_ip(event.dst_addr, event.is_ipv6());

        let ioc = svc.lookup(&src_ip).or_else(|| svc.lookup(&dst_ip)).cloned();
        drop(svc);

        // Read back what the datapath did with this packet rather than the
        // service mode: a feed carrying its own `default_action` is loaded
        // into the map with that action, so a match on it can be dropped
        // while the service mode still reads `alert`.
        let mode = if event.action == THREATINTEL_ACTION_DROP {
            DomainMode::Block
        } else {
            DomainMode::Alert
        };

        let Some(ioc) = ioc else {
            // IOC was in eBPF map but not in userspace engine (race during reload)
            tracing::debug!(
                src_ip = %event.src_ip(),
                dst_ip = %event.dst_ip(),
                "threatintel event but no IOC found in engine"
            );
            return;
        };
        let (feed_id, confidence, threat_type) = (ioc.feed_id, ioc.confidence, ioc.threat_type);

        // Count the match before it becomes an alert: dedup and throttling
        // downstream may drop the alert, but the IOC did match.
        self.metrics.record_threatintel_match(&feed_id);

        let ti_alert = ThreatIntelAlert {
            feed_id,
            confidence,
            threat_type,
            mode,
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            is_ipv6: event.is_ipv6(),
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            timestamp_ns: event.timestamp_ns,
            container: self.resolve_container_by_id(event.cgroup_id),
        };

        tracing::info!(
            src_ip = %event.src_ip(),
            dst_ip = %event.dst_ip(),
            feed_id = %ti_alert.feed_id,
            confidence = ti_alert.confidence,
            threat_type = %ti_alert.threat_type,
            action = action,
            "threat intel IOC matched"
        );

        let detail = format!(
            "threat intel IOC matched feed={} confidence={}",
            ti_alert.feed_id, ti_alert.confidence
        );
        self.audit_service.record_security_decision(
            AuditComponent::Threatintel,
            if mode == DomainMode::Block {
                AuditAction::Drop
            } else {
                AuditAction::Alert
            },
            event.timestamp_ns,
            event.src_addr,
            event.dst_addr,
            event.is_ipv6(),
            event.src_port,
            event.dst_port,
            event.protocol,
            &ti_alert.feed_id,
            &detail,
        );

        if self
            .alert_tx
            .try_send(AlertEvent::ThreatIntel(ti_alert))
            .is_err()
        {
            self.metrics.record_event_dropped("alert_channel_full");
        }
    }

    #[allow(clippy::too_many_lines)]
    fn process_l7_event(&self, header: PacketEvent, payload: &[u8]) {
        // If reassembly is enabled, accumulate fragments per flow. The
        // first full message emitted by the reassembler replaces the
        // raw payload slice for downstream protocol parsing.
        let reassembled_buf: Vec<u8>;
        let payload: &[u8] = if let Some(ref reassembler) = self.stream_reassembler {
            let flow = domain::l7::reassembler::FlowId::new(
                header.src_addr,
                header.dst_addr,
                header.src_port,
                header.dst_port,
                header.is_ipv6(),
            );
            match reassembler.ingest(flow, payload, header.timestamp_ns) {
                domain::l7::reassembler::Ingest::Complete(bytes) => {
                    reassembled_buf = bytes;
                    &reassembled_buf
                }
                domain::l7::reassembler::Ingest::Pending => {
                    // Still buffered - wait for more fragments or a
                    // periodic `flush_expired` sweep.
                    return;
                }
            }
        } else {
            payload
        };

        self.process_l7_payload(&header, payload);
    }

    /// Detect the protocol, compute fingerprints, run encrypted-DNS
    /// detection, and evaluate L7 rules for an already-reassembled payload.
    ///
    /// Shared by the live event path ([`process_l7_event`](Self::process_l7_event))
    /// and the reassembler idle-flush path ([`flush_reassembled`](Self::flush_reassembled))
    /// so flushed partial buffers receive identical treatment.
    fn process_l7_payload(&self, header: &PacketEvent, payload: &[u8]) {
        self.process_ids_content(header, payload);

        let protocol = detect_protocol(payload);
        let mut protocol_label = protocol.label();
        self.check_port_promise(header, protocol, payload.len());

        // Consult the optional extended L7 parser (enterprise protocols
        // like MQTT / AMQP / NATS / Cassandra). When the built-in
        // detector returned Unknown, fall back to the extension label.
        if protocol == DetectedProtocol::Unknown
            && let Some(ref parser) = self.extended_l7_parser
            && let Some(label) = parser.detect_label(payload)
        {
            protocol_label = label;
        }

        self.red_meter.observe(header, protocol_label, payload);
        self.crypto_posture
            .observe_payload(header, protocol_label, payload, wall_clock_ns());

        // Reuse the protocol detected above instead of re-scanning the payload.
        let parsed = parse_payload_with(protocol, payload);

        // Compute and cache JA4 fingerprint for TLS connections
        if let ParsedProtocol::Tls(ref tls_hello) = parsed {
            let fp = ja4::compute_ja4(tls_hello);
            self.metrics.record_fingerprint_seen(&fp.ja4);
            let flow_key = FlowKey {
                src_addr: header.src_addr,
                src_port: header.src_port,
                dst_addr: header.dst_addr,
                dst_port: header.dst_port,
            };
            self.fingerprint_cache.insert(flow_key, fp);

            // Detect encrypted DNS (DoH/DoT)
            self.check_encrypted_dns(tls_hello, header);
        }

        // Compute and cache JA4S fingerprint for TLS ServerHello replies.
        // The flow key swaps src/dst so it matches the originating ClientHello
        // direction (server → client view of the same 4-tuple).
        if let ParsedProtocol::TlsServer(ref server_hello) = parsed {
            let fp = ja4::compute_ja4s(server_hello);
            let flow_key = FlowKey {
                src_addr: header.dst_addr,
                src_port: header.dst_port,
                dst_addr: header.src_addr,
                dst_port: header.src_port,
            };
            self.ja4s_fingerprint_cache.insert(flow_key, fp);
            self.record_handshake(header, payload);
        }

        // Evaluate L7 rules against parsed content
        let l7_svc = self.l7_service.load();
        let l7_result = l7_svc.evaluate(header, &parsed);
        drop(l7_svc);

        self.apply_l7_rule_result(header, protocol_label, l7_result);
        self.notify_l7_observers(header, protocol_label, &parsed, payload.len());
    }

    /// Keep what a server's flight negotiated. The packet runs from the
    /// server to the client, so the client is its destination.
    fn record_handshake(&self, header: &PacketEvent, payload: &[u8]) {
        let Some(handshake) = domain::l7::handshake::read_server_flight(payload) else {
            return;
        };
        let ipv6 = header.is_ipv6();
        let observed_at_ns = wall_clock_ns();
        self.crypto_posture
            .observe_handshake(header, &handshake, observed_at_ns);
        self.handshake_log
            .record(domain::l7::handshake::HandshakeRecord {
                client: addr_to_ip(header.dst_addr, ipv6),
                client_port: header.dst_port,
                server: addr_to_ip(header.src_addr, ipv6),
                server_port: header.src_port,
                observed_at_ns,
                handshake,
            });
    }

    /// Hand one parsed payload to every registered observer, naming the
    /// workload that opened the connection once rather than once per observer.
    fn notify_l7_observers(
        &self,
        header: &PacketEvent,
        protocol: &'static str,
        parsed: &ParsedProtocol,
        payload_len: usize,
    ) {
        use ports::secondary::l7_observer_port::L7Exchange;

        if self.l7_observers.is_empty() {
            return;
        }
        let ipv6 = header.is_ipv6();
        let client = crate::addr_to_ip(header.src_addr, ipv6);
        let server = crate::addr_to_ip(header.dst_addr, ipv6);
        let workload = self.workloads.by_originated_flow(
            &ports::secondary::socket_identity_port::FlowEndpoints {
                local_addr: client,
                remote_addr: server,
                local_port: header.src_port,
                remote_port: header.dst_port,
                protocol: header.protocol,
            },
        );
        let exchange = L7Exchange {
            timestamp_ns: header.timestamp_ns,
            client,
            server,
            client_port: header.src_port,
            server_port: header.dst_port,
            ip_protocol: header.protocol,
            protocol,
            parsed,
            payload_len,
            workload: workload.as_ref(),
        };
        for observer in &self.l7_observers {
            observer.observe(&exchange);
        }
    }

    /// Compare a TCP connection's first payload with the protocol its port
    /// promises, count the verdict, and raise an alert on a mismatch.
    fn check_port_promise(&self, header: &PacketEvent, spoken: DetectedProtocol, len: usize) {
        use domain::l7::port_promise::{Offer, PORT_MISMATCH_RULE_ID, Verdict};

        const TCP: u8 = 6;
        let Some(ref tracker) = self.port_promise else {
            return;
        };
        if header.protocol != TCP {
            return;
        }
        // A poisoned lock leaves a table of connection keys and timestamps,
        // each written whole, so the table stays usable.
        let offer = tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .offer(
                (header.src_addr, header.src_port),
                (header.dst_addr, header.dst_port),
                header.is_ipv6(),
                spoken,
                len,
                header.timestamp_ns,
            );
        let judgement = match offer {
            Offer::Judged(judgement) => judgement,
            Offer::Uncounted => {
                self.metrics.record_l7_port_promise_uncounted();
                return;
            }
            Offer::AlreadyJudged | Offer::NoPromise => return,
        };
        let port = judgement.promise.port;
        self.metrics
            .record_l7_port_promise(port, judgement.verdict.as_str());
        if judgement.verdict != Verdict::Mismatch {
            return;
        }
        let promised: Vec<&str> = judgement
            .promise
            .protocols
            .iter()
            .map(|p| p.label())
            .collect();
        let detail = format!(
            "{} spoken on port {port}, which promises {}",
            spoken.label(),
            promised.join(" or ")
        );
        tracing::info!(
            src_ip = %header.src_ip(),
            dst_ip = %header.dst_ip(),
            src_port = header.src_port,
            dst_port = header.dst_port,
            l7_protocol = spoken.label(),
            promised_port = port,
            "protocol does not match its port"
        );
        self.emit_packet_security_alert(
            domain::alert::entity::PacketAlertComponent::L7,
            header,
            PORT_MISMATCH_RULE_ID,
            "alert",
            &detail,
        );
    }

    /// Log, audit, alert, and record metrics for the outcome of evaluating
    /// the L7 rule engine against a parsed payload.
    fn apply_l7_rule_result(
        &self,
        header: &PacketEvent,
        protocol_label: &str,
        l7_result: Option<(FirewallAction, domain::common::entity::RuleId)>,
    ) {
        if let Some((action, rule_id)) = l7_result {
            let action_label = match action {
                FirewallAction::Allow => "allow",
                FirewallAction::Deny => "deny",
                FirewallAction::Log => "log",
                FirewallAction::Reject => "reject",
            };

            if action == FirewallAction::Deny
                || action == FirewallAction::Log
                || action == FirewallAction::Reject
            {
                tracing::info!(
                    src_ip = %header.src_ip(),
                    dst_ip = %header.dst_ip(),
                    src_port = header.src_port,
                    dst_port = header.dst_port,
                    l7_protocol = protocol_label,
                    action = action_label,
                    rule_id = %rule_id,
                    "L7 rule matched"
                );
            } else {
                tracing::debug!(
                    src_ip = %header.src_ip(),
                    dst_ip = %header.dst_ip(),
                    l7_protocol = protocol_label,
                    action = action_label,
                    "L7 rule matched"
                );
            }

            let audit_action = match action {
                FirewallAction::Deny | FirewallAction::Reject => AuditAction::Drop,
                _ => AuditAction::Pass,
            };
            let detail = format!("L7 {protocol_label} {action_label} rule={rule_id}");
            self.audit_service.record_security_decision(
                AuditComponent::L7,
                audit_action,
                header.timestamp_ns,
                header.src_addr,
                header.dst_addr,
                header.is_ipv6(),
                header.src_port,
                header.dst_port,
                header.protocol,
                &rule_id.0,
                &detail,
            );

            // Emit alert for L7 deny/reject
            if action == FirewallAction::Deny || action == FirewallAction::Reject {
                self.emit_packet_security_alert(
                    domain::alert::entity::PacketAlertComponent::L7,
                    header,
                    &rule_id.0,
                    action_label,
                    &detail,
                );
            }

            self.metrics.record_packet("l7", action_label);
        } else {
            tracing::debug!(
                src_ip = %header.src_ip(),
                dst_ip = %header.dst_ip(),
                l7_protocol = protocol_label,
                "L7 event - no rule matched"
            );
            self.metrics.record_packet("l7", protocol_label);
        }
    }

    /// Flush reassembler flows that went idle past the configured timeout
    /// and run their (partial) buffers through the L7 parser.
    ///
    /// The reassembler only emits `Complete` for HTTP/1.x with a known
    /// `Content-Length`; every other protocol (TLS/DoH/DoT, SSH, Redis, …)
    /// stays buffered until it goes idle. Without this flush path those
    /// buffers would never reach [`process_l7_payload`](Self::process_l7_payload)
    /// and the protocol would silently never be detected.
    ///
    /// Returns the number of flows flushed.
    pub fn flush_reassembled(&self, now_ns: u64) -> usize {
        let Some(ref reassembler) = self.stream_reassembler else {
            return 0;
        };
        let flushed = reassembler.flush_expired(now_ns);
        let count = flushed.len();
        for (flow, bytes) in flushed {
            if bytes.is_empty() {
                continue;
            }
            let header = Self::l7_header_from_flow(&flow, now_ns);
            self.process_l7_payload(&header, &bytes);
        }
        count
    }

    /// Reconstruct a minimal `PacketEvent` header from a reassembler
    /// [`FlowId`](domain::l7::reassembler::FlowId) so a flushed buffer can be
    /// fed back through the same L7 processing as a live event. Only the
    /// 5-tuple and timestamp are meaningful; kernel-only metadata (socket
    /// cookie, cgroup, RSS hash) is unavailable for a flushed flow and left
    /// zeroed.
    fn l7_header_from_flow(flow: &domain::l7::reassembler::FlowId, now_ns: u64) -> PacketEvent {
        let mut flags = 0u8;
        if flow.is_ipv6 {
            flags |= ebpf_common::event::FLAG_IPV6;
        }
        PacketEvent {
            timestamp_ns: now_ns,
            src_addr: flow.src_addr,
            dst_addr: flow.dst_addr,
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            protocol: 6, // IPPROTO_TCP - L7 capture is TCP-only
            event_type: ebpf_common::event::EVENT_TYPE_L7,
            action: 0,
            flags,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            cgroup1_id: 0,
            rss_hash: 0,
            rss_hash_type: 0,
            rx_hw_timestamp_ns: 0,
        }
    }

    fn emit_packet_security_alert(
        &self,
        component: domain::alert::entity::PacketAlertComponent,
        event: &PacketEvent,
        rule_id: &str,
        action_label: &str,
        detail: &str,
    ) {
        let severity = match component {
            domain::alert::entity::PacketAlertComponent::Ips => {
                domain::common::entity::Severity::High
            }
            _ => domain::common::entity::Severity::Medium,
        };
        self.emit_packet_security_alert_with_severity(
            component,
            event,
            rule_id,
            action_label,
            detail,
            severity,
        );
    }

    /// Same as [`Self::emit_packet_security_alert`], for the callers that know
    /// the severity of the rule that fired rather than inheriting the
    /// component default.
    fn emit_packet_security_alert_with_severity(
        &self,
        component: domain::alert::entity::PacketAlertComponent,
        event: &PacketEvent,
        rule_id: &str,
        action_label: &str,
        detail: &str,
        severity: domain::common::entity::Severity,
    ) {
        let psa =
            self.packet_security_alert(component, event, rule_id, action_label, detail, severity);
        let _ = self.alert_tx.try_send(AlertEvent::PacketSecurity(psa));
    }

    /// The alert a packet-level decision becomes, with the flow's
    /// fingerprint and container attached where the datapath captured them.
    fn packet_security_alert(
        &self,
        component: domain::alert::entity::PacketAlertComponent,
        event: &PacketEvent,
        rule_id: &str,
        action_label: &str,
        detail: &str,
        severity: domain::common::entity::Severity,
    ) -> domain::alert::entity::PacketSecurityAlert {
        // Attach the flow's JA4 fingerprint when one was computed for the
        // originating ClientHello (same client→server flow key).
        let ja4_fingerprint = self
            .fingerprint_cache
            .get(&FlowKey {
                src_addr: event.src_addr,
                src_port: event.src_port,
                dst_addr: event.dst_addr,
                dst_port: event.dst_port,
            })
            .map(|fp| fp.ja4);
        // Attribute the alert to a container when the datapath captured a
        // cgroup id (TC ingress recovers it from the connect-hook cookie
        // map). No pid is available here, so resolution goes through the
        // cgroup-id path rather than `/proc/<pid>/cgroup`.
        let container = self.resolve_container_by_id(event.cgroup_id);
        domain::alert::entity::PacketSecurityAlert {
            component,
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            is_ipv6: event.is_ipv6(),
            timestamp_ns: event.timestamp_ns,
            rule_id: rule_id.to_string(),
            action_label: action_label.to_string(),
            severity,
            detail: detail.to_string(),
            ja4_fingerprint,
            container,
            kill_process: false,
        }
    }

    fn check_encrypted_dns(
        &self,
        tls_hello: &domain::l7::entity::TlsClientHello,
        header: &PacketEvent,
    ) {
        if let Some(detection) = self.encrypted_dns_detector.detect(
            tls_hello.sni.as_deref(),
            header.dst_port,
            header.src_addr,
            header.dst_addr,
        ) {
            let proto_label = match detection.protocol {
                domain::dns::encrypted_dns::EncryptedDnsProtocol::Doh => "doh",
                domain::dns::encrypted_dns::EncryptedDnsProtocol::Dot => "dot",
            };
            self.metrics
                .record_encrypted_dns(proto_label, &detection.resolver);
            tracing::info!(
                protocol = proto_label,
                resolver = %detection.resolver,
                src_ip = %header.src_ip(),
                dst_port = header.dst_port,
                "encrypted DNS detected"
            );

            // Emit DNS alert for encrypted DNS detection
            let dns_alert = domain::dns::entity::DnsAlert {
                domain: detection.resolver.clone(),
                resolved_ips: Vec::new(),
                reason: domain::dns::entity::DnsAlertReason::EncryptedDns {
                    protocol: proto_label.to_string(),
                    resolver: detection.resolver,
                },
                severity: domain::common::entity::Severity::Medium,
                timestamp_ns: header.timestamp_ns,
                container: self.resolve_container_by_id(header.cgroup_id),
            };
            let _ = self.alert_tx.try_send(AlertEvent::Dns(dns_alert));
        }
    }

    /// Resolve the socket that sent a query once, and hand the query to every
    /// observer with it.
    fn notify_dns_query_observers(&self, header: &DnsEvent, payload: &[u8]) {
        use ports::secondary::dns_query_observer_port::DnsQuery;

        if self.dns_query_observers.is_empty() {
            return;
        }
        let is_ipv6 = (header.flags & ebpf_common::event::FLAG_IPV6) != 0;
        let client = addr_to_ip(header.src_addr, is_ipv6);
        let server = addr_to_ip(header.dst_addr, is_ipv6);
        let Ok(domain::dns::entity::DnsPacket::Query(query)) =
            domain::dns::parser::parse_dns_packet(payload, client, header.timestamp_ns)
        else {
            return;
        };
        // IP protocol numbers: 6 for a query over TCP, 17 over UDP.
        let protocol: u8 = if ebpf_common::event::is_tcp(header.flags) {
            6
        } else {
            17
        };
        let workload = self.workloads.by_originated_flow(
            &ports::secondary::socket_identity_port::FlowEndpoints {
                local_addr: client,
                remote_addr: server,
                local_port: header.src_port,
                remote_port: header.dst_port,
                protocol,
            },
        );
        let exchange = DnsQuery {
            timestamp_ns: header.timestamp_ns,
            client,
            server,
            client_port: header.src_port,
            server_port: header.dst_port,
            ip_protocol: protocol,
            domain: &query.domain,
            workload: workload.as_ref(),
        };
        for observer in &self.dns_query_observers {
            let Some(mut alert) = observer.observe(&exchange) else {
                continue;
            };
            alert.src_addr = header.src_addr;
            alert.dst_addr = header.dst_addr;
            alert.src_port = header.src_port;
            alert.dst_port = header.dst_port;
            alert.protocol = protocol;
            alert.is_ipv6 = is_ipv6;
            if alert.matched_domain.is_none() {
                alert.matched_domain = Some(query.domain.clone());
            }
            if alert.workload.is_none() {
                alert.workload.clone_from(&workload);
            }
            if alert.container.is_none() {
                alert.container = self.resolve_container_by_id(header.cgroup_id);
            }
            let _ = self.alert_tx.try_send(AlertEvent::System(Box::new(alert)));
        }
    }

    fn process_dns_event(&self, header: DnsEvent, payload: &[u8]) {
        let is_tcp = ebpf_common::event::is_tcp(header.flags);
        let direction = if header.direction == ebpf_common::dns::DNS_DIRECTION_RESPONSE {
            "response"
        } else {
            "query"
        };
        let transport = if is_tcp { "tcp" } else { "udp" };

        self.metrics.record_packet("dns", direction);

        tracing::debug!(
            dns_payload_len = header.dns_payload_len,
            direction,
            transport,
            "DNS event received"
        );

        // A query is only of interest to the observers; everything below
        // reads the answers of a response.
        if header.direction != ebpf_common::dns::DNS_DIRECTION_RESPONSE {
            self.notify_dns_query_observers(&header, payload);
            return;
        }

        let is_ipv6 = (header.flags & ebpf_common::event::FLAG_IPV6) != 0;
        let src_ip = addr_to_ip(header.src_addr, is_ipv6);
        let parsed =
            match domain::dns::parser::parse_dns_packet(payload, src_ip, header.timestamp_ns) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = %e, "DNS packet parse error");
                    return;
                }
            };

        let domain::dns::entity::DnsPacket::Response(response) = parsed else {
            return;
        };

        // Insert each answer record into DNS cache
        if let Some(ref cache_svc) = self.dns_cache_svc {
            for record in &response.answers {
                if !record.resolved_ips.is_empty() {
                    cache_svc.insert(
                        record.domain.clone(),
                        record.resolved_ips.clone(),
                        u64::from(record.ttl),
                        header.timestamp_ns,
                    );
                }
            }
        }

        // Check DNS blocklist for each answered domain
        if let Some(ref blocklist_svc) = self.dns_blocklist_svc {
            for record in &response.answers {
                if !record.resolved_ips.is_empty() {
                    blocklist_svc.on_dns_response(
                        &record.domain,
                        &record.resolved_ips,
                        record.ttl,
                        header.timestamp_ns,
                    );
                }
            }
        }
    }

    fn process_dlp_event(&self, event: &DlpEvent) {
        self.metrics.record_packet("dlp", "captured");

        let direction = if event.direction == ebpf_common::dlp::DLP_DIRECTION_READ {
            "read"
        } else {
            "write"
        };

        tracing::debug!(
            pid = event.pid,
            tgid = event.tgid,
            data_len = event.data_len,
            direction,
            "DLP event received"
        );

        let actual_len = (event.data_len as usize).min(ebpf_common::dlp::DLP_MAX_EXCERPT);
        let data = &event.data_excerpt[..actual_len];
        // Resolved once per event and only when something will read them:
        // the pid is the same for every alert raised on one buffer, and the
        // process may exit between two of them.
        let mut context: Option<DlpEventContext> = None;

        if let Some(ref dlp_svc) = self.dlp_service {
            let svc = dlp_svc.load();
            if svc.enabled() {
                let matches = svc.scan_data(data);
                if !matches.is_empty() {
                    tracing::info!(
                        pid = event.pid,
                        match_count = matches.len(),
                        direction,
                        "DLP patterns matched in SSL traffic"
                    );
                    self.metrics.record_packet("dlp", "alert");

                    let ctx = context.get_or_insert_with(|| self.dlp_event_context(event));
                    let patterns = svc.list_patterns();
                    for m in &matches {
                        if let Some(pattern) = patterns.get(m.pattern_index) {
                            let mut dlp_alert = DlpAlert::from_event(event, pattern);
                            dlp_alert.container.clone_from(&ctx.container);
                            dlp_alert.executable.clone_from(&ctx.executable);
                            if self.alert_tx.try_send(AlertEvent::Dlp(dlp_alert)).is_err() {
                                self.metrics.record_event_dropped("alert_channel_full");
                            }
                        }
                    }
                }
            }
        }

        if !self.tls_plaintext_observers.is_empty() {
            let ctx = context.get_or_insert_with(|| self.dlp_event_context(event));
            self.notify_tls_plaintext_observers(event, data, ctx);
        }
    }

    fn dlp_event_context(&self, event: &DlpEvent) -> DlpEventContext {
        DlpEventContext {
            container: self.resolve_container_dlp(event.pid, event.cgroup_id),
            executable: self
                .executable_reader
                .as_ref()
                .and_then(|reader| reader.read_executable(event.pid)),
        }
    }

    fn notify_tls_plaintext_observers(&self, event: &DlpEvent, data: &[u8], ctx: &DlpEventContext) {
        use ports::secondary::tls_plaintext_observer_port::{PlaintextDirection, TlsPlaintext};

        let direction = if event.direction == ebpf_common::dlp::DLP_DIRECTION_READ {
            PlaintextDirection::Read
        } else {
            PlaintextDirection::Write
        };
        let flow = domain::dlp::entity::DlpFlow::from_socket(&event.flow);
        let plaintext = TlsPlaintext {
            timestamp_ns: event.timestamp_ns,
            pid: event.pid,
            tgid: event.tgid,
            cgroup_id: event.cgroup_id,
            direction,
            data,
            flow: flow.as_ref(),
            exe: ctx.executable.as_ref().map(|e| e.path.as_str()),
            container: ctx.container.as_ref(),
        };
        for observer in &self.tls_plaintext_observers {
            for mut alert in observer.observe(&plaintext) {
                if let Some(ref flow) = flow {
                    // The side that sent the bytes is the alert's source: the
                    // peer for a buffer the process read, the local end for
                    // one it wrote.
                    let (src, dst, src_port, dst_port) = match direction {
                        PlaintextDirection::Read => {
                            (flow.dst_addr, flow.src_addr, flow.dst_port, flow.src_port)
                        }
                        PlaintextDirection::Write => {
                            (flow.src_addr, flow.dst_addr, flow.src_port, flow.dst_port)
                        }
                    };
                    alert.src_addr = src;
                    alert.dst_addr = dst;
                    alert.src_port = src_port;
                    alert.dst_port = dst_port;
                    alert.protocol = flow.protocol;
                    alert.is_ipv6 = flow.is_ipv6;
                    alert.flow_source = Some(flow.source.as_str().to_string());
                }
                alert.pid = Some(event.pid);
                alert.tgid = Some(event.tgid);
                alert.direction = Some(event.direction);
                if alert.container.is_none() {
                    alert.container.clone_from(&ctx.container);
                }
                if alert.executable_path.is_none()
                    && let Some(ref exe) = ctx.executable
                {
                    alert.executable_path = Some(exe.path.clone());
                    alert.executable_dev = Some(exe.dev);
                    alert.executable_inode = Some(exe.inode);
                    alert.executable_source = Some(exe.source.as_str().to_string());
                }
                if self
                    .alert_tx
                    .try_send(AlertEvent::System(Box::new(alert)))
                    .is_err()
                {
                    self.metrics.record_event_dropped("alert_channel_full");
                }
            }
        }
    }

    fn process_ddos_event(&self, event: PacketEvent) {
        self.metrics.record_packet("ddos", "drop");

        let Some(ref ddos_service) = self.ddos_service else {
            return;
        };

        let Some(attack_type) = DdosAttackType::from_event_type(event.event_type) else {
            return;
        };

        let ddos_event = DdosEvent {
            timestamp_ns: event.timestamp_ns,
            attack_type,
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            is_ipv6: event.is_ipv6(),
        };

        let svc = ddos_service.load();
        let changed = svc.process_event(&ddos_event);

        if changed {
            tracing::info!(
                attack_type = ?attack_type,
                src_ip = %event.src_ip(),
                dst_ip = %event.dst_ip(),
                "DDoS attack state changed"
            );

            // Find the most recent matching attack and send an alert
            if let Some(attack) = svc
                .active_attacks()
                .iter()
                .rev()
                .find(|a| a.attack_type == attack_type)
            {
                let alert = AlertEvent::Ddos {
                    attack: attack.clone(),
                    src_addr: event.src_addr,
                    dst_addr: event.dst_addr,
                    is_ipv6: event.is_ipv6(),
                    src_port: event.src_port,
                    dst_port: event.dst_port,
                    protocol: event.protocol,
                };
                if self.alert_tx.try_send(alert).is_err() {
                    self.metrics.record_event_dropped("alert_channel_full");
                }
            }
        }

        // Filed under DDoS, the component that decided the drop, so
        // `audit logs --component ddos` finds it.
        self.audit_service.record_security_decision(
            AuditComponent::Ddos,
            AuditAction::Drop,
            event.timestamp_ns,
            event.src_addr,
            event.dst_addr,
            event.is_ipv6(),
            event.src_port,
            event.dst_port,
            event.protocol,
            "",
            &format!("ddos {attack_type:?} drop"),
        );
    }

    fn process_lb_event(&self, event: &PacketEvent) {
        let action_label = match event.action {
            LB_ACTION_FORWARD => "forward",
            LB_ACTION_NO_BACKEND => "no_backend",
            _ => "unknown",
        };
        self.metrics.record_packet("loadbalancer", action_label);

        tracing::debug!(
            src_ip = %event.src_ip(),
            dst_ip = %event.dst_ip(),
            src_port = event.src_port,
            dst_port = event.dst_port,
            protocol = event.protocol,
            action = action_label,
            "load balancer event"
        );
    }
}

/// Nanoseconds since the epoch, the clock the handshake log and the posture
/// table are read on.
fn wall_clock_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

fn action_label(action: u8) -> &'static str {
    match action {
        0 => "pass",
        1 => "drop",
        2 => "log",
        _ => "unknown",
    }
}

fn event_type_label(event_type: u8) -> &'static str {
    match event_type {
        EVENT_TYPE_FIREWALL => "firewall",
        EVENT_TYPE_IDS => "ids",
        EVENT_TYPE_RATELIMIT => "ratelimit",
        EVENT_TYPE_THREATINTEL => "threatintel",
        EVENT_TYPE_DDOS_SYN
        | EVENT_TYPE_DDOS_ICMP
        | EVENT_TYPE_DDOS_AMP
        | EVENT_TYPE_DDOS_CONNTRACK => "ddos",
        EVENT_TYPE_LB => "lb",
        _ => "unknown",
    }
}

use crate::addr_to_ip;

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, Protocol, RuleId, Severity};
    use domain::firewall::entity::FirewallAction;
    use domain::ids::engine::IdsEngine;
    use domain::ids::entity::IdsRule;
    use domain::l7::engine::L7Engine;
    use domain::l7::entity::{L7Matcher, L7Rule};
    use domain::threatintel::engine::ThreatIntelEngine;
    use ebpf_common::event::{EVENT_TYPE_DLP, EVENT_TYPE_IDS, EVENT_TYPE_L7, EVENT_TYPE_RATELIMIT};
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics, CtMetrics,
        DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics,
        FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
        ThreatIntelMetrics, ZoneMetrics,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::audit_service_impl::AuditAppService;
    use crate::threatintel_service_impl::ThreatIntelAppService;
    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use ports::secondary::audit_sink::AuditSink;

    struct TestMetrics {
        packet_calls: AtomicU32,
        dropped_calls: AtomicU32,
        fingerprint_calls: AtomicU32,
        encrypted_dns_calls: AtomicU32,
        last_component: std::sync::Mutex<String>,
        last_action: std::sync::Mutex<String>,
        last_fingerprint: std::sync::Mutex<String>,
        last_encrypted_dns: std::sync::Mutex<(String, String)>,
        port_promises: std::sync::Mutex<Vec<(u16, String)>>,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                packet_calls: AtomicU32::new(0),
                dropped_calls: AtomicU32::new(0),
                fingerprint_calls: AtomicU32::new(0),
                encrypted_dns_calls: AtomicU32::new(0),
                last_component: std::sync::Mutex::new(String::new()),
                last_action: std::sync::Mutex::new(String::new()),
                last_fingerprint: std::sync::Mutex::new(String::new()),
                last_encrypted_dns: std::sync::Mutex::new((String::new(), String::new())),
                port_promises: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl PacketMetrics for TestMetrics {
        fn record_packet(&self, interface: &str, action: &str) {
            self.packet_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_component.lock().unwrap() = interface.to_string();
            *self.last_action.lock().unwrap() = action.to_string();
        }

        fn record_l7_port_promise(&self, port: u16, verdict: &str) {
            self.port_promises
                .lock()
                .unwrap()
                .push((port, verdict.to_string()));
        }
    }
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {}
    impl IpsMetrics for TestMetrics {}
    impl DnsMetrics for TestMetrics {
        fn record_encrypted_dns(&self, protocol: &str, resolver: &str) {
            self.encrypted_dns_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_encrypted_dns.lock().unwrap() = (protocol.to_string(), resolver.to_string());
        }
    }
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {}
    impl ConfigMetrics for TestMetrics {}
    impl EventMetrics for TestMetrics {
        fn record_event_dropped(&self, _reason: &str) {
            self.dropped_calls.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl DlpMetrics for TestMetrics {}
    impl DdosMetrics for TestMetrics {}
    impl ConntrackMetrics for TestMetrics {}
    impl RoutingMetrics for TestMetrics {}
    impl AuditMetrics for TestMetrics {}
    impl LbMetrics for TestMetrics {}
    impl FingerprintMetrics for TestMetrics {
        fn record_fingerprint_seen(&self, ja4: &str) {
            self.fingerprint_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_fingerprint.lock().unwrap() = ja4.to_string();
        }
    }
    impl ContainerMetrics for TestMetrics {}
    impl CtMetrics for TestMetrics {}
    impl ThreatIntelMetrics for TestMetrics {}
    impl ZoneMetrics for TestMetrics {}

    fn make_ids_rule(id: &str) -> IdsRule {
        IdsRule {
            id: RuleId(id.to_string()),
            description: format!("Test rule {id}"),
            severity: Severity::High,
            mode: DomainMode::Alert,
            protocol: Protocol::Tcp,
            dst_port: Some(22),
            src_port: None,
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
            country_thresholds: None,
            group_mask: 0,
            tenant_id: 0,
            workload: None,
            kill_process: false,
            imported: None,
        }
    }

    fn make_event(event_type: u8, rule_id: u32) -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            event_type,
            action: 0,
            flags: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            cgroup1_id: 0,
            rss_hash: 0,
            rss_hash_type: 0,
            rx_hw_timestamp_ns: 0,
            rule_id,
        }
    }

    fn make_service_with_rules(rules: Vec<IdsRule>) -> Arc<ArcSwap<IdsAppService>> {
        let mut engine = IdsEngine::new();
        for rule in rules {
            engine.add_rule(rule).unwrap();
        }
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(IdsAppService::new(
            engine, None, metrics,
        )))
    }

    fn make_l7_service() -> Arc<ArcSwap<L7AppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(L7AppService::new(
            L7Engine::new(),
            metrics,
        )))
    }

    fn make_ti_service() -> Arc<ArcSwap<ThreatIntelAppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(ThreatIntelAppService::new(
            ThreatIntelEngine::new(1_000_000),
            metrics,
            vec![],
        )))
    }

    struct NoopAuditSink;
    impl AuditSink for NoopAuditSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    fn make_audit_service() -> Arc<AuditAppService> {
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        Arc::new(AuditAppService::new(sink))
    }

    fn make_l7_service_with_rules(rules: Vec<L7Rule>) -> Arc<ArcSwap<L7AppService>> {
        let mut engine = L7Engine::new();
        for rule in rules {
            engine.add_rule(rule).unwrap();
        }
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(L7AppService::new(engine, metrics)))
    }

    fn make_dispatcher(
        ids_service: Arc<ArcSwap<IdsAppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<AlertEvent>,
    ) -> EventDispatcher {
        EventDispatcher::new(
            ids_service,
            make_l7_service(),
            make_ti_service(),
            make_audit_service(),
            metrics,
            alert_tx,
            None,
        )
    }

    /// Unwrap an `AlertEvent::Ids` variant for test assertions.
    fn unwrap_ids_alert(event: AlertEvent) -> IdsAlert {
        match event {
            AlertEvent::Ids(a) => a,
            _ => panic!("expected AlertEvent::Ids"),
        }
    }

    fn make_dispatcher_with_l7(
        ids_service: Arc<ArcSwap<IdsAppService>>,
        l7_service: Arc<ArcSwap<L7AppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<AlertEvent>,
    ) -> EventDispatcher {
        EventDispatcher::new(
            ids_service,
            l7_service,
            make_ti_service(),
            make_audit_service(),
            metrics,
            alert_tx,
            None,
        )
    }

    /// Minimal well-formed TLS 1.2 `ClientHello` record carrying an SNI.
    fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let sni_value_len = 2 + 1 + 2 + name.len();
        let sni_list_len = 1 + 2 + name.len();
        let ext_data_len = 4 + sni_value_len;
        let ch_body_len = 2 + 32 + 1 + 4 + 2 + 2 + ext_data_len;
        let hs_len = 4 + ch_body_len;

        let mut pkt = Vec::new();
        pkt.push(0x16); // handshake record
        pkt.extend_from_slice(&[0x03, 0x01]); // record version (TLS 1.0)
        pkt.extend_from_slice(&u16::try_from(hs_len).unwrap().to_be_bytes());
        pkt.push(0x01); // ClientHello
        let body = u32::try_from(ch_body_len).unwrap();
        pkt.push((body >> 16) as u8);
        pkt.push((body >> 8) as u8);
        pkt.push(body as u8);
        pkt.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        pkt.extend_from_slice(&[0xAA; 32]); // random
        pkt.push(0x00); // session id
        pkt.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // 1 cipher suite
        pkt.extend_from_slice(&[0x01, 0x00]); // 1 compression method (null)
        pkt.extend_from_slice(&u16::try_from(ext_data_len).unwrap().to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // ext type SNI
        pkt.extend_from_slice(&u16::try_from(sni_value_len).unwrap().to_be_bytes());
        pkt.extend_from_slice(&u16::try_from(sni_list_len).unwrap().to_be_bytes());
        pkt.push(0x00); // host_name type
        pkt.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        pkt.extend_from_slice(name);
        pkt
    }

    // A complete TLS ClientHello is a self-contained record, so the
    // reassembler recognises its boundary and emits it inline - the L7 parser
    // (and JA4 fingerprinting) runs immediately, not deferred to the idle
    // flush. Nothing is left buffered for a later flush.
    #[tokio::test]
    async fn complete_tls_clienthello_parses_inline() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let reassembler = Arc::new(domain::l7::reassembler::StreamReassembler::new(
            domain::l7::reassembler::ReassemblerConfig::default(),
        ));
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_stream_reassembler(reassembler);

        // DoT flow: dst_port 853, complete TLS ClientHello record.
        let mut header = make_event(EVENT_TYPE_L7, 0);
        header.dst_port = 853;
        let client_hello = build_tls_client_hello("dot.example");

        // Live path: the complete record is parsed inline → DoT alert now.
        dispatcher.process_l7_event(header, &client_hello);
        match alert_rx.try_recv() {
            Ok(AlertEvent::Dns(alert)) => match alert.reason {
                domain::dns::entity::DnsAlertReason::EncryptedDns { protocol, .. } => {
                    assert_eq!(protocol, "dot");
                }
                _ => panic!("expected EncryptedDns reason"),
            },
            _ => panic!("expected AlertEvent::Dns emitted inline"),
        }

        // The flow was emitted, not buffered - the idle flush has nothing left.
        let flushed = dispatcher.flush_reassembled(10_000_000_000);
        assert_eq!(
            flushed, 0,
            "no flow should remain buffered after inline parse"
        );
    }

    // The two L7 call sites that reach the metrics port sit on the same
    // path: a ClientHello is fingerprinted, then handed to the encrypted-DNS
    // detector. The port gives both methods a default empty body, so a call
    // that reaches no implementation still compiles - what is asserted here
    // is that the pipeline reaches the port at all.
    #[tokio::test]
    async fn a_clienthello_records_the_fingerprint_and_the_encrypted_dns_metrics() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let reassembler = Arc::new(domain::l7::reassembler::StreamReassembler::new(
            domain::l7::reassembler::ReassemblerConfig::default(),
        ));
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_stream_reassembler(reassembler);

        let mut header = make_event(EVENT_TYPE_L7, 0);
        header.dst_port = 853;
        dispatcher.process_l7_event(header, &build_tls_client_hello("dot.example"));

        assert_eq!(metrics.fingerprint_calls.load(Ordering::Relaxed), 1);
        assert!(
            metrics.last_fingerprint.lock().unwrap().starts_with('t'),
            "the JA4 value the pipeline computed reaches the port"
        );
        assert_eq!(metrics.encrypted_dns_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            *metrics.last_encrypted_dns.lock().unwrap(),
            ("dot".to_string(), "dot.example".to_string())
        );
    }

    #[tokio::test]
    async fn firewall_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_FIREWALL, 0));

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "firewall");
        assert_eq!(*metrics.last_action.lock().unwrap(), "pass");
    }

    #[tokio::test]
    async fn ids_event_with_matching_rule_produces_alert() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
        assert_eq!(alert.rule_id.0, "ids-001");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ids");
    }

    #[tokio::test]
    async fn ids_alert_carries_the_container_the_datapath_resolved() {
        // The classifier writes the sending cgroup into the event, so an
        // alert raised for a containerised process has to name it. Left
        // unset, the field reads as "host traffic" and the operator loses
        // the only attribution the kernel could provide.
        struct StubIds(String);
        impl domain::container::engine::CgroupIdResolver for StubIds {
            fn path_for_id(&self, cgroup_id: u64) -> Option<String> {
                (cgroup_id == 42).then(|| self.0.clone())
            }
        }
        struct NoProc;
        impl domain::container::engine::CgroupReader for NoProc {
            fn read_cgroup(&self, _pid: u32) -> std::io::Result<String> {
                Err(std::io::Error::other("no proc in this test"))
            }
        }

        let cid = "b".repeat(64);
        let resolver = Arc::new(
            domain::container::engine::ContainerResolverEngine::new(Arc::new(NoProc), 16)
                .with_id_resolver(Arc::new(StubIds(format!(
                    "/system.slice/docker-{cid}.scope"
                )))),
        );

        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_container_resolver(resolver);

        let mut event = make_event(EVENT_TYPE_IDS, 0);
        event.cgroup_id = 42;
        dispatcher.dispatch_event(event);

        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
        assert_eq!(
            alert.container.as_ref().and_then(|c| c.container_id()),
            Some(cid.as_str())
        );
    }

    #[tokio::test]
    async fn ids_alert_from_host_traffic_names_no_container() {
        // cgroup_id 0 is the datapath saying it captured no cgroup, not a
        // resolution failure, so nothing is looked up and no container is
        // claimed.
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
        assert!(alert.container.is_none());
    }

    #[tokio::test]
    async fn detection_rule_sharing_a_port_with_a_prevention_rule_still_alerts() {
        // The kernel pattern map holds one rule per (port, protocol), so an
        // IPS rule on TCP/22 displaces an IDS rule watching the same port and
        // the classifier only ever names the IPS rule. The detection rule the
        // operator loaded must still fire: which of the two owns a map slot
        // is a kernel storage detail, not a policy decision.
        let ids = make_service_with_rules(vec![make_ids_rule("ids-ssh-bruteforce")]);
        let mut with_prevention = (**ids.load()).clone();
        let mut prevention = make_ids_rule("ips-ssh-bruteforce");
        prevention.mode = DomainMode::Block;
        with_prevention
            .set_prevention_rules(vec![prevention])
            .unwrap();
        ids.store(Arc::new(with_prevention));

        let ips_metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        let ips = Arc::new(ArcSwap::from_pointee(IpsAppService::new(
            domain::ips::engine::IpsEngine::new(domain::ips::entity::IpsPolicy::default()),
            ips_metrics,
        )));

        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx).with_ips_service(ips);

        // rule_id 1 is the prevention rule: it won the map slot.
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 1));

        let mut detection_ids = Vec::new();
        let mut prevention_ids = Vec::new();
        while let Ok(event) = alert_rx.try_recv() {
            match event {
                AlertEvent::Ids(a) => detection_ids.push(a.rule_id.0),
                AlertEvent::PacketSecurity(a)
                    if a.component == domain::alert::entity::PacketAlertComponent::Ips =>
                {
                    prevention_ids.push(a.rule_id);
                }
                _ => {}
            }
        }
        assert_eq!(detection_ids, vec!["ids-ssh-bruteforce".to_string()]);
        assert!(
            prevention_ids.contains(&"ips-ssh-bruteforce".to_string()),
            "prevention alert missing: {prevention_ids:?}"
        );
    }

    #[tokio::test]
    async fn a_blocking_prevention_rule_asking_for_the_process_says_so_on_its_alert() {
        for (mode, asks, expected) in [
            (DomainMode::Block, true, true),
            (DomainMode::Alert, true, false),
            (DomainMode::Block, false, false),
        ] {
            let ids = make_service_with_rules(vec![make_ids_rule("ids-ssh-bruteforce")]);
            let mut with_prevention = (**ids.load()).clone();
            let mut prevention = make_ids_rule("ips-ssh-bruteforce");
            prevention.mode = mode;
            prevention.kill_process = asks;
            with_prevention
                .set_prevention_rules(vec![prevention])
                .unwrap();
            ids.store(Arc::new(with_prevention));

            let ips_metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
            let ips = Arc::new(ArcSwap::from_pointee(IpsAppService::new(
                domain::ips::engine::IpsEngine::new(domain::ips::entity::IpsPolicy::default()),
                ips_metrics,
            )));
            let metrics = Arc::new(TestMetrics::new());
            let (alert_tx, mut alert_rx) = mpsc::channel(10);
            let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
                .with_ips_service(ips);

            dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 1));

            let mut kills = Vec::new();
            while let Ok(event) = alert_rx.try_recv() {
                if let AlertEvent::PacketSecurity(a) = event
                    && a.rule_id == "ips-ssh-bruteforce"
                {
                    kills.push(a.kill_process);
                }
            }
            assert_eq!(kills, vec![expected], "mode {mode:?}, asks {asks}");
        }
    }

    #[tokio::test]
    async fn shadowed_detection_rule_does_not_double_count_toward_auto_blacklist() {
        // One packet is one detection however many rules name it. Counting the
        // userspace replay as well would trip the IPS auto-blacklist threshold
        // at half the configured burst.
        let ids = make_service_with_rules(vec![make_ids_rule("ids-ssh-bruteforce")]);
        let mut with_prevention = (**ids.load()).clone();
        let mut prevention = make_ids_rule("ips-ssh-bruteforce");
        prevention.mode = DomainMode::Block;
        with_prevention
            .set_prevention_rules(vec![prevention])
            .unwrap();
        ids.store(Arc::new(with_prevention));

        let ips_metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        let mut ips_svc = IpsAppService::new(
            domain::ips::engine::IpsEngine::new(domain::ips::entity::IpsPolicy {
                auto_blacklist_threshold: 2,
                ..domain::ips::entity::IpsPolicy::default()
            }),
            ips_metrics,
        );
        ips_svc.set_mode(DomainMode::Block);
        let ips = Arc::new(ArcSwap::from_pointee(ips_svc));

        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(32);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_ips_service(Arc::clone(&ips));

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 1));

        let mut blacklisted = false;
        while let Ok(event) = alert_rx.try_recv() {
            if let AlertEvent::PacketSecurity(a) = event
                && a.action_label == "blacklist"
            {
                blacklisted = true;
            }
        }
        assert!(
            !blacklisted,
            "a single packet reached the 2-detection auto-blacklist threshold"
        );
    }

    #[tokio::test]
    async fn ids_event_with_no_matching_rule_produces_no_alert() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // rule_id=99 → out of range
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 99));

        assert!(alert_rx.try_recv().is_err());
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ids_event_with_disabled_service_produces_no_alert() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        {
            let mut svc = (**ids.load()).clone();
            svc.set_enabled(false);
            ids.store(Arc::new(svc));
        }
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unknown_event_type_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_DLP, 0));

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "unknown");
    }

    #[tokio::test]
    async fn backpressure_drops_alert_on_full_channel() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        // Channel capacity of 1
        let (alert_tx, _alert_rx) = mpsc::channel(1);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // Fill the channel
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));
        // This should trigger backpressure
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn run_drains_on_cancellation() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(100);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(100);
        let cancel = CancellationToken::new();

        // Send events before starting the dispatcher
        event_tx
            .send(AgentEvent::L4(make_event(EVENT_TYPE_IDS, 0)))
            .await
            .unwrap();
        event_tx
            .send(AgentEvent::L4(make_event(EVENT_TYPE_FIREWALL, 0)))
            .await
            .unwrap();

        // Cancel immediately
        cancel.cancel();

        // Run the dispatcher - it should drain both events then exit
        dispatcher.run(event_rx, cancel).await;

        // The IDS event should have produced an alert
        assert!(alert_rx.try_recv().is_ok());
        // Both events should have been processed (2 metric calls)
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn run_exits_on_channel_close() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(10);
        let cancel = CancellationToken::new();

        // Drop sender to close channel
        drop(event_tx);

        // Should exit immediately since channel is closed
        dispatcher.run(event_rx, cancel).await;
    }

    #[tokio::test]
    async fn firewall_event_action_labels() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // action=1 (drop)
        let mut event = make_event(EVENT_TYPE_FIREWALL, 0);
        event.action = 1;
        dispatcher.dispatch_event(event);
        assert_eq!(*metrics.last_action.lock().unwrap(), "drop");

        // action=2 (log)
        event.action = 2;
        dispatcher.dispatch_event(event);
        assert_eq!(*metrics.last_action.lock().unwrap(), "log");
    }

    #[tokio::test]
    async fn ratelimit_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let mut event = make_event(EVENT_TYPE_RATELIMIT, 0);
        event.action = 1; // drop (throttled)
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ratelimit");
        assert_eq!(*metrics.last_action.lock().unwrap(), "drop");
    }

    #[tokio::test]
    async fn ratelimit_event_pass_records_pass_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let event = make_event(EVENT_TYPE_RATELIMIT, 0); // action=0 (pass)
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ratelimit");
        assert_eq!(*metrics.last_action.lock().unwrap(), "pass");
    }

    #[tokio::test]
    async fn ratelimit_event_pass_still_alerts() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // A `pass` rule forwards the excess, and the kernel emits the event
        // only once the bucket is empty: staying silent would have made a
        // limit sized against live traffic report nothing at all.
        let event = make_event(EVENT_TYPE_RATELIMIT, 0);
        dispatcher.dispatch_event(event);

        let alert = alert_rx.try_recv().unwrap();
        match alert {
            AlertEvent::PacketSecurity(a) => {
                assert_eq!(
                    a.component,
                    domain::alert::entity::PacketAlertComponent::Ratelimit
                );
                assert_eq!(a.action_label, "pass");
                assert_eq!(a.detail, "ratelimit pass");
            }
            _ => panic!("expected AlertEvent::PacketSecurity from ratelimit"),
        }
    }

    // ── L7 dispatch tests ──────────────────────────────────────────

    #[tokio::test]
    async fn l7_event_with_http_payload_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();

        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "http");
    }

    #[tokio::test]
    async fn a_server_flight_lands_in_the_handshake_log_with_the_client_as_destination() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let header = PacketEvent {
            src_port: 443,
            dst_port: 51_000,
            ..make_event(EVENT_TYPE_L7, 0)
        };
        // TLS 1.3 ServerHello: TLS_AES_128_GCM_SHA256 over X25519MLKEM768.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0, 0x13, 0x01, 0, 0, 16]);
        body.extend_from_slice(&[0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]);
        body.extend_from_slice(&[0x00, 0x33, 0x00, 0x06, 0x11, 0xEC, 0x00, 0x02, 0xAA, 0xBB]);
        let mut hs = vec![0x02, 0, 0, u8::try_from(body.len()).unwrap()];
        hs.extend(body);
        let mut payload = vec![0x16, 0x03, 0x03, 0, u8::try_from(hs.len()).unwrap()];
        payload.extend(hs);

        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

        let log = dispatcher.handshake_log().recent();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].server_port, 443);
        assert_eq!(log[0].client_port, 51_000);
        assert_eq!(log[0].handshake.group, Some(0x11EC));
        assert_eq!(
            log[0].handshake.posture(),
            domain::l7::handshake::CryptoPosture::PostQuantum
        );

        // The same connection counts once on its edge, and a clear request
        // to another port counts as clear text there.
        dispatcher.dispatch_agent_event(AgentEvent::L7 {
            header: PacketEvent {
                src_port: 51_001,
                dst_port: 6379,
                ..make_event(EVENT_TYPE_L7, 0)
            },
            payload: b"*1\r\n$4\r\nPING\r\n".to_vec(),
        });
        let reading = dispatcher.crypto_posture().reading();
        assert_eq!(reading.edges.len(), 2);
        let tls = reading
            .edges
            .iter()
            .find(|(key, _)| key.server_port == 443)
            .map(|(_, edge)| edge.post_quantum);
        assert_eq!(tls, Some(1));
        let redis = reading
            .edges
            .iter()
            .find(|(key, _)| key.server_port == 6379)
            .map(|(_, edge)| edge.clear_text_connections());
        assert_eq!(redis, Some(1));
    }

    #[test]
    fn a_request_and_its_answer_land_on_the_same_worker() {
        let request = make_event(EVENT_TYPE_L7, 0);
        let answer = PacketEvent {
            src_addr: request.dst_addr,
            dst_addr: request.src_addr,
            src_port: request.dst_port,
            dst_port: request.src_port,
            ..request
        };
        let l7 = |header| AgentEvent::L7 {
            header,
            payload: Vec::new(),
        };
        for workers in 2..=16 {
            assert_eq!(
                EventDispatcher::worker_index(&l7(request), workers),
                EventDispatcher::worker_index(&l7(answer), workers),
                "{workers} workers"
            );
        }
    }

    #[tokio::test]
    async fn a_shared_posture_meter_keeps_its_counts_across_dispatchers() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let meter = Arc::new(crate::crypto_posture_meter::CryptoPostureMeter::new(
            crate::workload_resolver::WorkloadResolver::new(),
        ));
        let request = || AgentEvent::L7 {
            header: PacketEvent {
                src_port: 51_001,
                dst_port: 6379,
                ..make_event(EVENT_TYPE_L7, 0)
            },
            payload: b"*1\r\n$4\r\nPING\r\n".to_vec(),
        };
        let (first_tx, _first_rx) = mpsc::channel(10);
        let first = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), first_tx)
            .with_workload_resolver(crate::workload_resolver::WorkloadResolver::new())
            .with_crypto_posture(Arc::clone(&meter));
        first.dispatch_agent_event(request());
        drop(first);

        let (second_tx, _second_rx) = mpsc::channel(10);
        let second = make_dispatcher(ids, metrics, second_tx)
            .with_workload_resolver(crate::workload_resolver::WorkloadResolver::new())
            .with_crypto_posture(Arc::clone(&meter));
        assert!(Arc::ptr_eq(&second.crypto_posture(), &meter));
        assert_eq!(meter.reading().edges.len(), 1);
    }

    /// Protocol, payload length, HTTP host and process id of one exchange.
    type Seen = (&'static str, usize, Option<String>, Option<u32>);

    /// Keeps what each exchange lent it, as an extension would.
    #[derive(Default)]
    struct RecordingObserver {
        seen: Mutex<Vec<Seen>>,
    }

    impl ports::secondary::l7_observer_port::L7Observer for RecordingObserver {
        fn observe(&self, exchange: &ports::secondary::l7_observer_port::L7Exchange<'_>) {
            let host = match exchange.parsed {
                ParsedProtocol::Http(req) => req.host.clone(),
                _ => None,
            };
            self.seen.lock().unwrap().push((
                exchange.protocol,
                exchange.payload_len,
                host,
                exchange.workload.map(|w| w.pid),
            ));
        }
    }

    struct OwnedBy(u32);

    impl ports::secondary::socket_identity_port::SocketIdentityReader for OwnedBy {
        fn by_cookie(
            &self,
            _cookie: u64,
        ) -> Option<ports::secondary::socket_identity_port::SocketOwner> {
            None
        }
        fn by_flow(
            &self,
            _flow: &ports::secondary::socket_identity_port::FlowEndpoints,
        ) -> Option<ports::secondary::socket_identity_port::SocketOwner> {
            None
        }
        fn by_originated_flow(
            &self,
            _flow: &ports::secondary::socket_identity_port::FlowEndpoints,
        ) -> Option<ports::secondary::socket_identity_port::SocketOwner> {
            Some(ports::secondary::socket_identity_port::SocketOwner {
                pid: self.0,
                tgid: self.0,
                uid: 1_000,
                cgroup_id: 7,
                source: domain::workload::entity::WorkloadSource::Socket,
            })
        }
    }

    #[tokio::test]
    async fn an_l7_observer_sees_each_parsed_payload_without_a_workload_by_default() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let observer = Arc::new(RecordingObserver::default());
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_l7_observer(Arc::clone(&observer) as _);

        let payload = b"POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec();
        let len = payload.len();
        dispatcher.dispatch_agent_event(AgentEvent::L7 {
            header: make_event(EVENT_TYPE_L7, 0),
            payload,
        });

        let seen = observer.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "http");
        assert_eq!(seen[0].1, len);
        assert_eq!(seen[0].2.as_deref(), Some("api.example.com"));
        assert_eq!(seen[0].3, None);
    }

    #[tokio::test]
    async fn an_l7_observer_is_told_the_workload_that_opened_the_connection() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let observer = Arc::new(RecordingObserver::default());
        let workloads = crate::workload_resolver::WorkloadResolver::new()
            .with_sockets(Box::new(OwnedBy(4_242)));
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_workload_resolver(workloads)
            .with_l7_observer(Arc::clone(&observer) as _);

        dispatcher.dispatch_agent_event(AgentEvent::L7 {
            header: make_event(EVENT_TYPE_L7, 0),
            payload: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        });

        assert_eq!(observer.seen.lock().unwrap()[0].3, Some(4_242));
    }

    /// Raises one alert on every query naming `tunnel.example`, and keeps the
    /// process id each query was lent.
    #[derive(Default)]
    struct TunnelSpotter {
        seen: Mutex<Vec<(String, Option<u32>, u8)>>,
    }

    impl ports::secondary::dns_query_observer_port::DnsQueryObserver for TunnelSpotter {
        fn observe(
            &self,
            query: &ports::secondary::dns_query_observer_port::DnsQuery<'_>,
        ) -> Option<domain::alert::entity::Alert> {
            self.seen.lock().unwrap().push((
                query.domain.to_string(),
                query.workload.map(|w| w.pid),
                query.ip_protocol,
            ));
            query.domain.ends_with("tunnel.example").then(|| {
                domain::alert::entity::Alert::from_ai_security(
                    "dns",
                    "dns-tunnelling",
                    domain::common::entity::Severity::High,
                    DomainMode::Alert,
                    [0; 4],
                    [0; 4],
                    0,
                    0,
                    0,
                    false,
                    "tunnelling",
                    query.timestamp_ns,
                    &domain::alert::mitre::MitreContext::Dns(
                        domain::alert::mitre::DnsMitreReason::BlocklistOrEncrypted,
                    ),
                    None,
                    None,
                    None,
                    None,
                )
            })
        }
    }

    /// A DNS query for `name`, type A, as the wire carries it.
    fn dns_query_payload(name: &str) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            payload.push(u8::try_from(label.len()).unwrap());
            payload.extend_from_slice(label.as_bytes());
        }
        payload.extend_from_slice(&[0, 0, 1, 0, 1]);
        payload
    }

    fn dns_query_event(direction: u8) -> DnsEvent {
        DnsEvent {
            timestamp_ns: 1,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0808_0808, 0, 0, 0],
            dns_payload_len: 0,
            dns_payload_offset: DnsEvent::HEADER_SIZE,
            direction,
            flags: 0,
            vlan_id: 0,
            src_port: 40_000,
            dst_port: 53,
            _padding: [0; 4],
            cgroup_id: 0,
        }
    }

    fn dns_query_dispatcher(
        alert_tx: mpsc::Sender<AlertEvent>,
        observer: &Arc<TunnelSpotter>,
    ) -> EventDispatcher {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let workloads = crate::workload_resolver::WorkloadResolver::new()
            .with_sockets(Box::new(OwnedBy(4_242)));
        make_dispatcher(ids, metrics, alert_tx)
            .with_workload_resolver(workloads)
            .with_dns_query_observer(Arc::clone(observer) as _)
    }

    #[tokio::test]
    async fn a_dns_query_observer_alert_carries_the_flow_and_the_sending_workload() {
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let observer = Arc::new(TunnelSpotter::default());
        let dispatcher = dns_query_dispatcher(alert_tx, &observer);

        dispatcher.dispatch_agent_event(AgentEvent::Dns {
            header: dns_query_event(ebpf_common::dns::DNS_DIRECTION_QUERY),
            payload: dns_query_payload("agvsbg8.tunnel.example"),
        });

        assert_eq!(
            observer.seen.lock().unwrap().as_slice(),
            &[("agvsbg8.tunnel.example".to_string(), Some(4_242), 17)]
        );
        let Ok(AlertEvent::System(alert)) = alert_rx.try_recv() else {
            panic!("expected one alert on the system path");
        };
        assert_eq!(alert.rule_id.0, "dns-tunnelling");
        assert_eq!(alert.src_addr, [0xC0A8_0001, 0, 0, 0]);
        assert_eq!(alert.dst_addr, [0x0808_0808, 0, 0, 0]);
        assert_eq!(
            (alert.src_port, alert.dst_port, alert.protocol),
            (40_000, 53, 17)
        );
        assert_eq!(
            alert.matched_domain.as_deref(),
            Some("agvsbg8.tunnel.example")
        );
        assert_eq!(alert.workload.as_ref().map(|w| w.pid), Some(4_242));
    }

    #[tokio::test]
    async fn a_dns_query_observer_raises_nothing_it_did_not_find_and_never_sees_a_response() {
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let observer = Arc::new(TunnelSpotter::default());
        let dispatcher = dns_query_dispatcher(alert_tx, &observer);

        dispatcher.dispatch_agent_event(AgentEvent::Dns {
            header: dns_query_event(ebpf_common::dns::DNS_DIRECTION_QUERY),
            payload: dns_query_payload("www.example.com"),
        });
        dispatcher.dispatch_agent_event(AgentEvent::Dns {
            header: dns_query_event(ebpf_common::dns::DNS_DIRECTION_RESPONSE),
            payload: dns_query_payload("agvsbg8.tunnel.example"),
        });

        assert_eq!(observer.seen.lock().unwrap().len(), 1);
        assert!(alert_rx.try_recv().is_err());
    }

    fn l7_event_to(dst_port: u16) -> PacketEvent {
        PacketEvent {
            dst_port,
            ..make_event(EVENT_TYPE_L7, 0)
        }
    }

    fn port_mismatch_alerts(alert_rx: &mut mpsc::Receiver<AlertEvent>) -> Vec<String> {
        let mut details = Vec::new();
        while let Ok(event) = alert_rx.try_recv() {
            if let AlertEvent::PacketSecurity(a) = event
                && a.rule_id == domain::l7::port_promise::PORT_MISMATCH_RULE_ID
            {
                assert_eq!(a.component, domain::alert::entity::PacketAlertComponent::L7);
                assert_eq!(a.action_label, "alert");
                details.push(a.detail);
            }
        }
        details
    }

    #[tokio::test]
    async fn ssh_on_443_raises_one_port_mismatch_alert_per_connection() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let payload = b"SSH-2.0-OpenSSH_9.6\r\n".to_vec();
        for _ in 0..3 {
            dispatcher.dispatch_agent_event(AgentEvent::L7 {
                header: l7_event_to(443),
                payload: payload.clone(),
            });
        }

        assert_eq!(
            port_mismatch_alerts(&mut alert_rx),
            ["ssh spoken on port 443, which promises tls"]
        );
        assert_eq!(
            *metrics.port_promises.lock().unwrap(),
            [(443, "mismatch".to_string())]
        );
    }

    #[tokio::test]
    async fn the_promised_protocol_and_a_short_payload_raise_nothing() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher.dispatch_agent_event(AgentEvent::L7 {
            header: l7_event_to(22),
            payload: b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
        });
        dispatcher.dispatch_agent_event(AgentEvent::L7 {
            header: PacketEvent {
                src_port: 23_456,
                ..l7_event_to(443)
            },
            payload: b"GET".to_vec(),
        });

        assert!(port_mismatch_alerts(&mut alert_rx).is_empty());
        assert_eq!(
            *metrics.port_promises.lock().unwrap(),
            [(22, "match".to_string()), (443, "unclassified".to_string())]
        );
    }

    #[tokio::test]
    async fn a_disabled_port_promise_check_judges_nothing() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_port_promise(None);

        dispatcher.dispatch_agent_event(AgentEvent::L7 {
            header: l7_event_to(443),
            payload: b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
        });

        assert!(port_mismatch_alerts(&mut alert_rx).is_empty());
        assert!(metrics.port_promises.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn l7_event_with_unknown_protocol_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "unknown");
    }

    #[tokio::test]
    async fn l7_event_via_run_loop() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(10);
        let cancel = CancellationToken::new();

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n".to_vec();
        event_tx
            .send(AgentEvent::L7 { header, payload })
            .await
            .unwrap();

        cancel.cancel();
        dispatcher.run(event_rx, cancel).await;

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
    }

    // ── L7 rule evaluation tests ──────────────────────────────────

    #[tokio::test]
    async fn l7_matching_deny_rule_records_deny_metric() {
        let ids = make_service_with_rules(vec![]);
        let l7 = make_l7_service_with_rules(vec![L7Rule {
            id: RuleId("l7-deny-delete".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Http {
                method: Some("DELETE".to_string()),
                path_pattern: None,
                host_pattern: None,
                content_type: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
            src_country_codes: None,
            dst_country_codes: None,
            src_ip_alias: None,
            dst_ip_alias: None,
            dst_port_alias: None,
        }]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher_with_l7(Arc::clone(&ids), l7, Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"DELETE /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec();
        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

        // The L7 service records "deny" metric internally
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "deny");
    }

    #[tokio::test]
    async fn l7_no_matching_rule_records_protocol_metric() {
        let ids = make_service_with_rules(vec![]);
        let l7 = make_l7_service();
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher_with_l7(Arc::clone(&ids), l7, Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"GET /safe HTTP/1.1\r\nHost: ok.com\r\n\r\n".to_vec();
        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

        // No rule matched → dispatcher records protocol label
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "http");
    }

    #[tokio::test]
    async fn l7_disabled_service_records_protocol_metric() {
        let ids = make_service_with_rules(vec![]);
        let l7 = make_l7_service_with_rules(vec![L7Rule {
            id: RuleId("l7-deny".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Http {
                method: Some("DELETE".to_string()),
                path_pattern: None,
                host_pattern: None,
                content_type: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
            src_country_codes: None,
            dst_country_codes: None,
            src_ip_alias: None,
            dst_ip_alias: None,
            dst_port_alias: None,
        }]);
        {
            let mut svc = (**l7.load()).clone();
            svc.set_enabled(false);
            l7.store(Arc::new(svc));
        }
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher_with_l7(Arc::clone(&ids), l7, Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"DELETE /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec();
        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

        // Service disabled → no deny, just protocol metric
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "http");
    }

    // ── DNS-aware IDS pipeline tests ──────────────────────────────

    use domain::dns::entity::{DnsCacheEntry, DnsCacheStats};
    use domain::ids::entity::DomainMatchMode;
    use std::collections::HashMap;
    use std::net::IpAddr;

    /// Mock DNS cache that returns pre-configured domain→IP mappings.
    struct MockDnsCache {
        ip_to_domains: std::sync::Mutex<HashMap<IpAddr, Vec<String>>>,
    }

    impl MockDnsCache {
        fn new() -> Self {
            Self {
                ip_to_domains: std::sync::Mutex::new(HashMap::new()),
            }
        }

        fn with_mapping(ip: IpAddr, domains: Vec<String>) -> Self {
            let mut map = HashMap::new();
            map.insert(ip, domains);
            Self {
                ip_to_domains: std::sync::Mutex::new(map),
            }
        }
    }

    impl DnsCachePort for MockDnsCache {
        fn lookup_domain(&self, _domain: &str) -> Option<DnsCacheEntry> {
            None
        }

        fn lookup_ip(&self, ip: &IpAddr) -> Vec<String> {
            self.ip_to_domains
                .lock()
                .unwrap()
                .get(ip)
                .cloned()
                .unwrap_or_default()
        }

        fn lookup_all(&self, _page: usize, _page_size: usize) -> Vec<(String, DnsCacheEntry)> {
            vec![]
        }

        fn insert(&self, _domain: String, _ips: Vec<IpAddr>, _ttl_secs: u64, _timestamp_ns: u64) {}

        fn stats(&self) -> DnsCacheStats {
            DnsCacheStats::default()
        }

        fn flush(&self) {}
    }

    fn make_domain_ids_rule(id: &str, pattern: &str, mode: DomainMatchMode) -> IdsRule {
        IdsRule {
            domain_pattern: Some(pattern.to_string()),
            domain_match_mode: Some(mode),
            ..make_ids_rule(id)
        }
    }

    fn make_dispatcher_with_dns(
        ids_service: Arc<ArcSwap<IdsAppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<AlertEvent>,
        dns_cache: Arc<dyn DnsCachePort>,
    ) -> EventDispatcher {
        EventDispatcher::new(
            ids_service,
            make_l7_service(),
            make_ti_service(),
            make_audit_service(),
            metrics,
            alert_tx,
            Some(dns_cache),
        )
    }

    #[tokio::test]
    async fn ids_domain_rule_matches_with_dns_cache() {
        let ids = make_service_with_rules(vec![make_domain_ids_rule(
            "ids-dom-1",
            "evil.com",
            DomainMatchMode::Exact,
        )]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        // dst_addr[0] = 0x0A000001 → 10.0.0.1
        let dst_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let dns = Arc::new(MockDnsCache::with_mapping(
            dst_ip,
            vec!["evil.com".to_string()],
        ));

        let dispatcher =
            make_dispatcher_with_dns(Arc::clone(&ids), Arc::clone(&metrics), alert_tx, dns);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
        assert_eq!(alert.rule_id.0, "ids-dom-1");
        assert_eq!(alert.matched_domain, Some("evil.com".to_string()));
    }

    #[tokio::test]
    async fn ids_domain_rule_no_match_without_dns_entry() {
        let ids = make_service_with_rules(vec![make_domain_ids_rule(
            "ids-dom-1",
            "evil.com",
            DomainMatchMode::Exact,
        )]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        // Empty DNS cache - no domains resolved for this IP
        let dns: Arc<dyn DnsCachePort> = Arc::new(MockDnsCache::new());

        let dispatcher =
            make_dispatcher_with_dns(Arc::clone(&ids), Arc::clone(&metrics), alert_tx, dns);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        // Domain rule should not match - no alert
        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn ids_ip_only_rule_works_without_dns() {
        // IP-only rule (no domain pattern) should still match even without DNS cache
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        // DNS cache present but no entry for this IP
        let dns: Arc<dyn DnsCachePort> = Arc::new(MockDnsCache::new());

        let dispatcher =
            make_dispatcher_with_dns(Arc::clone(&ids), Arc::clone(&metrics), alert_tx, dns);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
        assert_eq!(alert.rule_id.0, "ids-001");
        assert!(alert.matched_domain.is_none());
    }

    #[tokio::test]
    async fn ids_dns_disabled_domain_rules_silently_skipped() {
        // DNS disabled (None) → domain rules can't match, IP rules still work
        let ids = make_service_with_rules(vec![
            make_domain_ids_rule("ids-dom-1", "evil.com", DomainMatchMode::Exact),
            make_ids_rule("ids-002"),
        ]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        // No DNS cache (dns_cache = None)
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // Event for rule index 0 (domain rule) - should NOT match
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));
        assert!(alert_rx.try_recv().is_err());

        // Event for rule index 1 (IP-only rule) - should match
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 1));
        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
        assert_eq!(alert.rule_id.0, "ids-002");
    }

    // ── Load Balancer dispatch tests ────────────────────────────────

    #[tokio::test]
    async fn lb_forward_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let mut event = make_event(EVENT_TYPE_LB, 0);
        event.action = LB_ACTION_FORWARD;
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "loadbalancer");
        assert_eq!(*metrics.last_action.lock().unwrap(), "forward");
    }

    #[tokio::test]
    async fn lb_no_backend_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let mut event = make_event(EVENT_TYPE_LB, 0);
        event.action = LB_ACTION_NO_BACKEND;
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "loadbalancer");
        assert_eq!(*metrics.last_action.lock().unwrap(), "no_backend");
    }

    // ── DDoS dispatch tests ──────────────────────────────────────

    use crate::ddos_service_impl::DdosAppService;
    use domain::ddos::engine::DdosEngine;

    fn make_ddos_service() -> Arc<ArcSwap<DdosAppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(DdosAppService::new(
            DdosEngine::new(),
            metrics,
        )))
    }

    #[tokio::test]
    async fn ddos_syn_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let event = make_event(EVENT_TYPE_DDOS_SYN, 0);
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ddos");
        assert_eq!(*metrics.last_action.lock().unwrap(), "drop");
    }

    #[tokio::test]
    async fn ddos_event_without_service_does_nothing() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        // No ddos_service attached (default make_dispatcher sets it to None)
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let event = make_event(EVENT_TYPE_DDOS_ICMP, 0);
        dispatcher.dispatch_event(event);

        // Metric is still recorded even without a service
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ddos");
    }

    #[tokio::test]
    async fn ddos_event_with_service_processes() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let ddos = make_ddos_service();
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_ddos_service(Arc::clone(&ddos));

        let event = make_event(EVENT_TYPE_DDOS_SYN, 0);
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ddos");
    }

    #[tokio::test]
    async fn a_ddos_drop_is_audited_under_ddos() {
        struct Capture(std::sync::Mutex<Vec<AuditComponent>>);
        impl AuditSink for Capture {
            fn write_entry(&self, entry: &AuditEntry) -> Result<(), AuditError> {
                self.0.lock().unwrap().push(entry.component);
                Ok(())
            }
        }
        let sink = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = EventDispatcher::new(
            make_service_with_rules(vec![]),
            make_l7_service(),
            make_ti_service(),
            Arc::new(AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>)),
            Arc::new(TestMetrics::new()),
            alert_tx,
            None,
        )
        .with_ddos_service(make_ddos_service());

        dispatcher.dispatch_event(make_event(EVENT_TYPE_DDOS_SYN, 0));

        assert_eq!(*sink.0.lock().unwrap(), vec![AuditComponent::Ddos]);
    }

    // ── Threatintel dispatch tests ───────────────────────────────

    use domain::threatintel::entity::{Ioc, ThreatType};

    #[tokio::test]
    async fn threatintel_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let event = make_event(EVENT_TYPE_THREATINTEL, 0);
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "threatintel");
        assert_eq!(*metrics.last_action.lock().unwrap(), "pass");
    }

    #[tokio::test]
    async fn threatintel_event_disabled_service_no_alert() {
        let ids = make_service_with_rules(vec![]);
        let ti = make_ti_service();
        {
            let mut svc = (**ti.load()).clone();
            svc.set_enabled(false);
            ti.store(Arc::new(svc));
        }
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        let dispatcher = EventDispatcher::new(
            ids,
            make_l7_service(),
            Arc::clone(&ti),
            make_audit_service(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            alert_tx,
            None,
        );

        let event = make_event(EVENT_TYPE_THREATINTEL, 0);
        dispatcher.dispatch_event(event);

        assert!(alert_rx.try_recv().is_err());
        // Metric is still recorded before the enabled check returns
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn threatintel_event_with_matching_ioc_produces_alert() {
        let ids = make_service_with_rules(vec![]);
        let ti = make_ti_service();

        // The src_addr in make_event is 0xC0A8_0001 = 192.168.0.1
        let src_ip: IpAddr = "192.168.0.1".parse().unwrap();
        {
            let mut svc = (**ti.load()).clone();
            svc.add_ioc(Ioc {
                ip: src_ip,
                feed_id: "test-feed".to_string(),
                confidence: 90,
                threat_type: ThreatType::Malware,
                last_seen: 0,
                source_feed: "test".to_string(),
            })
            .unwrap();
            ti.store(Arc::new(svc));
        }

        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        let dispatcher = EventDispatcher::new(
            ids,
            make_l7_service(),
            Arc::clone(&ti),
            make_audit_service(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            alert_tx,
            None,
        );

        let event = make_event(EVENT_TYPE_THREATINTEL, 0);
        dispatcher.dispatch_event(event);

        let alert = alert_rx.try_recv().unwrap();
        match alert {
            AlertEvent::ThreatIntel(a) => {
                // The feed that resolved the IOC, the confidence it carried
                // and the type it was filed under all survive the channel.
                assert_eq!(a.feed_id, "test-feed");
                assert_eq!(a.confidence, 90);
                assert_eq!(a.threat_type, ThreatType::Malware);
                // The kernel passed the packet, so the alert says so.
                assert_eq!(a.mode, DomainMode::Alert);
            }
            _ => panic!("expected AlertEvent::ThreatIntel from threatintel"),
        }
    }

    #[tokio::test]
    async fn threatintel_alert_reports_the_action_the_kernel_took() {
        let ti = make_ti_service();
        // The service is on `alert`, which is what a feed with its own
        // `default_action: block` overrides when its IOCs are loaded.
        assert_eq!(ti.load().mode(), DomainMode::Alert);

        let src_ip: IpAddr = "192.168.0.1".parse().unwrap();
        {
            let mut svc = (**ti.load()).clone();
            svc.add_ioc(Ioc {
                ip: src_ip,
                feed_id: "blocking-feed".to_string(),
                confidence: 95,
                threat_type: ThreatType::C2,
                last_seen: 0,
                source_feed: "test".to_string(),
            })
            .unwrap();
            ti.store(Arc::new(svc));
        }

        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = EventDispatcher::new(
            make_service_with_rules(vec![]),
            make_l7_service(),
            Arc::clone(&ti),
            make_audit_service(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            alert_tx,
            None,
        );

        let mut event = make_event(EVENT_TYPE_THREATINTEL, 0);
        event.action = THREATINTEL_ACTION_DROP;
        dispatcher.dispatch_event(event);

        match alert_rx.try_recv().unwrap() {
            AlertEvent::ThreatIntel(a) => assert_eq!(a.mode, DomainMode::Block),
            _ => panic!("expected AlertEvent::ThreatIntel from threatintel"),
        }
    }

    // ── DLP dispatch tests ───────────────────────────────────────

    use crate::dlp_service_impl::DlpAppService;
    use domain::dlp::engine::DlpEngine;
    use domain::dlp::entity::DlpPattern;
    use ebpf_common::dlp::DLP_MAX_EXCERPT;

    fn make_dlp_event_with_data(data: &[u8]) -> DlpEvent {
        let mut event = DlpEvent {
            pid: 1000,
            tgid: 2000,
            timestamp_ns: 0,
            cgroup_id: 0,
            #[allow(clippy::cast_possible_truncation)]
            data_len: data.len() as u32, // DLP_MAX_EXCERPT is small, no truncation possible
            direction: 0,
            _padding: [0; 3],
            flow: ebpf_common::dlp::DlpSocket::default(),
            data_excerpt: [0u8; DLP_MAX_EXCERPT],
        };
        let copy_len = data.len().min(DLP_MAX_EXCERPT);
        event.data_excerpt[..copy_len].copy_from_slice(&data[..copy_len]);
        event
    }

    fn make_dlp_service_with_pattern() -> Arc<ArcSwap<DlpAppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(DlpPattern {
                id: RuleId("dlp-pci-001".to_string()),
                name: "Credit Card".to_string(),
                regex: r"\d{4}".to_string(),
                severity: Severity::High,
                mode: DomainMode::Alert,
                data_type: "pci".to_string(),
                description: String::new(),
                enabled: true,
            })
            .unwrap();
        Arc::new(ArcSwap::from_pointee(DlpAppService::new(engine, metrics)))
    }

    /// Raises one alert on every buffer carrying `attack`, and keeps the
    /// direction and length of each buffer it was lent.
    #[derive(Default)]
    struct PlaintextSpotter {
        seen: Mutex<Vec<(&'static str, usize, Option<String>)>>,
    }

    impl ports::secondary::tls_plaintext_observer_port::TlsPlaintextObserver for PlaintextSpotter {
        fn observe(
            &self,
            plaintext: &ports::secondary::tls_plaintext_observer_port::TlsPlaintext<'_>,
        ) -> Vec<domain::alert::entity::Alert> {
            self.seen.lock().unwrap().push((
                plaintext.direction.as_str(),
                plaintext.data.len(),
                plaintext.exe.map(str::to_string),
            ));
            if !plaintext.data.windows(6).any(|w| w == b"attack") {
                return Vec::new();
            }
            vec![domain::alert::entity::Alert::from_ai_security(
                "l7-inspect",
                "l7-sqli",
                Severity::High,
                DomainMode::Alert,
                [0; 4],
                [0; 4],
                0,
                0,
                0,
                false,
                "attack",
                plaintext.timestamp_ns,
                &domain::alert::mitre::MitreContext::Dns(
                    domain::alert::mitre::DnsMitreReason::BlocklistOrEncrypted,
                ),
                None,
                None,
                None,
                None,
            )]
        }
    }

    fn inbound_plaintext(data: &[u8]) -> DlpEvent {
        let mut event = make_dlp_event_with_data(data);
        event.direction = ebpf_common::dlp::DLP_DIRECTION_READ;
        event.flow = ebpf_common::dlp::DlpSocket {
            src_addr: [0x0a00_0001, 0, 0, 0],
            dst_addr: [0xc633_6407, 0, 0, 0],
            src_port: 443,
            dst_port: 51_000,
            family: ebpf_common::dlp::DLP_FLOW_FAMILY_IPV4,
            protocol: 6,
            source: ebpf_common::dlp::DLP_FLOW_SOURCE_KERNEL_SOCKET,
            _pad: 0,
        };
        event
    }

    #[tokio::test]
    async fn a_tls_plaintext_observer_sees_every_buffer_without_dlp_scanning() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let observer = Arc::new(PlaintextSpotter::default());
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_tls_plaintext_observer(Arc::clone(&observer) as _);

        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(make_dlp_event_with_data(
            b"GET / HTTP/1.1",
        ))));
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(inbound_plaintext(
            b"GET /?q=1 HTTP/1.1",
        ))));

        let seen = observer.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "write");
        assert_eq!(seen[0].1, 14);
        assert_eq!(seen[1].0, "read");
        assert!(
            alert_rx.try_recv().is_err(),
            "nothing matched, nothing raised"
        );
    }

    #[tokio::test]
    async fn an_alert_on_a_buffer_read_names_the_peer_as_its_source() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let observer = Arc::new(PlaintextSpotter::default());
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_executable_reader(Arc::new(FixedExecutable(Some(
                domain::dlp::entity::DlpExecutable {
                    path: "/usr/sbin/nginx".to_string(),
                    dev: 3,
                    inode: 42,
                    source: domain::dlp::entity::DlpIdentitySource::ProcessAtAlertTime,
                },
            ))))
            .with_tls_plaintext_observer(Arc::clone(&observer) as _);

        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(inbound_plaintext(
            b"POST /login attack",
        ))));

        assert_eq!(
            observer.seen.lock().unwrap()[0].2.as_deref(),
            Some("/usr/sbin/nginx")
        );
        let AlertEvent::System(alert) = alert_rx.try_recv().unwrap() else {
            panic!("expected AlertEvent::System");
        };
        assert_eq!(alert.src_addr, [0xc633_6407, 0, 0, 0]);
        assert_eq!(alert.src_port, 51_000);
        assert_eq!(alert.dst_addr, [0x0a00_0001, 0, 0, 0]);
        assert_eq!(alert.dst_port, 443);
        assert_eq!(alert.protocol, 6);
        assert!(!alert.is_ipv6);
        assert_eq!(alert.pid, Some(1000));
        assert_eq!(alert.direction, Some(ebpf_common::dlp::DLP_DIRECTION_READ));
        assert_eq!(alert.executable_path.as_deref(), Some("/usr/sbin/nginx"));
        assert_eq!(alert.flow_source.as_deref(), Some("kernel_socket"));
    }

    #[tokio::test]
    async fn dlp_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let dlp_event = make_dlp_event_with_data(b"hello world");
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(dlp_event)));

        // record_packet is called twice: once for "dlp"/"captured" in process_dlp_event,
        // and once for observe_processing_duration via dispatch_agent_event.
        // But record_packet records the last call which is "dlp"/"captured".
        assert_eq!(*metrics.last_component.lock().unwrap(), "dlp");
        assert_eq!(*metrics.last_action.lock().unwrap(), "captured");
    }

    #[tokio::test]
    async fn dlp_event_without_service_no_panic() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        // No dlp_service attached (default make_dispatcher sets it to None)
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let dlp_event = make_dlp_event_with_data(b"some data 1234");
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(dlp_event)));

        // Metric recorded, no panic
        assert_eq!(*metrics.last_component.lock().unwrap(), "dlp");
        assert_eq!(*metrics.last_action.lock().unwrap(), "captured");
    }

    #[tokio::test]
    async fn dlp_event_with_match_produces_alert() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dlp = make_dlp_service_with_pattern();
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_dlp_service(Arc::clone(&dlp));

        // Data containing 4 consecutive digits should match the \d{4} pattern
        let dlp_event = make_dlp_event_with_data(b"card number 1234 here");
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(dlp_event)));

        let alert = alert_rx.try_recv().unwrap();
        match alert {
            AlertEvent::Dlp(a) => {
                assert_eq!(a.pattern_id.0, "dlp-pci-001");
                assert_eq!(a.pattern_name, "Credit Card");
            }
            _ => panic!("expected AlertEvent::Dlp"),
        }
    }

    /// A reader standing in for procfs, so the enrichment can be asserted
    /// without a live process to read.
    struct FixedExecutable(Option<domain::dlp::entity::DlpExecutable>);

    impl ports::secondary::process_executable_port::ProcessExecutableReader for FixedExecutable {
        fn read_executable(&self, _pid: u32) -> Option<domain::dlp::entity::DlpExecutable> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn a_dlp_alert_names_the_binary_and_the_destination() {
        use domain::dlp::entity::{DlpExecutable, DlpIdentitySource};

        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dlp = make_dlp_service_with_pattern();
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_dlp_service(Arc::clone(&dlp))
            .with_executable_reader(Arc::new(FixedExecutable(Some(DlpExecutable {
                path: "/usr/bin/curl".to_string(),
                dev: 66_306,
                inode: 98_765,
                source: DlpIdentitySource::ProcessAtAlertTime,
            }))));

        let mut dlp_event = make_dlp_event_with_data(b"card number 1234 here");
        dlp_event.flow = ebpf_common::dlp::DlpSocket {
            src_addr: [0x0a01_0203, 0, 0, 0],
            dst_addr: [0x5db8_d822, 0, 0, 0],
            src_port: 51234,
            dst_port: 443,
            family: ebpf_common::dlp::DLP_FLOW_FAMILY_IPV4,
            protocol: ebpf_common::dlp::DLP_FLOW_PROTOCOL_TCP,
            source: ebpf_common::dlp::DLP_FLOW_SOURCE_KERNEL_SOCKET,
            _pad: 0,
        };
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(dlp_event)));

        match alert_rx.try_recv().unwrap() {
            AlertEvent::Dlp(a) => {
                let exe = a.executable.expect("the reader answered");
                assert_eq!(exe.path, "/usr/bin/curl");
                assert_eq!(exe.inode, 98_765);
                let flow = a.flow.expect("the probe read the socket");
                assert_eq!(flow.dst_port, 443);
                assert_eq!(flow.source, DlpIdentitySource::KernelSocket);
            }
            _ => panic!("expected AlertEvent::Dlp"),
        }
    }

    #[tokio::test]
    async fn a_dlp_alert_claims_no_binary_when_the_process_is_gone() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dlp = make_dlp_service_with_pattern();
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_dlp_service(Arc::clone(&dlp))
            .with_executable_reader(Arc::new(FixedExecutable(None)));

        let dlp_event = make_dlp_event_with_data(b"card number 1234 here");
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(dlp_event)));

        match alert_rx.try_recv().unwrap() {
            AlertEvent::Dlp(a) => {
                assert!(a.executable.is_none());
                assert!(a.flow.is_none());
            }
            _ => panic!("expected AlertEvent::Dlp"),
        }
    }

    // ── LB unknown action test ───────────────────────────────────

    #[tokio::test]
    async fn lb_unknown_action_records_unknown() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let mut event = make_event(EVENT_TYPE_LB, 0);
        event.action = 255;
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "loadbalancer");
        assert_eq!(*metrics.last_action.lock().unwrap(), "unknown");
    }

    // ── Helper function tests ────────────────────────────────────

    #[test]
    fn action_label_all_values() {
        assert_eq!(action_label(0), "pass");
        assert_eq!(action_label(1), "drop");
        assert_eq!(action_label(2), "log");
        assert_eq!(action_label(99), "unknown");
    }

    #[test]
    fn event_type_label_all_values() {
        assert_eq!(event_type_label(EVENT_TYPE_FIREWALL), "firewall");
        assert_eq!(event_type_label(EVENT_TYPE_IDS), "ids");
        assert_eq!(event_type_label(EVENT_TYPE_RATELIMIT), "ratelimit");
        assert_eq!(event_type_label(EVENT_TYPE_THREATINTEL), "threatintel");
        assert_eq!(event_type_label(EVENT_TYPE_DDOS_SYN), "ddos");
        assert_eq!(event_type_label(EVENT_TYPE_DDOS_ICMP), "ddos");
        assert_eq!(event_type_label(EVENT_TYPE_DDOS_AMP), "ddos");
        assert_eq!(event_type_label(EVENT_TYPE_DDOS_CONNTRACK), "ddos");
        assert_eq!(event_type_label(EVENT_TYPE_LB), "lb");
        assert_eq!(event_type_label(254), "unknown");
    }
}
