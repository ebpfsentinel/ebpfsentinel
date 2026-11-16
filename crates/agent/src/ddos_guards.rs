//! The xdp-ratelimit anti-DDoS guards, kept for as long as the program is
//! loaded so a reload rewrites them.
//!
//! `check_syn_flood`, `process_icmp`, `process_conntrack` and the UDP
//! amplification path each read a map that is zeroed at load and bail when
//! `enabled == 0`. The writes below are what arm them, and what disarms them
//! when the file turns a guard, or the whole section, off.

use adapters::ebpf::{
    AmpProtectConfigManager, DdosConnTrackConfigManager, DdosSynConfigManager, EbpfLoader,
    IcmpConfigManager,
};
use ebpf_common::ddos::{DdosConnTrackConfig, DdosSynConfig, IcmpConfig};
use infrastructure::config::AgentConfig;
use tracing::{debug, info, warn};

/// IANA protocol number for UDP; the eBPF amplification path is UDP-only,
/// which is why the configuration refuses any other protocol on these ports.
const PROTO_UDP: u8 = 17;

/// The four guard maps of one loaded xdp-ratelimit. A map the object does
/// not carry stays `None` and its guard stays off.
pub struct DdosGuards {
    syn: Option<DdosSynConfigManager>,
    icmp: Option<IcmpConfigManager>,
    conntrack: Option<DdosConnTrackConfigManager>,
    amp: Option<AmpProtectConfigManager>,
}

impl DdosGuards {
    /// Take the guard maps out of a freshly loaded xdp-ratelimit.
    pub fn take(loader: &mut EbpfLoader) -> Self {
        Self {
            syn: DdosSynConfigManager::new(loader.ebpf_mut())
                .inspect_err(|e| warn!("DDOS_SYN_CONFIG map not available (non-fatal): {e}"))
                .ok(),
            icmp: IcmpConfigManager::new(loader.ebpf_mut())
                .inspect_err(|e| warn!("ICMP_CONFIG map not available (non-fatal): {e}"))
                .ok(),
            conntrack: DdosConnTrackConfigManager::new(loader.ebpf_mut())
                .inspect_err(|e| warn!("CONNTRACK_CONFIG map not available (non-fatal): {e}"))
                .ok(),
            amp: AmpProtectConfigManager::new(loader.ebpf_mut())
                .inspect_err(|e| warn!("AMP_PROTECT_CONFIG map not available (non-fatal): {e}"))
                .ok(),
        }
    }

    /// Put `config` in force: every guard the file enables is armed with its
    /// thresholds, every other one written disabled. Each write is
    /// best-effort; a failure leaves that guard as it was and is logged.
    pub fn write(&mut self, config: &AgentConfig) {
        let ddos = &config.ddos;
        let on = |guard: bool| ddos.enabled && guard;

        if let Some(mgr) = self.syn.as_mut() {
            let enabled = on(ddos.syn_protection.enabled);
            let cfg = DdosSynConfig {
                enabled: u8::from(enabled),
                threshold_mode: u8::from(ddos.syn_protection.threshold_mode),
                _pad: [0; 6],
                threshold_pps: ddos.syn_protection.threshold_pps,
            };
            if let Err(e) = mgr.set_config(&cfg) {
                warn!("DDOS_SYN_CONFIG write failed: {e}");
            }
            if enabled {
                set_syncookies_sysctl();
            }
        }

        if let Some(mgr) = self.icmp.as_mut() {
            let cfg = IcmpConfig {
                enabled: u8::from(on(ddos.icmp_protection.enabled)),
                _pad: 0,
                max_payload_size: ddos.icmp_protection.max_payload_size,
                max_pps: ddos.icmp_protection.max_pps,
            };
            if let Err(e) = mgr.set_config(&cfg) {
                warn!("ICMP_CONFIG write failed: {e}");
            }
        }

        if let Some(mgr) = self.conntrack.as_mut() {
            let ct = &ddos.connection_tracking;
            let cfg = DdosConnTrackConfig {
                enabled: u8::from(on(ct.enabled)),
                _pad: [0; 3],
                half_open_threshold: ct.half_open_threshold,
                rst_threshold: ct.rst_threshold,
                fin_threshold: ct.fin_threshold,
                ack_threshold: ct.ack_threshold,
            };
            if let Err(e) = mgr.set_config(&cfg) {
                warn!("CONNTRACK_CONFIG write failed: {e}");
            }
        }

        if let Some(mgr) = self.amp.as_mut() {
            let ports: Vec<(u16, u8, u32)> = if on(ddos.amplification_protection.enabled) {
                ddos.amplification_protection
                    .ports
                    .iter()
                    .map(|p| (p.port, PROTO_UDP, p.max_pps))
                    .collect()
            } else {
                Vec::new()
            };
            if let Err(e) = mgr.set_ports(&ports) {
                warn!("AMP_PROTECT_CONFIG write failed: {e}");
            }
        }
    }
}

/// The XDP syncookie path issues kernel cookies via
/// `bpf_tcp_raw_gen_syncookie`; the kernel only completes a legitimate
/// client's handshake from the passed cookie-ACK when it always validates
/// syncookies (mode 2 - mode 1 engages only on SYN-backlog overflow, which
/// never happens because XDP absorbs the flood SYNs). In the default token
/// deployment the privileged launcher already set this before the
/// user-namespace unshare; this best-effort write only succeeds in the
/// `CAP_NET_ADMIN` fallback, so a failure here is expected.
fn set_syncookies_sysctl() {
    match std::fs::write("/proc/sys/net/ipv4/tcp_syncookies", "2\n") {
        Ok(()) => info!("net.ipv4.tcp_syncookies=2 set for SYN-cookie handshake completion"),
        Err(e) => debug!("tcp_syncookies sysctl not writable here (set by the launcher): {e}"),
    }
}
