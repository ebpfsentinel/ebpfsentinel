//! Which kernel source serves each intention, and whether this host has it.
//!
//! The table below is where the kernel expertise lives so that no rule has
//! to carry any. Each intention names the sources it needs, the hook those
//! sources rest on and the oldest kernel that hook exists on. Whether a
//! source is present is not read off the kernel version: it is what the
//! agent observed when it attached, reported per host, and a rule naming an
//! intention this host cannot serve loads as **not applicable, with the
//! reason**, rather than as a rule that is quietly never matched.

use std::collections::BTreeMap;

use serde::Serialize;

use super::intent::Intent;

/// An event source the agent runs, any one of which an intention may need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The exec, fork and exit tracepoints behind the process table.
    ProcessTracing,
    /// The cgroup socket hooks naming the task behind a socket.
    SocketAttribution,
    /// The DNS capture program on the traffic-control path.
    DnsCapture,
    /// The intrusion detection program, which reads the TLS client hello.
    TlsCapture,
    /// The inventory of eBPF programs on the network path.
    NetworkProgramInventory,
    /// The inventory of packet sockets.
    RawSocketInventory,
    /// A file watch over the mounts a policy names.
    FileWatch,
    /// A comparison of the kernel's tasks with what `/proc` lists.
    HiddenProcessScan,
    /// A comparison of the kernel's sockets with what `/proc/net` lists.
    HiddenPortScan,
    /// The installed package inventory joined to the listening sockets.
    PackageInventory,
}

impl Source {
    /// Every source, in a stable order.
    pub const ALL: [Source; 10] = [
        Self::ProcessTracing,
        Self::SocketAttribution,
        Self::DnsCapture,
        Self::TlsCapture,
        Self::NetworkProgramInventory,
        Self::RawSocketInventory,
        Self::FileWatch,
        Self::HiddenProcessScan,
        Self::HiddenPortScan,
        Self::PackageInventory,
    ];

    /// The name the source is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessTracing => "process_tracing",
            Self::SocketAttribution => "socket_attribution",
            Self::DnsCapture => "dns_capture",
            Self::TlsCapture => "tls_capture",
            Self::NetworkProgramInventory => "network_program_inventory",
            Self::RawSocketInventory => "raw_socket_inventory",
            Self::FileWatch => "file_watch",
            Self::HiddenProcessScan => "hidden_process_scan",
            Self::HiddenPortScan => "hidden_port_scan",
            Self::PackageInventory => "package_inventory",
        }
    }
}

/// How one intention is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// Every source the intention needs; all of them have to be present.
    pub sources: &'static [Source],
    /// The kernel mechanism, in one line an operator can search for.
    pub hook: &'static str,
    /// Oldest kernel the hook exists on, as `(major, minor)`. Below the
    /// agent's own floor for every intention today, and kept because the
    /// day a hook needs more than the floor the check is already here.
    pub min_kernel: (u32, u32),
    /// What serves the intention, less well, when the hook is absent.
    pub fallback: Option<&'static str>,
}

const PROCESS: &[Source] = &[Source::ProcessTracing];
const SOCKET: &[Source] = &[Source::SocketAttribution];
const FILE: &[Source] = &[Source::FileWatch];

/// A binding with no fallback, the shape of every intention but one.
const fn served(sources: &'static [Source], hook: &'static str, min_kernel: (u32, u32)) -> Binding {
    Binding {
        sources,
        hook,
        min_kernel,
        fallback: None,
    }
}

impl Intent {
    /// The binding that serves this intention.
    #[must_use]
    pub fn binding(self) -> Binding {
        match self {
            Self::ProcessStarts => served(PROCESS, "raw tracepoint sched_process_exec", (4, 17)),
            Self::ProcessEnds => served(PROCESS, "raw tracepoint sched_process_exit", (4, 17)),
            Self::ProcessConnects => served(SOCKET, "cgroup connect4 and connect6", (4, 17)),
            Self::ProcessListens => served(SOCKET, "cgroup post_bind4 and post_bind6", (4, 17)),
            Self::ProcessResolves => served(
                &[Source::DnsCapture, Source::SocketAttribution],
                "traffic-control DNS capture joined to the socket's task",
                (4, 17),
            ),
            Self::ProcessSendsTls => served(
                &[Source::TlsCapture, Source::SocketAttribution],
                "traffic-control client hello capture joined to the socket's task",
                (4, 17),
            ),
            Self::FileChanges => served(FILE, "fanotify FAN_MODIFY on the watched mounts", (5, 1)),
            Self::FileAppears => served(FILE, "fanotify FAN_CREATE on the watched mounts", (5, 1)),
            Self::FileDisappears => {
                served(FILE, "fanotify FAN_DELETE on the watched mounts", (5, 1))
            }
            Self::FileRenames => Binding {
                sources: FILE,
                hook: "fanotify FAN_RENAME on the watched mounts, both names in one event",
                min_kernel: (5, 17),
                fallback: Some(
                    "file.disappears at the old name and file.appears at the new one, on a \
                     filesystem whose mark refused FAN_RENAME",
                ),
            },
            Self::FilePermissionsChange => {
                served(FILE, "fanotify FAN_ATTRIB on the watched mounts", (5, 1))
            }
            Self::FileIntegrityBreaks => served(
                FILE,
                "baseline digest compared on fanotify FAN_CLOSE_WRITE",
                (5, 1),
            ),
            Self::PortHidden => served(
                &[Source::HiddenPortScan],
                "bind probe compared with the socket listings of every network namespace",
                (5, 9),
            ),
            Self::ProcessHidden => served(
                &[Source::HiddenProcessScan],
                "null signal across the pid space compared with the listing of /proc",
                (5, 8),
            ),
            Self::BpfForeignProgram => served(
                &[Source::NetworkProgramInventory],
                "BPF program and link enumeration of the network path",
                (5, 8),
            ),
            Self::PacketSocketAppears => served(
                &[Source::RawSocketInventory],
                "sock_diag packet socket inventory",
                (4, 2),
            ),
            Self::PackageVulnerableReachable => served(
                &[Source::PackageInventory],
                "package database read joined to the listening sockets",
                (4, 17),
            ),
        }
    }
}

/// What one host reports about its sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSources {
    /// The running kernel, as `(major, minor)`, absent when it could not be
    /// read. An unread kernel is not held against an intention: whether its
    /// sources attached is the answer that counts.
    pub kernel: Option<(u32, u32)>,
    /// Each source this host reported on, present or absent with the
    /// reason. A source the host said nothing about is absent.
    pub sources: BTreeMap<Source, Result<(), String>>,
}

impl HostSources {
    /// A host on this kernel reporting nothing yet.
    #[must_use]
    pub fn new(kernel: Option<(u32, u32)>) -> Self {
        Self {
            kernel,
            sources: BTreeMap::new(),
        }
    }

    /// Record one source as present.
    #[must_use]
    pub fn present(mut self, source: Source) -> Self {
        self.sources.insert(source, Ok(()));
        self
    }

    /// Record one source as absent, and why.
    #[must_use]
    pub fn absent(mut self, source: Source, reason: impl Into<String>) -> Self {
        self.sources.insert(source, Err(reason.into()));
        self
    }
}

/// Whether this host can serve an intention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Applicability {
    /// Every source it needs is present.
    Applicable,
    /// It cannot be served here, and this is why.
    NotApplicable {
        /// One sentence per missing source, joined.
        reason: String,
    },
}

impl Applicability {
    /// Whether the intention is served.
    #[must_use]
    pub fn is_applicable(&self) -> bool {
        matches!(self, Self::Applicable)
    }
}

/// Resolve an intention against what a host reported.
///
/// Every missing source is named, not only the first, so an operator fixes
/// a host once rather than once per source.
#[must_use]
pub fn resolve(intent: Intent, host: &HostSources) -> Applicability {
    let binding = intent.binding();
    let mut reasons = Vec::new();
    if let Some(kernel) = host.kernel
        && kernel < binding.min_kernel
    {
        reasons.push(format!(
            "{} needs kernel {}.{}, this host runs {}.{}",
            binding.hook, binding.min_kernel.0, binding.min_kernel.1, kernel.0, kernel.1
        ));
    }
    for source in binding.sources {
        match host.sources.get(source) {
            Some(Ok(())) => {}
            Some(Err(reason)) => reasons.push(format!("{}: {reason}", source.as_str())),
            None => reasons.push(format!("{}: not reported by this host", source.as_str())),
        }
    }
    if reasons.is_empty() {
        Applicability::Applicable
    } else {
        Applicability::NotApplicable {
            reason: reasons.join("; "),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_source_present() -> HostSources {
        Source::ALL
            .into_iter()
            .fold(HostSources::new(Some((6, 12))), HostSources::present)
    }

    #[test]
    fn every_intent_is_bound_to_at_least_one_source_on_a_kernel_below_the_floor() {
        for intent in Intent::ALL {
            let binding = intent.binding();
            assert!(!binding.sources.is_empty(), "{intent}");
            assert!(!binding.hook.is_empty(), "{intent}");
            assert!(binding.min_kernel <= (6, 12), "{intent}");
        }
    }

    #[test]
    fn every_source_serves_at_least_one_intent() {
        for source in Source::ALL {
            assert!(
                Intent::ALL
                    .iter()
                    .any(|i| i.binding().sources.contains(&source)),
                "{} serves nothing",
                source.as_str()
            );
        }
    }

    #[test]
    fn a_host_with_every_source_serves_every_intent() {
        let host = every_source_present();
        for intent in Intent::ALL {
            assert_eq!(
                resolve(intent, &host),
                Applicability::Applicable,
                "{intent}"
            );
        }
    }

    #[test]
    fn an_absent_source_makes_the_intent_not_applicable_with_its_reason() {
        let host = every_source_present().absent(Source::FileWatch, "no file watch is configured");
        let verdict = resolve(Intent::FileChanges, &host);
        assert_eq!(
            verdict,
            Applicability::NotApplicable {
                reason: "file_watch: no file watch is configured".to_string()
            }
        );
        assert!(resolve(Intent::ProcessStarts, &host).is_applicable());
    }

    #[test]
    fn a_source_the_host_never_reported_is_absent_and_says_so() {
        let verdict = resolve(Intent::PortHidden, &HostSources::new(Some((6, 12))));
        let Applicability::NotApplicable { reason } = verdict else {
            panic!("an unreported source cannot be present");
        };
        assert_eq!(reason, "hidden_port_scan: not reported by this host");
    }

    #[test]
    fn every_missing_source_is_named_not_only_the_first() {
        let host = HostSources::new(Some((6, 12)))
            .absent(Source::DnsCapture, "tc-dns is not loaded")
            .absent(Source::SocketAttribution, "the cgroup hooks did not attach");
        let Applicability::NotApplicable { reason } = resolve(Intent::ProcessResolves, &host)
        else {
            panic!("both sources are absent");
        };
        assert!(
            reason.contains("dns_capture: tc-dns is not loaded"),
            "{reason}"
        );
        assert!(
            reason.contains("socket_attribution: the cgroup hooks did not attach"),
            "{reason}"
        );
    }

    #[test]
    fn a_kernel_older_than_the_hook_is_named_beside_the_sources() {
        let mut host = every_source_present();
        host.kernel = Some((5, 0));
        let Applicability::NotApplicable { reason } = resolve(Intent::FileChanges, &host) else {
            panic!("fanotify directory events need 5.1");
        };
        assert!(
            reason.contains("needs kernel 5.1, this host runs 5.0"),
            "{reason}"
        );
    }

    #[test]
    fn the_verdict_serialises_as_a_tagged_state() {
        let json = serde_json::to_value(Applicability::NotApplicable {
            reason: "x".to_string(),
        })
        .unwrap();
        assert_eq!(json["state"], "not_applicable");
        assert_eq!(json["reason"], "x");
        assert_eq!(
            serde_json::to_value(Applicability::Applicable).unwrap()["state"],
            "applicable"
        );
    }
}
