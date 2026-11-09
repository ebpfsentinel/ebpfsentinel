#![no_main]

//! The plan behind cgroup-clusterip: which Service cluster addresses the
//! connect hook resolves for opted-in workloads, built from what the
//! Kubernetes API reports. Services, pods and selectors are drawn from the
//! input so that duplicate addresses, empty backends, mixed families,
//! oversized backend sets and full tables all reach `plan`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use domain::clusterip::{BACKEND_BUDGET, WorkloadSelector, plan};
use domain::netpol::entity::{
    ClusterView, LabelSelector, NamedPort, NamespaceView, PodView, Protocol, ServiceBackend,
    ServicePort, ServiceRouting, ServiceView,
};
use libfuzzer_sys::fuzz_target;

struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn byte(&mut self) -> u8 {
        let Some((&b, rest)) = self.0.split_first() else {
            return 0;
        };
        self.0 = rest;
        b
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }

    fn word(&mut self) -> String {
        // A small alphabet so that labels and names collide often.
        format!("w{}", self.byte() % 4)
    }

    fn ip(&mut self) -> IpAddr {
        if self.byte() & 1 == 0 {
            IpAddr::V4(Ipv4Addr::new(10, 0, self.byte() % 4, self.byte() % 8))
        } else {
            IpAddr::V6(Ipv6Addr::new(
                0xfd00,
                0,
                0,
                0,
                0,
                0,
                0,
                u16::from(self.byte() % 8),
            ))
        }
    }

    fn protocol(&mut self) -> Protocol {
        match self.byte() % 3 {
            0 => Protocol::Tcp,
            1 => Protocol::Udp,
            _ => Protocol::Sctp,
        }
    }

    fn labels(&mut self) -> BTreeMap<String, String> {
        (0..self.byte() % 3)
            .map(|_| (self.word(), self.word()))
            .collect()
    }

    fn named_ports(&mut self) -> Vec<NamedPort> {
        (0..self.byte() % 3)
            .map(|_| NamedPort {
                name: self.word(),
                port: self.u16() % 4,
                protocol: self.protocol(),
            })
            .collect()
    }

    fn selector(&mut self) -> Option<LabelSelector> {
        (self.byte() & 1 == 1).then(|| LabelSelector {
            match_labels: self.labels(),
            match_expressions: Vec::new(),
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor(data);
    let mut view = ClusterView::default();
    for _ in 0..c.byte() % 4 {
        view.namespaces.push(NamespaceView {
            name: c.word(),
            labels: c.labels(),
        });
    }
    for _ in 0..c.byte() % 6 {
        let ips = (0..c.byte() % 3).map(|_| c.ip()).collect();
        view.pods.push(PodView {
            uid: c.word(),
            namespace: c.word(),
            name: c.word(),
            labels: c.labels(),
            ips,
            ports: c.named_ports(),
            host_ips: Vec::new(),
            host_network: c.byte() % 5 == 0,
            terminal: c.byte() % 5 == 0,
        });
    }
    for _ in 0..c.byte() % 6 {
        let cluster_ips = (0..c.byte() % 3).map(|_| c.ip()).collect();
        let ports = (0..c.byte() % 3)
            .map(|_| ServicePort {
                name: c.word(),
                port: c.u16(),
                protocol: c.protocol(),
            })
            .collect();
        // Sometimes more backends than one entry carries.
        let count = if c.byte() == 0xff {
            BACKEND_BUDGET + 1
        } else {
            usize::from(c.byte() % 5)
        };
        let backends = (0..count)
            .map(|_| ServiceBackend {
                ip: c.ip(),
                ports: c.named_ports(),
            })
            .collect();
        let flags = c.byte();
        view.services.push(ServiceView {
            namespace: c.word(),
            name: c.word(),
            cluster_ips,
            ports,
            backends,
            routing: ServiceRouting {
                affinity_secs: (flags & 1 == 1).then(|| u32::from(c.u16())),
                node_local: flags & 2 == 2,
                topology: flags & 4 == 4,
            },
        });
    }
    let workloads: Vec<WorkloadSelector> = (0..c.byte() % 3)
        .map(|_| WorkloadSelector {
            pods: c.selector(),
            namespaces: c.selector(),
        })
        .collect();

    let result = plan(&view, &workloads);
    for entry in &result.entries {
        assert!(!entry.backends.is_empty(), "an entry without a backend");
    }
    let _ = format!("{result:?}");
});
