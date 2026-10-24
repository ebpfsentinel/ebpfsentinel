//! The cluster as `NetworkPolicy` reads it, kept current by five watchers.
//!
//! Policies, pods, namespaces, services and endpoint slices are watched
//! cluster-wide, because a peer selected by a policy may run on any node, and
//! folded into one cache the compile reads a [`ClusterView`] from. Every
//! change bumps a generation on a `watch` channel; the reader recompiles from
//! whatever the cache holds when it wakes, so a burst of events costs one
//! compile and not one per event.
//!
//! A relist after a watch is interrupted replaces what the cache held for
//! that kind rather than adding to it, so an object deleted while the agent
//! was not listening does not keep a pod open or closed forever.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use domain::common::error::DomainError;
use domain::netpol::{
    ClusterView, Direction, IpBlock, LabelRequirement, LabelSelector, NamedPort, NamespaceView,
    NetPrefix, NetworkPolicy, Peer, PodView, PolicyPort, PolicyRule, PortRef, Protocol,
    SelectorOperator, ServiceBackend, ServicePort, ServiceView,
};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{
    NetworkPolicy as K8sNetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector as K8sLabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, Resource};
use ports::secondary::netpol_map_port::{ClusterViewPort, NetworkPolicyManifestPort};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// The label an endpoint slice names its Service by.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// The label the API server puts on every namespace, which a selector on a
/// namespace's name matches.
const NAMESPACE_NAME_LABEL: &str = "kubernetes.io/metadata.name";

/// A Service as its own object writes it, before its slices are joined.
#[derive(Debug, Clone)]
struct ServiceSpec {
    cluster_ips: Vec<IpAddr>,
    ports: Vec<ServicePort>,
}

/// One endpoint slice's contribution to its Service.
#[derive(Debug, Clone)]
struct SliceSpec {
    namespace: String,
    service: String,
    backends: Vec<ServiceBackend>,
}

/// Everything the watchers learned, one map per kind.
#[derive(Debug, Default)]
struct Store {
    policies: BTreeMap<String, NetworkPolicy>,
    pods: BTreeMap<String, PodView>,
    namespaces: BTreeMap<String, NamespaceView>,
    services: BTreeMap<String, (String, String, ServiceSpec)>,
    slices: BTreeMap<String, SliceSpec>,
}

/// The cache the five watchers write and the compile reads.
#[derive(Debug)]
pub struct NetpolClusterCache {
    store: Mutex<Store>,
    generation: watch::Sender<u64>,
}

impl Default for NetpolClusterCache {
    fn default() -> Self {
        Self {
            store: Mutex::new(Store::default()),
            generation: watch::Sender::new(0),
        }
    }
}

impl ClusterViewPort for NetpolClusterCache {
    fn view(&self) -> ClusterView {
        NetpolClusterCache::view(self)
    }
}

impl NetpolClusterCache {
    /// A receiver woken on every change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// The cluster as it stands, services joined with their ready backends.
    pub fn view(&self) -> ClusterView {
        let store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        let mut backends: BTreeMap<(&str, &str), Vec<ServiceBackend>> = BTreeMap::new();
        for slice in store.slices.values() {
            backends
                .entry((slice.namespace.as_str(), slice.service.as_str()))
                .or_default()
                .extend(slice.backends.iter().cloned());
        }
        ClusterView {
            policies: store.policies.values().cloned().collect(),
            pods: store.pods.values().cloned().collect(),
            namespaces: store.namespaces.values().cloned().collect(),
            services: store
                .services
                .values()
                .map(|(namespace, name, spec)| ServiceView {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    cluster_ips: spec.cluster_ips.clone(),
                    ports: spec.ports.clone(),
                    backends: backends
                        .get(&(namespace.as_str(), name.as_str()))
                        .cloned()
                        .unwrap_or_default(),
                })
                .collect(),
        }
    }

    fn with_store(&self, change: impl FnOnce(&mut Store)) {
        change(&mut self.store.lock().unwrap_or_else(PoisonError::into_inner));
        self.generation.send_modify(|generation| *generation += 1);
    }
}

/// What a watcher hands its kind's map.
enum Change<K> {
    Upsert(K),
    Delete(K),
    /// A relist finished: these keys are every object of the kind.
    Relisted(BTreeSet<String>),
}

/// Start the five watchers. They run until the process stops, backing off
/// five seconds after an error the way the pod enricher does.
pub fn spawn_netpol_watchers(
    client: &Client,
    cache: &Arc<NetpolClusterCache>,
) -> Vec<JoinHandle<()>> {
    vec![
        spawn_kind::<K8sNetworkPolicy, _>(
            client,
            "networkpolicies",
            Arc::clone(cache),
            |store, change| {
                apply(&mut store.policies, change, policy_from);
            },
        ),
        spawn_kind::<Pod, _>(client, "pods", Arc::clone(cache), |store, change| {
            apply(&mut store.pods, change, pod_from);
        }),
        spawn_kind::<Namespace, _>(client, "namespaces", Arc::clone(cache), |store, change| {
            apply(&mut store.namespaces, change, namespace_from);
        }),
        spawn_kind::<Service, _>(client, "services", Arc::clone(cache), |store, change| {
            apply(&mut store.services, change, service_from);
        }),
        spawn_kind::<EndpointSlice, _>(
            client,
            "endpointslices",
            Arc::clone(cache),
            |store, change| {
                apply(&mut store.slices, change, slice_from);
            },
        ),
    ]
}

/// The key every kind is stored under: its namespace and name.
fn key_of<K: Resource>(object: &K) -> String {
    let meta = object.meta();
    format!(
        "{}/{}",
        meta.namespace.as_deref().unwrap_or_default(),
        meta.name.as_deref().unwrap_or_default()
    )
}

fn apply<K: Resource, V>(
    map: &mut BTreeMap<String, V>,
    change: Change<K>,
    convert: fn(&K) -> Option<V>,
) {
    match change {
        Change::Upsert(object) => {
            let key = key_of(&object);
            match convert(&object) {
                Some(value) => {
                    map.insert(key, value);
                }
                None => {
                    map.remove(&key);
                }
            }
        }
        Change::Delete(object) => {
            map.remove(&key_of(&object));
        }
        Change::Relisted(keys) => map.retain(|key, _| keys.contains(key)),
    }
}

fn spawn_kind<K, F>(
    client: &Client,
    kind: &'static str,
    cache: Arc<NetpolClusterCache>,
    on_change: F,
) -> JoinHandle<()>
where
    K: Resource + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
    K::DynamicType: Default,
    F: Fn(&mut Store, Change<K>) + Send + 'static,
{
    let api: Api<K> = Api::all(client.clone());
    tokio::spawn(async move {
        info!(kind, "network policy watcher started");
        let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
        let mut relisting: Option<BTreeSet<String>> = None;
        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::Init) => relisting = Some(BTreeSet::new()),
                Ok(Event::InitApply(object)) => {
                    if let Some(keys) = relisting.as_mut() {
                        keys.insert(key_of(&object));
                    }
                    cache.with_store(|store| on_change(store, Change::Upsert(object)));
                }
                Ok(Event::InitDone) => {
                    let keys = relisting.take().unwrap_or_default();
                    cache.with_store(|store| on_change(store, Change::Relisted(keys)));
                }
                Ok(Event::Apply(object)) => {
                    cache.with_store(|store| on_change(store, Change::Upsert(object)));
                }
                Ok(Event::Delete(object)) => {
                    cache.with_store(|store| on_change(store, Change::Delete(object)));
                }
                Err(err) => {
                    warn!(kind, error = %err, "network policy watcher error, backing off 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
        debug!(kind, "network policy watcher stream closed");
    })
}

// ── Conversions ─────────────────────────────────────────────────────

fn selector_from(selector: &K8sLabelSelector) -> Option<LabelSelector> {
    let mut requirements = Vec::new();
    for requirement in selector.match_expressions.iter().flatten() {
        let operator = match requirement.operator.as_str() {
            "In" => SelectorOperator::In,
            "NotIn" => SelectorOperator::NotIn,
            "Exists" => SelectorOperator::Exists,
            "DoesNotExist" => SelectorOperator::DoesNotExist,
            _ => return None,
        };
        requirements.push(LabelRequirement {
            key: requirement.key.clone(),
            operator,
            values: requirement.values.clone().unwrap_or_default(),
        });
    }
    Some(LabelSelector {
        match_labels: selector.match_labels.clone().unwrap_or_default(),
        match_expressions: requirements,
    })
}

fn peer_from(peer: &NetworkPolicyPeer) -> Option<Peer> {
    if let Some(block) = &peer.ip_block {
        let mut except = Vec::new();
        for value in block.except.iter().flatten() {
            except.push(NetPrefix::parse(value)?);
        }
        return Some(Peer::Block(IpBlock {
            cidr: NetPrefix::parse(&block.cidr)?,
            except,
        }));
    }
    let namespaces = match &peer.namespace_selector {
        Some(selector) => Some(selector_from(selector)?),
        None => None,
    };
    let pods = match &peer.pod_selector {
        Some(selector) => Some(selector_from(selector)?),
        None => None,
    };
    Some(Peer::Pods { namespaces, pods })
}

fn port_from(port: &NetworkPolicyPort) -> Option<PolicyPort> {
    let reference = match &port.port {
        None => None,
        Some(IntOrString::Int(number)) => Some(PortRef::Number(u16::try_from(*number).ok()?)),
        Some(IntOrString::String(name)) => Some(PortRef::Name(name.clone())),
    };
    let end_port = match port.end_port {
        Some(end) => Some(u16::try_from(end).ok()?),
        None => None,
    };
    Some(PolicyPort {
        protocol: Protocol::parse(port.protocol.as_deref())?,
        port: reference,
        end_port,
    })
}

fn rule_from(
    peers: Option<&Vec<NetworkPolicyPeer>>,
    ports: Option<&Vec<NetworkPolicyPort>>,
) -> Option<PolicyRule> {
    Some(PolicyRule {
        peers: peers
            .into_iter()
            .flatten()
            .map(peer_from)
            .collect::<Option<_>>()?,
        ports: ports
            .into_iter()
            .flatten()
            .map(port_from)
            .collect::<Option<_>>()?,
    })
}

/// A policy, or `None` for one carrying a value the API server would not
/// have admitted. Such an object is logged and left out rather than half
/// read, since a rule read without its peers would open everything.
fn policy_from(object: &K8sNetworkPolicy) -> Option<NetworkPolicy> {
    let namespace = object.metadata.namespace.clone()?;
    let name = object.metadata.name.clone()?;
    let spec = object.spec.as_ref()?;
    let converted = (|| {
        let pod_selector = match &spec.pod_selector {
            Some(selector) => selector_from(selector)?,
            None => LabelSelector::default(),
        };
        let ingress = spec
            .ingress
            .iter()
            .flatten()
            .map(|rule| rule_from(rule.from.as_ref(), rule.ports.as_ref()))
            .collect::<Option<Vec<_>>>()?;
        let egress = spec
            .egress
            .iter()
            .flatten()
            .map(|rule| rule_from(rule.to.as_ref(), rule.ports.as_ref()))
            .collect::<Option<Vec<_>>>()?;
        let policy_types = match &spec.policy_types {
            Some(types) => Some(
                types
                    .iter()
                    .map(|value| match value.as_str() {
                        "Ingress" => Some(Direction::Ingress),
                        "Egress" => Some(Direction::Egress),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()?,
            ),
            None => None,
        };
        Some(NetworkPolicy {
            namespace: namespace.clone(),
            name: name.clone(),
            pod_selector,
            ingress,
            egress,
            policy_types,
        })
    })();
    if converted.is_none() {
        warn!(%namespace, %name, "network policy carries a value it could not be read with, left out");
    }
    converted
}

/// Reads `NetworkPolicy` manifests the way the watchers read the API
/// server's objects, so a replayed policy means what it will mean once
/// applied.
#[derive(Debug, Default, Clone, Copy)]
pub struct NetworkPolicyManifests;

impl NetworkPolicyManifestPort for NetworkPolicyManifests {
    fn parse(&self, manifests: &str) -> Result<Vec<NetworkPolicy>, DomainError> {
        let mut objects = Vec::new();
        for (index, document) in serde_norway::Deserializer::from_str(manifests).enumerate() {
            let value = serde_norway::Value::deserialize(document).map_err(|error| {
                DomainError::InvalidConfig(format!("document {}: {error}", index + 1))
            })?;
            if value.is_null() {
                continue;
            }
            // `kubectl get -o yaml` wraps what it returns in a list.
            if value.get("kind").and_then(serde_norway::Value::as_str) == Some("List") {
                let items = value
                    .get("items")
                    .and_then(serde_norway::Value::as_sequence)
                    .cloned()
                    .unwrap_or_default();
                objects.extend(items.into_iter().map(|item| (index, item)));
            } else {
                objects.push((index, value));
            }
        }
        objects
            .into_iter()
            .map(|(index, value)| {
                let object: K8sNetworkPolicy =
                    serde_norway::from_value(value).map_err(|error| {
                        DomainError::InvalidConfig(format!(
                            "document {}: not a networking.k8s.io/v1 NetworkPolicy: {error}",
                            index + 1
                        ))
                    })?;
                let name = object.metadata.name.clone().unwrap_or_default();
                if object.metadata.namespace.is_none() {
                    return Err(DomainError::InvalidConfig(format!(
                        "network policy {name:?} names no namespace, and a policy applies to one"
                    )));
                }
                policy_from(&object).ok_or_else(|| {
                    DomainError::InvalidConfig(format!(
                        "network policy {name:?} carries a value it could not be read with"
                    ))
                })
            })
            .collect()
    }
}

fn pod_from(pod: &Pod) -> Option<PodView> {
    let meta = &pod.metadata;
    let status = pod.status.as_ref();
    let spec = pod.spec.as_ref();
    let mut ips: Vec<IpAddr> = status
        .and_then(|status| status.pod_ips.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|ip| ip.ip.parse().ok())
        .collect();
    if ips.is_empty()
        && let Some(ip) = status
            .and_then(|s| s.pod_ip.as_deref())
            .and_then(|ip| ip.parse().ok())
    {
        ips.push(ip);
    }
    let mut host_ips: Vec<IpAddr> = status
        .and_then(|status| status.host_ips.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|ip| ip.ip.parse().ok())
        .collect();
    if host_ips.is_empty()
        && let Some(ip) = status
            .and_then(|s| s.host_ip.as_deref())
            .and_then(|ip| ip.parse().ok())
    {
        host_ips.push(ip);
    }
    let ports = spec
        .into_iter()
        .flat_map(|spec| spec.containers.iter())
        .flat_map(|container| container.ports.iter().flatten())
        .filter_map(|port| {
            Some(NamedPort {
                name: port.name.clone()?,
                port: u16::try_from(port.container_port).ok()?,
                protocol: Protocol::parse(port.protocol.as_deref())?,
            })
        })
        .collect();
    let phase = status.and_then(|status| status.phase.as_deref());
    Some(PodView {
        uid: meta.uid.clone()?,
        namespace: meta.namespace.clone()?,
        name: meta.name.clone()?,
        labels: meta.labels.clone().unwrap_or_default(),
        ips,
        ports,
        host_ips,
        host_network: spec.and_then(|spec| spec.host_network).unwrap_or(false),
        terminal: matches!(phase, Some("Succeeded" | "Failed")),
    })
}

fn namespace_from(namespace: &Namespace) -> Option<NamespaceView> {
    let name = namespace.metadata.name.clone()?;
    let mut labels = namespace.metadata.labels.clone().unwrap_or_default();
    // Set by the API server on every namespace since it became immutable;
    // written here too so a selector on it holds on any server.
    labels
        .entry(NAMESPACE_NAME_LABEL.to_string())
        .or_insert_with(|| name.clone());
    Some(NamespaceView { name, labels })
}

fn service_from(service: &Service) -> Option<(String, String, ServiceSpec)> {
    let spec = service.spec.as_ref()?;
    let cluster_ips: Vec<IpAddr> = spec
        .cluster_ips
        .iter()
        .flatten()
        .chain(spec.cluster_ip.iter())
        .filter_map(|ip| ip.parse().ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // A headless Service has no address of its own to open.
    if cluster_ips.is_empty() {
        return None;
    }
    let ports = spec
        .ports
        .iter()
        .flatten()
        .filter_map(|port| {
            Some(ServicePort {
                name: port.name.clone().unwrap_or_default(),
                port: u16::try_from(port.port).ok()?,
                protocol: Protocol::parse(port.protocol.as_deref())?,
            })
        })
        .collect();
    Some((
        service.metadata.namespace.clone()?,
        service.metadata.name.clone()?,
        ServiceSpec { cluster_ips, ports },
    ))
}

fn slice_from(slice: &EndpointSlice) -> Option<SliceSpec> {
    let service = slice
        .metadata
        .labels
        .as_ref()?
        .get(SERVICE_NAME_LABEL)?
        .clone();
    let ports: Vec<NamedPort> = slice
        .ports
        .iter()
        .flatten()
        .filter_map(|port| {
            Some(NamedPort {
                name: port.name.clone().unwrap_or_default(),
                port: u16::try_from(port.port?).ok()?,
                protocol: Protocol::parse(port.protocol.as_deref())?,
            })
        })
        .collect();
    let backends = slice
        .endpoints
        .iter()
        // An absent condition is ready, as the API documents it.
        .filter(|endpoint| {
            endpoint
                .conditions
                .as_ref()
                .and_then(|conditions| conditions.ready)
                .unwrap_or(true)
        })
        .flat_map(|endpoint| endpoint.addresses.iter())
        .filter_map(|address| address.parse().ok())
        .map(|ip| ServiceBackend {
            ip,
            ports: ports.clone(),
        })
        .collect();
    Some(SliceSpec {
        namespace: slice.metadata.namespace.clone()?,
        service,
        backends,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{PodIP, PodSpec, PodStatus, ServiceSpec as K8sServiceSpec};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort};
    use k8s_openapi::api::networking::v1::{
        IPBlock, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicySpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelectorRequirement, ObjectMeta};

    fn meta(namespace: &str, name: &str) -> ObjectMeta {
        ObjectMeta {
            namespace: Some(namespace.into()),
            name: Some(name.into()),
            uid: Some(format!("{namespace}-{name}")),
            ..ObjectMeta::default()
        }
    }

    const API_POLICY: &str = "apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web
      ports:
        - protocol: TCP
          port: 8080
";

    #[test]
    fn a_manifest_stream_reads_every_policy_in_it() {
        let stream = format!(
            "---\n{API_POLICY}---\napiVersion: v1\nkind: List\nitems:\n  - apiVersion: networking.k8s.io/v1\n    kind: NetworkPolicy\n    metadata: {{name: deny, namespace: shop}}\n    spec: {{podSelector: {{}}, policyTypes: [Egress]}}\n---\n"
        );
        let policies = NetworkPolicyManifests.parse(&stream).unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(
            (policies[0].namespace.as_str(), policies[0].name.as_str()),
            ("shop", "api")
        );
        assert_eq!(
            policies[0].ingress[0].ports[0].port,
            Some(PortRef::Number(8080))
        );
        assert_eq!(policies[1].policy_types, Some(vec![Direction::Egress]));
    }

    #[test]
    fn a_manifest_that_is_not_a_namespaced_policy_is_refused() {
        let other_kind = API_POLICY.replace("kind: NetworkPolicy", "kind: Service");
        let error = NetworkPolicyManifests.parse(&other_kind).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not a networking.k8s.io/v1 NetworkPolicy")
        );

        let no_namespace = API_POLICY.replace("  namespace: shop\n", "");
        let error = NetworkPolicyManifests.parse(&no_namespace).unwrap_err();
        assert!(error.to_string().contains("names no namespace"));

        let bad_type = API_POLICY.replace("ingress:\n", "policyTypes: [Sideways]\n  ingress:\n");
        assert!(NetworkPolicyManifests.parse(&bad_type).is_err());
    }

    #[test]
    fn a_policy_reads_with_every_field_the_compile_uses() {
        let object = K8sNetworkPolicy {
            metadata: meta("shop", "db"),
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(K8sLabelSelector {
                    match_labels: Some([("app".to_string(), "db".to_string())].into()),
                    match_expressions: Some(vec![LabelSelectorRequirement {
                        key: "tier".into(),
                        operator: "NotIn".into(),
                        values: Some(vec!["test".into()]),
                    }]),
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![
                        NetworkPolicyPeer {
                            namespace_selector: Some(K8sLabelSelector::default()),
                            ..NetworkPolicyPeer::default()
                        },
                        NetworkPolicyPeer {
                            ip_block: Some(IPBlock {
                                cidr: "10.0.0.0/8".into(),
                                except: Some(vec!["10.1.0.0/16".into()]),
                            }),
                            ..NetworkPolicyPeer::default()
                        },
                    ]),
                    ports: Some(vec![NetworkPolicyPort {
                        port: Some(IntOrString::String("pg".into())),
                        ..NetworkPolicyPort::default()
                    }]),
                }]),
                egress: Some(vec![NetworkPolicyEgressRule::default()]),
                policy_types: Some(vec!["Ingress".into(), "Egress".into()]),
            }),
        };
        let policy = policy_from(&object).unwrap();
        assert_eq!(
            policy.pod_selector.match_expressions[0].operator,
            SelectorOperator::NotIn
        );
        let rule = &policy.ingress[0];
        assert_eq!(
            rule.peers[0],
            Peer::Pods {
                namespaces: Some(LabelSelector::default()),
                pods: None
            }
        );
        assert!(matches!(&rule.peers[1], Peer::Block(block) if block.except.len() == 1));
        assert_eq!(rule.ports[0].protocol, Protocol::Tcp);
        assert_eq!(rule.ports[0].port, Some(PortRef::Name("pg".into())));
        assert_eq!(policy.egress, vec![PolicyRule::default()]);
        assert_eq!(
            policy.policy_types,
            Some(vec![Direction::Ingress, Direction::Egress])
        );
    }

    #[test]
    fn a_policy_with_an_unreadable_value_is_left_out_whole() {
        let object = K8sNetworkPolicy {
            metadata: meta("shop", "bad"),
            spec: Some(NetworkPolicySpec {
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        ip_block: Some(IPBlock {
                            cidr: "not-a-cidr".into(),
                            except: None,
                        }),
                        ..NetworkPolicyPeer::default()
                    }]),
                    ports: None,
                }]),
                ..NetworkPolicySpec::default()
            }),
        };
        assert!(policy_from(&object).is_none());
    }

    #[test]
    fn a_pod_carries_its_addresses_ports_and_host() {
        let pod = Pod {
            metadata: meta("shop", "web"),
            spec: Some(PodSpec {
                containers: vec![k8s_openapi::api::core::v1::Container {
                    name: "web".into(),
                    ports: Some(vec![k8s_openapi::api::core::v1::ContainerPort {
                        name: Some("http".into()),
                        container_port: 8080,
                        ..k8s_openapi::api::core::v1::ContainerPort::default()
                    }]),
                    ..k8s_openapi::api::core::v1::Container::default()
                }],
                ..PodSpec::default()
            }),
            status: Some(PodStatus {
                pod_ips: Some(vec![PodIP {
                    ip: "10.0.0.5".into(),
                }]),
                host_ip: Some("192.168.1.10".into()),
                phase: Some("Running".into()),
                ..PodStatus::default()
            }),
        };
        let view = pod_from(&pod).unwrap();
        assert_eq!(view.ips, vec!["10.0.0.5".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            view.host_ips,
            vec!["192.168.1.10".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(view.ports[0].port, 8080);
        assert!(!view.terminal);
    }

    #[test]
    fn a_service_is_joined_with_the_ready_backends_of_its_slices() {
        let cache = NetpolClusterCache::default();
        let service = Service {
            metadata: meta("shop", "api"),
            spec: Some(K8sServiceSpec {
                cluster_ip: Some("10.96.0.10".into()),
                ports: Some(vec![k8s_openapi::api::core::v1::ServicePort {
                    name: Some("http".into()),
                    port: 80,
                    ..k8s_openapi::api::core::v1::ServicePort::default()
                }]),
                ..K8sServiceSpec::default()
            }),
            ..Service::default()
        };
        let mut slice_meta = meta("shop", "api-abc");
        slice_meta.labels = Some([(SERVICE_NAME_LABEL.to_string(), "api".to_string())].into());
        let slice = EndpointSlice {
            metadata: slice_meta,
            address_type: "IPv4".into(),
            endpoints: vec![
                Endpoint {
                    addresses: vec!["10.0.0.5".into()],
                    ..Endpoint::default()
                },
                Endpoint {
                    addresses: vec!["10.0.0.6".into()],
                    conditions: Some(EndpointConditions {
                        ready: Some(false),
                        ..EndpointConditions::default()
                    }),
                    ..Endpoint::default()
                },
            ],
            ports: Some(vec![EndpointPort {
                name: Some("http".into()),
                port: Some(8080),
                ..EndpointPort::default()
            }]),
        };
        cache.with_store(|store| {
            apply(&mut store.services, Change::Upsert(service), service_from);
            apply(&mut store.slices, Change::Upsert(slice), slice_from);
        });
        let view = cache.view();
        assert_eq!(view.services.len(), 1);
        let backends = &view.services[0].backends;
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].ports[0].port, 8080);
    }

    #[test]
    fn a_relist_drops_what_was_deleted_while_nobody_listened() {
        let cache = NetpolClusterCache::default();
        let mut generation = cache.subscribe();
        let namespace = |name: &str| Namespace {
            metadata: meta("", name),
            ..Namespace::default()
        };
        cache.with_store(|store| {
            apply(
                &mut store.namespaces,
                Change::Upsert(namespace("a")),
                namespace_from,
            );
            apply(
                &mut store.namespaces,
                Change::Upsert(namespace("b")),
                namespace_from,
            );
        });
        assert!(generation.has_changed().unwrap());
        generation.mark_unchanged();
        cache.with_store(|store| {
            apply::<Namespace, _>(
                &mut store.namespaces,
                Change::Relisted(["/b".to_string()].into()),
                namespace_from,
            );
        });
        assert!(generation.has_changed().unwrap());
        let view = cache.view();
        assert_eq!(view.namespaces.len(), 1);
        assert_eq!(
            view.namespaces[0]
                .labels
                .get(NAMESPACE_NAME_LABEL)
                .map(String::as_str),
            Some("b")
        );
    }
}
