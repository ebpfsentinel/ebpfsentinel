//! Kubernetes `NetworkPolicy`, compiled for the pods of one node.
//!
//! The agent reads the policies, pods, namespaces and services of the
//! cluster, and this module turns them into what the cgroup hooks look up:
//! for each pod of this node that some policy selects, which peer prefixes
//! are open on which ports in each direction. The semantics are the
//! Kubernetes ones exactly - a pod no policy selects is open, a pod selected
//! in a direction is closed in that direction but for the union of every rule
//! selecting it - and `conformance` asserts them case by case.

pub mod compile;
pub mod entity;

#[cfg(test)]
mod conformance;

pub use compile::{
    CompileReport, CompiledPolicy, NodeContext, PodAssignment, PortRange, PortSet, RefusedService,
    SlotEntry, SlotProgram, Truncation, compile,
};
pub use entity::{
    ClusterView, Direction, IpBlock, LabelRequirement, LabelSelector, NamedPort, NamespaceView,
    NetPrefix, NetworkPolicy, Peer, PodView, PolicyPort, PolicyRule, PortRef, Protocol,
    SelectorOperator, ServiceBackend, ServicePort, ServiceView,
};
