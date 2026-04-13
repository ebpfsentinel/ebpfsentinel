//! Re-exports the `CgroupReader` trait from the domain crate under the
//! `ContainerResolverPort` name so adapters targeting the secondary-port
//! layer can find it alongside the other `*_port` modules.

pub use domain::container::engine::CgroupReader as ContainerResolverPort;
