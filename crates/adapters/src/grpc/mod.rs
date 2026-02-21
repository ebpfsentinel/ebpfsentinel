pub mod alert_service;
pub mod interceptor;
pub mod server;

/// Generated protobuf types and tonic service stubs.
#[allow(clippy::doc_markdown, clippy::default_trait_access)]
pub mod proto {
    tonic::include_proto!("ebpfsentinel.v1");

    /// File descriptor set for tonic-reflection service discovery.
    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("ebpfsentinel.v1");
}
