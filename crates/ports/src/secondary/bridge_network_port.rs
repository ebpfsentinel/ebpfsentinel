//! Bridge network secondary port.
//!
//! What the container runtime says about its bridge networks: the subnets
//! each one carries, its gateway, whether the runtime answers names on it,
//! and which containers sit on it at which address. Read when somebody asks
//! for a segmentation document, never on the packet path.

use async_trait::async_trait;

use domain::container::error::ContainerError;
use domain::learning::segmentation::BridgeNetwork;

#[async_trait]
pub trait BridgeNetworkPort: Send + Sync {
    /// Every bridge network the runtime holds, with its containers.
    ///
    /// # Errors
    ///
    /// Returns a [`ContainerError`] when the runtime cannot be reached or its
    /// answer cannot be read.
    async fn bridge_networks(&self) -> Result<Vec<BridgeNetwork>, ContainerError>;
}
