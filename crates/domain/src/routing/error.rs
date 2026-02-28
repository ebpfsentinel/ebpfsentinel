use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("gateway not found: {id}")]
    GatewayNotFound { id: u8 },
    #[error("duplicate gateway ID: {id}")]
    DuplicateGateway { id: u8 },
    #[error("no healthy gateway available")]
    NoHealthyGateway,
}
