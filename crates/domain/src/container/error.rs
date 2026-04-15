use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("failed to read cgroup for pid {pid}: {source}")]
    ProcRead {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("cgroup file for pid {pid} is empty")]
    EmptyCgroup { pid: u32 },

    #[error("cgroup line is malformed: {line}")]
    MalformedCgroup { line: String },

    #[error("docker runtime unavailable at {socket}")]
    DockerUnavailable { socket: String },

    #[error("docker inspect timed out after {timeout_ms}ms")]
    DockerTimeout { timeout_ms: u64 },

    #[error("container {id} not found")]
    ContainerNotFound { id: String },

    #[error("docker api error: HTTP {status}")]
    DockerApi { status: u16 },

    #[error("malformed docker response: {reason}")]
    DockerMalformed { reason: String },
}
