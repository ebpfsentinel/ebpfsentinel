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
}
