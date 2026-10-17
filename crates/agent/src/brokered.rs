//! Running a synchronous, warden-brokered call from an async context.
//!
//! Conntrack reads, conntrack flushes and route writes are synchronous port
//! methods, and in a rootless deployment each of them is a round trip to the
//! warden over a unix socket. Called straight from an async handler they park a
//! tokio worker for the whole round trip, so a warden that has stopped
//! answering takes a worker with every request until the runtime has none left.
//!
//! The work therefore goes to the blocking pool, and the caller waits on it for
//! a bounded time. Two bounds are in play and they are deliberately different:
//! the warden client's own socket timeout ends the normal case and says which
//! operation timed out, while [`WARDEN_BROKER_CALL_TIMEOUT`] is the outer net
//! for a thread stuck somewhere the socket timeout cannot see - a lock held by
//! a wedged caller, a child the warden is still killing.

use std::time::Duration;

use infrastructure::constants::WARDEN_BROKER_CALL_TIMEOUT;

/// Run `op` on a blocking thread, waiting at most
/// [`WARDEN_BROKER_CALL_TIMEOUT`] for its answer.
///
/// `what` names the operation for the error, which is what the caller reports
/// to whoever asked. On timeout the thread is left running: a blocking thread
/// is cheap, and the alternative - a request that never answers - is not.
pub async fn brokered<T, F>(what: &str, op: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    brokered_within(what, WARDEN_BROKER_CALL_TIMEOUT, op).await
}

/// [`brokered`] with an explicit bound, which is what the tests drive.
pub async fn brokered_within<T, F>(what: &str, timeout: Duration, op: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let task = tokio::task::spawn_blocking(op);
    match tokio::time::timeout(timeout, task).await {
        Ok(Ok(value)) => Ok(value),
        // A panic in the blocking thread is reported rather than retried: it is
        // a bug in the port, and the caller gets an error instead of a hang.
        Ok(Err(e)) => Err(format!("{what} could not be run: {e}")),
        Err(_) => Err(format!("{what} did not answer within {timeout:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{brokered, brokered_within};
    use std::time::Duration;

    #[tokio::test]
    async fn an_answer_comes_back_as_itself() {
        let value = brokered("test call", || 7_u32).await.expect("the op runs");
        assert_eq!(value, 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_call_that_never_answers_frees_the_caller() {
        // One worker thread, and the op blocks for far longer than the bound:
        // if the work ran on the worker rather than on the blocking pool, this
        // test would not finish.
        let err = brokered_within("conntrack query", Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(10));
        })
        .await
        .expect_err("a call past its bound is an error, not a wait");
        assert!(
            err.contains("conntrack query") && err.contains("did not answer"),
            "the error must name the call that hung, got: {err}"
        );
    }

    #[tokio::test]
    async fn a_panic_in_the_work_is_an_error_not_a_crash() {
        let err = brokered("route write", || panic!("the port gave up"))
            .await
            .expect_err("a panicking op is an error");
        assert!(
            err.contains("route write"),
            "the error must name the call that panicked, got: {err}"
        );
    }
}
