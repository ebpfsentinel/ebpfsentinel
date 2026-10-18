//! The process table: the one place a pid becomes a name.
//!
//! Everything else in this agent sees numbers. A packet carries addresses, a
//! socket identity carries a pid and a cgroup id, and neither is something an
//! operator can act on. The table here is what turns the number into a
//! binary, a command line, a parent and a container, and it is deliberately
//! the only place that mapping is kept, so there is one answer to correct
//! when it is wrong.
//!
//! It is bounded and it is not a cache. An entry arrives when the kernel says
//! a task replaced its image and leaves when the kernel says that task is
//! gone, which is why nothing here ages out on a timer: a process that has
//! run for a year is not stale, and a pid freed a millisecond ago must not be
//! readable as the process that held it. The bound exists for the case the
//! kernel cannot help with - a lost exit notification - and the eviction it
//! performs is the oldest exec first, counted so the operator sees it.

pub mod engine;
pub mod entity;
