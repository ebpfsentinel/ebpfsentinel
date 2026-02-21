use std::sync::Arc;
use std::time::Duration;

use ports::secondary::metrics_port::MetricsPort;
use tokio_util::sync::CancellationToken;

/// Collects process-level system metrics (RSS memory, CPU usage) from
/// `/proc/self/status` and `/proc/self/stat`.
pub struct SystemMetricsCollector {
    metrics: Arc<dyn MetricsPort>,
    prev_cpu_ticks: u64,
    prev_total_ticks: u64,
}

impl SystemMetricsCollector {
    pub fn new(metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            metrics,
            prev_cpu_ticks: 0,
            prev_total_ticks: 0,
        }
    }

    /// Run the collection loop, sampling every `interval`.
    /// Exits when the cancellation token is triggered.
    pub async fn run(mut self, interval: Duration, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    self.collect();
                }
            }
        }
    }

    fn collect(&mut self) {
        if let Some(rss_bytes) = read_rss_bytes() {
            self.metrics.set_memory_usage_bytes(rss_bytes);
        }

        if let Some((cpu_ticks, total_ticks)) = read_cpu_ticks() {
            if self.prev_total_ticks > 0 {
                let cpu_delta = cpu_ticks.saturating_sub(self.prev_cpu_ticks);
                let total_delta = total_ticks.saturating_sub(self.prev_total_ticks);
                if total_delta > 0 {
                    #[allow(clippy::cast_precision_loss)] // acceptable precision loss for CPU %
                    let percent = (cpu_delta as f64 / total_delta as f64) * 100.0;
                    self.metrics.set_cpu_usage_percent(percent);
                }
            }
            self.prev_cpu_ticks = cpu_ticks;
            self.prev_total_ticks = total_ticks;
        }
    }
}

/// Parse `VmRSS` from `/proc/self/status`. Returns RSS in bytes.
fn read_rss_bytes() -> Option<u64> {
    read_rss_bytes_from(&std::fs::read_to_string("/proc/self/status").ok()?)
}

fn read_rss_bytes_from(content: &str) -> Option<u64> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let trimmed = rest.trim();
            // Format: "12345 kB"
            let kb_str = trimmed.strip_suffix("kB").unwrap_or(trimmed).trim();
            let kb: u64 = kb_str.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Read process CPU ticks (utime + stime) from `/proc/self/stat`,
/// and total system ticks from `/proc/stat`.
/// Returns `(process_ticks, total_system_ticks)`.
fn read_cpu_ticks() -> Option<(u64, u64)> {
    let proc_stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let process_ticks = parse_process_cpu_ticks(&proc_stat)?;

    let sys_stat = std::fs::read_to_string("/proc/stat").ok()?;
    let total_ticks = parse_total_cpu_ticks(&sys_stat)?;

    Some((process_ticks, total_ticks))
}

/// Parse `utime` + `stime` from `/proc/self/stat`.
/// Format: `pid (comm) state ppid ... utime(13) stime(14) ...`
fn parse_process_cpu_ticks(content: &str) -> Option<u64> {
    // Find the closing ')' of the comm field to handle spaces in process name
    let after_comm = content.find(')')? + 1;
    let fields: Vec<&str> = content[after_comm..].split_whitespace().collect();
    // After ')': state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5)
    //            flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10)
    //            utime(11) stime(12) ...
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// Parse total CPU ticks from the first line of `/proc/stat`.
/// Format: `cpu user nice system idle iowait irq softirq steal guest guest_nice`
fn parse_total_cpu_ticks(content: &str) -> Option<u64> {
    let first_line = content.lines().next()?;
    if !first_line.starts_with("cpu ") {
        return None;
    }
    let total: u64 = first_line
        .split_whitespace()
        .skip(1) // skip "cpu"
        .filter_map(|s| s.parse::<u64>().ok())
        .sum();
    Some(total)
}

/// Convenience function to spawn the collection loop as a background task.
pub fn spawn_collection_loop(
    metrics: Arc<dyn MetricsPort>,
    interval: Duration,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let collector = SystemMetricsCollector::new(metrics);
    tokio::spawn(collector.run(interval, cancel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ports::secondary::metrics_port::{
        AlertMetrics, ConfigMetrics, DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics,
        IpsMetrics, PacketMetrics, SystemMetrics,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestMetrics {
        memory: AtomicU64,
        cpu: std::sync::Mutex<f64>,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                memory: AtomicU64::new(0),
                cpu: std::sync::Mutex::new(0.0),
            }
        }
    }

    impl PacketMetrics for TestMetrics {}
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {}
    impl IpsMetrics for TestMetrics {}
    impl DnsMetrics for TestMetrics {}
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {
        fn set_memory_usage_bytes(&self, bytes: u64) {
            self.memory.store(bytes, Ordering::Relaxed);
        }
        fn set_cpu_usage_percent(&self, percent: f64) {
            *self.cpu.lock().unwrap() = percent;
        }
    }
    impl ConfigMetrics for TestMetrics {}
    impl EventMetrics for TestMetrics {}

    #[test]
    fn parse_vmrss_from_status() {
        let content = "\
VmPeak:   123456 kB
VmSize:   100000 kB
VmRSS:    51200 kB
VmData:    80000 kB";
        let bytes = read_rss_bytes_from(content).unwrap();
        assert_eq!(bytes, 51200 * 1024);
    }

    #[test]
    fn parse_vmrss_missing_returns_none() {
        let content = "VmPeak:   123456 kB\nVmSize:   100000 kB\n";
        assert!(read_rss_bytes_from(content).is_none());
    }

    #[test]
    fn parse_process_cpu_ticks_valid() {
        // Simulated /proc/self/stat line
        let content = "1234 (my process) S 1 1234 1234 0 -1 4194304 100 0 0 0 500 200 0 0 20 0 1 0 1000 1000000 100 18446744073709551615";
        let ticks = parse_process_cpu_ticks(content).unwrap();
        assert_eq!(ticks, 700); // utime(500) + stime(200)
    }

    #[test]
    fn parse_process_cpu_ticks_with_spaces_in_name() {
        let content = "1234 (my proc name) S 1 1234 1234 0 -1 4194304 100 0 0 0 300 100 0 0 20 0 1 0 1000 1000000 100 18446744073709551615";
        let ticks = parse_process_cpu_ticks(content).unwrap();
        assert_eq!(ticks, 400); // 300 + 100
    }

    #[test]
    fn parse_total_cpu_ticks_valid() {
        let content =
            "cpu  1000 200 300 5000 100 50 25 0 0 0\ncpu0 500 100 150 2500 50 25 12 0 0 0";
        let total = parse_total_cpu_ticks(content).unwrap();
        assert_eq!(total, 6675); // 1000+200+300+5000+100+50+25
    }

    #[test]
    fn parse_total_cpu_ticks_empty() {
        assert!(parse_total_cpu_ticks("").is_none());
    }

    #[test]
    fn parse_total_cpu_ticks_wrong_prefix() {
        assert!(parse_total_cpu_ticks("memory 1234").is_none());
    }

    #[test]
    fn collector_collect_sets_metrics() {
        // This test reads actual /proc on Linux; skip on non-Linux
        if !cfg!(target_os = "linux") {
            return;
        }

        let metrics = Arc::new(TestMetrics::new());
        let mut collector =
            SystemMetricsCollector::new(Arc::clone(&metrics) as Arc<dyn MetricsPort>);

        // First collect initializes baselines
        collector.collect();
        let rss = metrics.memory.load(Ordering::Relaxed);
        assert!(rss > 0, "RSS should be non-zero on a running process");

        // Second collect computes CPU delta
        collector.collect();
        // CPU percent may be 0.0 if interval is tiny, but should not panic
    }
}
