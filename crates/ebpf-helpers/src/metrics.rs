//! Per-CPU metric helper macros.
//!
//! Each eBPF program defines its own `PerCpuArray<u64>` map for metrics.
//! These macros provide a uniform increment/add interface without needing
//! to know the map name at compile time in this crate.

/// Increment a per-CPU metric counter by 1.
///
/// # Usage
///
/// ```ignore
/// use ebpf_helpers::increment_metric;
///
/// #[map]
/// static MY_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5, 0);
///
/// increment_metric!(MY_METRICS, 0);
/// ```
#[macro_export]
macro_rules! increment_metric {
    ($map:expr, $index:expr) => {
        if let Some(counter) = $map.get_ptr_mut($index) {
            unsafe {
                *counter += 1;
            }
        }
    };
}

/// Add an arbitrary value to a per-CPU metric counter.
///
/// # Usage
///
/// ```ignore
/// use ebpf_helpers::add_metric;
///
/// add_metric!(MY_METRICS, BYTES_INDEX, pkt_len);
/// ```
#[macro_export]
macro_rules! add_metric {
    ($map:expr, $index:expr, $value:expr) => {
        if let Some(counter) = $map.get_ptr_mut($index) {
            unsafe {
                *counter += $value;
            }
        }
    };
}
