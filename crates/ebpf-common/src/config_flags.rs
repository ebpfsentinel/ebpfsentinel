/// Shared feature flags read by all eBPF programs via CONFIG_FLAGS Array map.
/// Size: 8 bytes (all u8 fields, explicit padding to 8-byte boundary).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigFlags {
    pub firewall_enabled: u8,
    pub ids_enabled: u8,
    pub ips_enabled: u8,
    pub dlp_enabled: u8,
    pub ratelimit_enabled: u8,
    pub threatintel_enabled: u8,
    pub conntrack_enabled: u8,
    pub nat_enabled: u8,
}

// SAFETY: ConfigFlags is #[repr(C)], Copy, 'static, and contains only primitive
// types with explicit padding. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConfigFlags {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_config_flags_size() {
        assert_eq!(mem::size_of::<ConfigFlags>(), 8);
    }

    #[test]
    fn test_config_flags_alignment() {
        assert_eq!(mem::align_of::<ConfigFlags>(), 1);
    }
}
