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

    #[test]
    fn test_config_flags_field_offsets() {
        assert_eq!(mem::offset_of!(ConfigFlags, firewall_enabled), 0);
        assert_eq!(mem::offset_of!(ConfigFlags, ids_enabled), 1);
        assert_eq!(mem::offset_of!(ConfigFlags, ips_enabled), 2);
        assert_eq!(mem::offset_of!(ConfigFlags, dlp_enabled), 3);
        assert_eq!(mem::offset_of!(ConfigFlags, ratelimit_enabled), 4);
        assert_eq!(mem::offset_of!(ConfigFlags, threatintel_enabled), 5);
        assert_eq!(mem::offset_of!(ConfigFlags, conntrack_enabled), 6);
        assert_eq!(mem::offset_of!(ConfigFlags, nat_enabled), 7);
    }
}
