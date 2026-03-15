//! Config command protocol for User RingBuf (userspace → kernel).
//!
//! Userspace writes `ConfigCommand` entries into a `BPF_MAP_TYPE_USER_RINGBUF`.
//! The eBPF program calls `bpf_user_ringbuf_drain()` at entry to consume
//! pending commands and apply config changes atomically.

/// Command types for the config ring buffer.
pub const CMD_ADD_FW_RULE_5TUPLE: u8 = 1;
pub const CMD_DEL_FW_RULE_5TUPLE: u8 = 2;
pub const CMD_ADD_FW_RULE_PORT: u8 = 3;
pub const CMD_DEL_FW_RULE_PORT: u8 = 4;
pub const CMD_SET_DEFAULT_POLICY: u8 = 5;

/// Maximum payload size in a config command.
/// Must accommodate the largest inline rule struct (FwHashKey5Tuple=16 + FwHashValue=4 = 20 bytes).
pub const MAX_CONFIG_CMD_PAYLOAD: usize = 128;

/// Size of the User RingBuf (64 KB).
pub const CONFIG_RINGBUF_SIZE: u32 = 64 * 1024;

/// Config command sent from userspace to eBPF via User RingBuf.
///
/// Fixed-size (136 bytes) to simplify verifier analysis. The `payload`
/// field contains command-specific data (rule key+value, policy byte, etc.).
///
/// Size: 136 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConfigCommand {
    /// Command type: `CMD_ADD_FW_RULE_5TUPLE`, etc.
    pub cmd_type: u8,
    pub _pad: [u8; 3],
    /// Number of valid bytes in `payload`.
    pub payload_len: u32,
    /// Command-specific payload (inline, zero-padded).
    pub payload: [u8; MAX_CONFIG_CMD_PAYLOAD],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConfigCommand {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn config_command_size() {
        assert_eq!(mem::size_of::<ConfigCommand>(), 136);
    }

    #[test]
    fn config_command_alignment() {
        assert_eq!(mem::align_of::<ConfigCommand>(), 4);
    }

    #[test]
    fn config_command_offsets() {
        assert_eq!(mem::offset_of!(ConfigCommand, cmd_type), 0);
        assert_eq!(mem::offset_of!(ConfigCommand, payload_len), 4);
        assert_eq!(mem::offset_of!(ConfigCommand, payload), 8);
    }

    #[test]
    fn command_constants() {
        assert_eq!(CMD_ADD_FW_RULE_5TUPLE, 1);
        assert_eq!(CMD_DEL_FW_RULE_5TUPLE, 2);
        assert_eq!(CMD_ADD_FW_RULE_PORT, 3);
        assert_eq!(CMD_DEL_FW_RULE_PORT, 4);
        assert_eq!(CMD_SET_DEFAULT_POLICY, 5);
    }
}
