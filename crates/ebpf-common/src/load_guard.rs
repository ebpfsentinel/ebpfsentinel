//! The guard on `BPF_PROG_LOAD`, shared between the kernel program that
//! decides and the warden that loads it.
//!
//! The kernel verifies a program's signature when the load names one, and
//! refuses one that does not verify before any security module is asked. What
//! it does not do on its own is refuse a load that names no signature at all.
//! The guard, attached by the warden at the BPF LSM's `bpf_prog_load` hook,
//! does that for every load made through a BPF token: such a load passes only
//! when it carries a signature and names the keyring the warden made. A load
//! the kernel makes on its own behalf (the inner load of a signed loader) and
//! a load made without a token (by a privileged process) are left to the
//! kernel.
//!
//! The offsets below are those of the `BPF_PROG_LOAD` arm of `union bpf_attr`
//! from the kernel that introduced signed loads; they are the same the agent
//! writes when it loads through a signed loader.

/// The ELF object holding the guard.
pub const LOAD_GUARD_OBJECT: &str = "lsm-bpf-load-guard";

/// The program inside it.
pub const LOAD_GUARD_PROGRAM: &str = "bpf_load_guard";

/// The read-only global the warden writes the keyring serial into before the
/// load. Zero, the value the object is built with, refuses every token load.
pub const LOAD_GUARD_KEYRING_SYMBOL: &str = "LOAD_GUARD_KEYRING";

/// Offset of `prog_flags` in `union bpf_attr`.
pub const LOAD_GUARD_ATTR_PROG_FLAGS: usize = 44;

/// Offset of `signature`, a user pointer, in `union bpf_attr`.
pub const LOAD_GUARD_ATTR_SIGNATURE: usize = 152;

/// Offset of `keyring_id`, a signed 32-bit serial, in `union bpf_attr`.
pub const LOAD_GUARD_ATTR_KEYRING_ID: usize = 164;

/// `BPF_F_TOKEN_FD`: the load is made through the token in `prog_token_fd`.
pub const LOAD_GUARD_F_TOKEN_FD: u32 = 1 << 16;

/// What the guard answers a load it refuses: `-EPERM`.
pub const LOAD_GUARD_REFUSAL: i32 = -1;

/// The facts the guard reads off one `BPF_PROG_LOAD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadFacts {
    /// The kernel is loading on its own behalf.
    pub kernel: bool,
    /// The load came through a BPF token, by the token argument or the flag.
    pub token: bool,
    /// The `signature` pointer of the attribute block; zero when none.
    pub signature: u64,
    /// The keyring the load names.
    pub keyring_id: i32,
}

/// The verdict on one load: `0` to leave it to the kernel, or
/// [`LOAD_GUARD_REFUSAL`]. `warden_keyring` is the serial written before the
/// load; a guard loaded without one (zero or negative) refuses every token
/// load, so a mistake closes rather than opens.
#[inline(always)]
#[must_use]
pub const fn load_guard_verdict(facts: LoadFacts, warden_keyring: i32) -> i32 {
    if facts.kernel || !facts.token {
        return 0;
    }
    if facts.signature == 0 || warden_keyring <= 0 || facts.keyring_id != warden_keyring {
        return LOAD_GUARD_REFUSAL;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const RING: i32 = 0x2f3e_4d5c;

    fn token_load(signature: u64, keyring_id: i32) -> LoadFacts {
        LoadFacts {
            kernel: false,
            token: true,
            signature,
            keyring_id,
        }
    }

    #[test]
    fn a_token_load_without_a_signature_is_refused() {
        assert_eq!(
            load_guard_verdict(token_load(0, 0), RING),
            LOAD_GUARD_REFUSAL
        );
        assert_eq!(
            load_guard_verdict(token_load(0, RING), RING),
            LOAD_GUARD_REFUSAL
        );
    }

    #[test]
    fn a_token_load_signed_against_another_keyring_is_refused() {
        assert_eq!(
            load_guard_verdict(token_load(0x7fff_0000, RING + 1), RING),
            LOAD_GUARD_REFUSAL
        );
        assert_eq!(
            load_guard_verdict(token_load(0x7fff_0000, 1), RING),
            LOAD_GUARD_REFUSAL
        );
    }

    #[test]
    fn a_token_load_signed_against_the_warden_keyring_passes() {
        assert_eq!(load_guard_verdict(token_load(0x7fff_0000, RING), RING), 0);
    }

    #[test]
    fn the_kernel_loading_on_its_own_behalf_passes() {
        let inner = LoadFacts {
            kernel: true,
            ..token_load(0, 0)
        };
        assert_eq!(load_guard_verdict(inner, RING), 0);
    }

    #[test]
    fn a_load_without_a_token_is_left_to_the_kernel() {
        let privileged = LoadFacts {
            token: false,
            ..token_load(0, 0)
        };
        assert_eq!(load_guard_verdict(privileged, RING), 0);
    }

    #[test]
    fn a_guard_loaded_without_a_serial_refuses_every_token_load() {
        assert_eq!(
            load_guard_verdict(token_load(0x7fff_0000, 0), 0),
            LOAD_GUARD_REFUSAL
        );
        assert_eq!(
            load_guard_verdict(token_load(0x7fff_0000, -1), -1),
            LOAD_GUARD_REFUSAL
        );
    }

    #[test]
    fn the_offsets_are_the_signed_load_layout() {
        assert_eq!(LOAD_GUARD_ATTR_PROG_FLAGS, 44);
        assert_eq!(LOAD_GUARD_ATTR_SIGNATURE, 152);
        assert_eq!(LOAD_GUARD_ATTR_KEYRING_ID, 164);
        assert_eq!(LOAD_GUARD_F_TOKEN_FD, 0x1_0000);
    }
}
