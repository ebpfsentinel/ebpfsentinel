//! Interface group constants for multi-interface rule scoping.
//!
//! Each rule carries a `group_mask: u32` bitmask. Bit 31 is the invert flag.
//! Bits 0-30 identify interface groups. `group_mask = 0` means floating (all interfaces).

/// Maximum number of interface groups (bits 0-30).
pub const MAX_INTERFACE_GROUPS: u32 = 31;

/// Bit 31: invert the group match (apply to all EXCEPT specified groups).
pub const GROUP_FLAG_INVERT: u32 = 0x8000_0000;

/// Mask for group bits only (bits 0-30).
pub const GROUP_BITS_MASK: u32 = 0x7FFF_FFFF;

/// Check if a rule's `tenant_id` matches the packet's tenant context.
/// Returns true if the rule should apply to this tenant.
/// `rule_tenant_id = 0` means floating rule, always matches.
/// `pkt_tenant_id = 0` means unassigned traffic, only matches floating rules.
#[inline(always)]
pub fn tenant_matches(rule_tenant_id: u32, pkt_tenant_id: u32) -> bool {
    rule_tenant_id == 0 || rule_tenant_id == pkt_tenant_id
}

/// Check if a rule's group_mask matches the interface's group membership.
/// Returns true if the rule should apply to this interface.
/// `group_mask = 0` → floating rule, always matches.
#[inline(always)]
pub fn group_matches(rule_group_mask: u32, iface_groups: u32) -> bool {
    let mask = rule_group_mask & GROUP_BITS_MASK;
    if mask == 0 {
        return true; // floating rule
    }
    let hit = (mask & iface_groups) != 0;
    let invert = (rule_group_mask & GROUP_FLAG_INVERT) != 0;
    hit != invert // XOR: hit&&!invert || !hit&&invert
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_floating_matches_any() {
        assert!(tenant_matches(0, 0));
        assert!(tenant_matches(0, 1));
        assert!(tenant_matches(0, 42));
    }

    #[test]
    fn tenant_exact_match() {
        assert!(tenant_matches(1, 1));
        assert!(tenant_matches(42, 42));
    }

    #[test]
    fn tenant_mismatch() {
        assert!(!tenant_matches(1, 2));
        assert!(!tenant_matches(42, 1));
    }

    #[test]
    fn tenant_nonzero_vs_unassigned() {
        // Non-floating rule does not match unassigned (0) traffic
        assert!(!tenant_matches(1, 0));
    }

    #[test]
    fn floating_rule_matches_everything() {
        assert!(group_matches(0, 0));
        assert!(group_matches(0, 0x7FFF_FFFF));
        assert!(group_matches(0, 1));
    }

    #[test]
    fn specific_group_matches() {
        // Rule targets group 0 (bit 0)
        assert!(group_matches(0x01, 0x01));
        assert!(group_matches(0x01, 0x03)); // iface in groups 0+1
        assert!(!group_matches(0x01, 0x02)); // iface only in group 1
        assert!(!group_matches(0x01, 0x00)); // iface in no groups
    }

    #[test]
    fn multi_group_matches() {
        // Rule targets groups 0 and 2 (bits 0+2 = 0x05)
        assert!(group_matches(0x05, 0x01)); // iface in group 0
        assert!(group_matches(0x05, 0x04)); // iface in group 2
        assert!(group_matches(0x05, 0x07)); // iface in groups 0,1,2
        assert!(!group_matches(0x05, 0x02)); // iface only in group 1
    }

    #[test]
    fn inverted_group_matches() {
        // Rule targets NOT group 0 (invert + bit 0)
        let mask = GROUP_FLAG_INVERT | 0x01;
        assert!(!group_matches(mask, 0x01)); // iface in group 0 -> excluded
        assert!(group_matches(mask, 0x02)); // iface in group 1 -> included
        assert!(!group_matches(mask, 0x03)); // iface in groups 0+1 -> has group 0, excluded
        assert!(group_matches(mask, 0x00)); // iface in no groups -> included
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(MAX_INTERFACE_GROUPS, 31);
        assert_eq!(GROUP_FLAG_INVERT, 0x8000_0000);
        assert_eq!(GROUP_BITS_MASK, 0x7FFF_FFFF);
        assert_eq!(GROUP_FLAG_INVERT | GROUP_BITS_MASK, u32::MAX);
    }
}
