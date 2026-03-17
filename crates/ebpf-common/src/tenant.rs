//! Tenant isolation constants for multi-tenancy eBPF maps.
//!
//! Each tenant can have subnet and VLAN isolation rules that restrict
//! which traffic belongs to that tenant. `tenant_id = 0` means floating
//! (applies to all tenants).

/// Maximum entries in the tenant subnet isolation map.
pub const MAX_TENANT_SUBNET_ENTRIES: u32 = 4096;

/// Maximum entries in the tenant VLAN isolation map.
pub const MAX_TENANT_VLAN_ENTRIES: u32 = 1024;
