//! Tenant isolation constants and the per-tenant rule contract for the
//! multi-tenancy eBPF maps.
//!
//! Each tenant can have subnet and VLAN isolation rules that restrict
//! which traffic belongs to that tenant. `tenant_id = 0` means floating
//! (applies to all tenants).
//!
//! # Per-tenant rule segmentation contract
//!
//! Rule maps are keyed so a rule can be scoped to a single tenant while the
//! standalone OSS agent keeps working unchanged. The shared rules are:
//!
//! - **`xdp-firewall`** — `FIREWALL_RULES` / `FIREWALL_RULES_V6` are priority
//!   ordered arrays; each [`crate::firewall::FirewallRuleEntry`] carries a
//!   `tenant_id`. The kernel scan matches an entry when
//!   `entry.tenant_id == 0 || entry.tenant_id == packet_tenant`, so a
//!   tenant-specific rule placed ahead of a global one wins and a global
//!   (`tenant_id == 0`) rule still applies to every tenant.
//! - **`tc-ids`** — `IDS_PATTERNS` / `IDS_SRC_PATTERNS` are keyed by
//!   [`crate::ids::IdsPatternKey`] `(tenant_id, dst_port, protocol)`. The
//!   kernel looks up the packet's tenant first, then falls back to the
//!   `tenant_id == 0` entry.
//! - **`xdp-ratelimit`** — `RATELIMIT_CONFIG` / buckets are keyed by
//!   [`crate::ratelimit::RateLimitKey`] `(tenant_id, src_ip)`. Lookup falls
//!   back `(tenant, src_ip) → (tenant, 0) → (0, src_ip) → (0, 0)`.
//!
//! In all three, **`tenant_id == [`TENANT_ID_GLOBAL`]` (0)` is the
//! global/floating tenant**. A standalone OSS agent only ever resolves
//! tenant 0, so the per-tenant maps exist but stay inert (only tenant-0
//! entries) until the enterprise control plane writes non-zero entries.

/// The global / floating tenant id. Rules written under this tenant apply to
/// every tenant and a standalone OSS agent only ever resolves this value.
pub const TENANT_ID_GLOBAL: u32 = 0;

/// Maximum entries in the tenant subnet isolation map.
pub const MAX_TENANT_SUBNET_ENTRIES: u32 = 4096;

/// Maximum entries in the tenant VLAN isolation map.
pub const MAX_TENANT_VLAN_ENTRIES: u32 = 1024;

/// Maximum entries in the tenant subnet LPM trie (IPv4).
pub const MAX_TENANT_SUBNET_LPM_ENTRIES: u32 = 4096;

/// Maximum entries in the tenant subnet LPM trie (IPv6).
pub const MAX_TENANT_SUBNET_V6_LPM_ENTRIES: u32 = 2048;
