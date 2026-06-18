//! Secondary port for an external DLP pattern matcher.
//!
//! The OSS [`DlpEngine`](domain::dlp::engine::DlpEngine) matches captured
//! plaintext with `regex`. The Enterprise edition replaces that matcher with a
//! Vectorscan (Hyperscan) engine so its richer pattern set and higher-throughput
//! scanning apply to the same uprobe-dlp capture path. This port is the seam:
//! when an implementation is injected into the [`DlpAppService`], it scans in
//! place of the OSS regex engine.
//!
//! The returned matches' `pattern_index` MUST align with the pattern list the
//! owning `DlpAppService` reports via `list_patterns()` — the caller loads the
//! same patterns, in the same order, into both.

use domain::dlp::entity::DlpMatch;

/// An external matcher that scans data for DLP pattern hits.
pub trait DlpMatcherPort: Send + Sync {
    /// Scan `data`, returning every match. Each match's `pattern_index` indexes
    /// the owning service's pattern list (`DlpAppService::list_patterns`).
    fn scan_data(&self, data: &[u8]) -> Vec<DlpMatch>;
}
