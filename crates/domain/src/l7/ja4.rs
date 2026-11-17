//! JA4 fingerprint of a TLS `ClientHello`.
//!
//! Follows the JA4 method by [FoxIO](https://github.com/FoxIO-LLC/ja4),
//! which is licensed BSD 3-Clause.
//! Only the client fingerprint is computed: the other methods of that
//! family are under a different licence and are not implemented here.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::entity::TlsClientHello;

/// JA4 fingerprint for a TLS `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4Fingerprint {
    /// Full JA4 hash: `{a}_{b}_{c}`.
    pub ja4: String,
    /// Section a (readable prefix): protocol + version + SNI + counts + ALPN hint.
    pub ja4_a: String,
    /// Section b: truncated SHA-256 of sorted cipher suites.
    pub ja4_b: String,
    /// Section c: truncated SHA-256 of sorted extensions + signature algorithms.
    pub ja4_c: String,
}

/// Compute the JA4 fingerprint from a parsed `TlsClientHello`.
pub fn compute_ja4(hello: &TlsClientHello) -> Ja4Fingerprint {
    let ja4_a = compute_section_a(hello);
    let ja4_b = compute_section_b(hello);
    let ja4_c = compute_section_c(hello);
    let ja4 = format!("{ja4_a}_{ja4_b}_{ja4_c}");

    Ja4Fingerprint {
        ja4,
        ja4_a,
        ja4_b,
        ja4_c,
    }
}

/// Section a: `t{version}{d|i}{cipher_count:02}{ext_count:02}{alpn_hint}`
fn compute_section_a(hello: &TlsClientHello) -> String {
    // Protocol: "t" for TCP (we don't support QUIC yet)
    let proto = 't';

    // TLS version: the highest the client offers in supported_versions, which
    // a client lists in any order it likes, else the handshake header.
    let version = tls_version_str(
        hello
            .supported_versions
            .iter()
            .copied()
            .max()
            .unwrap_or(hello.handshake_version),
    );

    // SNI indicator: "d" if domain present, "i" if absent
    let sni_indicator = if hello.sni.is_some() { 'd' } else { 'i' };

    // Counts (capped at 99 for 2-digit display)
    let cipher_count = hello.cipher_suites.len().min(99);
    let ext_count = hello.extension_types.len().min(99);

    // ALPN hint: first and last character of the first protocol, or "00".
    // A value whose first or last byte is not alphanumeric is written as the
    // first and last hex digit of the whole value instead.
    let alpn_hint = hello
        .alpn_protocols
        .first()
        .and_then(|p| alpn_hint(p.as_bytes()))
        .unwrap_or_else(|| "00".to_string());

    format!("{proto}{version}{sni_indicator}{cipher_count:02}{ext_count:02}{alpn_hint}")
}

/// Section b: SHA-256(sorted cipher suites as comma-separated hex), truncated
/// to 12 hex chars, or twelve zeros when the hello offers no cipher.
fn compute_section_b(hello: &TlsClientHello) -> String {
    if hello.cipher_suites.is_empty() {
        return EMPTY_SECTION.to_string();
    }
    let mut sorted = hello.cipher_suites.clone();
    sorted.sort_unstable();
    sha256_12(&hex_csv(&sorted))
}

/// Section c: SHA-256(sorted extensions + `_` + signature algorithms in the
/// order the client sent them), truncated to 12 hex chars.
///
/// SNI and ALPN are left out of the extension list (they are already in
/// section a). The signature algorithms are not sorted: their order is part
/// of what tells one client from another, and sorting them gives a value no
/// published JA4 matches. With no signature algorithm the underscore is left
/// out; with no extension at all the section is twelve zeros.
fn compute_section_c(hello: &TlsClientHello) -> String {
    let mut sorted_ext: Vec<u16> = hello
        .extension_types
        .iter()
        .copied()
        .filter(|&e| e != 0x0000 && e != 0x0010)
        .collect();
    if sorted_ext.is_empty() {
        return EMPTY_SECTION.to_string();
    }
    sorted_ext.sort_unstable();

    let ext_csv = hex_csv(&sorted_ext);
    let input = if hello.signature_algorithms.is_empty() {
        ext_csv
    } else {
        format!("{ext_csv}_{}", hex_csv(&hello.signature_algorithms))
    };
    sha256_12(&input)
}

/// Section b or c of a hello that carries nothing to hash.
const EMPTY_SECTION: &str = "000000000000";

fn hex_csv(values: &[u16]) -> String {
    values.iter().fold(String::new(), |mut acc, &value| {
        if !acc.is_empty() {
            acc.push(',');
        }
        let _ = write!(acc, "{value:04x}");
        acc
    })
}

fn alpn_hint(value: &[u8]) -> Option<String> {
    let (&first, &last) = (value.first()?, value.last()?);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        return Some(format!("{}{}", first as char, last as char));
    }
    let hex = value.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    });
    let (head, tail) = (hex.chars().next()?, hex.chars().last()?);
    Some(format!("{head}{tail}"))
}

fn tls_version_str(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    }
}

fn sha256_12(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    // First 6 bytes = 12 hex characters
    hash.iter()
        .take(6)
        .fold(String::with_capacity(12), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// ── Flow fingerprint cache ────────────────────────────────────────

/// 4-tuple flow key for fingerprint caching.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_addr: [u32; 4],
    pub src_port: u16,
    pub dst_addr: [u32; 4],
    pub dst_port: u16,
}

struct CacheEntry<T> {
    fingerprint: T,
    inserted_at: SystemTime,
}

/// Persistence port for the JA4 fingerprint cache. Implementations
/// can back the cache with an embedded KV store (redb), allowing the
/// agent to repopulate the in-memory cache after a restart.
pub trait Ja4Persist: Send + Sync {
    /// Persist a fresh cache entry. Errors are swallowed by the cache
    /// (best-effort: persistence must never block the hot path).
    fn save(&self, key: &FlowKey, fp: &Ja4Fingerprint, inserted_at: SystemTime);

    /// Load every persisted entry. Called once at cache construction
    /// to repopulate after restart. Implementations should skip
    /// entries older than the cache TTL.
    fn load_all(&self) -> Vec<(FlowKey, Ja4Fingerprint, SystemTime)>;
}

/// LRU-ish fingerprint cache with configurable TTL and max size.
///
/// Uses interior mutability (`Mutex`) so all methods take `&self`.
/// Safe to share via `Arc<FingerprintCache>` without an external lock.
pub struct FingerprintCache {
    entries: std::sync::Mutex<HashMap<FlowKey, CacheEntry<Ja4Fingerprint>>>,
    max_size: usize,
    ttl: Duration,
    persist: Option<Arc<dyn Ja4Persist>>,
}

impl FingerprintCache {
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
            max_size,
            ttl,
            persist: None,
        }
    }

    /// Build a cache that mirrors writes to `persist` and primes itself
    /// from `persist.load_all()` at construction time.
    pub fn with_persist(max_size: usize, ttl: Duration, persist: Arc<dyn Ja4Persist>) -> Self {
        let mut map: HashMap<FlowKey, CacheEntry<Ja4Fingerprint>> = HashMap::new();
        let now = SystemTime::now();
        for (key, fp, ts) in persist.load_all() {
            if now.duration_since(ts).is_ok_and(|d| d <= ttl) && map.len() < max_size {
                map.insert(
                    key,
                    CacheEntry {
                        fingerprint: fp,
                        inserted_at: ts,
                    },
                );
            }
        }
        Self {
            entries: std::sync::Mutex::new(map),
            max_size,
            ttl,
            persist: Some(persist),
        }
    }

    /// Look up a cached fingerprint. Returns a clone; `None` if absent or expired.
    pub fn get(&self, key: &FlowKey) -> Option<Ja4Fingerprint> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = entries.get(key)?;
        if entry.inserted_at.elapsed().is_ok_and(|d| d > self.ttl) {
            return None;
        }
        Some(entry.fingerprint.clone())
    }

    /// Insert a fingerprint. Evicts oldest entries if cache is full.
    pub fn insert(&self, key: FlowKey, fingerprint: Ja4Fingerprint) {
        let now = SystemTime::now();
        if let Some(persist) = self.persist.as_ref() {
            persist.save(&key, &fingerprint, now);
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.len() >= self.max_size {
            evict_expired_or_oldest(&mut entries, self.ttl, self.max_size);
        }
        entries.insert(
            key,
            CacheEntry {
                fingerprint,
                inserted_at: now,
            },
        );
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    /// Returns whether a persistence backend is wired to this cache.
    pub fn is_persistent(&self) -> bool {
        self.persist.is_some()
    }

    /// How many entries the cache holds before it evicts, as it was built.
    ///
    /// Read rather than restated, because a reader asking how full the cache
    /// is compares this against `len()` and two copies of the number drift.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_size
    }

    /// How long an entry stays before it expires, as the cache was built.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

fn evict_expired_or_oldest<T>(
    entries: &mut HashMap<FlowKey, CacheEntry<T>>,
    ttl: Duration,
    max_size: usize,
) {
    entries.retain(|_, entry| entry.inserted_at.elapsed().map_or(true, |d| d <= ttl));

    if entries.len() >= max_size
        && let Some(oldest_key) = entries
            .iter()
            .min_by_key(|(_, e)| e.inserted_at)
            .map(|(k, _)| k.clone())
    {
        entries.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hello() -> TlsClientHello {
        TlsClientHello {
            sni: Some("example.com".to_string()),
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            extension_types: vec![0x0000, 0x000A, 0x000D, 0x0010, 0x002B],
            supported_groups: vec![0x001D, 0x0017],
            signature_algorithms: vec![0x0403, 0x0804],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            supported_versions: vec![0x0304, 0x0303],
            session_id: None,
        }
    }

    /// The worked example of the JA4 technical details published by `FoxIO`:
    /// the value every JA4 database and feed uses for this client.
    #[test]
    fn ja4_matches_the_published_example() {
        let hello = TlsClientHello {
            sni: Some("example.com".to_string()),
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extension_types: vec![
                0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
                0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            supported_versions: vec![0x0304, 0x0303],
            session_id: None,
        };
        assert_eq!(
            compute_ja4(&hello).ja4,
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
    }

    #[test]
    fn ja4_signature_algorithm_order_matters() {
        let hello = make_hello();
        let mut swapped = make_hello();
        swapped.signature_algorithms.reverse();
        assert_ne!(compute_ja4(&hello).ja4_c, compute_ja4(&swapped).ja4_c);
    }

    #[test]
    fn ja4_version_is_the_highest_offered() {
        let mut hello = make_hello();
        hello.supported_versions = vec![0x0303, 0x0304];
        assert!(compute_section_a(&hello).starts_with("t13"));
    }

    #[test]
    fn ja4_empty_sections_are_zeros_and_no_signature_drops_the_underscore() {
        let mut hello = make_hello();
        hello.cipher_suites.clear();
        assert_eq!(compute_section_b(&hello), EMPTY_SECTION);
        hello.signature_algorithms.clear();
        assert_eq!(compute_section_c(&hello), sha256_12("000a,000d,002b"));
        hello.extension_types = vec![0x0000, 0x0010];
        assert_eq!(compute_section_c(&hello), EMPTY_SECTION);
    }

    #[test]
    fn ja4_alpn_that_is_not_alphanumeric_is_written_in_hex() {
        assert_eq!(alpn_hint(b"h2").as_deref(), Some("h2"));
        assert_eq!(alpn_hint(&[0xab, 0x01]).as_deref(), Some("a1"));
        assert_eq!(alpn_hint(b"").as_deref(), None);
    }

    #[test]
    fn ja4_section_a_format() {
        let hello = make_hello();
        let a = compute_section_a(&hello);
        // t (TCP) + 13 (TLS 1.3 via supported_versions) + d (domain) + 03 (3 ciphers) + 05 (5 extensions) + h2 (ALPN)
        assert_eq!(a, "t13d0305h2");
    }

    #[test]
    fn ja4_section_a_no_sni() {
        let mut hello = make_hello();
        hello.sni = None;
        let a = compute_section_a(&hello);
        assert!(a.contains('i'), "should use 'i' for absent SNI: {a}");
    }

    #[test]
    fn ja4_section_a_no_alpn() {
        let mut hello = make_hello();
        hello.alpn_protocols.clear();
        let a = compute_section_a(&hello);
        assert!(a.ends_with("00"), "should end with '00' for no ALPN: {a}");
    }

    #[test]
    fn ja4_section_a_no_supported_versions() {
        let mut hello = make_hello();
        hello.supported_versions.clear();
        let a = compute_section_a(&hello);
        // Falls back to handshake_version 0x0303 = TLS 1.2
        assert!(a.starts_with("t12"), "should show TLS 1.2: {a}");
    }

    #[test]
    fn ja4_section_b_sorted_and_hashed() {
        let hello = make_hello();
        let b = compute_section_b(&hello);
        assert_eq!(b.len(), 12, "section b should be 12 hex chars");
        // Verify deterministic
        assert_eq!(b, compute_section_b(&hello));
    }

    #[test]
    fn ja4_section_c_excludes_sni_and_alpn() {
        let hello = make_hello();
        let c = compute_section_c(&hello);
        assert_eq!(c.len(), 12, "section c should be 12 hex chars");
    }

    #[test]
    fn ja4_full_format() {
        let hello = make_hello();
        let fp = compute_ja4(&hello);
        // Format: {a}_{b}_{c}
        let parts: Vec<&str> = fp.ja4.split('_').collect();
        assert_eq!(
            parts.len(),
            3,
            "JA4 should have 3 underscore-separated parts"
        );
        assert_eq!(parts[0], fp.ja4_a);
        assert_eq!(parts[1], fp.ja4_b);
        assert_eq!(parts[2], fp.ja4_c);
        assert_eq!(fp.ja4_a, "t13d0305h2");
    }

    #[test]
    fn ja4_deterministic() {
        let hello = make_hello();
        let fp1 = compute_ja4(&hello);
        let fp2 = compute_ja4(&hello);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn ja4_different_ciphers_different_hash() {
        let hello1 = make_hello();
        let mut hello2 = make_hello();
        hello2.cipher_suites = vec![0x002F]; // different cipher
        assert_ne!(compute_ja4(&hello1).ja4_b, compute_ja4(&hello2).ja4_b);
    }

    #[test]
    fn ja4_cipher_order_independent() {
        let mut hello1 = make_hello();
        hello1.cipher_suites = vec![0x1301, 0x1302, 0x1303];
        let mut hello2 = make_hello();
        hello2.cipher_suites = vec![0x1303, 0x1301, 0x1302];
        // Section b sorts cipher suites, so order doesn't matter
        assert_eq!(compute_ja4(&hello1).ja4_b, compute_ja4(&hello2).ja4_b);
    }

    #[test]
    fn sha256_12_length() {
        let result = sha256_12("test input");
        assert_eq!(result.len(), 12);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn is_grease_in_tls_version_str() {
        assert_eq!(tls_version_str(0x0304), "13");
        assert_eq!(tls_version_str(0x0303), "12");
        assert_eq!(tls_version_str(0x0302), "11");
        assert_eq!(tls_version_str(0x0301), "10");
        assert_eq!(tls_version_str(0x0300), "00");
    }

    // ── Cache tests ──────────────────────────────────────────────────

    fn make_flow_key(port: u16) -> FlowKey {
        FlowKey {
            src_addr: [0x0A00_0001, 0, 0, 0],
            src_port: port,
            dst_addr: [0x0A00_0002, 0, 0, 0],
            dst_port: 443,
        }
    }

    #[test]
    fn cache_insert_and_get() {
        let cache = FingerprintCache::new(100, Duration::from_mins(5));
        let fp = compute_ja4(&make_hello());
        let key = make_flow_key(12345);
        cache.insert(key.clone(), fp.clone());
        assert_eq!(cache.get(&key), Some(fp));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_miss() {
        let cache = FingerprintCache::new(100, Duration::from_mins(5));
        assert!(cache.get(&make_flow_key(12345)).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_evicts_at_capacity() {
        let cache = FingerprintCache::new(2, Duration::from_mins(5));
        let fp = compute_ja4(&make_hello());
        cache.insert(make_flow_key(1), fp.clone());
        cache.insert(make_flow_key(2), fp.clone());
        cache.insert(make_flow_key(3), fp.clone());
        // Should have evicted one entry
        assert!(cache.len() <= 2);
    }

    #[test]
    fn cache_reports_the_ceiling_and_the_ttl_it_was_built_with() {
        let cache = FingerprintCache::new(64, Duration::from_secs(90));
        assert_eq!(cache.capacity(), 64);
        assert_eq!(cache.ttl(), Duration::from_secs(90));
    }
}
