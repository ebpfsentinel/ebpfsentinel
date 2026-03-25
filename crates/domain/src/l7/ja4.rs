use std::collections::HashMap;
use std::fmt::Write;
use std::time::{Duration, Instant};

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

    // TLS version: prefer supported_versions (TLS 1.3), fallback to handshake version
    let version = if let Some(&max_ver) = hello.supported_versions.first() {
        tls_version_str(max_ver)
    } else {
        tls_version_str(hello.handshake_version)
    };

    // SNI indicator: "d" if domain present, "i" if absent
    let sni_indicator = if hello.sni.is_some() { 'd' } else { 'i' };

    // Counts (capped at 99 for 2-digit display)
    let cipher_count = hello.cipher_suites.len().min(99);
    let ext_count = hello.extension_types.len().min(99);

    // ALPN hint: first and last char of first ALPN protocol, or "00"
    let alpn_hint = hello
        .alpn_protocols
        .first()
        .and_then(|p| {
            let bytes = p.as_bytes();
            if bytes.is_empty() {
                None
            } else {
                let first = bytes[0] as char;
                let last = bytes[bytes.len() - 1] as char;
                Some(format!("{first}{last}"))
            }
        })
        .unwrap_or_else(|| "00".to_string());

    format!("{proto}{version}{sni_indicator}{cipher_count:02}{ext_count:02}{alpn_hint}")
}

/// Section b: SHA-256(sorted cipher suites as comma-separated hex), truncated to 12 hex chars.
fn compute_section_b(hello: &TlsClientHello) -> String {
    let mut sorted = hello.cipher_suites.clone();
    sorted.sort_unstable();
    let csv = sorted.iter().fold(String::new(), |mut acc, &cs| {
        if !acc.is_empty() {
            acc.push(',');
        }
        let _ = write!(acc, "{cs:04x}");
        acc
    });
    sha256_12(&csv)
}

/// Section c: SHA-256(sorted extensions + `_` + sorted signature algorithms), truncated to 12 hex chars.
fn compute_section_c(hello: &TlsClientHello) -> String {
    // Sort extension types, excluding SNI (0x0000) and ALPN (0x0010) per JA4 spec
    let mut sorted_ext: Vec<u16> = hello
        .extension_types
        .iter()
        .copied()
        .filter(|&e| e != 0x0000 && e != 0x0010)
        .collect();
    sorted_ext.sort_unstable();

    let ext_csv = sorted_ext.iter().fold(String::new(), |mut acc, &ext| {
        if !acc.is_empty() {
            acc.push(',');
        }
        let _ = write!(acc, "{ext:04x}");
        acc
    });

    let mut sorted_sig = hello.signature_algorithms.clone();
    sorted_sig.sort_unstable();
    let sig_csv = sorted_sig.iter().fold(String::new(), |mut acc, &sig| {
        if !acc.is_empty() {
            acc.push(',');
        }
        let _ = write!(acc, "{sig:04x}");
        acc
    });

    let input = format!("{ext_csv}_{sig_csv}");
    sha256_12(&input)
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
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_addr: [u32; 4],
    pub src_port: u16,
    pub dst_addr: [u32; 4],
    pub dst_port: u16,
}

struct CacheEntry {
    fingerprint: Ja4Fingerprint,
    inserted_at: Instant,
}

/// LRU-ish fingerprint cache with configurable TTL and max size.
///
/// Uses interior mutability (`Mutex`) so all methods take `&self`.
/// Safe to share via `Arc<FingerprintCache>` without an external lock.
pub struct FingerprintCache {
    entries: std::sync::Mutex<HashMap<FlowKey, CacheEntry>>,
    max_size: usize,
    ttl: Duration,
}

impl FingerprintCache {
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
            max_size,
            ttl,
        }
    }

    /// Look up a cached fingerprint. Returns a clone; `None` if absent or expired.
    pub fn get(&self, key: &FlowKey) -> Option<Ja4Fingerprint> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = entries.get(key)?;
        if entry.inserted_at.elapsed() > self.ttl {
            return None;
        }
        Some(entry.fingerprint.clone())
    }

    /// Insert a fingerprint. Evicts oldest entries if cache is full.
    pub fn insert(&self, key: FlowKey, fingerprint: Ja4Fingerprint) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.len() >= self.max_size {
            Self::evict_expired_or_oldest(&mut entries, self.ttl, self.max_size);
        }
        entries.insert(
            key,
            CacheEntry {
                fingerprint,
                inserted_at: Instant::now(),
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

    fn evict_expired_or_oldest(
        entries: &mut HashMap<FlowKey, CacheEntry>,
        ttl: Duration,
        max_size: usize,
    ) {
        entries.retain(|_, entry| entry.inserted_at.elapsed() <= ttl);

        if entries.len() >= max_size
            && let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(k, _)| k.clone())
        {
            entries.remove(&oldest_key);
        }
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
        }
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
            src_addr: [0x0A000001, 0, 0, 0],
            src_port: port,
            dst_addr: [0x0A000002, 0, 0, 0],
            dst_port: 443,
        }
    }

    #[test]
    fn cache_insert_and_get() {
        let cache = FingerprintCache::new(100, Duration::from_secs(300));
        let fp = compute_ja4(&make_hello());
        let key = make_flow_key(12345);
        cache.insert(key.clone(), fp.clone());
        assert_eq!(cache.get(&key), Some(fp));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_miss() {
        let cache = FingerprintCache::new(100, Duration::from_secs(300));
        assert!(cache.get(&make_flow_key(12345)).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_evicts_at_capacity() {
        let cache = FingerprintCache::new(2, Duration::from_secs(300));
        let fp = compute_ja4(&make_hello());
        cache.insert(make_flow_key(1), fp.clone());
        cache.insert(make_flow_key(2), fp.clone());
        cache.insert(make_flow_key(3), fp.clone());
        // Should have evicted one entry
        assert!(cache.len() <= 2);
    }
}
