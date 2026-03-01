use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use domain::alias::entity::GeoIpInfo;
use domain::firewall::entity::IpNetwork;
use maxminddb::{Reader, WithinOptions};
use ports::secondary::geoip_port::GeoIpPort;
use tracing::{info, warn};

/// `GeoIP` adapter backed by `MaxMind` `.mmdb` database files.
///
/// Supports separate City and ASN databases. Lookups are in-memory
/// and lock-free (the `Reader` uses `mmap` or `Vec<u8>` internally).
pub struct MaxMindGeoIpAdapter {
    city_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
}

impl MaxMindGeoIpAdapter {
    /// Load from local .mmdb files.
    pub fn from_files(city_path: &Path, asn_path: Option<&Path>) -> anyhow::Result<Self> {
        let city_reader = if city_path.exists() {
            let reader = Reader::open_readfile(city_path)?;
            info!(path = %city_path.display(), "GeoIP City database loaded");
            Some(reader)
        } else {
            warn!(path = %city_path.display(), "GeoIP City database file not found");
            None
        };

        let asn_reader = if let Some(path) = asn_path {
            if path.exists() {
                let reader = Reader::open_readfile(path)?;
                info!(path = %path.display(), "GeoIP ASN database loaded");
                Some(reader)
            } else {
                warn!(path = %path.display(), "GeoIP ASN database file not found");
                None
            }
        } else {
            None
        };

        Ok(Self {
            city_reader,
            asn_reader,
        })
    }

    /// Download from `MaxMind` API, then load.
    pub async fn from_maxmind_account(
        account_id: &str,
        license_key: &str,
        edition_ids: &[String],
        db_dir: &Path,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(db_dir)?;

        let client = reqwest::Client::new();
        let mut city_path = None;
        let mut asn_path = None;

        for edition in edition_ids {
            let url = format!(
                "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
            );
            let dest = db_dir.join(format!("{edition}.mmdb"));

            info!(edition, url = %url, "downloading MaxMind database");

            let response = client
                .get(&url)
                .basic_auth(account_id, Some(license_key))
                .send()
                .await?;

            if !response.status().is_success() {
                anyhow::bail!(
                    "MaxMind download failed for {edition}: HTTP {}",
                    response.status()
                );
            }

            let bytes = response.bytes().await?;

            // Try to extract .mmdb from tar.gz, or write directly if it's already mmdb
            let mmdb_bytes = extract_mmdb_from_targz(&bytes).unwrap_or_else(|| bytes.to_vec());
            std::fs::write(&dest, &mmdb_bytes)?;
            info!(edition, path = %dest.display(), "MaxMind database saved");

            if edition.contains("City") {
                city_path = Some(dest);
            } else if edition.contains("ASN") {
                asn_path = Some(dest);
            }
        }

        let city = city_path.as_deref().unwrap_or(Path::new(""));
        Self::from_files(city, asn_path.as_deref())
    }

    /// Download from arbitrary URLs, then load.
    pub async fn from_urls(
        city_url: &str,
        asn_url: Option<&str>,
        db_dir: &Path,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(db_dir)?;
        let client = reqwest::Client::new();

        let city_path = db_dir.join("city.mmdb");
        download_mmdb(&client, city_url, &city_path).await?;

        let asn_path = if let Some(url) = asn_url {
            let path = db_dir.join("asn.mmdb");
            download_mmdb(&client, url, &path).await?;
            Some(path)
        } else {
            None
        };

        Self::from_files(&city_path, asn_path.as_deref())
    }

    /// Reload databases from disk (called after refresh download).
    pub fn reload(&mut self, city_path: &Path, asn_path: Option<&Path>) -> anyhow::Result<()> {
        if city_path.exists() {
            self.city_reader = Some(Reader::open_readfile(city_path)?);
            info!(path = %city_path.display(), "GeoIP City database reloaded");
        }
        if let Some(path) = asn_path
            && path.exists()
        {
            self.asn_reader = Some(Reader::open_readfile(path)?);
            info!(path = %path.display(), "GeoIP ASN database reloaded");
        }
        Ok(())
    }

    /// Extract all CIDR networks from the City database for the given ISO country codes.
    ///
    /// Iterates all IPv4 and IPv6 networks in the database and returns those whose
    /// country ISO code matches one of the provided codes. The returned
    /// `IpNetwork` values can be converted to LPM Trie entries for eBPF maps.
    pub fn networks_by_country(&self, country_codes: &[String]) -> Vec<IpNetwork> {
        let Some(ref reader) = self.city_reader else {
            return Vec::new();
        };
        let codes: HashSet<&str> = country_codes.iter().map(String::as_str).collect();
        let mut result = Vec::new();
        let opts = WithinOptions::default().skip_empty_values();

        // Iterate all IPv4 networks
        if let Ok(iter) = reader.within(
            ipnetwork::IpNetwork::V4("0.0.0.0/0".parse().unwrap()),
            opts,
        ) {
            for lookup_result in iter.flatten() {
                if let Ok(Some(city)) = lookup_result.decode::<maxminddb::geoip2::City>()
                    && let Some(iso) = city.country.iso_code
                    && codes.contains(iso)
                    && let Ok(net) = lookup_result.network()
                    && let ipnetwork::IpNetwork::V4(net) = net
                {
                    result.push(IpNetwork::V4 {
                        addr: u32::from(net.ip()),
                        prefix_len: net.prefix(),
                    });
                }
            }
        }

        // Iterate all IPv6 networks
        if let Ok(iter) = reader.within(
            ipnetwork::IpNetwork::V6("::/0".parse().unwrap()),
            opts,
        ) {
            for lookup_result in iter.flatten() {
                if let Ok(Some(city)) = lookup_result.decode::<maxminddb::geoip2::City>()
                    && let Some(iso) = city.country.iso_code
                    && codes.contains(iso)
                    && let Ok(net) = lookup_result.network()
                    && let ipnetwork::IpNetwork::V6(net) = net
                {
                    result.push(IpNetwork::V6 {
                        addr: net.ip().octets(),
                        prefix_len: net.prefix(),
                    });
                }
            }
        }

        info!(
            codes = ?country_codes,
            v4 = result.iter().filter(|n| matches!(n, IpNetwork::V4 { .. })).count(),
            v6 = result.iter().filter(|n| matches!(n, IpNetwork::V6 { .. })).count(),
            "GeoIP networks extracted"
        );
        result
    }
}

impl GeoIpPort for MaxMindGeoIpAdapter {
    fn lookup(&self, ip: &IpAddr) -> Option<GeoIpInfo> {
        let mut info = GeoIpInfo::default();
        let mut found = false;

        // City lookup
        if let Some(ref reader) = self.city_reader
            && let Ok(result) = reader.lookup(*ip)
            && let Ok(Some(city)) = result.decode::<maxminddb::geoip2::City>()
        {
            let country = &city.country;
            if country.iso_code.is_some() {
                info.country_code = country.iso_code.map(String::from);
                info.country_name = country.names.english.map(ToString::to_string);
                found = true;
            }
            let city_data = &city.city;
            if city_data.geoname_id.is_some() {
                info.city = city_data.names.english.map(ToString::to_string);
                found = true;
            }
            let loc = &city.location;
            info.latitude = loc.latitude;
            info.longitude = loc.longitude;
        }

        // ASN lookup
        if let Some(ref reader) = self.asn_reader
            && let Ok(result) = reader.lookup(*ip)
            && let Ok(Some(asn)) = result.decode::<maxminddb::geoip2::Asn>()
        {
            info.asn = asn.autonomous_system_number;
            info.as_org = asn.autonomous_system_organization.map(String::from);
            found = true;
        }

        if found { Some(info) } else { None }
    }

    fn is_ready(&self) -> bool {
        self.city_reader.is_some()
    }
}

async fn download_mmdb(client: &reqwest::Client, url: &str, dest: &Path) -> anyhow::Result<()> {
    info!(url, path = %dest.display(), "downloading GeoIP database");

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("GeoIP download failed: HTTP {}", response.status());
    }

    let bytes = response.bytes().await?;
    let mmdb_bytes = extract_mmdb_from_targz(&bytes).unwrap_or_else(|| bytes.to_vec());
    std::fs::write(dest, &mmdb_bytes)?;
    info!(path = %dest.display(), "GeoIP database saved");
    Ok(())
}

/// Try to extract a .mmdb file from a tar.gz archive.
/// Returns `None` if the data doesn't appear to be a valid tar.gz.
fn extract_mmdb_from_targz(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;

    // Check gzip magic bytes
    if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
        return None;
    }

    let decoder = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    let entries = archive.entries().ok()?;
    for entry_result in entries {
        let mut entry = entry_result.ok()?;
        let path = entry.path().ok()?;
        if path.extension().is_some_and(|ext| ext == "mmdb") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).ok()?;
            return Some(buf);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_adapter_is_not_ready() {
        let adapter = MaxMindGeoIpAdapter {
            city_reader: None,
            asn_reader: None,
        };
        assert!(!adapter.is_ready());
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(adapter.lookup(&ip).is_none());
    }

    #[test]
    fn from_files_missing_path() {
        let result = MaxMindGeoIpAdapter::from_files(
            Path::new("/nonexistent/city.mmdb"),
            Some(Path::new("/nonexistent/asn.mmdb")),
        );
        // Should succeed but with None readers (graceful degradation)
        let adapter = result.unwrap();
        assert!(!adapter.is_ready());
    }

    #[test]
    fn extract_mmdb_from_non_gzip() {
        let data = b"not a gzip file";
        assert!(extract_mmdb_from_targz(data).is_none());
    }
}
