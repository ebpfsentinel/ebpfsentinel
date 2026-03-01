use std::net::IpAddr;
use std::path::Path;

use domain::alias::entity::GeoIpInfo;
use maxminddb::Reader;
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
}

impl GeoIpPort for MaxMindGeoIpAdapter {
    fn lookup(&self, ip: &IpAddr) -> Option<GeoIpInfo> {
        let mut info = GeoIpInfo::default();
        let mut found = false;

        // City lookup
        if let Some(ref reader) = self.city_reader
            && let Ok(city) = reader.lookup::<maxminddb::geoip2::City>(*ip)
        {
            if let Some(ref country) = city.country {
                info.country_code = country.iso_code.map(String::from);
                info.country_name = country
                    .names
                    .as_ref()
                    .and_then(|n| n.get("en").map(|s| (*s).to_string()));
                found = true;
            }
            if let Some(ref city_data) = city.city {
                info.city = city_data
                    .names
                    .as_ref()
                    .and_then(|n| n.get("en").map(|s| (*s).to_string()));
                found = true;
            }
            if let Some(ref loc) = city.location {
                info.latitude = loc.latitude;
                info.longitude = loc.longitude;
            }
        }

        // ASN lookup
        if let Some(ref reader) = self.asn_reader
            && let Ok(asn) = reader.lookup::<maxminddb::geoip2::Asn>(*ip)
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
