use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;

use domain::alias::entity::GeoIpInfo;
use domain::firewall::entity::IpNetwork;
use maxminddb::{Reader, WithinOptions};
use ports::secondary::geoip_port::GeoIpPort;
use ports::secondary::metrics_port::MetricsPort;
use tracing::{info, warn};

/// `GeoIP` adapter backed by `MaxMind` `.mmdb` database files.
///
/// Supports separate City and ASN databases. Lookups are in-memory and
/// lock-free; a refresh swaps a whole reader in, so a lookup sees either the
/// database before it or the one after, never half of each.
pub struct MaxMindGeoIpAdapter {
    city_reader: ArcSwapOption<Reader<Vec<u8>>>,
    asn_reader: ArcSwapOption<Reader<Vec<u8>>>,
    metrics: Option<Arc<dyn MetricsPort>>,
}

/// Where a download put the databases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoIpPaths {
    pub city: PathBuf,
    pub asn: Option<PathBuf>,
}

/// Where the databases come from when the agent fetches them itself.
#[derive(Debug, Clone)]
pub enum GeoIpDownload {
    /// The `MaxMind` download service, one archive per edition.
    MaxMindAccount {
        account_id: String,
        license_key: String,
        edition_ids: Vec<String>,
    },
    /// A mirror the operator runs.
    Urls {
        city_url: String,
        asn_url: Option<String>,
    },
}

impl GeoIpDownload {
    /// The files this source writes into `db_dir`, whether or not they exist
    /// yet: what a previous run left there is served until the next download.
    #[must_use]
    pub fn paths(&self, db_dir: &Path) -> GeoIpPaths {
        match self {
            Self::MaxMindAccount { edition_ids, .. } => {
                let file = |e: &String| db_dir.join(format!("{e}.mmdb"));
                GeoIpPaths {
                    city: edition_ids
                        .iter()
                        .find(|e| e.contains("City") || e.contains("Country"))
                        .map_or_else(|| db_dir.join("city.mmdb"), file),
                    asn: edition_ids.iter().find(|e| e.contains("ASN")).map(file),
                }
            }
            Self::Urls { asn_url, .. } => GeoIpPaths {
                city: db_dir.join("city.mmdb"),
                asn: asn_url.as_ref().map(|_| db_dir.join("asn.mmdb")),
            },
        }
    }

    /// Download every database into `db_dir`.
    ///
    /// A file is replaced only by one that opens as a database, written
    /// beside it and renamed over it, so a failed or truncated download
    /// leaves the previous file in place.
    ///
    /// # Errors
    ///
    /// The first database that could not be fetched or did not open.
    pub async fn fetch(&self, db_dir: &Path) -> anyhow::Result<GeoIpPaths> {
        tokio::fs::create_dir_all(db_dir).await?;
        let client = reqwest::Client::builder()
            .timeout(DOWNLOAD_TIMEOUT)
            .build()?;
        let paths = self.paths(db_dir);
        match self {
            Self::MaxMindAccount {
                account_id,
                license_key,
                edition_ids,
            } => {
                for edition in edition_ids {
                    let url = format!(
                        "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
                    );
                    info!(edition, "downloading MaxMind database");
                    let request = client.get(&url).basic_auth(account_id, Some(license_key));
                    fetch_into(request, &db_dir.join(format!("{edition}.mmdb"))).await?;
                }
            }
            Self::Urls { city_url, asn_url } => {
                fetch_into(client.get(city_url), &paths.city).await?;
                if let (Some(url), Some(path)) = (asn_url, &paths.asn) {
                    fetch_into(client.get(url), path).await?;
                }
            }
        }
        Ok(paths)
    }
}

/// How long one database download may take.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

impl MaxMindGeoIpAdapter {
    /// Load from local .mmdb files. A file that does not exist leaves its
    /// database empty; one that exists and does not open is an error.
    ///
    /// # Errors
    ///
    /// A file that exists and is not a database.
    pub fn from_files(city_path: &Path, asn_path: Option<&Path>) -> anyhow::Result<Self> {
        let adapter = Self {
            city_reader: ArcSwapOption::empty(),
            asn_reader: ArcSwapOption::empty(),
            metrics: None,
        };
        if !city_path.exists() {
            warn!(path = %city_path.display(), "GeoIP City database file not found");
        }
        if let Some(path) = asn_path
            && !path.exists()
        {
            warn!(path = %path.display(), "GeoIP ASN database file not found");
        }
        adapter.reload(city_path, asn_path)?;
        Ok(adapter)
    }

    /// Attach a metrics sink so each lookup records a hit/miss counter.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn MetricsPort>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Reopen the databases from disk, after a download replaced them. A
    /// file that is absent keeps the database already open.
    ///
    /// # Errors
    ///
    /// A file that exists and is not a database; nothing is swapped then.
    pub fn reload(&self, city_path: &Path, asn_path: Option<&Path>) -> anyhow::Result<()> {
        let city = open_if_present(city_path)?;
        let asn = match asn_path {
            Some(path) => open_if_present(path)?,
            None => None,
        };
        if let Some(reader) = city {
            self.city_reader.store(Some(Arc::new(reader)));
            info!(path = %city_path.display(), "GeoIP City database loaded");
        }
        if let (Some(reader), Some(path)) = (asn, asn_path) {
            self.asn_reader.store(Some(Arc::new(reader)));
            info!(path = %path.display(), "GeoIP ASN database loaded");
        }
        Ok(())
    }

    /// Extract all CIDR networks from the City database for the given ISO country codes.
    ///
    /// Iterates all IPv4 and IPv6 networks in the database and returns those whose
    /// country ISO code matches one of the provided codes. The returned
    /// `IpNetwork` values can be converted to LPM Trie entries for eBPF maps.
    pub fn networks_by_country(&self, country_codes: &[String]) -> Vec<IpNetwork> {
        let Some(reader) = self.city_reader.load_full() else {
            return Vec::new();
        };
        let codes: HashSet<&str> = country_codes.iter().map(String::as_str).collect();
        let mut result = Vec::new();
        let opts = WithinOptions::default().skip_empty_values();

        // Iterate all IPv4 networks
        if let Ok(iter) = reader.within(
            ipnetwork::IpNetwork::V4("0.0.0.0/0".parse().expect("literal network")),
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
            ipnetwork::IpNetwork::V6("::/0".parse().expect("literal network")),
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

    /// Extract all CIDR networks from the ASN database for the given AS numbers.
    pub fn networks_by_asn(&self, asn_numbers: &[u32]) -> Vec<IpNetwork> {
        let Some(reader) = self.asn_reader.load_full() else {
            return Vec::new();
        };
        let asns: HashSet<u32> = asn_numbers.iter().copied().collect();
        let mut result = Vec::new();
        let opts = WithinOptions::default().skip_empty_values();

        if let Ok(iter) = reader.within(
            ipnetwork::IpNetwork::V4("0.0.0.0/0".parse().expect("literal network")),
            opts,
        ) {
            for lookup_result in iter.flatten() {
                if let Ok(Some(asn_record)) = lookup_result.decode::<maxminddb::geoip2::Asn>()
                    && let Some(asn_num) = asn_record.autonomous_system_number
                    && asns.contains(&asn_num)
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

        if let Ok(iter) = reader.within(
            ipnetwork::IpNetwork::V6("::/0".parse().expect("literal network")),
            opts,
        ) {
            for lookup_result in iter.flatten() {
                if let Ok(Some(asn_record)) = lookup_result.decode::<maxminddb::geoip2::Asn>()
                    && let Some(asn_num) = asn_record.autonomous_system_number
                    && asns.contains(&asn_num)
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
            asns = ?asn_numbers,
            v4 = result.iter().filter(|n| matches!(n, IpNetwork::V4 { .. })).count(),
            v6 = result.iter().filter(|n| matches!(n, IpNetwork::V6 { .. })).count(),
            "BGP ASN networks extracted"
        );
        result
    }
}

impl GeoIpPort for MaxMindGeoIpAdapter {
    fn lookup(&self, ip: &IpAddr) -> Option<GeoIpInfo> {
        let mut info = GeoIpInfo::default();
        let mut found = false;

        // City lookup
        if let Some(reader) = self.city_reader.load().as_deref()
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
        if let Some(reader) = self.asn_reader.load().as_deref()
            && let Ok(result) = reader.lookup(*ip)
            && let Ok(Some(asn)) = result.decode::<maxminddb::geoip2::Asn>()
        {
            info.asn = asn.autonomous_system_number;
            info.as_org = asn.autonomous_system_organization.map(String::from);
            found = true;
        }

        if let Some(ref metrics) = self.metrics {
            metrics.record_geoip_lookup(found);
        }

        if found { Some(info) } else { None }
    }

    fn is_ready(&self) -> bool {
        self.city_reader.load().is_some()
    }
}

fn open_if_present(path: &Path) -> anyhow::Result<Option<Reader<Vec<u8>>>> {
    if !path.exists() {
        return Ok(None);
    }
    Reader::open_readfile(path)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("{} is not a GeoIP database: {e}", path.display()))
}

async fn fetch_into(request: reqwest::RequestBuilder, dest: &Path) -> anyhow::Result<()> {
    let response = request.send().await?;
    if !response.status().is_success() {
        anyhow::bail!(
            "GeoIP download for {} failed: HTTP {}",
            dest.display(),
            response.status()
        );
    }
    let bytes = response.bytes().await?;
    let mmdb = extract_mmdb_from_targz(&bytes).unwrap_or_else(|| bytes.to_vec());
    Reader::from_source(mmdb.as_slice()).map_err(|e| {
        anyhow::anyhow!(
            "download for {} is not a GeoIP database: {e}",
            dest.display()
        )
    })?;
    let partial = dest.with_extension("mmdb.partial");
    tokio::fs::write(&partial, &mmdb).await?;
    tokio::fs::rename(&partial, dest).await?;
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
            city_reader: ArcSwapOption::empty(),
            asn_reader: ArcSwapOption::empty(),
            metrics: None,
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

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name);
        std::fs::read(path).expect("fixture database")
    }

    /// Answer every request on a local port with `body`, once per connection.
    async fn serve(body: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        format!("http://{addr}/db")
    }

    #[tokio::test]
    async fn a_url_source_downloads_and_a_refresh_swaps_the_database_in() {
        let dir = tempfile::tempdir().unwrap();
        let download = GeoIpDownload::Urls {
            city_url: serve(fixture("GeoLite2-City.mmdb")).await,
            asn_url: Some(serve(fixture("GeoLite2-ASN.mmdb")).await),
        };
        let paths = download.fetch(dir.path()).await.unwrap();
        assert_eq!(paths, download.paths(dir.path()));
        assert!(paths.city.exists());

        let adapter =
            MaxMindGeoIpAdapter::from_files(Path::new("/nonexistent/city.mmdb"), None).unwrap();
        assert!(!adapter.is_ready());
        adapter.reload(&paths.city, paths.asn.as_deref()).unwrap();
        assert!(adapter.is_ready());
    }

    #[tokio::test]
    async fn a_download_that_is_not_a_database_leaves_the_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let good = GeoIpDownload::Urls {
            city_url: serve(fixture("GeoLite2-City.mmdb")).await,
            asn_url: None,
        };
        let paths = good.fetch(dir.path()).await.unwrap();
        let before = std::fs::read(&paths.city).unwrap();

        let bad = GeoIpDownload::Urls {
            city_url: serve(b"<html>maintenance</html>".to_vec()).await,
            asn_url: None,
        };
        assert!(bad.fetch(dir.path()).await.is_err());
        assert_eq!(std::fs::read(&paths.city).unwrap(), before);
    }
}
