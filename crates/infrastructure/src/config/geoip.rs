//! `GeoIP` database configuration: provisioning mode and refresh settings.

use serde::{Deserialize, Serialize};

use super::common::ConfigError;

/// `GeoIP` database provisioning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum GeoIpSource {
    /// `MaxMind` account: auto-download via account ID + license key.
    #[serde(rename = "maxmind_account")]
    MaxMindAccount {
        account_id: String,
        license_key: String,
        /// Edition IDs to download (default: `["GeoLite2-City", "GeoLite2-ASN"]`).
        #[serde(default = "default_editions")]
        edition_ids: Vec<String>,
    },
    /// Direct download URL (e.g. self-hosted mirror).
    #[serde(rename = "url")]
    Url {
        /// URL for the City database (.mmdb or .tar.gz).
        city_url: String,
        /// URL for the ASN database (.mmdb or .tar.gz).
        asn_url: Option<String>,
    },
    /// Local file path to pre-downloaded .mmdb files.
    #[serde(rename = "file")]
    File {
        /// Path to City .mmdb file.
        city_path: String,
        /// Path to ASN .mmdb file.
        asn_path: Option<String>,
    },
}

fn default_editions() -> Vec<String> {
    vec!["GeoLite2-City".to_string(), "GeoLite2-ASN".to_string()]
}

fn default_refresh_hours() -> u64 {
    24
}

fn default_db_dir() -> String {
    "/var/lib/ebpfsentinel/geoip".to_string()
}

/// Top-level `GeoIP` configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,

    pub source: GeoIpSource,

    /// Auto-refresh interval in hours (for `maxmind_account` and `url` modes).
    #[serde(default = "default_refresh_hours")]
    pub refresh_interval_hours: u64,

    /// Directory to store downloaded databases.
    #[serde(default = "default_db_dir")]
    pub database_dir: String,
}

impl GeoIpConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match &self.source {
            GeoIpSource::MaxMindAccount {
                account_id,
                license_key,
                edition_ids,
            } => {
                if account_id.is_empty() {
                    return Err(ConfigError::Validation {
                        field: "geoip.source.account_id".to_string(),
                        message: "account_id must not be empty".to_string(),
                    });
                }
                if license_key.is_empty() {
                    return Err(ConfigError::Validation {
                        field: "geoip.source.license_key".to_string(),
                        message: "license_key must not be empty".to_string(),
                    });
                }
                if edition_ids.is_empty() {
                    return Err(ConfigError::Validation {
                        field: "geoip.source.edition_ids".to_string(),
                        message: "edition_ids must not be empty".to_string(),
                    });
                }
            }
            GeoIpSource::Url { city_url, .. } => {
                if city_url.is_empty() {
                    return Err(ConfigError::Validation {
                        field: "geoip.source.city_url".to_string(),
                        message: "city_url must not be empty".to_string(),
                    });
                }
            }
            GeoIpSource::File { city_path, .. } => {
                if city_path.is_empty() {
                    return Err(ConfigError::Validation {
                        field: "geoip.source.city_path".to_string(),
                        message: "city_path must not be empty".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_file_mode() {
        let yaml = r"
enabled: true
source:
  mode: file
  city_path: /opt/geoip/GeoLite2-City.mmdb
  asn_path: /opt/geoip/GeoLite2-ASN.mmdb
refresh_interval_hours: 0
";
        let cfg: GeoIpConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert!(matches!(cfg.source, GeoIpSource::File { .. }));
        if let GeoIpSource::File {
            city_path,
            asn_path,
        } = &cfg.source
        {
            assert_eq!(city_path, "/opt/geoip/GeoLite2-City.mmdb");
            assert_eq!(asn_path.as_deref(), Some("/opt/geoip/GeoLite2-ASN.mmdb"));
        }
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn deserialize_url_mode() {
        let yaml = r#"
enabled: true
source:
  mode: url
  city_url: "https://mirror.example.com/GeoLite2-City.mmdb"
"#;
        let cfg: GeoIpConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(matches!(cfg.source, GeoIpSource::Url { .. }));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn deserialize_maxmind_account_mode() {
        let yaml = r#"
enabled: true
source:
  mode: maxmind_account
  account_id: "123456"
  license_key: "test-key"
"#;
        let cfg: GeoIpConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(matches!(cfg.source, GeoIpSource::MaxMindAccount { .. }));
        if let GeoIpSource::MaxMindAccount { edition_ids, .. } = &cfg.source {
            assert_eq!(edition_ids.len(), 2);
        }
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_city_path() {
        let cfg = GeoIpConfig {
            enabled: true,
            source: GeoIpSource::File {
                city_path: String::new(),
                asn_path: None,
            },
            refresh_interval_hours: 0,
            database_dir: "/tmp".to_string(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_account_id() {
        let cfg = GeoIpConfig {
            enabled: true,
            source: GeoIpSource::MaxMindAccount {
                account_id: String::new(),
                license_key: "key".to_string(),
                edition_ids: default_editions(),
            },
            refresh_interval_hours: 24,
            database_dir: "/tmp".to_string(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_city_url() {
        let cfg = GeoIpConfig {
            enabled: true,
            source: GeoIpSource::Url {
                city_url: String::new(),
                asn_url: None,
            },
            refresh_interval_hours: 24,
            database_dir: "/tmp".to_string(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn default_values() {
        assert_eq!(default_refresh_hours(), 24);
        assert_eq!(default_db_dir(), "/var/lib/ebpfsentinel/geoip");
        assert_eq!(default_editions().len(), 2);
    }
}
