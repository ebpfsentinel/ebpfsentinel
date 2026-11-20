//! Writing one section of the agent's own configuration file.
//!
//! The read half has always existed: `/api/v1/config` serves the running
//! configuration and `/api/v1/config/reload` re-reads the file. What was
//! missing is the middle - a way for an operator editing a section on a
//! screen to put it back, which meant every configuration screen in the
//! dashboard could copy a document and download it and do nothing with it.
//!
//! Three things make this safe to expose rather than merely possible:
//!
//! * It is off unless `agent.config_writes` is `allowed`, because an agent
//!   whose file is rendered by the Kubernetes operator has it rewritten at
//!   the next reconcile and a write accepted here would vanish silently.
//! * A masked value is never written back. The served configuration masks
//!   every secret as `***`, and a URL that may carry one as
//!   `scheme://host/***`, so a section round-tripped through a screen
//!   carries those strings where the secret was; writing them would replace
//!   the secret with asterisks. Wherever the submitted document holds a
//!   mask, the value already on disk is kept, and a list item is matched to
//!   the one on disk by its `id`, or its `name`, never by its position.
//! * The merged document is validated as a whole, by the checks start-up
//!   runs, before it replaces anything, and it lands by rename, so a
//!   rejected edit leaves the file exactly as it was and an accepted one is
//!   never half-written. Writes are taken one at a time, and the answer is
//!   the reload's own: a file the agent refuses to run is an error, and the
//!   settings that wait for a restart are named.
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::extract::{Path, State};
use infrastructure::config::{ConfigWrites, url_host_only};
use serde::Deserialize;
use serde_norway::Value;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::ops_handler::{ReloadResponse, load_and_validate, trigger_and_confirm_reload};
use super::state::AppState;

/// What the served configuration writes where a secret is.
const MASK: &str = "***";

/// What the served configuration ends a URL with when it dropped the path,
/// query and credentials, which is where a URL carries a secret.
const URL_MASK_TAIL: &str = "/***";

/// One configuration write at a time, from the file read to the reload's
/// answer: two writes merged into the same file read would each drop the
/// other's section, and a reload answer would describe whichever file won.
static WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Tells the staging files of one process apart.
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

/// One section of the configuration, as the editor holds it.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigSectionWrite {
    /// A YAML document rooted at the section's own key, exactly as the read
    /// route renders it, so the text an operator edited is the text that
    /// comes back.
    pub yaml: String,
}

/// The same rules the dashboard applies before a section name reaches a
/// lookup: a name is spliced into a path walk and echoed in errors.
fn valid_section(section: &str) -> bool {
    !section.is_empty()
        && section.len() <= 64
        && !section.starts_with('.')
        && !section.ends_with('.')
        && !section.contains("..")
        && section
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Walks a dotted section down a document.
fn at<'a>(document: &'a Value, section: &str) -> Option<&'a Value> {
    section
        .split('.')
        .try_fold(document, |value, key| value.get(key))
}

/// Replaces the value at a dotted section, creating the maps on the way.
fn put_at(document: &mut Value, section: &str, value: Value) -> Result<(), String> {
    let mut cursor = document;
    let keys: Vec<&str> = section.split('.').collect();
    let (last, parents) = keys.split_last().unwrap_or((&"", &[]));
    for key in parents {
        let Value::Mapping(map) = cursor else {
            return Err(format!("`{key}` is not a mapping"));
        };
        cursor = map
            .entry(Value::String((*key).to_string()))
            .or_insert_with(|| Value::Mapping(serde_norway::Mapping::new()));
    }
    match cursor {
        Value::Mapping(map) => {
            map.insert(Value::String((*last).to_string()), value);
            Ok(())
        }
        _ => Err(format!("`{last}` is not a mapping")),
    }
}

/// The submitted section, with every masked value taken from what is on
/// disk instead.
///
/// The mask is a string the served document carries in place of a secret,
/// so the rule is only ever about strings: anywhere the incoming value is
/// exactly `***`, the file wins, and anywhere it is a URL ending in `/***`,
/// the file's URL wins when its scheme and host are the ones shown.
///
/// A list item is paired with the item on disk that carries the same `id`,
/// or the same `name` when it has no `id`: an editor that reorders, inserts
/// or deletes items moves positions, and pairing by position would hand one
/// item's secret to another. An item with neither key, or whose key is not
/// unique on disk, has nothing behind it.
///
/// A mask with nothing behind it is refused rather than resolved to
/// something - writing `***` as a password and quietly dropping the field
/// are both ways of destroying a secret nobody asked to change.
fn keep_masked(incoming: Value, on_disk: Option<&Value>, path: &str) -> Result<Value, String> {
    match incoming {
        Value::String(ref text) if text == MASK => on_disk.cloned().ok_or_else(|| {
            format!("`{path}` is masked and the file holds no value there; write the value out")
        }),
        Value::String(ref text) if text.ends_with(URL_MASK_TAIL) => match on_disk {
            Some(Value::String(held)) if url_host_only(held) == *text => {
                Ok(Value::String(held.clone()))
            }
            _ => Err(format!(
                "`{path}` is a masked URL and the file holds no URL with that scheme and host \
                 there; write the URL out"
            )),
        },
        Value::Mapping(map) => {
            let mut merged = serde_norway::Mapping::new();
            for (key, value) in map {
                let held = on_disk.and_then(|v| v.get(&key));
                let below = match key.as_str() {
                    Some(name) if path.is_empty() => name.to_string(),
                    Some(name) => format!("{path}.{name}"),
                    None => path.to_string(),
                };
                merged.insert(key, keep_masked(value, held, &below)?);
            }
            Ok(Value::Mapping(merged))
        }
        Value::Sequence(items) => {
            let held = on_disk.and_then(|v| v.as_sequence());
            items
                .into_iter()
                .enumerate()
                .map(|(i, item)| {
                    let paired = held.and_then(|s| same_item(&item, s));
                    keep_masked(item, paired, &format!("{path}[{i}]"))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Sequence)
        }
        other => Ok(other),
    }
}

/// The key a list item is known by: its `id`, else its `name`, when that is
/// a string.
fn item_key(item: &Value) -> Option<(&'static str, &str)> {
    ["id", "name"]
        .into_iter()
        .find_map(|field| item.get(field).and_then(Value::as_str).map(|v| (field, v)))
}

/// The one item of `on_disk` known by the same key as `item`; `None` when
/// `item` has no key or the key names no item, or more than one.
fn same_item<'a>(item: &Value, on_disk: &'a [Value]) -> Option<&'a Value> {
    let (field, key) = item_key(item)?;
    let mut matching = on_disk
        .iter()
        .filter(|held| held.get(field).and_then(Value::as_str) == Some(key));
    let found = matching.next()?;
    matching.next().is_none().then_some(found)
}

/// A temporary file beside the target, so the rename that follows stays on
/// one filesystem and is therefore atomic.
fn staging_path(target: &FsPath) -> PathBuf {
    let name = target
        .file_name()
        .map_or_else(|| "config.yaml".to_string(), |n| n.to_string_lossy().into());
    let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    target.with_file_name(format!(".{name}.{}.{seq}.tmp", std::process::id()))
}

/// Write one section of the agent configuration file and reload.
#[utoipa::path(
    put, path = "/api/v1/config/{section}",
    tag = "Operations",
    params(
        ("section" = String, Path, description = "Configuration key, dotted for a nested one"),
    ),
    request_body = ConfigSectionWrite,
    responses(
        (status = 200, description = "Section written; `ok` once the agent runs it, `pending` while the reload is still in progress; `pending_restart` names what waits for a restart", body = ReloadResponse),
        (status = 400, description = "Malformed section, malformed YAML, a mask with no value behind it (`UNRESOLVED_MASK`), a configuration start-up would refuse (`INVALID_CONFIG`), or one the reload refused (`RELOAD_REFUSED`)", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Configuration writes are not enabled on this agent", body = ErrorBody),
        (status = 500, description = "The file could not be read or replaced", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn put_config_section(
    State(state): State<Arc<AppState>>,
    Path(section): Path<String>,
    Json(body): Json<ConfigSectionWrite>,
) -> Result<Json<ReloadResponse>, ApiError> {
    if !valid_section(&section) {
        return Err(ApiError::BadRequest {
            code: "INVALID_SECTION",
            message: "malformed section name".to_string(),
        });
    }
    if state.config.read().await.agent.config_writes != ConfigWrites::Allowed {
        return Err(ApiError::Forbidden {
            code: "CONFIG_WRITE_DISABLED",
            message: "configuration writes are refused on this agent \
                      (agent.config_writes)"
                .to_string(),
        });
    }
    let Some(path) = state.config_path.as_deref() else {
        return Err(ApiError::Forbidden {
            code: "CONFIG_WRITE_DISABLED",
            message: "this agent was not started from a configuration file".to_string(),
        });
    };
    let path = PathBuf::from(path);

    let submitted: Value =
        serde_norway::from_str(&body.yaml).map_err(|e| ApiError::BadRequest {
            code: "INVALID_YAML",
            message: format!("section is not valid YAML: {e}"),
        })?;
    let Some(incoming) = at(&submitted, &section) else {
        return Err(ApiError::BadRequest {
            code: "SECTION_MISSING",
            message: format!("the document does not carry `{section}`"),
        });
    };
    let incoming = incoming.clone();

    // Held until the reload has answered: the file read, the merge, the
    // replace and the verdict belong to this write alone.
    let _write = WRITE_LOCK.lock().await;
    let text = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| ApiError::Internal {
            message: format!("configuration file unreadable: {e}"),
        })?;
    let mut document: Value = serde_norway::from_str(&text).map_err(|e| ApiError::Internal {
        message: format!("configuration file is not valid YAML: {e}"),
    })?;

    let merged = keep_masked(incoming, at(&document, &section), &section).map_err(|message| {
        ApiError::BadRequest {
            code: "UNRESOLVED_MASK",
            message,
        }
    })?;
    put_at(&mut document, &section, merged).map_err(|message| ApiError::BadRequest {
        code: "INVALID_SECTION",
        message,
    })?;
    let rendered = serde_norway::to_string(&document).map_err(|e| ApiError::Internal {
        message: format!("merged configuration could not be written: {e}"),
    })?;

    write_validated(&path, rendered).await?;

    tracing::info!(section = %section, "agent configuration section written");
    Ok(Json(trigger_and_confirm_reload(&state).await?))
}

/// Stage, validate, and only then replace.
///
/// Validation is what start-up runs: `AgentConfig::load`, then every
/// conversion the agent refuses to start without. It runs on a blocking
/// thread because it parses and validates the whole document and a runtime
/// worker blocked on it is every request in flight blocked with it.
/// The staged file carries the permissions of the file it replaces, so a
/// configuration holding secrets does not widen to the process umask on the
/// way through - and it is set before validation rather than after, since
/// the loader refuses a world-readable configuration file outright.
async fn write_validated(path: &FsPath, rendered: String) -> Result<(), ApiError> {
    let staging = staging_path(path);
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt as _;
        tokio::fs::metadata(path)
            .await
            .map_or(0o600, |m| m.permissions().mode())
    };

    tokio::fs::write(&staging, rendered)
        .await
        .map_err(|e| ApiError::Internal {
            message: format!("configuration could not be staged: {e}"),
        })?;

    // Before validation rather than after: the loader refuses a configuration
    // file anyone can read, and a staged file inherits the process umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tokio::fs::set_permissions(&staging, std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|e| ApiError::Internal {
                message: format!("staged configuration could not be secured: {e}"),
            })?;
    }

    let candidate = staging.clone();
    let validated = tokio::task::spawn_blocking(move || load_and_validate(&candidate).map(|_| ()))
        .await
        .map_err(|e| ApiError::Internal {
            message: format!("config validation task failed: {e}"),
        })?;
    if let Err(e) = validated {
        let _ = tokio::fs::remove_file(&staging).await;
        return Err(ApiError::BadRequest {
            code: "INVALID_CONFIG",
            message: format!("configuration rejected: {e}"),
        });
    }

    tokio::fs::rename(&staging, path)
        .await
        .map_err(|e| ApiError::Internal {
            message: format!("configuration could not be replaced: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Value {
        serde_norway::from_str(text).expect("test fixture parses")
    }

    #[test]
    fn a_section_name_is_what_a_lookup_can_be_handed() {
        assert!(valid_section("agent"));
        assert!(valid_section("enterprise.ml_detection"));
        assert!(!valid_section(""));
        assert!(!valid_section(".agent"));
        assert!(!valid_section("agent."));
        assert!(!valid_section("agent..tls"));
        assert!(!valid_section("agent/tls"));
        assert!(!valid_section(&"a".repeat(65)));
    }

    #[test]
    fn a_dotted_section_is_created_on_the_way_down() {
        let mut document = yaml("agent:\n  interfaces: [eth0]\n");
        put_at(&mut document, "auth.jwt", yaml("issuer: here\n")).expect("the walk succeeds");
        assert_eq!(
            at(&document, "auth.jwt.issuer").and_then(Value::as_str),
            Some("here"),
        );
        assert_eq!(
            at(&document, "agent.interfaces")
                .and_then(Value::as_sequence)
                .map(Vec::len),
            Some(1),
            "the rest of the document is left alone",
        );
    }

    #[test]
    fn a_scalar_in_the_way_of_the_walk_is_refused() {
        let mut document = yaml("auth: off\n");
        put_at(&mut document, "auth.jwt.issuer", Value::from("here"))
            .expect_err("a scalar cannot hold a key");
    }

    /// The failure this route exists to avoid: the served document carries
    /// `***` where the secret is, so a section edited on a screen and sent
    /// back would write three asterisks over a real password.
    #[test]
    fn a_masked_value_is_taken_from_the_file_rather_than_written() {
        let on_disk = yaml("smtp:\n  host: mail\n  password: hunter2\n");
        let incoming = yaml("smtp:\n  host: relay\n  password: '***'\n");
        let merged = keep_masked(incoming, Some(&on_disk), "alerting").expect("nothing unresolved");
        assert_eq!(
            at(&merged, "smtp.password").and_then(Value::as_str),
            Some("hunter2"),
        );
        assert_eq!(
            at(&merged, "smtp.host").and_then(Value::as_str),
            Some("relay"),
            "what was actually edited still lands",
        );
    }

    fn keys_by_name(merged: &Value, list: &str) -> Vec<(String, String)> {
        merged
            .get(list)
            .and_then(Value::as_sequence)
            .expect("the list survives")
            .iter()
            .map(|entry| {
                let field = |name: &str| {
                    entry
                        .get(name)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                };
                (field("name"), field("key"))
            })
            .collect()
    }

    #[test]
    fn a_masked_value_in_a_list_is_paired_by_key_not_position() {
        let on_disk =
            yaml("api_keys:\n  - name: one\n    key: first\n  - name: two\n    key: second\n");
        // The editor reordered the list and inserted a key of its own.
        let incoming = yaml(
            "api_keys:\n  - name: new\n    key: fresh\n  - name: two\n    key: '***'\n  \
             - name: one\n    key: '***'\n",
        );
        let merged = keep_masked(incoming, Some(&on_disk), "auth").expect("nothing unresolved");
        assert_eq!(
            keys_by_name(&merged, "api_keys"),
            vec![
                ("new".to_string(), "fresh".to_string()),
                ("two".to_string(), "second".to_string()),
                ("one".to_string(), "first".to_string()),
            ],
            "each secret stays with the item that owns it"
        );
    }

    #[test]
    fn a_list_item_is_known_by_its_id_before_its_name() {
        let on_disk = yaml(
            "feeds:\n  - id: a\n    name: same\n    auth_header: 'Bearer A'\n  \
             - id: b\n    name: same\n    auth_header: 'Bearer B'\n",
        );
        let incoming = yaml(
            "feeds:\n  - id: b\n    name: same\n    auth_header: '***'\n  \
             - id: a\n    name: same\n    auth_header: '***'\n",
        );
        let merged =
            keep_masked(incoming, Some(&on_disk), "threatintel").expect("nothing unresolved");
        let headers: Vec<&str> = merged
            .get("feeds")
            .and_then(Value::as_sequence)
            .expect("the list survives")
            .iter()
            .filter_map(|feed| feed.get("auth_header").and_then(Value::as_str))
            .collect();
        assert_eq!(headers, vec!["Bearer B", "Bearer A"]);
    }

    /// Deleting the first item used to hand the second item the deleted
    /// one's secret, by position.
    #[test]
    fn a_deleted_item_takes_its_secret_with_it() {
        let on_disk =
            yaml("api_keys:\n  - name: one\n    key: first\n  - name: two\n    key: second\n");
        let incoming = yaml("api_keys:\n  - name: two\n    key: '***'\n");
        let merged = keep_masked(incoming, Some(&on_disk), "auth").expect("nothing unresolved");
        assert_eq!(
            keys_by_name(&merged, "api_keys"),
            vec![("two".to_string(), "second".to_string())]
        );
    }

    #[test]
    fn a_masked_item_with_no_key_is_refused() {
        let on_disk = yaml("tokens:\n  - secret: first\n");
        let incoming = yaml("tokens:\n  - secret: '***'\n");
        let refusal = keep_masked(incoming, Some(&on_disk), "auth")
            .expect_err("a keyless item is not paired by position");
        assert!(refusal.contains("auth.tokens[0].secret"), "{refusal}");
    }

    #[test]
    fn a_masked_item_whose_key_is_not_unique_on_disk_is_refused() {
        let on_disk =
            yaml("api_keys:\n  - name: dup\n    key: first\n  - name: dup\n    key: second\n");
        let incoming = yaml("api_keys:\n  - name: dup\n    key: '***'\n");
        keep_masked(incoming, Some(&on_disk), "auth")
            .expect_err("which secret is meant is unknown");
    }

    /// The served configuration shows a webhook or feed URL as
    /// `scheme://host/***`; sent back unchanged it is the URL on disk.
    #[test]
    fn a_masked_url_is_taken_from_the_file_when_scheme_and_host_match() {
        let on_disk = yaml(
            "routes:\n  - name: hook\n    webhook_url: 'https://hooks.example.com/T0/B0/s3cr3t?k=v'\n",
        );
        let incoming =
            yaml("routes:\n  - name: hook\n    webhook_url: 'https://hooks.example.com/***'\n");
        let merged =
            keep_masked(incoming, Some(&on_disk), "alerting").expect("the URL is restored");
        let url = merged
            .get("routes")
            .and_then(Value::as_sequence)
            .and_then(|routes| routes.first())
            .and_then(|route| route.get("webhook_url"))
            .and_then(Value::as_str);
        assert_eq!(url, Some("https://hooks.example.com/T0/B0/s3cr3t?k=v"));
    }

    #[test]
    fn a_masked_url_whose_host_changed_is_refused() {
        let on_disk = yaml("url: 'https://feeds.example.com/list?token=abc'\n");
        let incoming = yaml("url: 'https://elsewhere.example.com/***'\n");
        let refusal = keep_masked(incoming, Some(&on_disk), "threatintel")
            .expect_err("a masked URL cannot move to another host");
        assert!(refusal.contains("threatintel.url"), "{refusal}");

        let incoming = yaml("url: 'https://new.example.com/***'\n");
        keep_masked(incoming, None, "threatintel").expect_err("nothing on disk to restore");
    }

    /// A mask with nothing behind it is refused rather than resolved: both
    /// ways of guessing - writing the mask, or dropping the field - destroy a
    /// secret the operator never meant to touch.
    #[test]
    fn a_mask_the_file_cannot_answer_is_refused_by_name() {
        let on_disk = yaml("smtp:\n  host: mail\n");
        let incoming = yaml("smtp:\n  host: mail\n  password: '***'\n");
        let refusal = keep_masked(incoming, Some(&on_disk), "alerting")
            .expect_err("the mask resolves to nothing");
        assert!(
            refusal.contains("alerting.smtp.password"),
            "the refusal names the value: {refusal}",
        );
    }

    #[test]
    fn the_staging_file_is_a_sibling_so_the_rename_stays_atomic() {
        let staged = staging_path(FsPath::new("/etc/ebpfsentinel/agent.yaml"));
        assert_eq!(
            staged.parent(),
            FsPath::new("/etc/ebpfsentinel/agent.yaml").parent()
        );
        assert_ne!(staged, PathBuf::from("/etc/ebpfsentinel/agent.yaml"));
    }

    /// Two writes in flight never share a staging file, so neither can
    /// rename the other's half-written document into place.
    #[test]
    fn every_staging_file_has_a_name_of_its_own() {
        let target = FsPath::new("/etc/ebpfsentinel/agent.yaml");
        assert_ne!(staging_path(target), staging_path(target));
    }

    fn config_file(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, text).expect("the fixture is written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("the fixture is not world-readable");
        }
        (dir, path)
    }

    #[tokio::test]
    async fn a_valid_configuration_replaces_the_file() {
        let (_dir, path) = config_file("agent:\n  interfaces: [eth0]\n");
        write_validated(&path, "agent:\n  interfaces: [eth1]\n".to_string())
            .await
            .expect("the configuration is accepted");
        let written = std::fs::read_to_string(&path).expect("the file is readable");
        assert!(written.contains("eth1"));
    }

    #[tokio::test]
    async fn a_rejected_configuration_leaves_the_file_exactly_as_it_was() {
        let original = "agent:\n  interfaces: [eth0]\n";
        let (dir, path) = config_file(original);
        let refusal = write_validated(&path, "agent:\n  interfaces: []\n".to_string())
            .await
            .expect_err("an agent with no interface is not a configuration");
        assert!(matches!(refusal, ApiError::BadRequest { code, .. } if code == "INVALID_CONFIG"));
        assert_eq!(
            std::fs::read_to_string(&path).expect("the file is readable"),
            original,
        );
        let left_behind: Vec<_> = std::fs::read_dir(dir.path())
            .expect("the directory is readable")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name != "agent.yaml")
            .collect();
        assert!(left_behind.is_empty(), "the staged file is cleaned up");
    }

    /// The file parses, and start-up would still refuse it: a rule scoped
    /// to an interface the agent does not watch. Accepting it would leave an
    /// agent that runs the previous rules and a file the next start refuses.
    #[tokio::test]
    async fn a_configuration_start_up_refuses_is_refused_before_it_lands() {
        let original = "agent:\n  interfaces: [eth0]\n";
        let (_dir, path) = config_file(original);
        let refusal = write_validated(
            &path,
            "agent:\n  interfaces: [eth0]\nfirewall:\n  rules:\n    - id: deny-eth9\n      \
             priority: 10\n      action: deny\n      scope: { interface: eth9 }\n"
                .to_string(),
        )
        .await
        .expect_err("start-up refuses this rule");
        assert!(
            matches!(&refusal, ApiError::BadRequest { code, message }
                if *code == "INVALID_CONFIG" && message.contains("eth9")),
            "{refusal:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("the file is readable"),
            original,
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_replacement_keeps_the_permissions_of_what_it_replaced() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path) = config_file("agent:\n  interfaces: [eth0]\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("the fixture is narrowed");
        write_validated(&path, "agent:\n  interfaces: [eth1]\n".to_string())
            .await
            .expect("the configuration is accepted");
        let mode = std::fs::metadata(&path)
            .expect("the file is readable")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640);
    }
}
