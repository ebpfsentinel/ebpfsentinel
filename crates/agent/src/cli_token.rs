//! Where the CLI finds a credential when nobody handed it one.
//!
//! The control plane authenticates by default, and with no method configured
//! the agent draws a key for itself and keeps it in a file only root can read.
//! A command run on the same host can read that file, so `ebpfsentinel-agent
//! status` keeps working the way it always did rather than answering 401 and
//! asking the operator to paste a key the agent already wrote down.
//!
//! `--token` and `EBPFSENTINEL_TOKEN` win, because a key named there is the
//! one the caller means. Nothing here fails a command: a missing or
//! unreadable file leaves the request unauthenticated and the API answers for
//! itself.

use std::fs;

use adapters::auth::bootstrap_key::DEFAULT_BOOTSTRAP_KEY_PATH;

/// The one field this reads out of the configuration file.
#[derive(serde::Deserialize)]
struct AuthPath {
    auth: Option<AuthSection>,
}

#[derive(serde::Deserialize)]
struct AuthSection {
    bootstrap_key_path: Option<String>,
}

/// Read the key the agent drew for itself, if there is one to read.
///
/// `config_path` is the file the command was pointed at; the key's location is
/// `auth.bootstrap_key_path` in it, and the built-in default where the file
/// says nothing or cannot be read at all.
pub fn from_bootstrap_key_file(config_path: &str) -> Option<String> {
    let path = key_path(config_path);
    if path.is_empty() {
        return None;
    }
    let key = fs::read_to_string(path).ok()?;
    let key = key.trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

/// Where the configuration says the generated key lives.
fn key_path(config_path: &str) -> String {
    let Ok(text) = fs::read_to_string(config_path) else {
        return DEFAULT_BOOTSTRAP_KEY_PATH.to_string();
    };
    match serde_norway::from_str::<AuthPath>(&text) {
        Ok(parsed) => parsed
            .auth
            .and_then(|a| a.bootstrap_key_path)
            .unwrap_or_else(|| DEFAULT_BOOTSTRAP_KEY_PATH.to_string()),
        Err(_) => DEFAULT_BOOTSTRAP_KEY_PATH.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write as _;

    fn write(dir: &std::path::Path, name: &str, body: &str) -> String {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn the_configured_path_is_where_the_key_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let key = write(dir.path(), "api-key", "sk-abc\n");
        let cfg = write(
            dir.path(),
            "config.yaml",
            &format!("auth:\n  bootstrap_key_path: {key}\n"),
        );
        assert_eq!(from_bootstrap_key_file(&cfg).as_deref(), Some("sk-abc"));
    }

    #[test]
    fn a_configuration_refusing_the_generated_key_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write(
            dir.path(),
            "config.yaml",
            "auth:\n  bootstrap_key_path: \"\"\n",
        );
        assert!(from_bootstrap_key_file(&cfg).is_none());
    }

    #[test]
    fn an_unreadable_configuration_falls_back_to_the_default_path() {
        assert_eq!(
            key_path("/nonexistent/ebpfsentinel.yaml"),
            DEFAULT_BOOTSTRAP_KEY_PATH
        );
    }

    #[test]
    fn a_missing_key_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write(
            dir.path(),
            "config.yaml",
            &format!(
                "auth:\n  bootstrap_key_path: {}/absent\n",
                dir.path().display()
            ),
        );
        assert!(from_bootstrap_key_file(&cfg).is_none());
    }

    #[test]
    fn a_configuration_naming_no_auth_section_uses_the_default_path() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write(dir.path(), "config.yaml", "agent:\n  interfaces: [eth0]\n");
        assert_eq!(key_path(&cfg), DEFAULT_BOOTSTRAP_KEY_PATH);
    }
}
