//! The node directory through which a pod profile agent says which pods it
//! inspects inside, and the node agent reads it.
//!
//! One file per pod, named after the pod's uid and holding three numbers: the
//! inode of the network namespace the chain went on in, when it went on, and
//! when the pod agent last said it was still there. The pod agent rewrites
//! the file on every pass and removes it when it lets the pod go; the node
//! agent never writes here. Which of the two then reads a pod's link is
//! decided by [`domain::coverage::link_inspector`], so a file left behind by
//! a pod agent that went lapses on its own.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use domain::coverage::PodClaim;
use tracing::debug;

use super::pod_cgroups::pod_uid;

/// The claims directory, as either agent sees it.
#[derive(Debug, Clone)]
pub struct PodClaimsDir {
    dir: PathBuf,
}

impl PodClaimsDir {
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Say the chain is inside pod `uid`, in namespace `netns`, since
    /// `since_secs`, as of now. The file is written beside its place and
    /// renamed over it, so a reader never finds half of one.
    pub fn claim(&self, uid: &str, netns: u64, since_secs: u64) -> io::Result<()> {
        let path = self.path_of(uid)?;
        let staged = self.dir.join(format!(".{uid}.tmp"));
        std::fs::write(&staged, format!("{netns} {since_secs} {}\n", now_secs()))?;
        std::fs::rename(&staged, path)
    }

    /// Withdraw the claim on pod `uid`. One already gone is not an error.
    pub fn release(&self, uid: &str) -> io::Result<()> {
        match std::fs::remove_file(self.path_of(uid)?) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }

    /// Every claim the directory holds, by pod uid. A file that names no pod
    /// or does not parse is skipped rather than trusted.
    #[must_use]
    pub fn read(&self) -> HashMap<String, PodClaim> {
        let mut claims = HashMap::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return claims;
        };
        for entry in entries.flatten() {
            let Some(uid) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !names_a_pod(&uid) {
                continue;
            }
            if let Some(claim) = std::fs::read_to_string(entry.path())
                .ok()
                .and_then(|raw| parse(&raw))
            {
                claims.insert(uid, claim);
            } else {
                debug!(pod = %uid, "pod claims: a claim that does not parse is ignored");
            }
        }
        claims
    }

    fn path_of(&self, uid: &str) -> io::Result<PathBuf> {
        if !names_a_pod(uid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{uid:?} is not a pod uid"),
            ));
        }
        Ok(self.dir.join(uid))
    }

    /// The directory itself.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Whether `name` is a pod uid as the API writes it, so nothing else ever
/// becomes a path under the directory.
fn names_a_pod(name: &str) -> bool {
    pod_uid(&format!("pod{name}")).as_deref() == Some(name)
}

fn parse(raw: &str) -> Option<PodClaim> {
    let mut fields = raw.split_whitespace().map(str::parse::<u64>);
    let claim = PodClaim {
        netns: fields.next()?.ok()?,
        since_secs: fields.next()?.ok()?,
        refreshed_secs: fields.next()?.ok()?,
    };
    fields.next().is_none().then_some(claim)
}

/// Seconds since the Unix epoch, the clock both agents on a node share.
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const UID: &str = "6f1c2d3e-4a5b-4c6d-8e7f-0123456789ab";

    #[test]
    fn a_claim_written_is_read_back_and_a_release_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let claims = PodClaimsDir::new(dir.path());
        claims.claim(UID, 4_026_532_001, 1_000).unwrap();
        let read = claims.read();
        let claim = read[UID];
        assert_eq!(claim.netns, 4_026_532_001);
        assert_eq!(claim.since_secs, 1_000);
        assert!(claim.refreshed_secs >= now_secs().saturating_sub(5));
        claims.release(UID).unwrap();
        claims.release(UID).unwrap();
        assert!(claims.read().is_empty());
    }

    #[test]
    fn a_name_that_is_not_a_pod_uid_never_becomes_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let claims = PodClaimsDir::new(dir.path());
        for bad in [
            "../etc/passwd",
            "",
            "6f1c2d3e",
            "6f1c2d3e_4a5b_4c6d_8e7f_0123456789ab",
        ] {
            assert!(claims.claim(bad, 1, 1).is_err(), "{bad:?}");
            assert!(claims.release(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn stray_and_malformed_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes"), "1 2 3\n").unwrap();
        std::fs::write(dir.path().join(UID), "1 2\n").unwrap();
        std::fs::write(
            dir.path().join("7a2b3c4d-5e6f-4a1b-8c2d-0123456789cd"),
            "1 2 3 4\n",
        )
        .unwrap();
        assert!(PodClaimsDir::new(dir.path()).read().is_empty());
    }

    #[test]
    fn a_missing_directory_holds_no_claim() {
        assert!(PodClaimsDir::new("/nonexistent/claims").read().is_empty());
    }
}
