//! Sign every built eBPF object: generate a loader per program, sign each
//! loader with the openssl command line, and write `<object>.loaders` and the
//! certificate the signatures verify against beside the objects.
//!
//! The key comes from `EBPFSENTINEL_LOADER_SIGNING_KEY` and
//! `EBPFSENTINEL_LOADER_SIGNING_CERT` (PEM paths). Without them the committed
//! test key under `crates/xtask/signing/` signs, which no release accepts: with
//! `EBPFSENTINEL_RELEASE_BUILD` set both variables are required and a
//! certificate equal to the test one is refused. OpenSSL stays a tool of the
//! build and never becomes a dependency of the code.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use adapters::ebpf::signed_loader::bundle::{self, BUNDLE_EXTENSION, Bundle};
use adapters::ebpf::signed_loader::generate;
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// Private key of the signing pair, PEM.
pub(crate) const KEY_ENV: &str = "EBPFSENTINEL_LOADER_SIGNING_KEY";
/// Certificate of the signing pair, PEM.
pub(crate) const CERT_ENV: &str = "EBPFSENTINEL_LOADER_SIGNING_CERT";
/// Set (to anything) by the release build.
pub(crate) const RELEASE_ENV: &str = "EBPFSENTINEL_RELEASE_BUILD";
/// The certificate the build writes beside the objects, DER, the name the
/// images copy it under.
pub(crate) const CERT_FILE: &str = "loader-signing.der";

/// A signing pair on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigningKey {
    pub(crate) key: PathBuf,
    pub(crate) cert: PathBuf,
}

/// The committed development pair.
fn test_key() -> SigningKey {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("signing");
    SigningKey {
        key: dir.join("test-loader-signing.key.pem"),
        cert: dir.join("test-loader-signing.crt.pem"),
    }
}

/// Which pair this build signs with, from the environment.
fn choose_key(key: Option<PathBuf>, cert: Option<PathBuf>, release: bool) -> Result<SigningKey> {
    match (key, cert) {
        (Some(key), Some(cert)) => Ok(SigningKey { key, cert }),
        (None, None) if !release => Ok(test_key()),
        (None, None) => {
            bail!("a release build signs with its own key: set {KEY_ENV} and {CERT_ENV}")
        }
        _ => bail!("{KEY_ENV} and {CERT_ENV} are set together or not at all"),
    }
}

/// Refuse a release build whose certificate is the committed test one.
pub(crate) fn refuse_test_cert(
    release: bool,
    cert_sha256: &[u8; 32],
    test_sha256: &[u8; 32],
) -> Result<()> {
    if release && cert_sha256 == test_sha256 {
        bail!(
            "a release build refuses the committed test key: its certificate is \
             trusted by no release"
        );
    }
    Ok(())
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn is_release() -> bool {
    std::env::var_os(RELEASE_ENV).is_some_and(|v| !v.is_empty())
}

/// Run openssl with `args`, feeding `input` on stdin, and return stdout.
fn openssl(args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run openssl: the signing step needs the openssl command line")?;
    let mut stdin = child.stdin.take().context("openssl stdin")?;
    let input = input.to_vec();
    // A writer thread, so a large input never waits on a full stdout pipe.
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().context("wait for openssl")?;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("openssl stdin writer panicked"))?
        .context("write openssl stdin")?;
    if !out.status.success() {
        bail!(
            "openssl {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// The certificate at `pem`, as DER.
fn cert_der(pem: &Path) -> Result<Vec<u8>> {
    let pem_text = pem.to_str().context("certificate path is not UTF-8")?;
    openssl(&["x509", "-in", pem_text, "-outform", "DER"], &[])
}

/// A detached CMS signature over `data`: no signed attributes, no
/// certificate inside, SHA-256, DER - the shape the kernel verifies a
/// program signature in.
fn sign(key: &SigningKey, data: &[u8]) -> Result<Vec<u8>> {
    let cert = key.cert.to_str().context("certificate path is not UTF-8")?;
    let inkey = key.key.to_str().context("key path is not UTF-8")?;
    openssl(
        &[
            "cms", "-sign", "-binary", "-noattr", "-nocerts", "-md", "sha256", "-outform", "DER",
            "-signer", cert, "-inkey", inkey,
        ],
        data,
    )
}

/// Sign every object of `objects` found in `dir`, with the key the
/// environment chooses.
pub(crate) fn sign_dir(dir: &Path, objects: &[&str]) -> Result<()> {
    let release = is_release();
    let key = choose_key(env_path(KEY_ENV), env_path(CERT_ENV), release)?;
    let der = cert_der(&key.cert)?;
    let cert_sha256: [u8; 32] = Sha256::digest(&der).into();
    let test_sha256: [u8; 32] = Sha256::digest(cert_der(&test_key().cert)?).into();
    refuse_test_cert(release, &cert_sha256, &test_sha256)?;
    if cert_sha256 == test_sha256 {
        println!("Signing eBPF loaders with the committed TEST key (no release trusts it)");
    }

    let mut signed = 0usize;
    for object in objects {
        let path = dir.join(object);
        let elf = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let generated = match generate::generate(&elf) {
            Ok(generated) => generated,
            Err(e) if !release => {
                println!("  {object}: no loaders ({e}), the object loads unsigned");
                continue;
            }
            Err(e) => bail!("generate the loaders of {object}: {e}"),
        };
        let signatures = generated
            .programs
            .iter()
            .map(|p| sign(&key, &p.loader))
            .collect::<Result<Vec<_>>>()
            .with_context(|| format!("sign the loaders of {object}"))?;
        signed += signatures.len();
        let encoded = bundle::encode(&Bundle {
            object: generated,
            cert_sha256,
            signatures,
        })
        .map_err(|e| anyhow::anyhow!("encode the loaders of {object}: {e}"))?;
        let out = dir.join(format!("{object}.{BUNDLE_EXTENSION}"));
        std::fs::write(&out, encoded).with_context(|| format!("write {}", out.display()))?;
    }

    let cert_out = dir.join(CERT_FILE);
    std::fs::write(&cert_out, &der).with_context(|| format!("write {}", cert_out.display()))?;
    println!(
        "Signed {signed} loaders; certificate sha256 {} at {}",
        hex(&cert_sha256),
        cert_out.display()
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_build_refuses_the_test_certificate() {
        let test = [7u8; 32];
        assert!(refuse_test_cert(true, &test, &test).is_err());
        assert!(refuse_test_cert(true, &[8u8; 32], &test).is_ok());
        assert!(refuse_test_cert(false, &test, &test).is_ok());
    }

    #[test]
    fn a_release_build_names_its_own_key() {
        assert!(choose_key(None, None, true).is_err());
        assert_eq!(choose_key(None, None, false).expect("dev"), test_key());
        let own = choose_key(Some("k.pem".into()), Some("c.pem".into()), true).expect("own");
        assert_eq!(own.key, PathBuf::from("k.pem"));
    }

    #[test]
    fn half_a_pair_is_refused() {
        assert!(choose_key(Some("k.pem".into()), None, false).is_err());
        assert!(choose_key(None, Some("c.pem".into()), true).is_err());
    }

    #[test]
    fn the_test_pair_is_committed() {
        let key = test_key();
        assert!(key.key.is_file(), "{}", key.key.display());
        assert!(key.cert.is_file(), "{}", key.cert.display());
    }

    #[test]
    fn a_digest_prints_as_lowercase_hex() {
        assert_eq!(hex(&[0x00, 0xab, 0x0f]), "00ab0f");
    }
}
