//! The file the build writes beside each object, `<object>.loaders`: every
//! program's loader, its metadata and its signature, and which object and
//! which certificate they belong to. Little-endian, length-prefixed, read
//! whole; anything malformed is refused and the object loads unsigned.

use super::generate::{GeneratedObject, GeneratedProgram};

/// The first eight bytes of a bundle, version included.
const MAGIC: &[u8; 8] = b"EBSLDR01";

/// The extension the bundle carries beside its object.
pub const BUNDLE_EXTENSION: &str = "loaders";

/// A generated object with a signature per loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// What the generator made.
    pub object: GeneratedObject,
    /// SHA-256 of the DER certificate the signatures verify against.
    pub cert_sha256: [u8; 32],
    /// One detached CMS signature per program, in program order.
    pub signatures: Vec<Vec<u8>>,
}

/// Encode `bundle`.
///
/// # Errors
///
/// A count or a length does not fit its prefix, or the signatures do not
/// match the programs one for one.
pub fn encode(bundle: &Bundle) -> Result<Vec<u8>, String> {
    if bundle.signatures.len() != bundle.object.programs.len() {
        return Err(format!(
            "{} signatures for {} programs",
            bundle.signatures.len(),
            bundle.object.programs.len()
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&bundle.object.elf_sha256);
    out.extend_from_slice(&bundle.cert_sha256);
    put_u32(&mut out, bundle.object.maps.len())?;
    for map in &bundle.object.maps {
        put_str(&mut out, map)?;
    }
    put_u32(&mut out, bundle.object.programs.len())?;
    for (program, signature) in bundle.object.programs.iter().zip(&bundle.signatures) {
        put_str(&mut out, &program.name)?;
        out.extend_from_slice(&program.prog_type.to_le_bytes());
        out.extend_from_slice(&program.expected_attach_type.to_le_bytes());
        put_u32(&mut out, program.kfuncs.len())?;
        for kfunc in &program.kfuncs {
            put_str(&mut out, kfunc)?;
        }
        out.extend_from_slice(&program.neutralizable.to_le_bytes());
        put_bytes(&mut out, &program.loader)?;
        put_bytes(&mut out, &program.blob)?;
        put_bytes(&mut out, signature)?;
    }
    Ok(out)
}

/// Decode a bundle written by [`encode`].
///
/// # Errors
///
/// The bytes are not a bundle of this version, or end early, or carry bytes
/// past the last program.
pub fn decode(bytes: &[u8]) -> Result<Bundle, String> {
    let mut r = Reader { bytes, at: 0 };
    if r.take(MAGIC.len())? != MAGIC {
        return Err("not a loader bundle of this version".to_owned());
    }
    let elf_sha256 = r.array()?;
    let cert_sha256 = r.array()?;
    let maps = (0..r.u32()?)
        .map(|_| r.string())
        .collect::<Result<Vec<_>, _>>()?;
    let count = r.u32()?;
    let mut programs = Vec::new();
    let mut signatures = Vec::new();
    for _ in 0..count {
        let name = r.string()?;
        let prog_type = r.u32()?;
        let expected_attach_type = r.u32()?;
        let kfuncs = (0..r.u32()?)
            .map(|_| r.string())
            .collect::<Result<Vec<_>, _>>()?;
        let neutralizable = u64::from_le_bytes(r.array()?);
        let loader = r.bytes()?;
        let blob = r.bytes()?;
        signatures.push(r.bytes()?);
        programs.push(GeneratedProgram {
            name,
            prog_type,
            expected_attach_type,
            kfuncs,
            neutralizable,
            loader,
            blob,
        });
    }
    if r.at != bytes.len() {
        return Err("bytes past the last program".to_owned());
    }
    Ok(Bundle {
        object: GeneratedObject {
            elf_sha256,
            maps,
            programs,
        },
        cert_sha256,
        signatures,
    })
}

fn put_u32(out: &mut Vec<u8>, n: usize) -> Result<(), String> {
    let n = u32::try_from(n).map_err(|_| format!("{n} does not fit a u32"))?;
    out.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), String> {
    let n = u16::try_from(s.len()).map_err(|_| format!("name `{s}` too long"))?;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), String> {
    put_u32(out, b.len())?;
    out.extend_from_slice(b);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "bundle ends early".to_owned())?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn string(&mut self) -> Result<String, String> {
        let n = u16::from_le_bytes(self.array()?);
        let raw = self.take(usize::from(n))?;
        String::from_utf8(raw.to_vec()).map_err(|e| e.to_string())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = usize::try_from(self.u32()?).map_err(|e| e.to_string())?;
        Ok(self.take(n)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Bundle {
        Bundle {
            object: GeneratedObject {
                elf_sha256: [7; 32],
                maps: vec!["CONFIG".to_owned(), "FIREWALL_RULES".to_owned()],
                programs: vec![GeneratedProgram {
                    name: "xdp_firewall".to_owned(),
                    prog_type: 6,
                    expected_attach_type: 0,
                    kfuncs: vec!["bpf_xdp_metadata_rx_hash".to_owned()],
                    neutralizable: 1,
                    loader: vec![0x95, 0, 0, 0, 0, 0, 0, 0],
                    blob: vec![1; 16],
                }],
            },
            cert_sha256: [9; 32],
            signatures: vec![vec![0x30, 0x82, 1, 2]],
        }
    }

    #[test]
    fn a_bundle_survives_the_round_trip() {
        let bundle = sample();
        let bytes = encode(&bundle).expect("encoded");
        assert_eq!(decode(&bytes).expect("decoded"), bundle);
    }

    #[test]
    fn a_truncated_bundle_is_refused() {
        let bytes = encode(&sample()).expect("encoded");
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = encode(&sample()).expect("encoded");
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn another_version_is_refused() {
        let mut bytes = encode(&sample()).expect("encoded");
        bytes[7] = b'2';
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn a_signature_per_program_is_required() {
        let mut bundle = sample();
        bundle.signatures.clear();
        assert!(encode(&bundle).is_err());
    }
}
