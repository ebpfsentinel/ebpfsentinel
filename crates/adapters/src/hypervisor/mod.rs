//! Naming the virtual machine behind a tap or macvtap device.
//!
//! Two hypervisors write down which guest a device was made for, each in a
//! file the host can read:
//!
//! - Proxmox VE names a guest's tap `tap<vmid>i<n>` and keeps the guest's
//!   configuration in `<vmid>.conf`, whose `name:` and `tags:` lines are what
//!   its interface shows. Lines after the first `[section]` header belong to
//!   a snapshot and describe the guest as it was, so reading stops there.
//! - libvirt keeps a status file for each running domain, holding the domain
//!   definition with every interface's host-side device in
//!   `<interface><target dev='...'/></interface>`. Only targets inside an
//!   `<interface>` element are read, since a disk's target names a guest
//!   device rather than a host one.
//!
//! Both are read when asked, never cached: libvirt writes the status file
//! after it made the device, so a name read at the moment the device appears
//! may not exist yet.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use domain::guest::{GuestIdentity, GuestNaming, GuestSource, UnnamedReason};
use ports::secondary::guest_naming_port::GuestNamingPort;

/// Reads the Proxmox and libvirt records on this host.
#[derive(Debug, Clone, Default)]
pub struct HypervisorGuestNamer {
    proxmox_dir: Option<PathBuf>,
    libvirt_dir: Option<PathBuf>,
}

impl HypervisorGuestNamer {
    /// A namer reading Proxmox configurations from `proxmox_dir` and libvirt
    /// status files from `libvirt_dir`. An empty path turns that source off.
    #[must_use]
    pub fn new(proxmox_dir: &str, libvirt_dir: &str) -> Self {
        let dir = |d: &str| (!d.is_empty()).then(|| PathBuf::from(d));
        Self {
            proxmox_dir: dir(proxmox_dir),
            libvirt_dir: dir(libvirt_dir),
        }
    }
}

impl GuestNamingPort for HypervisorGuestNamer {
    fn name_guest(&self, interface: &str) -> GuestNaming {
        if self.proxmox_dir.is_none() && self.libvirt_dir.is_none() {
            return GuestNaming::Unnamed(UnnamedReason::NoSource);
        }
        let mut failure = None;
        if let (Some(dir), Some(vmid)) = (&self.proxmox_dir, proxmox_vmid(interface)) {
            let path = dir.join(format!("{vmid}.conf"));
            match fs::read_to_string(&path) {
                Ok(conf) => return proxmox_naming(&conf, vmid, &path),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => failure = Some(unreadable(&path, &e)),
            }
        }
        if let Some(dir) = &self.libvirt_dir {
            match libvirt_naming(dir, interface) {
                Ok(Some(naming)) => return naming,
                Ok(None) => {}
                Err(reason) => failure = failure.or(Some(reason)),
            }
        }
        GuestNaming::Unnamed(failure.unwrap_or(UnnamedReason::NoRecord))
    }
}

fn unreadable(path: &Path, error: &io::Error) -> UnnamedReason {
    UnnamedReason::RecordUnreadable {
        path: path.display().to_string(),
        error: error.to_string(),
    }
}

/// The VMID in a Proxmox tap name, `tap<vmid>i<n>`.
fn proxmox_vmid(interface: &str) -> Option<u32> {
    let rest = interface.strip_prefix("tap")?;
    let (vmid, index) = rest.split_once('i')?;
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if vmid.is_empty() || !vmid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    vmid.parse().ok()
}

/// The guest a Proxmox configuration describes, from its current section.
fn proxmox_naming(conf: &str, vmid: u32, path: &Path) -> GuestNaming {
    let mut name = None;
    let mut tags = Vec::new();
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "name" => name = Some(value.trim().to_owned()).filter(|n| !n.is_empty()),
            "tags" => {
                tags = value
                    .split([';', ',', ' '])
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            _ => {}
        }
    }
    match name {
        Some(name) => GuestNaming::Named(GuestIdentity {
            name,
            id: vmid.to_string(),
            source: GuestSource::Proxmox,
            tags,
        }),
        None => GuestNaming::Unnamed(UnnamedReason::RecordWithoutName {
            path: path.display().to_string(),
        }),
    }
}

/// The libvirt domain whose status file lists `interface` as a host-side
/// device. A file that cannot be read is reported only when no other file
/// names the device.
fn libvirt_naming(dir: &Path, interface: &str) -> Result<Option<GuestNaming>, UnnamedReason> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unreadable(dir, &e)),
    };
    let mut failure = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "xml") {
            continue;
        }
        let xml = match fs::read_to_string(&path) {
            Ok(xml) => xml,
            Err(e) => {
                failure = failure.or_else(|| Some(unreadable(&path, &e)));
                continue;
            }
        };
        if !interface_targets(&xml).any(|dev| dev == interface) {
            continue;
        }
        let domain = xml.find("<domain ").map_or(xml.as_str(), |at| &xml[at..]);
        let name = element_text(domain, "name");
        return Ok(Some(match name {
            Some(name) => GuestNaming::Named(GuestIdentity {
                name,
                id: element_text(domain, "uuid").unwrap_or_default(),
                source: GuestSource::Libvirt,
                tags: Vec::new(),
            }),
            None => GuestNaming::Unnamed(UnnamedReason::RecordWithoutName {
                path: path.display().to_string(),
            }),
        }));
    }
    failure.map_or(Ok(None), Err)
}

/// The `dev` of every `<target>` inside an `<interface>` element.
fn interface_targets(xml: &str) -> impl Iterator<Item = String> + '_ {
    xml.match_indices("<interface")
        .filter(|(at, _)| {
            // `<interface` must open the element, not prefix a longer name.
            xml[at + "<interface".len()..]
                .chars()
                .next()
                .is_some_and(|c| c == ' ' || c == '>')
        })
        .filter_map(|(at, _)| {
            let body = &xml[at..];
            let end = body.find("</interface>")?;
            let body = &body[..end];
            let target = body.find("<target")?;
            attribute(&body[target..], "dev")
        })
}

/// The value of `name` in the first tag of `tag`.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let tag = &tag[..tag.find('>')?];
    let at = tag.find(&format!(" {name}="))? + name.len() + 2;
    let quote = tag[at..]
        .chars()
        .next()
        .filter(|q| *q == '\'' || *q == '"')?;
    let value = &tag[at + 1..];
    let end = value.find(quote)?;
    Some(unescape(&value[..end]))
}

/// The text of the first `<tag>...</tag>` element.
fn element_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))?;
    Some(unescape(xml[start..start + end].trim())).filter(|t| !t.is_empty())
}

/// The five predefined XML entities, which is every one libvirt writes.
fn unescape(raw: &str) -> String {
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const PROXMOX_CONF: &str = "boot: order=scsi0\n\
        name: web-01\n\
        net0: virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1\n\
        tags: prod;eu-west\n\
        \n\
        [before-upgrade]\n\
        name: web-old\n\
        tags: staging\n";

    const LIBVIRT_STATUS: &str = "<domstatus state='running' pid='4242'>\n\
        <monitor path='/var/lib/libvirt/qemu/domain-3-db/monitor.sock'/>\n\
        <domain type='kvm' id='3'>\n\
          <name>db &amp; cache</name>\n\
          <uuid>6f1c1a8e-0a7b-4d3c-9b8e-2f9d1e7c4a55</uuid>\n\
          <devices>\n\
            <disk type='file' device='disk'><target dev='vda' bus='virtio'/></disk>\n\
            <interface type='network'>\n\
              <mac address='52:54:00:12:34:56'/>\n\
              <target dev=\"vnet7\"/>\n\
            </interface>\n\
            <interface type='direct'><target dev='macvtap2'/></interface>\n\
          </devices>\n\
        </domain>\n\
        </domstatus>\n";

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ebpfsentinel-guests-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_proxmox_tap_name_carries_its_vmid() {
        assert_eq!(proxmox_vmid("tap101i0"), Some(101));
        assert_eq!(proxmox_vmid("tap4101i12"), Some(4101));
        for name in ["tap0", "tapi0", "tap101i", "tap1x1i0", "vnet0", "tap101i0a"] {
            assert_eq!(proxmox_vmid(name), None, "{name}");
        }
    }

    #[test]
    fn a_proxmox_configuration_names_its_guest_from_the_current_section() {
        let naming = proxmox_naming(PROXMOX_CONF, 101, Path::new("101.conf"));
        assert_eq!(
            naming,
            GuestNaming::Named(GuestIdentity {
                name: "web-01".into(),
                id: "101".into(),
                source: GuestSource::Proxmox,
                tags: vec!["prod".into(), "eu-west".into()],
            })
        );
        let nameless = proxmox_naming("cores: 2\n", 7, Path::new("/pve/7.conf"));
        assert_eq!(
            nameless,
            GuestNaming::Unnamed(UnnamedReason::RecordWithoutName {
                path: "/pve/7.conf".into()
            })
        );
    }

    #[test]
    fn only_interface_targets_are_host_devices() {
        let targets: Vec<String> = interface_targets(LIBVIRT_STATUS).collect();
        assert_eq!(targets, ["vnet7", "macvtap2"]);
    }

    #[test]
    fn the_namer_reads_proxmox_then_libvirt_and_says_why_it_cannot_name() {
        let pve = temp_dir("pve");
        let libvirt = temp_dir("libvirt");
        fs::write(pve.join("101.conf"), PROXMOX_CONF).unwrap();
        fs::write(libvirt.join("db.xml"), LIBVIRT_STATUS).unwrap();
        fs::write(
            libvirt.join("db.xml.bak"),
            "<interface><target dev='vnet9'/></interface>",
        )
        .unwrap();
        let namer = HypervisorGuestNamer::new(pve.to_str().unwrap(), libvirt.to_str().unwrap());

        let GuestNaming::Named(web) = namer.name_guest("tap101i0") else {
            panic!("tap101i0 is named");
        };
        assert_eq!(
            (web.name.as_str(), web.source),
            ("web-01", GuestSource::Proxmox)
        );

        let GuestNaming::Named(db) = namer.name_guest("vnet7") else {
            panic!("vnet7 is named");
        };
        assert_eq!(db.name, "db & cache");
        assert_eq!(db.id, "6f1c1a8e-0a7b-4d3c-9b8e-2f9d1e7c4a55");
        assert_eq!(db.source, GuestSource::Libvirt);
        assert_eq!(db.tags.len(), 0);

        assert_eq!(
            namer.name_guest("vda"),
            GuestNaming::Unnamed(UnnamedReason::NoRecord)
        );
        assert_eq!(
            namer.name_guest("vnet9"),
            GuestNaming::Unnamed(UnnamedReason::NoRecord)
        );
        // A Proxmox-shaped name with no configuration falls through to libvirt.
        assert_eq!(
            namer.name_guest("tap999i0"),
            GuestNaming::Unnamed(UnnamedReason::NoRecord)
        );
        assert_eq!(
            HypervisorGuestNamer::new("", "").name_guest("vnet7"),
            GuestNaming::Unnamed(UnnamedReason::NoSource)
        );
        let missing = HypervisorGuestNamer::new("/nonexistent/pve", "/nonexistent/libvirt");
        assert_eq!(
            missing.name_guest("tap101i0"),
            GuestNaming::Unnamed(UnnamedReason::NoRecord)
        );
        fs::remove_dir_all(&pve).unwrap();
        fs::remove_dir_all(&libvirt).unwrap();
    }
}
