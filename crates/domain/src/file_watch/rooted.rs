//! The path a change names, as the process that made it sees it.
//!
//! The watch marks the backing filesystem, so a write inside a container
//! arrives naming the container's upper directory on the host:
//! `/var/lib/containerd/.../fs/etc/passwd` rather than `/etc/passwd`. The
//! writer's own mount table says where its root lives, and the path inside
//! the container is what is left once that prefix is taken away. A writer
//! whose root is not an overlay sees the host's paths already.

/// What a process's root mount says about where its files live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootMount {
    /// Filesystem type of the mount at `/`.
    pub fstype: String,
    /// The overlay's upper directory, where its writes land.
    pub upper: Option<String>,
    /// The overlay's lower directories, the image's layers, topmost first.
    pub lowers: Vec<String>,
}

/// A changed path, and where it is from the writer's side.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RootedPath {
    /// The path inside the writer's root, `None` when the change landed
    /// outside it, on a volume mounted into a container.
    pub path: Option<String>,
    /// The same name in each of the image's layers, topmost first: where a
    /// file the container writes for the first time was copied up from.
    pub layers: Vec<String>,
}

/// The root mount in a `/proc/<pid>/mountinfo`: the last line mounted on
/// `/`, since a mount stacked on another hides it.
#[must_use]
pub fn root_mount(mountinfo: &str) -> Option<RootMount> {
    mountinfo.lines().filter_map(parse_line).next_back()
}

fn parse_line(line: &str) -> Option<RootMount> {
    let (head, tail) = line.split_once(" - ")?;
    let mountpoint = head.split(' ').nth(4)?;
    if mountpoint != "/" {
        return None;
    }
    let mut tail = tail.split(' ');
    let fstype = tail.next()?.to_owned();
    let _source = tail.next()?;
    let options = tail.next().unwrap_or("");
    let mut upper = None;
    let mut lowers = Vec::new();
    for option in options.split(',') {
        if let Some(value) = option.strip_prefix("upperdir=") {
            upper = Some(unescape(value));
        } else if let Some(value) = option.strip_prefix("lowerdir+=") {
            lowers.push(unescape(value));
        } else if let Some(value) = option.strip_prefix("lowerdir=") {
            lowers.extend(split_lowers(value));
        }
    }
    Some(RootMount {
        fstype,
        upper,
        lowers,
    })
}

/// `lowerdir=a:b:c`, where a colon inside a name was written `\:` and the
/// kernel then showed that backslash as `\134`.
fn split_lowers(value: &str) -> Vec<String> {
    let mut layers = Vec::new();
    let mut current = String::new();
    for part in value.split(':') {
        if let Some(kept) = current.strip_suffix("\\134") {
            current = format!("{kept}:{part}");
        } else {
            if !current.is_empty() {
                layers.push(unescape(&current));
            }
            part.clone_into(&mut current);
        }
    }
    if !current.is_empty() {
        layers.push(unescape(&current));
    }
    layers
}

/// The kernel's octal escapes in a mount table: `\040` for a space, `\011`
/// for a tab, `\012` for a newline, `\134` for a backslash, and the same
/// form for anything else it chose to escape.
fn unescape(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value = (u32::from(bytes[i + 1] - b'0') << 6)
                | (u32::from(bytes[i + 2] - b'0') << 3)
                | u32::from(bytes[i + 3] - b'0');
            if let Ok(byte) = u8::try_from(value) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Where `host_path` is for a writer whose root is `root`.
#[must_use]
pub fn rooted(host_path: &str, root: &RootMount) -> RootedPath {
    if root.fstype != "overlay" {
        return RootedPath {
            path: Some(host_path.to_owned()),
            layers: Vec::new(),
        };
    }
    let Some(upper) = root.upper.as_deref() else {
        return RootedPath::default();
    };
    let upper = upper.trim_end_matches('/');
    let Some(rest) = host_path.strip_prefix(upper) else {
        return RootedPath::default();
    };
    if !(rest.is_empty() || rest.starts_with('/')) {
        return RootedPath::default();
    }
    let inside = if rest.is_empty() { "/" } else { rest };
    RootedPath {
        path: Some(inside.to_owned()),
        layers: root
            .lowers
            .iter()
            .map(|lower| format!("{}{inside}", lower.trim_end_matches('/')))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
23 22 0:21 / /proc rw,nosuid shared:2 - proc proc rw
";

    const CONTAINER: &str = "\
811 640 0:94 / / rw,relatime master:1 - overlay overlay rw,lowerdir=/var/lib/c/snap/3/fs:/var/lib/c/snap/2/fs,upperdir=/var/lib/c/snap/9/fs,workdir=/var/lib/c/snap/9/work
812 811 0:96 / /proc rw,nosuid - proc proc rw
813 811 259:2 /var/lib/kubelet/pods/x/volumes/data /data rw - ext4 /dev/nvme0n1p2 rw
";

    #[test]
    fn a_host_root_is_its_own_path() {
        let root = root_mount(HOST).unwrap();
        assert_eq!(root.fstype, "ext4");
        let r = rooted("/etc/passwd", &root);
        assert_eq!(r.path.as_deref(), Some("/etc/passwd"));
        assert!(r.layers.is_empty());
    }

    #[test]
    fn a_container_write_is_named_inside_the_container() {
        let root = root_mount(CONTAINER).unwrap();
        assert_eq!(root.upper.as_deref(), Some("/var/lib/c/snap/9/fs"));
        let r = rooted("/var/lib/c/snap/9/fs/etc/passwd", &root);
        assert_eq!(r.path.as_deref(), Some("/etc/passwd"));
        assert_eq!(
            r.layers,
            vec![
                "/var/lib/c/snap/3/fs/etc/passwd".to_string(),
                "/var/lib/c/snap/2/fs/etc/passwd".to_string(),
            ]
        );
    }

    #[test]
    fn a_write_outside_the_upper_directory_has_no_rooted_path() {
        let root = root_mount(CONTAINER).unwrap();
        let r = rooted("/var/lib/kubelet/pods/x/volumes/data/out", &root);
        assert_eq!(r, RootedPath::default());
        // A sibling whose name merely starts with the upper directory's.
        let r = rooted("/var/lib/c/snap/9/fsx/etc", &root);
        assert_eq!(r, RootedPath::default());
    }

    #[test]
    fn the_last_mount_on_root_wins() {
        let stacked = format!("{HOST}40 22 0:50 / / rw - tmpfs tmpfs rw\n");
        assert_eq!(root_mount(&stacked).unwrap().fstype, "tmpfs");
    }

    #[test]
    fn escapes_and_appended_layers_are_read() {
        let line = "1 0 0:1 / / rw - overlay overlay rw,lowerdir+=/l/a\\040b,lowerdir+=/l/c,upperdir=/u/x\\134y\n";
        let root = root_mount(line).unwrap();
        assert_eq!(root.lowers, vec!["/l/a b".to_string(), "/l/c".to_string()]);
        assert_eq!(root.upper.as_deref(), Some("/u/x\\y"));
        let joined = "1 0 0:1 / / rw - overlay overlay rw,lowerdir=/l/a\\134:b:/l/c,upperdir=/u\n";
        assert_eq!(
            root_mount(joined).unwrap().lowers,
            vec!["/l/a:b".to_string(), "/l/c".to_string()]
        );
    }

    #[test]
    fn a_table_without_a_root_says_nothing() {
        assert!(root_mount("23 22 0:21 / /proc rw - proc proc rw\n").is_none());
        assert!(root_mount("garbage").is_none());
    }
}
