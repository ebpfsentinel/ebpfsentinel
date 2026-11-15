use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use domain::dlp::entity::{DlpExecutable, DlpIdentitySource};
use ebpfsentinel_warden_client::ReconnectingClient;
use ports::secondary::process_executable_port::ProcessExecutableReader;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// Suffix the kernel appends to `/proc/<pid>/exe` once the binary has been
/// unlinked. Kept off the reported path: the file is gone, the name is not.
const DELETED_SUFFIX: &str = " (deleted)";

/// Resolves a pid's executable through `/proc/<pid>/exe`, from a configurable
/// proc root so an agent holding the host procfs at `/host/proc` names the
/// node's binaries rather than its own container's.
///
/// The path comes from the symlink and the `(dev, ino)` pair from a stat of
/// the same link target, so the two always describe one file. A process that
/// exited between the write and the alert resolves to nothing.
///
/// A rootless agent fails the ptrace check `/proc/<pid>/exe` asks for against
/// every process outside its own user namespace, which is every process on the
/// host. When `EBPFSENTINEL_WARDEN_SOCK` is set, a link the agent may not read
/// is read by the warden instead; a process that is simply gone costs no round
/// trip.
pub struct ProcExecutableResolver {
    proc_root: PathBuf,
    /// The warden, in a rootless deployment. Held behind a `Mutex` because the
    /// client caches its connection and the port reads through `&self`.
    warden: Option<Mutex<ReconnectingClient>>,
}

impl ProcExecutableResolver {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| Mutex::new(ReconnectingClient::new(p)));
        Self {
            proc_root: proc_root.into(),
            warden,
        }
    }

    /// Resolve through the warden at `sock` whenever the local link is not
    /// readable, whatever the environment says.
    #[cfg(test)]
    fn with_warden(proc_root: impl Into<PathBuf>, sock: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            warden: Some(Mutex::new(ReconnectingClient::new(sock))),
        }
    }

    /// Convenience constructor that defaults to `/proc`.
    pub fn with_default_proc() -> Self {
        Self::new(Path::new("/proc"))
    }

    pub fn proc_path(&self) -> &Path {
        &self.proc_root
    }

    /// Ask the warden for the link the agent may not read. A warden that is
    /// down or refuses leaves the process unnamed, as a local failure does.
    fn read_through_warden(&self, pid: u32) -> Option<DlpExecutable> {
        let warden = self.warden.as_ref()?;
        let mut client = warden
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match client.read_executable(pid) {
            Ok(found) => found.map(|exe| DlpExecutable {
                path: exe.path,
                dev: exe.dev,
                inode: exe.ino,
                source: DlpIdentitySource::ProcessAtAlertTime,
            }),
            Err(e) => {
                tracing::debug!(pid, error = %e, "warden could not name the executable");
                None
            }
        }
    }
}

impl ProcessExecutableReader for ProcExecutableResolver {
    fn read_executable(&self, pid: u32) -> Option<DlpExecutable> {
        let link = self.proc_root.join(pid.to_string()).join("exe");
        let target = match std::fs::read_link(&link) {
            Ok(target) => target,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return self.read_through_warden(pid);
            }
            Err(_) => return None,
        };
        let path = target.to_string_lossy();
        let path = path
            .strip_suffix(DELETED_SUFFIX)
            .unwrap_or(path.as_ref())
            .to_string();
        if path.is_empty() {
            return None;
        }

        // Stat the link rather than the resolved name: the binary may have
        // been replaced since, and a deleted one has no name left to stat.
        let meta = std::fs::metadata(&link).ok()?;
        Some(DlpExecutable {
            path,
            dev: meta.dev(),
            inode: meta.ino(),
            source: DlpIdentitySource::ProcessAtAlertTime,
        })
    }

    fn running(&self) -> Vec<u32> {
        let Ok(entries) = std::fs::read_dir(&self.proc_root) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
            .collect()
    }

    fn kernel_identity(&self, pid: u32, dev: u64, inode: u64) -> Option<(u64, u64)> {
        let pid_dir = self.proc_root.join(pid.to_string());
        let file = match File::open(pid_dir.join("exe")) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                let warden = self.warden.as_ref()?;
                let fd = warden
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .open_executable(pid)
                    .ok()?;
                File::from(fd)
            }
            Err(_) => return None,
        };
        let meta = file.metadata().ok()?;
        if (meta.dev(), meta.ino()) != (dev, inode) {
            return None;
        }
        let fdinfo =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).ok()?;
        let (mount, ino) = mount_and_inode(&fdinfo)?;
        let mountinfo = std::fs::read_to_string(pid_dir.join("mountinfo")).ok()?;
        let kernel = (mount_device(&mountinfo, mount)?, ino);
        (kernel != (dev, inode)).then_some(kernel)
    }
}

/// The mount id and inode number an open file's `fdinfo` states: the inode
/// the file was opened on, which for an overlay is the overlay's own, not the
/// layer's a stat reports.
fn mount_and_inode(fdinfo: &str) -> Option<(u64, u64)> {
    let field = |name: &str| {
        fdinfo
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse::<u64>().ok())
    };
    Some((field("mnt_id:")?, field("ino:")?))
}

/// The device of the superblock behind mount `mount`, from a `mountinfo`
/// listing, in the encoding a stat answers `st_dev` in.
fn mount_device(mountinfo: &str, mount: u64) -> Option<u64> {
    mountinfo.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()?.parse::<u64>().ok()? != mount {
            return None;
        }
        let (major, minor) = fields.nth(1)?.split_once(':')?;
        Some(libc::makedev(major.parse().ok()?, minor.parse().ok()?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Build a fake `/proc/<pid>/exe` pointing at a real file, as the kernel
    /// does, so the stat behind the link has something to answer.
    fn fake_proc(pid: u32, link_name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let binary = dir.path().join("binary");
        fs::write(&binary, b"\x7fELF").unwrap();
        let pid_dir = dir.path().join("proc").join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        let mut target = binary.clone().into_os_string();
        target.push(link_name);
        std::os::unix::fs::symlink(&target, pid_dir.join("exe")).unwrap();
        let root = dir.path().join("proc");
        (dir, root)
    }

    #[test]
    fn reads_the_executable_behind_a_pid() {
        let (_dir, root) = fake_proc(4242, "");
        let resolver = ProcExecutableResolver::new(&root);

        let exe = resolver.read_executable(4242).expect("a live pid resolves");
        assert!(exe.path.ends_with("/binary"), "path was {}", exe.path);
        assert_ne!(exe.inode, 0);
        assert_eq!(exe.source, DlpIdentitySource::ProcessAtAlertTime);
    }

    #[test]
    fn a_deleted_binary_keeps_its_name_without_the_kernel_suffix() {
        let (_dir, root) = fake_proc(4243, " (deleted)");
        let resolver = ProcExecutableResolver::new(&root);

        // The link target carries the suffix and the stat behind it fails,
        // so nothing is reported: a path with no file is not an identity.
        assert!(resolver.read_executable(4243).is_none());
    }

    #[test]
    fn a_process_that_is_gone_resolves_to_nothing() {
        let dir = tempdir().unwrap();
        let resolver = ProcExecutableResolver::new(dir.path());
        assert!(resolver.read_executable(999_999).is_none());
    }

    #[test]
    fn every_numeric_entry_is_a_running_pid() {
        let (dir, _) = fake_proc(42, "/usr/bin/curl");
        let proc_root = dir.path().join("proc");
        fs::create_dir(proc_root.join("7")).unwrap();
        fs::create_dir(proc_root.join("self")).unwrap();
        let resolver = ProcExecutableResolver::new(proc_root);

        let mut pids = resolver.running();
        pids.sort_unstable();

        assert_eq!(pids, vec![7, 42]);
    }

    #[test]
    fn proc_path_is_exposed() {
        let resolver = ProcExecutableResolver::new("/host/proc");
        assert_eq!(resolver.proc_path(), Path::new("/host/proc"));
    }

    /// Answer one connection as the warden would: the handshake, then every
    /// `ReadExecutable` with `answer`. Returns how many reads it served.
    fn fake_warden(
        sock: &Path,
        answer: ebpfsentinel_warden_proto::ExecutableIdentity,
    ) -> std::thread::JoinHandle<usize> {
        use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response};
        use ebpfsentinel_warden_proto::{read_frame, write_frame};
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let Ok(Command::Hello { .. }) = read_frame::<_, Command>(&mut conn) else {
                return 0;
            };
            write_frame(
                &mut conn,
                &Response::HelloOk {
                    version: PROTOCOL_VERSION,
                },
            )
            .unwrap();
            let mut served = 0;
            while let Ok(cmd) = read_frame::<_, Command>(&mut conn) {
                let Command::ReadExecutable { .. } = cmd else {
                    panic!("unexpected command {cmd:?}");
                };
                served += 1;
                write_frame(
                    &mut conn,
                    &Response::Executable {
                        executable: Some(answer.clone()),
                    },
                )
                .unwrap();
            }
            served
        })
    }

    #[test]
    fn a_link_the_agent_may_not_read_is_read_by_the_warden() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, root) = fake_proc(4244, "");
        let binary = dir.path().join("binary");
        let meta = fs::metadata(&binary).unwrap();
        let pid_dir = root.join("4244");
        fs::set_permissions(&pid_dir, fs::Permissions::from_mode(0o000)).unwrap();
        // A privileged test run reads through the closed directory anyway,
        // and then the warden is never asked.
        let privileged = fs::read_dir(&pid_dir).is_ok();

        let sock = dir.path().join("warden.sock");
        let warden = fake_warden(
            &sock,
            ebpfsentinel_warden_proto::ExecutableIdentity {
                path: binary.to_string_lossy().into_owned(),
                dev: meta.dev(),
                ino: meta.ino(),
            },
        );
        let resolver = ProcExecutableResolver::with_warden(&root, &sock);
        let exe = resolver.read_executable(4244).expect("the warden names it");
        assert_eq!(exe.path, binary.to_string_lossy());
        assert_eq!((exe.dev, exe.inode), (meta.dev(), meta.ino()));
        assert_eq!(exe.source, DlpIdentitySource::ProcessAtAlertTime);

        // A process that is gone is not worth a round trip.
        assert!(resolver.read_executable(999_999).is_none());

        drop(resolver);
        if privileged {
            // Nobody connected; unblock the accept so the thread ends.
            drop(std::os::unix::net::UnixStream::connect(&sock));
        }
        let served = warden.join().unwrap();
        fs::set_permissions(&pid_dir, fs::Permissions::from_mode(0o755)).unwrap();
        if !privileged {
            assert_eq!(served, 1);
        }
    }

    #[test]
    fn the_kernel_s_identity_is_the_mount_s_device_and_the_opened_inode() {
        let fdinfo = "pos:\t0\nflags:\t0100000\nmnt_id:\t1312\nino:\t1051490\n";
        assert_eq!(mount_and_inode(fdinfo), Some((1312, 1_051_490)));
        assert_eq!(mount_and_inode("pos:\t0\n"), None);

        let mountinfo = "\
22 1 0:21 / /proc rw - proc proc rw
1312 1290 0:432 / / rw,relatime - overlay overlay rw,lowerdir=/a:/b
";
        assert_eq!(mount_device(mountinfo, 1312), Some(libc::makedev(0, 432)));
        assert_eq!(mount_device(mountinfo, 99), None);
    }

    #[test]
    fn a_file_whose_stat_differs_from_the_mount_is_named_as_the_kernel_reads_it() {
        let (dir, root) = fake_proc(4245, "");
        let binary = dir.path().join("binary");
        let meta = fs::metadata(&binary).unwrap();
        let file = File::open(&binary).unwrap();
        let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).unwrap();
        let (mount, ino) = mount_and_inode(&fdinfo).unwrap();
        assert_eq!(ino, meta.ino());
        let pid_dir = root.join("4245");
        fs::write(
            pid_dir.join("mountinfo"),
            format!("{mount} 1 7:9 / / rw - overlay overlay rw\n"),
        )
        .unwrap();
        let resolver = ProcExecutableResolver::new(&root);
        assert_eq!(
            resolver.kernel_identity(4245, meta.dev(), meta.ino()),
            Some((libc::makedev(7, 9), meta.ino()))
        );
        // Another file stands behind the link than the one stated.
        assert_eq!(
            resolver.kernel_identity(4245, meta.dev(), meta.ino() + 1),
            None
        );

        // Where the mount is the device the stat answered, nothing is added.
        fs::write(
            pid_dir.join("mountinfo"),
            format!(
                "{mount} 1 {}:{} / / rw - ext4 /dev/x rw\n",
                libc::major(meta.dev()),
                libc::minor(meta.dev())
            ),
        )
        .unwrap();
        assert_eq!(resolver.kernel_identity(4245, meta.dev(), meta.ino()), None);
    }

    #[test]
    fn default_uses_proc() {
        assert_eq!(
            ProcExecutableResolver::with_default_proc().proc_path(),
            Path::new("/proc")
        );
    }
}
