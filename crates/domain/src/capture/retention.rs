//! What captures are allowed to cost on disk, and which files pay for it.
//!
//! A capture is a diagnostic an operator starts and forgets, and the files it
//! writes outlive the session that wrote them: nothing deleted them, so a node
//! that captured often filled `/var/lib/ebpfsentinel/captures` and the next
//! capture was the one that failed. The policy is two numbers, an age and a
//! total size, either of which can be turned off, and it decides over a listing
//! rather than over a directory: no filesystem is reached from here.

/// A capture file as the policy sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFile {
    /// Absolute path, which is what the caller is told to delete.
    pub path: String,
    /// How long ago the file was last written, in seconds.
    pub age_secs: u64,
    /// What the file occupies, in bytes.
    pub size_bytes: u64,
}

/// Seconds in a day, so the age limit can be written in days where an operator
/// reads it and in seconds where it is compared.
const SECS_PER_DAY: u64 = 86_400;

/// How long capture files are kept and how much room they may take together.
///
/// `0` turns a limit off on either axis, and both off is the behaviour this
/// type replaced: files are kept for ever. The two are independent, so a node
/// can keep a week of captures or a gigabyte of them, or whichever comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    retention_days: u32,
    max_total_bytes: u64,
}

impl RetentionPolicy {
    /// Build a policy from the configured days and megabytes.
    #[must_use]
    pub fn new(retention_days: u32, max_total_mb: u64) -> Self {
        Self {
            retention_days,
            max_total_bytes: max_total_mb.saturating_mul(1024 * 1024),
        }
    }

    /// The age limit in seconds, or `None` when age is not a limit here.
    #[must_use]
    pub fn max_age_secs(&self) -> Option<u64> {
        if self.retention_days == 0 {
            None
        } else {
            Some(u64::from(self.retention_days) * SECS_PER_DAY)
        }
    }

    /// The total-size limit in bytes, or `None` when size is not a limit here.
    #[must_use]
    pub fn max_total_bytes(&self) -> Option<u64> {
        if self.max_total_bytes == 0 {
            None
        } else {
            Some(self.max_total_bytes)
        }
    }

    /// The paths to delete, oldest first.
    ///
    /// `keep` is the paths that may not be deleted whatever the numbers say,
    /// which is every capture still writing: deleting the file out from under
    /// a running reader would leave a session reporting figures for a file
    /// nobody can open. Their bytes still count towards the total, because the
    /// disk they occupy is occupied.
    #[must_use]
    pub fn files_to_delete(&self, files: &[CaptureFile], keep: &[String]) -> Vec<String> {
        let mut candidates: Vec<&CaptureFile> =
            files.iter().filter(|f| !keep.contains(&f.path)).collect();
        // Oldest first, and by path where two files share an age, so a sweep
        // is the same sweep whatever order the directory was read in.
        candidates.sort_by(|a, b| {
            b.age_secs
                .cmp(&a.age_secs)
                .then_with(|| a.path.cmp(&b.path))
        });

        let mut total: u64 = files.iter().map(|f| f.size_bytes).sum();
        let mut doomed: Vec<String> = Vec::new();

        if let Some(max_age) = self.max_age_secs() {
            for file in &candidates {
                if file.age_secs > max_age {
                    doomed.push(file.path.clone());
                    total = total.saturating_sub(file.size_bytes);
                }
            }
        }

        if let Some(ceiling) = self.max_total_bytes() {
            for file in &candidates {
                if total <= ceiling {
                    break;
                }
                if doomed.iter().any(|p| p == &file.path) {
                    continue;
                }
                doomed.push(file.path.clone());
                total = total.saturating_sub(file.size_bytes);
            }
        }

        doomed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, age_secs: u64, size_mb: u64) -> CaptureFile {
        CaptureFile {
            path: path.to_string(),
            age_secs,
            size_bytes: size_mb * 1024 * 1024,
        }
    }

    #[test]
    fn a_policy_with_both_limits_off_deletes_nothing() {
        let policy = RetentionPolicy::new(0, 0);
        let files = vec![file("/c/old.pcap", 400 * SECS_PER_DAY, 4096)];

        assert!(policy.files_to_delete(&files, &[]).is_empty());
        assert_eq!(policy.max_age_secs(), None);
        assert_eq!(policy.max_total_bytes(), None);
    }

    #[test]
    fn a_file_past_the_age_goes_and_one_inside_it_stays() {
        let policy = RetentionPolicy::new(7, 0);
        let files = vec![
            file("/c/old.pcap", 8 * SECS_PER_DAY, 1),
            file("/c/fresh.pcap", 6 * SECS_PER_DAY, 1),
            file("/c/exactly.pcap", 7 * SECS_PER_DAY, 1),
        ];

        assert_eq!(
            policy.files_to_delete(&files, &[]),
            vec!["/c/old.pcap".to_string()],
            "the limit is a limit, so a file exactly at it is still inside it"
        );
    }

    #[test]
    fn the_ceiling_takes_the_oldest_until_the_total_fits() {
        let policy = RetentionPolicy::new(0, 100);
        let files = vec![
            file("/c/a.pcap", 30, 60),
            file("/c/b.pcap", 20, 60),
            file("/c/c.pcap", 10, 60),
        ];

        assert_eq!(
            policy.files_to_delete(&files, &[]),
            vec!["/c/a.pcap".to_string(), "/c/b.pcap".to_string()],
            "180 MB against a 100 MB ceiling takes the two oldest, not all three"
        );
    }

    #[test]
    fn a_capture_still_writing_is_never_deleted_but_still_counts() {
        let policy = RetentionPolicy::new(1, 100);
        let running = "/c/running.pcap".to_string();
        let files = vec![
            file(&running, 10 * SECS_PER_DAY, 90),
            file("/c/history.pcap", 2 * SECS_PER_DAY, 20),
        ];

        let doomed = policy.files_to_delete(&files, std::slice::from_ref(&running));

        assert_eq!(
            doomed,
            vec!["/c/history.pcap".to_string()],
            "the running file is past the age and over the ceiling and still stays"
        );
    }

    #[test]
    fn the_two_limits_do_not_delete_the_same_file_twice() {
        let policy = RetentionPolicy::new(1, 1);
        let files = vec![
            file("/c/a.pcap", 5 * SECS_PER_DAY, 10),
            file("/c/b.pcap", 2 * SECS_PER_DAY, 10),
        ];

        let doomed = policy.files_to_delete(&files, &[]);

        assert_eq!(doomed.len(), 2);
        assert_eq!(doomed[0], "/c/a.pcap");
        assert_eq!(doomed[1], "/c/b.pcap");
    }

    #[test]
    fn an_empty_directory_sweeps_to_nothing() {
        let policy = RetentionPolicy::new(7, 1024);
        assert!(policy.files_to_delete(&[], &[]).is_empty());
    }

    #[test]
    fn megabytes_become_bytes() {
        assert_eq!(
            RetentionPolicy::new(0, 1).max_total_bytes(),
            Some(1_048_576)
        );
        assert_eq!(RetentionPolicy::new(7, 0).max_age_secs(), Some(604_800));
    }
}
