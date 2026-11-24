//! The command line a process table keeps: one bound and one shape, whether
//! the bytes came from the kernel at exec or from `/proc/<pid>/cmdline`
//! after it.

/// Most bytes of a command line kept.
///
/// argv is not bounded by the kernel at any size an agent wants to hold per
/// process, and a table of a few thousand entries holding a megabyte each is
/// the memory bug this bound exists to prevent. What is kept is the start of
/// the line, which is the part that names the program and its first
/// arguments; the cut is marked so nobody reads a truncated command as the
/// whole one.
pub const MAX_COMMAND_LINE: usize = 4096;

/// The marker appended where argv was longer than the bound.
pub const TRUNCATION_MARKER: &str = " ...";

/// argv as `/proc/<pid>/cmdline` holds it: NUL-separated, NUL-terminated.
///
/// `cut` says the bytes are already known to stop short of the whole argv,
/// which a reader that bounded its own copy knows and the bytes alone do
/// not show; the line then ends in the marker as one cut here would.
///
/// Returns `None` for no argument at all, which is what a kernel thread
/// has: it never execed anything, so it has no command line rather than an
/// empty one.
#[must_use]
pub fn from_argv(raw: &[u8], cut: bool) -> Option<String> {
    let mut joined = String::new();
    for argument in raw.split(|byte| *byte == 0) {
        if argument.is_empty() {
            continue;
        }
        if !joined.is_empty() {
            joined.push(' ');
        }
        joined.push_str(&String::from_utf8_lossy(argument));
        if joined.len() >= MAX_COMMAND_LINE {
            break;
        }
    }
    if joined.is_empty() {
        return None;
    }
    if joined.len() > MAX_COMMAND_LINE {
        // Cut on a character boundary: argv is bytes and the lossy decode
        // above can land a multi-byte character across the bound.
        let mut at = MAX_COMMAND_LINE;
        while at > 0 && !joined.is_char_boundary(at) {
            at -= 1;
        }
        joined.truncate(at);
        joined.push_str(TRUNCATION_MARKER);
    } else if cut {
        joined.push_str(TRUNCATION_MARKER);
    }
    Some(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_is_joined_with_single_spaces() {
        let raw = b"curl\0-s\0https://example.test\0";
        assert_eq!(
            from_argv(raw, false).as_deref(),
            Some("curl -s https://example.test")
        );
    }

    #[test]
    fn a_kernel_thread_has_no_command_line_rather_than_an_empty_one() {
        assert_eq!(from_argv(b"", false), None);
        assert_eq!(from_argv(b"\0\0\0", false), None);
        assert_eq!(from_argv(b"", true), None);
    }

    #[test]
    fn a_long_argv_is_cut_and_says_so() {
        let mut raw = Vec::new();
        for _ in 0..1000 {
            raw.extend_from_slice(b"argument-of-some-length\0");
        }
        let line = from_argv(&raw, false).unwrap();
        assert!(line.ends_with(TRUNCATION_MARKER));
        assert_eq!(line.len(), MAX_COMMAND_LINE + TRUNCATION_MARKER.len());
    }

    #[test]
    fn a_cut_the_reader_made_is_marked_once() {
        assert_eq!(
            from_argv(b"curl\0-s\0", true).as_deref(),
            Some("curl -s ...")
        );
        let long = vec![b'a'; MAX_COMMAND_LINE + 10];
        let line = from_argv(&long, true).unwrap();
        assert_eq!(line.matches(TRUNCATION_MARKER).count(), 1);
    }

    #[test]
    fn a_character_across_the_bound_is_not_split() {
        let mut raw = vec![b'a'; MAX_COMMAND_LINE - 1];
        raw.extend_from_slice("é".as_bytes());
        raw.push(0);
        let line = from_argv(&raw, false).unwrap();
        assert_eq!(line.len(), MAX_COMMAND_LINE - 1 + TRUNCATION_MARKER.len());
    }
}
