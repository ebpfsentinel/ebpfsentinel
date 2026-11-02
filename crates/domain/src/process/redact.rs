//! Redaction of the secret-bearing shapes an argument vector carries.
//!
//! An argv routinely holds a password, a token or a connection string that
//! somebody typed, and a table that keeps it raw turns every reader of the
//! process table, every alert and every frozen incident into a credential
//! store. The redaction runs where the vector is captured, before the line is
//! stored anywhere, so a secret matched here never reaches memory past the
//! read, a disk, a SIEM or a screen.
//!
//! What is removed is the value and only the value: the flag, the key, the
//! user name and the host stay, because they are what an investigation reads
//! and none of them opens anything. The shapes are a closed list, written in
//! the published privacy notice beside this one:
//!
//! - a flag or an assignment whose name says it holds a secret
//!   (`--password=x`, `--token x`, `API_KEY=x`, `password=x;` inside a
//!   connection string, `?token=x&` inside a query string);
//! - the password half of `user:password` given to `-u`/`--user` and of a URL's
//!   `scheme://user:password@host`;
//! - the credential following `Bearer` or `Basic` in a header;
//! - a value whose own shape names it as a credential wherever it stands:
//!   cloud access key ids, forge and chat platform tokens, private key
//!   material and JSON web tokens.
//!
//! A secret in a shape this list does not name - a positional argument, a
//! value behind a flag whose name says nothing - is kept, and the notice says
//! so rather than promising a scrub nobody can deliver.

use std::sync::LazyLock;

use regex::Regex;

/// What replaces a removed value.
pub const REDACTED: &str = "[redacted]";

/// Fragments of a flag or key name that say the value is a secret. Compared
/// against the name lowercased with `-` and `_` removed.
const SECRET_NAMES: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "credential",
    "auth",
    "sessionid",
    "cookie",
];

/// Values whose own shape marks them as a credential, wherever they stand.
static CREDENTIAL_SHAPES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        r"|\bgh[pousr]_[0-9A-Za-z]{30,}",
        r"|\bgithub_pat_[0-9A-Za-z_]{30,}",
        r"|\bglpat-[0-9A-Za-z_\-]{20,}",
        r"|\bxox[abprs]-[0-9A-Za-z\-]{10,}",
        r"|\beyJ[0-9A-Za-z_\-]{8,}\.eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]+",
        r"|-----BEGIN [A-Z ]*PRIVATE KEY-----",
    ))
    .expect("the credential shapes are a constant pattern")
});

/// `scheme://user:password@` inside a token.
static URL_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<head>[A-Za-z][A-Za-z0-9+.\-]*://[^:/@\s]*:)[^@/\s]+@")
        .expect("the userinfo pattern is a constant")
});

/// Whether a flag or key name says its value is a secret.
fn names_a_secret(name: &str) -> bool {
    let folded: String = name
        .trim_start_matches('-')
        .chars()
        .filter(|c| *c != '-' && *c != '_' && *c != '.')
        .flat_map(char::to_lowercase)
        .collect();
    !folded.is_empty() && SECRET_NAMES.iter().any(|s| folded.contains(s))
}

/// A token's `key=value` pieces, split on the separators connection and query
/// strings use, with each secret-named value replaced.
fn redact_assignments(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut piece = String::new();
    for c in token.chars() {
        if matches!(c, ';' | '&' | '?') {
            out.push_str(&redact_assignment(&piece));
            out.push(c);
            piece.clear();
        } else {
            piece.push(c);
        }
    }
    out.push_str(&redact_assignment(&piece));
    out
}

fn redact_assignment(piece: &str) -> String {
    match piece.split_once('=') {
        Some((name, value)) if !value.is_empty() && names_a_secret(name) => {
            format!("{name}={REDACTED}")
        }
        _ => piece.to_owned(),
    }
}

/// `user:password` with the password removed, or the token unchanged where
/// it carries no colon.
fn redact_user_pair(token: &str) -> String {
    match token.split_once(':') {
        Some((user, pass)) if !pass.is_empty() => format!("{user}:{REDACTED}"),
        _ => token.to_owned(),
    }
}

/// What the next token is, given the one before it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Nothing,
    /// The value of a flag whose name says it is a secret.
    Secret,
    /// The `user:password` given to `-u` or `--user`.
    UserPair,
}

/// The command line with every secret-bearing shape this module names
/// replaced by [`REDACTED`]. Whitespace between tokens is kept as one space,
/// which is how the capture joins argv in the first place.
#[must_use]
pub fn redact_command_line(line: &str) -> String {
    let mut pending = Pending::Nothing;
    let mut tokens = Vec::new();
    for token in line.split_whitespace() {
        let redacted = match pending {
            Pending::Secret => REDACTED.to_owned(),
            Pending::UserPair => redact_user_pair(token),
            Pending::Nothing => redact_token(token),
        };
        pending = match token {
            "-u" | "--user" | "--proxy-user" => Pending::UserPair,
            _ if pending == Pending::Nothing && is_bare_secret_flag(token) => Pending::Secret,
            _ if token.eq_ignore_ascii_case("bearer") || token.eq_ignore_ascii_case("basic") => {
                Pending::Secret
            }
            _ => Pending::Nothing,
        };
        tokens.push(redacted);
    }
    tokens.join(" ")
}

/// A flag with no `=` whose name says its value follows as the next token.
fn is_bare_secret_flag(token: &str) -> bool {
    token.starts_with("--") && !token.contains('=') && names_a_secret(token)
}

fn redact_token(token: &str) -> String {
    let token = URL_USERINFO.replace_all(token, |c: &regex::Captures<'_>| {
        format!("{}{REDACTED}@", &c["head"])
    });
    let token = CREDENTIAL_SHAPES.replace_all(&token, REDACTED);
    redact_assignments(&token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_named_flag_keeps_its_name_and_loses_its_value() {
        assert_eq!(
            redact_command_line("mysql --user=app --password=hunter2 db"),
            "mysql --user=app --password=[redacted] db"
        );
        assert_eq!(
            redact_command_line("vault login --token s.abcdef --address https://v"),
            "vault login --token [redacted] --address https://v"
        );
        assert_eq!(
            redact_command_line("env API_KEY=abc DB_PASSWORD=x PATH=/bin run"),
            "env API_KEY=[redacted] DB_PASSWORD=[redacted] PATH=/bin run"
        );
    }

    #[test]
    fn a_connection_or_query_string_loses_only_its_secret_pieces() {
        assert_eq!(
            redact_command_line("app Server=db;User Id=sa;Password=p@ss;Database=x"),
            "app Server=db;User Id=sa;Password=[redacted];Database=x"
        );
        assert_eq!(
            redact_command_line("curl https://api.test/v1?user=a&access_token=xyz&page=2"),
            "curl https://api.test/v1?user=a&access_token=[redacted]&page=2"
        );
    }

    #[test]
    fn a_url_keeps_its_user_and_host_and_loses_its_password() {
        assert_eq!(
            redact_command_line("psql postgres://app:s3cret@db.internal:5432/main"),
            "psql postgres://app:[redacted]@db.internal:5432/main"
        );
        assert_eq!(
            redact_command_line("git clone https://github.com/org/repo"),
            "git clone https://github.com/org/repo"
        );
    }

    #[test]
    fn a_user_pair_and_an_authorization_header_lose_the_credential() {
        assert_eq!(
            redact_command_line("curl -u admin:letmein https://example.test"),
            "curl -u admin:[redacted] https://example.test"
        );
        assert_eq!(
            redact_command_line("curl -H Authorization: Bearer abc.def.ghi https://x"),
            "curl -H Authorization: Bearer [redacted] https://x"
        );
        assert_eq!(
            redact_command_line("curl -u admin https://example.test"),
            "curl -u admin https://example.test"
        );
    }

    #[test]
    fn a_value_shaped_like_a_credential_goes_wherever_it_stands() {
        assert_eq!(
            redact_command_line("deploy AKIAABCDEFGHIJKLMNOP eu-west-1"),
            "deploy [redacted] eu-west-1"
        );
        assert_eq!(
            redact_command_line("gh api -f t=ghp_0123456789abcdefghijABCDEFGHIJ0123"),
            "gh api -f t=[redacted]"
        );
        assert_eq!(
            redact_command_line(
                "client eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"
            ),
            "client [redacted]"
        );
    }

    #[test]
    fn a_line_with_nothing_secret_in_it_is_kept_as_typed() {
        let line = "zfs destroy -r tank/home@daily";
        assert_eq!(redact_command_line(line), line);
        assert_eq!(
            redact_command_line("nginx -g daemon off;"),
            "nginx -g daemon off;"
        );
    }

    #[test]
    fn a_positional_secret_is_kept_because_no_shape_names_it() {
        assert_eq!(
            redact_command_line("sshpass -p hunter2 ssh host"),
            "sshpass -p hunter2 ssh host"
        );
    }
}
