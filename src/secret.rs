//! Resolved values and their emit-safe identities.
//!
//! `REG-003` and `REG-004` fix how a label is derived: from the key or name
//! only, never from a path, and reduced to a conservative character set before
//! it can reach a placeholder or a terminal.

use std::path::PathBuf;

/// Identity of one enrolled source (`CFG-006`).
///
/// The path is already expanded and lexically normalized, without filesystem
/// canonicalization or symlink resolution, so identity does not depend on
/// filesystem state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceId {
    /// An environment variable inherited by the hook process.
    Env { name: String },
    /// One key in a dotenv file.
    DotenvKey { path: PathBuf, key: String },
    /// Every current key in a dotenv file.
    DotenvAll { path: PathBuf },
    /// One exact RFC 6901 pointer in a JSON file.
    Json {
        path: PathBuf,
        pointer: String,
        token: String,
    },
}

impl SourceId {
    pub fn env(name: impl Into<String>) -> Self {
        SourceId::Env { name: name.into() }
    }

    pub fn dotenv_key(path: PathBuf, key: impl Into<String>) -> Self {
        SourceId::DotenvKey {
            path,
            key: key.into(),
        }
    }

    pub fn dotenv_all(path: PathBuf) -> Self {
        SourceId::DotenvAll { path }
    }

    pub fn json(path: PathBuf, pointer: impl Into<String>, token: impl Into<String>) -> Self {
        SourceId::Json {
            path,
            pointer: pointer.into(),
            token: token.into(),
        }
    }

    /// The key or name a label derives from. Never a path (`REG-003`).
    ///
    /// A wildcard entry has no key of its own; each value it resolves carries
    /// the identity of the specific key it came from.
    pub fn key(&self) -> Option<&str> {
        match self {
            SourceId::Env { name } => Some(name),
            SourceId::DotenvKey { key, .. } => Some(key),
            SourceId::DotenvAll { .. } => None,
            SourceId::Json { token, .. } => Some(token),
        }
    }

    /// The dotenv file this identity refers to, if any.
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            SourceId::Env { .. } => None,
            SourceId::DotenvKey { path, .. }
            | SourceId::DotenvAll { path }
            | SourceId::Json { path, .. } => Some(path),
        }
    }

    /// Emit-safe label for this source, when it has a key.
    pub fn label(&self) -> Option<String> {
        self.key().map(safe_label)
    }
}

/// A current, non-empty UTF-8 value obtained from an enrolled source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSecret {
    pub value: String,
    pub label: String,
    pub source: SourceId,
}

impl ResolvedSecret {
    /// Builds a resolved secret.
    ///
    /// Only keyed identities resolve to a value, so the label is always
    /// derivable; an identity without a key yields an empty label, which the
    /// matcher then treats as unnamed rather than emitting `<SECRET:>`.
    pub fn new(source: SourceId, value: String) -> Self {
        let label = source.label().unwrap_or_default();
        Self {
            value,
            label,
            source,
        }
    }
}

/// Reduces a key or name to the `REG-004` label character set.
///
/// ASCII letters, digits, `_`, `-`, and `.` are preserved; every other
/// non-empty run collapses to a single `_`. Labels need not be unique.
pub fn safe_label(name: &str) -> String {
    let mut label = String::with_capacity(name.len());
    let mut in_replaced_run = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            label.push(character);
            in_replaced_run = false;
        } else if !in_replaced_run {
            label.push('_');
            in_replaced_run = true;
        }
    }
    label
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_keep_only_the_allowed_character_set() {
        assert_eq!(safe_label("GITHUB_TOKEN"), "GITHUB_TOKEN");
        assert_eq!(safe_label("api.key-1"), "api.key-1");
        assert_eq!(safe_label("weird key!!name"), "weird_key_name");
        assert_eq!(safe_label("ünïcode"), "_n_code");
        assert_eq!(safe_label("   "), "_");
        assert_eq!(safe_label(""), "");
    }

    #[test]
    fn labels_collapse_control_and_escape_sequences() {
        // Terminal-hostile input must not survive into a placeholder.
        assert_eq!(safe_label("A\u{1b}[31mB"), "A_31mB");
        assert_eq!(safe_label("line\nbreak"), "line_break");
        assert_eq!(safe_label("bidi\u{202e}override"), "bidi_override");
    }

    #[test]
    fn labels_derive_from_the_key_only() {
        assert_eq!(
            SourceId::env("GITHUB_TOKEN").label().as_deref(),
            Some("GITHUB_TOKEN")
        );
        assert_eq!(
            SourceId::dotenv_key(PathBuf::from("/secret/path/.env"), "API_KEY")
                .label()
                .as_deref(),
            Some("API_KEY")
        );
        // A wildcard entry has no key, so it has no label.
        assert_eq!(SourceId::dotenv_all(PathBuf::from("/x/.env")).label(), None);
        assert_eq!(
            SourceId::json(PathBuf::from("/secret/auth.json"), "/a~1b", "a/b")
                .label()
                .as_deref(),
            Some("a_b")
        );
    }

    #[test]
    fn identities_distinguish_source_kinds_and_json_pointers() {
        let path = PathBuf::from("/project/.env");
        assert_ne!(
            SourceId::dotenv_key(path.clone(), "A"),
            SourceId::dotenv_all(path.clone())
        );
        assert_ne!(
            SourceId::dotenv_key(path.clone(), "A"),
            SourceId::dotenv_key(path.clone(), "B")
        );
        assert_ne!(SourceId::env("A"), SourceId::env("a"));
        assert_ne!(
            SourceId::json(path.clone(), "/A", "A"),
            SourceId::json(path, "/a", "a")
        );
    }

    #[test]
    fn case_is_preserved_because_names_are_case_sensitive() {
        assert_eq!(safe_label("Token"), "Token");
        assert_ne!(safe_label("Token"), safe_label("TOKEN"));
    }
}
