//! Configuration file locations, parsing, and validation.
//!
//! `CFG-001` fixes the global path, `CFG-002` the project filename, and
//! `CFG-006` through `CFG-010` the schema, source identity, and path handling.
//! Parsing is strict per file, and use of the effective registry is
//! all-or-nothing (`CFG-012`): an invalid or unreadable file disables every
//! redaction for the event rather than contributing part of a matcher.
//!
//! Diagnostics carry a stable classification and a location, never file text.
//! Project configuration is attacker-influenced (`LIM-008`), so parser messages
//! are never echoed.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::paths::{self, PathProblem};
use crate::source::{Environment, SourceRef};

/// The only supported configuration schema version (`CFG-006`).
pub const SCHEMA_VERSION: i64 = 1;

/// A validated configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub sources: Vec<SourceRef>,
}

/// Outcome of loading one configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Load {
    /// The file does not exist. Normal for a project, incomplete setup for the
    /// global file (`CFG-013`).
    Missing,
    Valid(Config),
    Invalid(ConfigError),
}

/// A stable, secret-safe reason a configuration file cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub path: PathBuf,
    pub kind: ConfigErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigErrorKind {
    /// Permission denial or a non-`NotFound` I/O error (`CFG-012`).
    Unreadable,
    /// The file is not valid UTF-8.
    NotUtf8,
    /// TOML syntax error, an unknown field, or a wrongly typed field, at a
    /// one-based position in the file.
    Syntax { line: usize, column: usize },
    /// `version` is absent or is not `1`.
    UnsupportedVersion,
    /// An entry violates `CFG-006` through `CFG-010`.
    InvalidEntry { index: usize, problem: EntryProblem },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryProblem {
    UnknownSourceType,
    /// A field this source type requires is absent.
    MissingRequiredField,
    /// A required field is present but empty.
    EmptyField,
    /// A field the source type does not accept, or two mutually exclusive
    /// fields together (`CFG-007`, `CFG-008`).
    UnexpectedField,
    /// The path cannot be expanded (`CFG-010`).
    InvalidPath(PathProblem),
    /// A JSON pointer is not a supported plain RFC 6901 pointer (`CFG-016`).
    InvalidJsonPointer,
    /// The same source identity appears twice in one file (`CFG-006`).
    DuplicateIdentity,
}

impl ConfigErrorKind {
    /// Short reason suitable for a warning. Contains no file content.
    pub fn reason(&self) -> String {
        match self {
            ConfigErrorKind::Unreadable => "the file could not be read".to_string(),
            ConfigErrorKind::NotUtf8 => "the file is not valid UTF-8".to_string(),
            ConfigErrorKind::Syntax { line, column } => {
                format!("invalid TOML at line {line}, column {column}")
            }
            ConfigErrorKind::UnsupportedVersion => {
                format!("`version = {SCHEMA_VERSION}` is required")
            }
            ConfigErrorKind::InvalidEntry { index, problem } => {
                let position = index + 1;
                format!("secret entry {position} {}", problem.reason())
            }
        }
    }
}

impl EntryProblem {
    fn reason(&self) -> String {
        match self {
            EntryProblem::UnknownSourceType => "uses an unknown source type".to_string(),
            EntryProblem::MissingRequiredField => "is missing a required field".to_string(),
            EntryProblem::EmptyField => "has an empty required field".to_string(),
            EntryProblem::UnexpectedField => {
                "sets a field its source type does not accept".to_string()
            }
            EntryProblem::InvalidPath(problem) => problem.reason().to_string(),
            EntryProblem::InvalidJsonPointer => "has an invalid JSON pointer".to_string(),
            EntryProblem::DuplicateIdentity => "duplicates an earlier source identity".to_string(),
        }
    }
}

/// Returns the global configuration path (`CFG-001`).
///
/// `XDG_CONFIG_HOME` is honored only when it is a non-empty absolute path, as
/// the XDG base directory specification requires.
pub fn global_config_path(environment: &Environment) -> Option<PathBuf> {
    let base = match environment.get_str("XDG_CONFIG_HOME") {
        Some(value) if !value.is_empty() && Path::new(value).is_absolute() => PathBuf::from(value),
        _ => environment.home()?.join(".config"),
    };
    Some(base.join("contextveil").join("config.toml"))
}

/// Loads and validates one configuration file.
///
/// Relative source paths resolve against the directory containing `path`
/// (`CFG-010`).
pub fn load(path: &Path, home: Option<&Path>) -> Load {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Load::Missing,
        Err(_) => {
            return Load::Invalid(ConfigError {
                path: path.to_path_buf(),
                kind: ConfigErrorKind::Unreadable,
            });
        }
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            return Load::Invalid(ConfigError {
                path: path.to_path_buf(),
                kind: ConfigErrorKind::NotUtf8,
            });
        }
    };
    let base = path.parent().unwrap_or(Path::new("."));
    match parse(&text, base, home) {
        Ok(config) => Load::Valid(config),
        Err(kind) => Load::Invalid(ConfigError {
            path: path.to_path_buf(),
            kind,
        }),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: Option<i64>,
    #[serde(default)]
    secret: Vec<RawSecret>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecret {
    source: String,
    name: Option<String>,
    file: Option<String>,
    key: Option<String>,
    all: Option<bool>,
    pointer: Option<String>,
}

/// Parses configuration text strictly (`CFG-006`).
pub fn parse(text: &str, base: &Path, home: Option<&Path>) -> Result<Config, ConfigErrorKind> {
    let raw: RawConfig = toml::from_str(text).map_err(|error| {
        let (line, column) = error
            .span()
            .map(|span| position_of(text, span.start))
            .unwrap_or((1, 1));
        ConfigErrorKind::Syntax { line, column }
    })?;

    if raw.version != Some(SCHEMA_VERSION) {
        return Err(ConfigErrorKind::UnsupportedVersion);
    }

    let mut sources: Vec<SourceRef> = Vec::with_capacity(raw.secret.len());
    for (index, entry) in raw.secret.iter().enumerate() {
        let source = parse_entry(entry, base, home)
            .map_err(|problem| ConfigErrorKind::InvalidEntry { index, problem })?;
        let identity = source.id();
        if sources.iter().any(|existing| existing.id() == identity) {
            return Err(ConfigErrorKind::InvalidEntry {
                index,
                problem: EntryProblem::DuplicateIdentity,
            });
        }
        sources.push(source);
    }

    Ok(Config { sources })
}

fn parse_entry(
    entry: &RawSecret,
    base: &Path,
    home: Option<&Path>,
) -> Result<SourceRef, EntryProblem> {
    match entry.source.as_str() {
        // `CFG-007`: one non-empty `name` and no dotenv-only fields.
        "env" => {
            if entry.file.is_some()
                || entry.key.is_some()
                || entry.all.is_some()
                || entry.pointer.is_some()
            {
                return Err(EntryProblem::UnexpectedField);
            }
            let name = entry
                .name
                .as_deref()
                .ok_or(EntryProblem::MissingRequiredField)?;
            if name.is_empty() {
                return Err(EntryProblem::EmptyField);
            }
            Ok(SourceRef::Env {
                name: name.to_string(),
            })
        }
        // `CFG-008`: one non-empty `file` plus exactly one of `key` or
        // `all = true`.
        "dotenv" => {
            if entry.name.is_some() || entry.pointer.is_some() {
                return Err(EntryProblem::UnexpectedField);
            }
            let file = entry
                .file
                .as_deref()
                .ok_or(EntryProblem::MissingRequiredField)?;
            if file.is_empty() {
                return Err(EntryProblem::EmptyField);
            }
            let path = paths::expand(file, base, home).map_err(EntryProblem::InvalidPath)?;
            let wildcard = entry.all.unwrap_or(false);
            match (&entry.key, wildcard) {
                (Some(_), true) => Err(EntryProblem::UnexpectedField),
                (Some(key), false) => {
                    if key.is_empty() {
                        return Err(EntryProblem::EmptyField);
                    }
                    Ok(SourceRef::DotenvKey {
                        entered: file.to_string(),
                        path,
                        key: key.clone(),
                    })
                }
                (None, true) => Ok(SourceRef::DotenvAll {
                    entered: file.to_string(),
                    path,
                }),
                (None, false) => Err(EntryProblem::MissingRequiredField),
            }
        }
        // `CFG-016`: an explicit file and one exact plain RFC 6901 pointer.
        "json" => {
            if entry.name.is_some() || entry.key.is_some() || entry.all.is_some() {
                return Err(EntryProblem::UnexpectedField);
            }
            let file = entry
                .file
                .as_deref()
                .ok_or(EntryProblem::MissingRequiredField)?;
            let pointer = entry
                .pointer
                .as_deref()
                .ok_or(EntryProblem::MissingRequiredField)?;
            if file.is_empty() || pointer.is_empty() {
                return Err(EntryProblem::EmptyField);
            }
            let token =
                crate::json::final_token(pointer).map_err(|_| EntryProblem::InvalidJsonPointer)?;
            let path = paths::expand(file, base, home).map_err(EntryProblem::InvalidPath)?;
            Ok(SourceRef::Json {
                entered: file.to_string(),
                path,
                pointer: pointer.to_string(),
                token,
            })
        }
        _ => Err(EntryProblem::UnknownSourceType),
    }
}

/// Converts a byte offset into a one-based line and column.
fn position_of(text: &str, offset: usize) -> (usize, usize) {
    // The reported span comes from the parser and is only used for slicing, so
    // it is clamped to a character boundary rather than trusted.
    let mut clamped = offset.min(text.len());
    while clamped > 0 && !text.is_char_boundary(clamped) {
        clamped -= 1;
    }
    let prefix = &text[..clamped];
    let line = prefix.matches('\n').count() + 1;
    let column = prefix
        .rfind('\n')
        .map(|index| prefix[index + 1..].chars().count() + 1)
        .unwrap_or_else(|| prefix.chars().count() + 1);
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "/project";
    const HOME: &str = "/home/user";

    fn parse_text(text: &str) -> Result<Config, ConfigErrorKind> {
        parse(text, Path::new(BASE), Some(Path::new(HOME)))
    }

    fn entry_problem(text: &str) -> EntryProblem {
        match parse_text(text) {
            Err(ConfigErrorKind::InvalidEntry { problem, .. }) => problem,
            other => panic!("expected an invalid entry, got {other:?}"),
        }
    }

    #[test]
    fn the_documented_schema_parses() {
        let config = parse_text(
            r#"
version = 1

[[secret]]
source = "env"
name = "GITHUB_TOKEN"

[[secret]]
source = "dotenv"
file = ".env.local"
key = "STRIPE_API_KEY"

[[secret]]
source = "dotenv"
file = "~/shared/project.env"
all = true

[[secret]]
source = "json"
file = "~/.codex/auth.json"
pointer = "/tokens/access_token"
"#,
        )
        .expect("valid config");

        assert_eq!(
            config.sources,
            vec![
                SourceRef::Env {
                    name: "GITHUB_TOKEN".to_string()
                },
                SourceRef::DotenvKey {
                    entered: ".env.local".to_string(),
                    path: PathBuf::from("/project/.env.local"),
                    key: "STRIPE_API_KEY".to_string(),
                },
                SourceRef::DotenvAll {
                    entered: "~/shared/project.env".to_string(),
                    path: PathBuf::from("/home/user/shared/project.env"),
                },
                SourceRef::Json {
                    entered: "~/.codex/auth.json".to_string(),
                    path: PathBuf::from("/home/user/.codex/auth.json"),
                    pointer: "/tokens/access_token".to_string(),
                    token: "access_token".to_string(),
                },
            ]
        );
    }

    #[test]
    fn an_empty_registry_is_valid() {
        assert_eq!(parse_text("version = 1\n"), Ok(Config { sources: vec![] }));
    }

    #[test]
    fn the_version_is_required_and_pinned() {
        assert_eq!(
            parse_text("[[secret]]\nsource = \"env\"\nname = \"A\"\n"),
            Err(ConfigErrorKind::UnsupportedVersion)
        );
        assert_eq!(
            parse_text("version = 2\n"),
            Err(ConfigErrorKind::UnsupportedVersion)
        );
        assert_eq!(
            parse_text("version = \"1\"\n"),
            Err(ConfigErrorKind::Syntax {
                line: 1,
                column: 11
            })
        );
    }

    #[test]
    fn unknown_fields_invalidate_the_file() {
        assert!(matches!(
            parse_text("version = 1\nunexpected = true\n"),
            Err(ConfigErrorKind::Syntax { .. })
        ));
        assert!(matches!(
            parse_text("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"A\"\nextra = 1\n"),
            Err(ConfigErrorKind::Syntax { .. })
        ));
    }

    #[test]
    fn environment_entries_reject_dotenv_fields() {
        assert_eq!(
            entry_problem(
                "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"A\"\nfile = \".env\"\n"
            ),
            EntryProblem::UnexpectedField
        );
        assert_eq!(
            entry_problem("version = 1\n\n[[secret]]\nsource = \"env\"\n"),
            EntryProblem::MissingRequiredField
        );
        assert_eq!(
            entry_problem("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"\"\n"),
            EntryProblem::EmptyField
        );
    }

    #[test]
    fn dotenv_entries_require_exactly_one_of_key_or_all() {
        assert_eq!(
            entry_problem(
                "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nkey = \"A\"\nall = true\n"
            ),
            EntryProblem::UnexpectedField
        );
        assert_eq!(
            entry_problem("version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\n"),
            EntryProblem::MissingRequiredField
        );
        assert_eq!(
            entry_problem(
                "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nkey = \"\"\n"
            ),
            EntryProblem::EmptyField
        );
        assert_eq!(
            entry_problem("version = 1\n\n[[secret]]\nsource = \"dotenv\"\nkey = \"A\"\n"),
            EntryProblem::MissingRequiredField
        );
        assert_eq!(
            entry_problem(
                "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nname = \"A\"\nkey = \"B\"\n"
            ),
            EntryProblem::UnexpectedField
        );
    }

    #[test]
    fn unknown_source_types_invalidate_the_file() {
        assert_eq!(
            entry_problem("version = 1\n\n[[secret]]\nsource = \"keychain\"\nname = \"A\"\n"),
            EntryProblem::UnknownSourceType
        );
    }

    #[test]
    fn json_entries_are_strict_and_require_a_supported_pointer() {
        for text in [
            "version = 1\n\n[[secret]]\nsource = \"json\"\npointer = \"/token\"\n",
            "version = 1\n\n[[secret]]\nsource = \"json\"\nfile = \"auth.json\"\n",
        ] {
            assert_eq!(entry_problem(text), EntryProblem::MissingRequiredField);
        }
        for pointer in ["", "/", "/tokens/", "#/token", "token", "/tokens/*", "/~2"] {
            let text = format!(
                "version = 1\n\n[[secret]]\nsource = \"json\"\nfile = \"auth.json\"\npointer = {pointer:?}\n"
            );
            assert!(matches!(
                entry_problem(&text),
                EntryProblem::EmptyField | EntryProblem::InvalidJsonPointer
            ));
        }
        for field in ["name = \"A\"", "key = \"A\"", "all = false"] {
            let text = format!(
                "version = 1\n\n[[secret]]\nsource = \"json\"\nfile = \"auth.json\"\npointer = \"/token\"\n{field}\n"
            );
            assert_eq!(entry_problem(&text), EntryProblem::UnexpectedField);
        }
    }

    #[test]
    fn json_identity_uses_the_normalized_path_and_exact_case_sensitive_pointer() {
        let duplicate = "version = 1\n\n[[secret]]\nsource = \"json\"\nfile = \"auth.json\"\npointer = \"/Token\"\n\n[[secret]]\nsource = \"json\"\nfile = \"./nested/../auth.json\"\npointer = \"/Token\"\n";
        assert_eq!(entry_problem(duplicate), EntryProblem::DuplicateIdentity);

        let distinct = "version = 1\n\n[[secret]]\nsource = \"json\"\nfile = \"auth.json\"\npointer = \"/Token\"\n\n[[secret]]\nsource = \"json\"\nfile = \"auth.json\"\npointer = \"/token\"\n";
        assert_eq!(
            parse_text(distinct)
                .expect("distinct pointers")
                .sources
                .len(),
            2
        );
    }

    #[test]
    fn identity_is_computed_after_expansion_and_normalization() {
        // `CFG-006`: these two entries name the same file through different
        // spellings and are therefore duplicates.
        let text = "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nkey = \"A\"\n\n[[secret]]\nsource = \"dotenv\"\nfile = \"./sub/../.env\"\nkey = \"A\"\n";
        assert_eq!(entry_problem(text), EntryProblem::DuplicateIdentity);
    }

    #[test]
    fn a_keyed_entry_and_a_wildcard_entry_for_one_file_may_coexist() {
        let config = parse_text(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nkey = \"A\"\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nall = true\n",
        )
        .expect("valid config");
        assert_eq!(config.sources.len(), 2);
    }

    #[test]
    fn duplicate_identities_in_one_file_are_rejected() {
        assert_eq!(
            entry_problem(
                "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"A\"\n\n[[secret]]\nsource = \"env\"\nname = \"A\"\n"
            ),
            EntryProblem::DuplicateIdentity
        );
        assert_eq!(
            entry_problem(
                "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nall = true\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nall = true\n"
            ),
            EntryProblem::DuplicateIdentity
        );
    }

    #[test]
    fn names_and_keys_are_case_sensitive_so_variants_are_distinct() {
        let config = parse_text(
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"A\"\n\n[[secret]]\nsource = \"env\"\nname = \"a\"\n",
        )
        .expect("valid config");
        assert_eq!(config.sources.len(), 2);
    }

    #[test]
    fn paths_are_stored_as_entered() {
        // `CFG-010`: the entered spelling is preserved for rewriting the file.
        let config = parse_text(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \"~/shared/.env\"\nkey = \"A\"\n",
        )
        .expect("valid config");
        match &config.sources[0] {
            SourceRef::DotenvKey { entered, path, .. } => {
                assert_eq!(entered, "~/shared/.env");
                assert_eq!(path, &PathBuf::from("/home/user/shared/.env"));
            }
            other => panic!("expected a dotenv key entry, got {other:?}"),
        }
    }

    #[test]
    fn a_tilde_path_without_a_home_is_an_invalid_entry() {
        let error = parse(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \"~/x/.env\"\nkey = \"A\"\n",
            Path::new(BASE),
            None,
        );
        assert_eq!(
            error,
            Err(ConfigErrorKind::InvalidEntry {
                index: 0,
                problem: EntryProblem::InvalidPath(PathProblem::NoHome)
            })
        );
    }

    #[test]
    fn project_config_may_reference_external_paths_and_environment_names() {
        // `CFG-009` and `LIM-008`: allowed by design, and reviewed by the user.
        let config = parse_text(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \"/etc/app/.env\"\nall = true\n\n[[secret]]\nsource = \"env\"\nname = \"HOME_TOKEN\"\n",
        )
        .expect("valid config");
        assert_eq!(config.sources.len(), 2);
    }

    #[test]
    fn diagnostics_never_quote_file_content() {
        let error = parse_text("version = 1\nthis is not toml\n").expect_err("invalid");
        match error {
            ConfigErrorKind::Syntax { line, .. } => assert_eq!(line, 2),
            other => panic!("expected a syntax error, got {other:?}"),
        }
        assert!(!error.reason().contains("this is not toml"));
    }

    #[test]
    fn the_global_path_follows_xdg_rules() {
        let with_xdg = Environment::from_pairs([("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/home/a")]);
        assert_eq!(
            global_config_path(&with_xdg),
            Some(PathBuf::from("/xdg/contextveil/config.toml"))
        );

        let without_xdg = Environment::from_pairs([("HOME", "/home/a")]);
        assert_eq!(
            global_config_path(&without_xdg),
            Some(PathBuf::from("/home/a/.config/contextveil/config.toml"))
        );

        // A relative or empty XDG_CONFIG_HOME is ignored, per the XDG spec.
        let relative = Environment::from_pairs([("XDG_CONFIG_HOME", "relative"), ("HOME", "/h")]);
        assert_eq!(
            global_config_path(&relative),
            Some(PathBuf::from("/h/.config/contextveil/config.toml"))
        );
        let empty = Environment::from_pairs([("XDG_CONFIG_HOME", ""), ("HOME", "")]);
        assert_eq!(global_config_path(&empty), None);
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let path = std::env::temp_dir().join("contextveil-missing-config-does-not-exist.toml");
        assert_eq!(load(&path, None), Load::Missing);
    }

    #[test]
    fn relative_paths_resolve_against_the_config_file_directory() {
        let root = std::env::temp_dir().join(format!(
            "contextveil-config-{}-{}",
            std::process::id(),
            crate::testing::Canary::generate("CONFIG").token()
        ));
        std::fs::create_dir_all(root.join("nested")).expect("fixture directories");
        let config_path = root.join("nested").join(".contextveil.toml");
        std::fs::write(
            &config_path,
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nkey = \"A\"\n",
        )
        .expect("write config");

        match load(&config_path, None) {
            Load::Valid(config) => assert_eq!(
                config.sources[0].file(),
                Some(root.join("nested").join(".env").as_path())
            ),
            other => panic!("expected a valid config, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
