//! Source references and their resolution.
//!
//! V1 has environment, dotenv, and exact-pointer JSON resolver families
//! (`architecture.md`). A resolver returns resolved, unresolved, or malfunction;
//! it never decides whether a value looks secret.
//!
//! `SRC-009`: sources are resolved afresh for every event. The dotenv cache here
//! exists only so one file referenced by several entries is read once per event;
//! it never survives the process. `SRC-010` follows from that: a dotenv edit is
//! visible on the next event, while an environment change needs the harness to be
//! restarted, because the hook inherits the harness environment.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::dotenv::{self, Dotenv, ParseErrorKind};
use crate::json;
use crate::secret::{ResolvedSecret, SourceId};

/// One enrolled source reference from a configuration file.
///
/// `entered` preserves the path exactly as written in the file (`CFG-010`);
/// `path` is its expanded, lexically normalized form used for identity and
/// reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceRef {
    Env {
        name: String,
    },
    DotenvKey {
        entered: String,
        path: PathBuf,
        key: String,
    },
    DotenvAll {
        entered: String,
        path: PathBuf,
    },
    Json {
        entered: String,
        path: PathBuf,
        pointer: String,
        token: String,
    },
}

impl SourceRef {
    pub fn id(&self) -> SourceId {
        match self {
            SourceRef::Env { name } => SourceId::env(name.clone()),
            SourceRef::DotenvKey { path, key, .. } => SourceId::dotenv_key(path.clone(), key),
            SourceRef::DotenvAll { path, .. } => SourceId::dotenv_all(path.clone()),
            SourceRef::Json {
                path,
                pointer,
                token,
                ..
            } => SourceId::json(path.clone(), pointer, token),
        }
    }

    /// The file this reference reads, if any.
    pub fn file(&self) -> Option<&Path> {
        match self {
            SourceRef::Env { .. } => None,
            SourceRef::DotenvKey { path, .. } | SourceRef::DotenvAll { path, .. } => Some(path),
            SourceRef::Json { path, .. } => Some(path),
        }
    }

    /// The dotenv file this reference reads, if any.
    pub fn dotenv_file(&self) -> Option<&Path> {
        match self {
            SourceRef::DotenvKey { path, .. } | SourceRef::DotenvAll { path, .. } => Some(path),
            SourceRef::Env { .. } | SourceRef::Json { .. } => None,
        }
    }
}

/// Why a source has no usable value right now.
///
/// An unresolved source is normal, stays silent during runtime (`RED-009`), and
/// is never a malfunction (`SRC-005`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unresolved {
    /// The environment variable is unset or the dotenv file does not exist.
    Absent,
    /// The dotenv file exists but does not assign the key.
    KeyAbsent,
    /// The configured JSON Pointer does not select a value.
    PointerAbsent,
    /// The value exists but is empty.
    Empty,
    /// An environment value is not valid UTF-8 (`SRC-002`).
    NonUtf8,
    /// The selected JSON value is not a string.
    NotString,
}

impl Unresolved {
    pub fn reason(&self) -> &'static str {
        match self {
            Unresolved::Absent => "is not present",
            Unresolved::KeyAbsent => "is not assigned in its file",
            Unresolved::PointerAbsent => "is not present at its JSON pointer",
            Unresolved::Empty => "is empty",
            Unresolved::NonUtf8 => "is not valid UTF-8",
            Unresolved::NotString => "is not a string at its JSON pointer",
        }
    }
}

/// A source error that disables the entire effective registry (`SRC-006`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMalfunction {
    /// Permission denial or a non-`NotFound` I/O failure.
    Unreadable,
    /// The file is not valid UTF-8.
    NotUtf8,
    /// The file does not match the dotenv grammar.
    Malformed { line: usize, kind: ParseErrorKind },
    /// The file is not a complete valid JSON document.
    MalformedJson,
    /// The JSON document contains a duplicate object member.
    DuplicateJsonMember,
}

impl SourceMalfunction {
    /// Secret-safe reason. It never quotes file content (`SEC-004`).
    pub fn reason(&self) -> String {
        match self {
            SourceMalfunction::Unreadable => "could not be read".to_string(),
            SourceMalfunction::NotUtf8 => "is not valid UTF-8".to_string(),
            SourceMalfunction::Malformed { line, kind } => {
                format!("has a malformed assignment: line {line} {}", kind.reason())
            }
            SourceMalfunction::MalformedJson => "is malformed JSON".to_string(),
            SourceMalfunction::DuplicateJsonMember => {
                "contains a duplicate JSON object member".to_string()
            }
        }
    }
}

/// Result of resolving one source reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Zero or more current values. A wildcard entry can yield many, and an
    /// entry whose keys are all empty yields none.
    Resolved(Vec<ResolvedSecret>),
    Unresolved {
        source: SourceId,
        why: Unresolved,
    },
    Malfunction {
        source: SourceId,
        path: PathBuf,
        why: SourceMalfunction,
    },
}

/// The environment a run resolves against.
///
/// A snapshot is taken once per process so tests can supply a fixed environment
/// without mutating process state.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    variables: HashMap<OsString, OsString>,
}

impl Environment {
    /// Snapshots the environment inherited by this process.
    pub fn from_process() -> Self {
        Self {
            variables: std::env::vars_os().collect(),
        }
    }

    /// Builds a fixed environment for tests and synthetic checks.
    pub fn from_pairs<K, V, I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self {
            variables: pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }

    pub fn get(&self, name: &str) -> Option<&OsStr> {
        self.variables
            .get(OsStr::new(name))
            .map(OsString::as_os_str)
    }

    /// Returns a UTF-8 variable value, or `None` when unset or undecodable.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(OsStr::to_str)
    }

    /// Every UTF-8 variable name in the snapshot, in unspecified order.
    ///
    /// Setup inspects these for name-gated and URL-shaped candidates (`SET-002`).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.variables.keys().filter_map(|name| name.to_str())
    }

    /// The current user's home directory, when known.
    pub fn home(&self) -> Option<PathBuf> {
        self.get_str("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
    }
}

/// State of one dotenv file for the duration of a single event.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileState {
    Missing,
    Parsed(Dotenv),
    Malfunction(SourceMalfunction),
}

#[derive(Debug, Clone, PartialEq)]
enum JsonFileState {
    Missing,
    Parsed(serde_json::Value),
    Malfunction(SourceMalfunction),
}

/// Resolves source references, reading each dotenv file at most once per event.
#[derive(Debug, Clone, Default)]
pub struct Resolver {
    files: HashMap<PathBuf, FileState>,
    json_files: HashMap<PathBuf, JsonFileState>,
}

impl Resolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolves one reference against the environment and filesystem.
    pub fn resolve(&mut self, reference: &SourceRef, environment: &Environment) -> Resolution {
        match reference {
            SourceRef::Env { name } => resolve_environment(name, environment),
            SourceRef::DotenvKey { path, key, .. } => {
                let id = SourceId::dotenv_key(path.clone(), key);
                match self.file(path) {
                    FileState::Missing => Resolution::Unresolved {
                        source: id,
                        why: Unresolved::Absent,
                    },
                    FileState::Malfunction(why) => Resolution::Malfunction {
                        source: id,
                        path: path.clone(),
                        why: *why,
                    },
                    FileState::Parsed(dotenv) => match dotenv.get(key) {
                        None => Resolution::Unresolved {
                            source: id,
                            why: Unresolved::KeyAbsent,
                        },
                        Some("") => Resolution::Unresolved {
                            source: id,
                            why: Unresolved::Empty,
                        },
                        Some(value) => {
                            Resolution::Resolved(vec![ResolvedSecret::new(id, value.to_string())])
                        }
                    },
                }
            }
            SourceRef::DotenvAll { path, .. } => {
                let id = SourceId::dotenv_all(path.clone());
                match self.file(path) {
                    FileState::Missing => Resolution::Unresolved {
                        source: id,
                        why: Unresolved::Absent,
                    },
                    FileState::Malfunction(why) => Resolution::Malfunction {
                        source: id,
                        path: path.clone(),
                        why: *why,
                    },
                    // `SRC-007`: every current non-empty key is enrolled, so keys
                    // added later need no further setup run.
                    FileState::Parsed(dotenv) => Resolution::Resolved(
                        dotenv
                            .entries()
                            .filter(|(_, value)| !value.is_empty())
                            .map(|(key, value)| {
                                ResolvedSecret::new(
                                    SourceId::dotenv_key(path.clone(), key),
                                    value.to_string(),
                                )
                            })
                            .collect(),
                    ),
                }
            }
            SourceRef::Json {
                path,
                pointer,
                token,
                ..
            } => {
                let id = SourceId::json(path.clone(), pointer, token);
                match self.json_file(path) {
                    JsonFileState::Missing => Resolution::Unresolved {
                        source: id,
                        why: Unresolved::Absent,
                    },
                    JsonFileState::Malfunction(why) => Resolution::Malfunction {
                        source: id,
                        path: path.clone(),
                        why: *why,
                    },
                    JsonFileState::Parsed(value) => match json::select(value, pointer) {
                        None => Resolution::Unresolved {
                            source: id,
                            why: Unresolved::PointerAbsent,
                        },
                        Some(serde_json::Value::String(value)) if value.is_empty() => {
                            Resolution::Unresolved {
                                source: id,
                                why: Unresolved::Empty,
                            }
                        }
                        Some(serde_json::Value::String(value)) => {
                            Resolution::Resolved(vec![ResolvedSecret::new(id, value.clone())])
                        }
                        Some(_) => Resolution::Unresolved {
                            source: id,
                            why: Unresolved::NotString,
                        },
                    },
                }
            }
        }
    }

    /// Keys assigned more than once in an already-read file (`SRC-004`).
    pub fn duplicate_keys(&self, path: &Path) -> &[String] {
        match self.files.get(path) {
            Some(FileState::Parsed(dotenv)) => dotenv.duplicates(),
            _ => &[],
        }
    }

    fn file(&mut self, path: &Path) -> &FileState {
        if !self.files.contains_key(path) {
            let state = read_dotenv(path);
            self.files.insert(path.to_path_buf(), state);
        }
        self.files.get(path).expect("the file was just inserted")
    }

    fn json_file(&mut self, path: &Path) -> &JsonFileState {
        if !self.json_files.contains_key(path) {
            let state = read_json(path);
            self.json_files.insert(path.to_path_buf(), state);
        }
        self.json_files
            .get(path)
            .expect("the JSON file was just inserted")
    }
}

fn read_dotenv(path: &Path) -> FileState {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        // `SRC-005`: an absent file is unresolved, not a malfunction.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return FileState::Missing,
        Err(_) => return FileState::Malfunction(SourceMalfunction::Unreadable),
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return FileState::Malfunction(SourceMalfunction::NotUtf8),
    };
    match dotenv::parse(&text) {
        Ok(parsed) => FileState::Parsed(parsed),
        Err(error) => FileState::Malfunction(SourceMalfunction::Malformed {
            line: error.line,
            kind: error.kind,
        }),
    }
}

fn read_json(path: &Path) -> JsonFileState {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return JsonFileState::Missing;
        }
        Err(_) => return JsonFileState::Malfunction(SourceMalfunction::Unreadable),
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return JsonFileState::Malfunction(SourceMalfunction::NotUtf8),
    };
    match json::parse(&text) {
        Ok(value) => JsonFileState::Parsed(value),
        Err(json::ParseError::Malformed) => {
            JsonFileState::Malfunction(SourceMalfunction::MalformedJson)
        }
        Err(json::ParseError::DuplicateMember) => {
            JsonFileState::Malfunction(SourceMalfunction::DuplicateJsonMember)
        }
    }
}

fn resolve_environment(name: &str, environment: &Environment) -> Resolution {
    let id = SourceId::env(name);
    match environment.get(name) {
        None => Resolution::Unresolved {
            source: id,
            why: Unresolved::Absent,
        },
        Some(raw) => match raw.to_str() {
            None => Resolution::Unresolved {
                source: id,
                why: Unresolved::NonUtf8,
            },
            Some("") => Resolution::Unresolved {
                source: id,
                why: Unresolved::Empty,
            },
            Some(value) => Resolution::Resolved(vec![ResolvedSecret::new(id, value.to_string())]),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Canary;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "contextveil-source-{}-{}",
                std::process::id(),
                Canary::generate("SOURCE").token()
            ));
            std::fs::create_dir_all(&root).expect("fixture root");
            Self { root }
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.root.join(name);
            std::fs::write(&path, contents).expect("write fixture file");
            path
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn key_ref(path: &Path, key: &str) -> SourceRef {
        SourceRef::DotenvKey {
            entered: path.to_string_lossy().into_owned(),
            path: path.to_path_buf(),
            key: key.to_string(),
        }
    }

    fn all_ref(path: &Path) -> SourceRef {
        SourceRef::DotenvAll {
            entered: path.to_string_lossy().into_owned(),
            path: path.to_path_buf(),
        }
    }

    fn env_ref(name: &str) -> SourceRef {
        SourceRef::Env {
            name: name.to_string(),
        }
    }

    fn json_ref(path: &Path, pointer: &str) -> SourceRef {
        SourceRef::Json {
            entered: path.to_string_lossy().into_owned(),
            path: path.to_path_buf(),
            pointer: pointer.to_string(),
            token: crate::json::final_token(pointer).expect("valid test pointer"),
        }
    }

    #[test]
    fn a_present_environment_value_resolves_with_a_safe_label() {
        let canary = Canary::generate("GITHUB_TOKEN");
        let environment = Environment::from_pairs([("GITHUB_TOKEN", canary.value())]);
        let mut resolver = Resolver::new();
        match resolver.resolve(&env_ref("GITHUB_TOKEN"), &environment) {
            Resolution::Resolved(secrets) => {
                assert_eq!(secrets.len(), 1);
                assert_eq!(secrets[0].value, canary.value());
                assert_eq!(secrets[0].label, "GITHUB_TOKEN");
            }
            other => panic!("expected a resolved secret, got {other:?}"),
        }
    }

    #[test]
    fn environment_names_are_case_sensitive_and_empty_values_are_unresolved() {
        let environment = Environment::from_pairs([("TOKEN", "value"), ("EMPTY", "")]);
        let mut resolver = Resolver::new();
        assert!(matches!(
            resolver.resolve(&env_ref("token"), &environment),
            Resolution::Unresolved {
                why: Unresolved::Absent,
                ..
            }
        ));
        assert!(matches!(
            resolver.resolve(&env_ref("EMPTY"), &environment),
            Resolution::Unresolved {
                why: Unresolved::Empty,
                ..
            }
        ));
    }

    #[test]
    #[cfg(unix)]
    fn non_utf8_environment_values_never_enter_the_matcher() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = OsString::from_vec(vec![b'a', 0xff]);
        let environment = Environment::from_pairs([(OsString::from("BINARY"), invalid)]);
        let mut resolver = Resolver::new();
        assert!(matches!(
            resolver.resolve(&env_ref("BINARY"), &environment),
            Resolution::Unresolved {
                why: Unresolved::NonUtf8,
                ..
            }
        ));
    }

    #[test]
    fn a_dotenv_key_resolves_to_its_current_value() {
        let canary = Canary::generate("STRIPE_API_KEY");
        let fixture = Fixture::new();
        let path = fixture.write(
            ".env.local",
            &format!("OTHER=1\nSTRIPE_API_KEY={}\n", canary.value()),
        );
        let mut resolver = Resolver::new();
        match resolver.resolve(&key_ref(&path, "STRIPE_API_KEY"), &Environment::default()) {
            Resolution::Resolved(secrets) => {
                assert_eq!(secrets[0].value, canary.value());
                assert_eq!(secrets[0].label, "STRIPE_API_KEY");
            }
            other => panic!("expected a resolved secret, got {other:?}"),
        }
    }

    #[test]
    fn absent_files_keys_and_empty_values_are_unresolved() {
        let fixture = Fixture::new();
        let path = fixture.write(".env", "PRESENT=value\nEMPTY=\n");
        let mut resolver = Resolver::new();
        let environment = Environment::default();

        assert!(matches!(
            resolver.resolve(&key_ref(&fixture.path(".env.missing"), "ANY"), &environment),
            Resolution::Unresolved {
                why: Unresolved::Absent,
                ..
            }
        ));
        assert!(matches!(
            resolver.resolve(&key_ref(&path, "MISSING"), &environment),
            Resolution::Unresolved {
                why: Unresolved::KeyAbsent,
                ..
            }
        ));
        assert!(matches!(
            resolver.resolve(&key_ref(&path, "EMPTY"), &environment),
            Resolution::Unresolved {
                why: Unresolved::Empty,
                ..
            }
        ));
    }

    #[test]
    fn a_wildcard_entry_resolves_every_current_non_empty_key() {
        let first = Canary::generate("A_TOKEN");
        let second = Canary::generate("B_SECRET");
        let fixture = Fixture::new();
        let path = fixture.write(
            ".env",
            &format!(
                "A_TOKEN={}\nEMPTY=\nB_SECRET={}\n",
                first.value(),
                second.value()
            ),
        );
        let mut resolver = Resolver::new();
        match resolver.resolve(&all_ref(&path), &Environment::default()) {
            Resolution::Resolved(secrets) => {
                assert_eq!(secrets.len(), 2);
                assert_eq!(secrets[0].label, "A_TOKEN");
                assert_eq!(secrets[1].label, "B_SECRET");
            }
            other => panic!("expected resolved secrets, got {other:?}"),
        }
    }

    #[test]
    fn malformed_and_invalid_utf8_files_are_malfunctions() {
        let fixture = Fixture::new();
        let malformed = fixture.write(".env.malformed", "A=1\nthis is not an assignment\n");
        let invalid = fixture.path(".env.binary");
        std::fs::write(&invalid, [b'A', b'=', 0xff, b'\n']).expect("write binary fixture");

        let mut resolver = Resolver::new();
        let environment = Environment::default();
        assert!(matches!(
            resolver.resolve(&key_ref(&malformed, "A"), &environment),
            Resolution::Malfunction {
                why: SourceMalfunction::Malformed { line: 2, .. },
                ..
            }
        ));
        assert!(matches!(
            resolver.resolve(&key_ref(&invalid, "A"), &environment),
            Resolution::Malfunction {
                why: SourceMalfunction::NotUtf8,
                ..
            }
        ));
    }

    #[test]
    #[cfg(unix)]
    fn unreadable_dotenv_and_json_files_are_malfunctions() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let path = fixture.write(".env.locked", "A=1\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("remove permissions");

        let mut resolver = Resolver::new();
        let resolution = resolver.resolve(&key_ref(&path, "A"), &Environment::default());
        // A privileged test runner can still read the file; skip in that case.
        if std::fs::read(&path).is_err() {
            assert!(matches!(
                &resolution,
                Resolution::Malfunction {
                    why: SourceMalfunction::Unreadable,
                    ..
                }
            ));
            let mut resolver = Resolver::new();
            assert!(matches!(
                resolver.resolve(&json_ref(&path, "/token"), &Environment::default()),
                Resolution::Malfunction {
                    why: SourceMalfunction::Unreadable,
                    ..
                }
            ));
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    #[test]
    fn a_file_is_read_once_per_event_and_duplicates_are_recorded() {
        let fixture = Fixture::new();
        let path = fixture.write(".env", "A=first\nB=2\nA=second\n");
        let mut resolver = Resolver::new();
        let environment = Environment::default();

        assert!(matches!(
            resolver.resolve(&key_ref(&path, "A"), &environment),
            Resolution::Resolved(_)
        ));
        assert_eq!(resolver.duplicate_keys(&path), ["A"]);

        // Removing the file after the first read must not change this event.
        std::fs::remove_file(&path).expect("remove fixture file");
        match resolver.resolve(&key_ref(&path, "A"), &environment) {
            Resolution::Resolved(secrets) => assert_eq!(secrets[0].value, "second"),
            other => panic!("expected the cached parse, got {other:?}"),
        }
    }

    #[test]
    fn dotenv_labels_derive_from_the_key_never_the_path() {
        let fixture = Fixture::new();
        let path = fixture.write("secret-directory-name.env", "API_KEY=value\n");
        let mut resolver = Resolver::new();
        match resolver.resolve(&key_ref(&path, "API_KEY"), &Environment::default()) {
            Resolution::Resolved(secrets) => {
                assert_eq!(secrets[0].label, "API_KEY");
                assert!(!secrets[0].label.contains("secret-directory-name"));
            }
            other => panic!("expected a resolved secret, got {other:?}"),
        }
    }

    #[test]
    fn a_json_pointer_resolves_only_a_non_empty_string() {
        let canary = Canary::generate("JSON_TOKEN");
        let fixture = Fixture::new();
        let path = fixture.write(
            "auth.json",
            &format!(
                r#"{{"tokens":{{"access/token":"{}","empty":"","null":null,"number":1}}}}"#,
                canary.value()
            ),
        );
        let mut resolver = Resolver::new();
        let environment = Environment::default();

        match resolver.resolve(&json_ref(&path, "/tokens/access~1token"), &environment) {
            Resolution::Resolved(secrets) => {
                assert_eq!(secrets[0].value, canary.value());
                assert_eq!(secrets[0].label, "access_token");
                assert!(!secrets[0].label.contains("auth"));
            }
            other => panic!("expected a resolved JSON string, got {other:?}"),
        }
        assert!(matches!(
            resolver.resolve(&json_ref(&path, "/tokens/missing"), &environment),
            Resolution::Unresolved {
                why: Unresolved::PointerAbsent,
                ..
            }
        ));
        assert!(matches!(
            resolver.resolve(&json_ref(&path, "/tokens/empty"), &environment),
            Resolution::Unresolved {
                why: Unresolved::Empty,
                ..
            }
        ));
        for pointer in ["/tokens/null", "/tokens/number", "/tokens"] {
            assert!(matches!(
                resolver.resolve(&json_ref(&path, pointer), &environment),
                Resolution::Unresolved {
                    why: Unresolved::NotString,
                    ..
                }
            ));
        }
    }

    #[test]
    fn missing_malformed_non_utf8_and_duplicate_json_are_classified() {
        let fixture = Fixture::new();
        let malformed = fixture.write("malformed.json", r#"{"token":}"#);
        let duplicate = fixture.write("duplicate.json", r#"{"token":"a","token":"b"}"#);
        let invalid = fixture.path("invalid.json");
        std::fs::write(&invalid, [b'{', b'"', 0xff, b'"', b':', b'1', b'}'])
            .expect("write invalid UTF-8");
        let environment = Environment::default();

        let cases = [
            (fixture.path("missing.json"), None),
            (malformed, Some(SourceMalfunction::MalformedJson)),
            (duplicate, Some(SourceMalfunction::DuplicateJsonMember)),
            (invalid, Some(SourceMalfunction::NotUtf8)),
        ];
        for (path, malfunction) in cases {
            let resolution = Resolver::new().resolve(&json_ref(&path, "/token"), &environment);
            match malfunction {
                None => assert!(matches!(
                    resolution,
                    Resolution::Unresolved {
                        why: Unresolved::Absent,
                        ..
                    }
                )),
                Some(expected) => assert!(matches!(
                    resolution,
                    Resolution::Malfunction { why, .. } if why == expected
                )),
            }
        }
    }

    #[test]
    fn a_json_file_is_parsed_once_per_event_and_fresh_next_event() {
        let fixture = Fixture::new();
        let path = fixture.write("auth.json", r#"{"first":"one","second":"two"}"#);
        let environment = Environment::default();
        let mut resolver = Resolver::new();
        assert!(matches!(
            resolver.resolve(&json_ref(&path, "/first"), &environment),
            Resolution::Resolved(_)
        ));

        std::fs::write(&path, r#"{"first":"changed","second":"changed"}"#).expect("rotate JSON");
        match resolver.resolve(&json_ref(&path, "/second"), &environment) {
            Resolution::Resolved(secrets) => assert_eq!(secrets[0].value, "two"),
            other => panic!("expected cached event parse, got {other:?}"),
        }
        match Resolver::new().resolve(&json_ref(&path, "/second"), &environment) {
            Resolution::Resolved(secrets) => assert_eq!(secrets[0].value, "changed"),
            other => panic!("expected fresh event parse, got {other:?}"),
        }
    }
}
