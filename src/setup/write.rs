//! Configuration writing.
//!
//! `SET-014`: writes are atomic enough that a runtime reader observes either the
//! complete old file or the complete new one. `CFG-001`: newly created
//! directories and global files are user-only where Unix permissions exist.
//!
//! Values are never written. Only source references are persisted (`SEC-004`),
//! and paths are stored exactly as entered (`CFG-010`).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::SCHEMA_VERSION;
use crate::source::SourceRef;

/// Why a configuration file could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    /// The parent directory could not be created.
    Directory,
    /// The temporary file could not be written.
    Temporary,
    /// The temporary file could not replace the target.
    Replace,
    /// The configuration could not be serialized.
    Serialize,
}

impl WriteError {
    pub fn reason(&self) -> &'static str {
        match self {
            WriteError::Directory => "its directory could not be created",
            WriteError::Temporary => "a temporary file could not be written",
            WriteError::Replace => "the new file could not replace the old one",
            WriteError::Serialize => "the configuration could not be serialized",
        }
    }
}

#[derive(Debug, Serialize)]
struct FileOut {
    version: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    secret: Vec<SecretOut>,
}

#[derive(Debug, Serialize)]
struct SecretOut {
    source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    all: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointer: Option<String>,
}

/// Renders a configuration file exactly as it will be persisted.
pub fn render(sources: &[SourceRef]) -> Result<String, WriteError> {
    let file = FileOut {
        version: SCHEMA_VERSION,
        secret: sources
            .iter()
            .map(|source| match source {
                SourceRef::Env { name } => SecretOut {
                    source: "env",
                    name: Some(name.clone()),
                    file: None,
                    key: None,
                    all: None,
                    pointer: None,
                },
                SourceRef::DotenvKey { entered, key, .. } => SecretOut {
                    source: "dotenv",
                    name: None,
                    file: Some(entered.clone()),
                    key: Some(key.clone()),
                    all: None,
                    pointer: None,
                },
                SourceRef::DotenvAll { entered, .. } => SecretOut {
                    source: "dotenv",
                    name: None,
                    file: Some(entered.clone()),
                    key: None,
                    all: Some(true),
                    pointer: None,
                },
                SourceRef::Json {
                    entered, pointer, ..
                } => SecretOut {
                    source: "json",
                    name: None,
                    file: Some(entered.clone()),
                    key: None,
                    all: None,
                    pointer: Some(pointer.clone()),
                },
            })
            .collect(),
    };
    toml::to_string_pretty(&file).map_err(|_| WriteError::Serialize)
}

/// Writes a configuration file atomically.
///
/// Returns `Ok(false)` when the file already has exactly this content, so a
/// rerun with no changes touches nothing.
pub fn write(path: &Path, sources: &[SourceRef], user_only: bool) -> Result<bool, WriteError> {
    write_text(path, &render(sources)?, user_only)
}

/// Writes any text file atomically, with the same guarantees as `write`.
///
/// Used for configuration and for the integration ownership record.
pub fn write_text(path: &Path, contents: &str, user_only: bool) -> Result<bool, WriteError> {
    if std::fs::read_to_string(path).is_ok_and(|existing| existing == contents) {
        return Ok(false);
    }

    let directory = path.parent().unwrap_or(Path::new("."));
    create_directory(directory, user_only)?;

    let temporary = temporary_path(path);
    write_temporary(&temporary, contents.as_bytes(), user_only).inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })?;

    std::fs::rename(&temporary, path).map_err(|_| {
        let _ = std::fs::remove_file(&temporary);
        WriteError::Replace
    })?;
    Ok(true)
}

fn create_directory(directory: &Path, user_only: bool) -> Result<(), WriteError> {
    if directory.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    if user_only {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory).map_err(|_| WriteError::Directory)
}

fn write_temporary(path: &Path, contents: &[u8], user_only: bool) -> Result<(), WriteError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if user_only {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| WriteError::Temporary)?;
    file.write_all(contents)
        .map_err(|_| WriteError::Temporary)?;
    // Flush to disk before the rename so a crash cannot leave a renamed but
    // empty file behind.
    file.sync_all().map_err(|_| WriteError::Temporary)?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    path.with_file_name(format!(
        ".{name}.contextveil-{}-{sequence}.tmp",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::testing::Canary;

    fn temporary_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "contextveil-write-{name}-{}-{}",
            std::process::id(),
            Canary::generate("WRITE").token()
        ));
        std::fs::create_dir_all(&root).expect("fixture root");
        root
    }

    fn sources() -> Vec<SourceRef> {
        vec![
            SourceRef::Env {
                name: "GITHUB_TOKEN".to_string(),
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
    }

    #[test]
    fn rendered_config_round_trips_through_the_parser() {
        let rendered = render(&sources()).expect("rendered");
        let parsed = config::parse(
            &rendered,
            Path::new("/project"),
            Some(Path::new("/home/user")),
        )
        .expect("the written file parses");
        assert_eq!(parsed.sources, sources());
        assert!(rendered.starts_with("version = 1"));
    }

    #[test]
    fn an_empty_registry_is_still_a_valid_file() {
        let rendered = render(&[]).expect("rendered");
        assert_eq!(rendered.trim(), "version = 1");
        assert!(
            config::parse(&rendered, Path::new("/p"), None)
                .expect("valid")
                .sources
                .is_empty()
        );
    }

    #[test]
    fn paths_are_written_exactly_as_entered() {
        let rendered = render(&sources()).expect("rendered");
        assert!(rendered.contains("\"~/shared/project.env\""));
        assert!(rendered.contains("\".env.local\""));
        assert!(!rendered.contains("/home/user/shared"));
    }

    #[test]
    fn unusual_names_are_escaped_by_the_serializer() {
        let awkward = vec![SourceRef::Env {
            name: "WEIRD\"NAME\\WITH\tESCAPES".to_string(),
        }];
        let rendered = render(&awkward).expect("rendered");
        let parsed = config::parse(&rendered, Path::new("/p"), None).expect("valid");
        assert_eq!(parsed.sources, awkward);
    }

    #[test]
    fn writing_is_idempotent() {
        let root = temporary_root("idempotent");
        let path = root.join("contextveil").join("config.toml");
        assert!(write(&path, &sources(), true).expect("first write"));
        let first = std::fs::read_to_string(&path).expect("read back");
        assert!(!write(&path, &sources(), true).expect("second write"));
        assert_eq!(std::fs::read_to_string(&path).expect("read back"), first);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let root = temporary_root("no-temporary");
        let path = root.join("config.toml");
        write(&path, &sources(), false).expect("write");
        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .expect("read directory")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "config.toml")
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[cfg(unix)]
    fn global_files_and_directories_are_user_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = temporary_root("permissions");
        let path = root.join("contextveil").join("config.toml");
        write(&path, &sources(), true).expect("write");

        let file_mode = std::fs::metadata(&path)
            .expect("file metadata")
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600, "file mode {file_mode:o}");
        let directory_mode = std::fs::metadata(root.join("contextveil"))
            .expect("directory metadata")
            .permissions()
            .mode();
        assert_eq!(
            directory_mode & 0o777,
            0o700,
            "directory mode {directory_mode:o}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_reader_never_observes_a_partial_file() {
        // The new content only becomes visible through an atomic rename, so a
        // reader sees either the previous file or the complete new one.
        let root = temporary_root("atomic");
        let path = root.join("config.toml");
        write(&path, &[], false).expect("first write");
        let before = std::fs::read_to_string(&path).expect("read");
        write(&path, &sources(), false).expect("second write");
        let after = std::fs::read_to_string(&path).expect("read");
        assert_ne!(before, after);
        assert!(config::parse(&before, Path::new("/p"), None).is_ok());
        assert!(config::parse(&after, Path::new("/p"), Some(Path::new("/h"))).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_write_failure_is_classified_without_a_path() {
        let root = temporary_root("failure");
        // A directory where the file should be makes the rename fail.
        let path = root.join("config.toml");
        std::fs::create_dir_all(&path).expect("directory in the way");
        std::fs::write(path.join("occupied"), "x").expect("make the directory non-empty");
        let error = write(&path, &sources(), false).expect_err("write fails");
        assert!(
            !error
                .reason()
                .contains(&root.to_string_lossy().into_owned())
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
