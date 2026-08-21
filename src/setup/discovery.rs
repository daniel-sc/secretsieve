//! Bounded project and dotenv discovery for setup.
//!
//! `SET-003` governs recursive project discovery and `SET-004` the bounded
//! global probe. Both refuse to follow symlinks or touch special files, so
//! discovery cannot be steered into reading a device, a FIFO, or a location
//! outside the tree being inspected.
//!
//! A file whose project-relative path is not valid UTF-8 cannot be represented
//! in TOML (`LIM-022`); it is reported as unavailable using `SEC-006` rendering
//! and skipped.

use std::path::{Path, PathBuf};

use crate::dotenv::{self, Dotenv, ParseErrorKind};
use crate::sanitize;

/// Directories never entered by project discovery or collision analysis.
///
/// `SET-003` requires excluding `.git` and maintained dependency, vendor, and
/// build directories. The exact list is tactical (`architecture.md`).
pub const EXCLUDED_DIRECTORIES: [&str; 30] = [
    ".git",
    ".hg",
    ".svn",
    ".jj",
    "node_modules",
    "bower_components",
    "vendor",
    "target",
    "build",
    "dist",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".parcel-cache",
    ".gradle",
    ".m2",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    ".yarn",
    ".pnpm-store",
    "Pods",
    "DerivedData",
];

/// A discovered dotenv file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Absolute, lexically normalized path.
    pub path: PathBuf,
    /// Display form, already sanitized for terminal output.
    pub display: String,
    /// Path exactly as it should be written into configuration (`CFG-010`).
    pub entered: Option<String>,
    pub state: State,
}

/// Files recognized during the one bounded project traversal.
#[derive(Debug, Default)]
pub struct ProjectFiles {
    pub dotenv: Vec<Discovered>,
    pub claude_settings: Vec<PathBuf>,
    pub claude_mcp: Vec<PathBuf>,
}

/// Whether a discovered file can be offered as a candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Available(Dotenv),
    /// Shown as unavailable and excluded from candidates (`SET-013`).
    Unavailable(Unavailable),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// The path cannot be represented losslessly in TOML (`LIM-022`).
    NonUtf8Path,
    Unreadable,
    NotUtf8,
    Malformed {
        line: usize,
        kind: ParseErrorKind,
    },
}

impl Unavailable {
    pub fn reason(&self) -> String {
        match self {
            Unavailable::NonUtf8Path => "its path is not valid UTF-8".to_string(),
            Unavailable::Unreadable => "it could not be read".to_string(),
            Unavailable::NotUtf8 => "it is not valid UTF-8".to_string(),
            Unavailable::Malformed { line, kind } => {
                format!("line {line} {}", kind.reason())
            }
        }
    }
}

/// True when a file name is a dotenv file for discovery purposes (`SET-003`).
pub fn is_dotenv_name(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.")
}

/// Name matching over raw bytes.
///
/// A matching file whose name is not valid UTF-8 must still be reported as
/// unavailable rather than silently skipped (`SET-003`, `LIM-022`), so the check
/// cannot require a decodable name.
fn is_dotenv_file_name(name: &std::ffi::OsStr) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = name.as_bytes();
        bytes == b".env" || bytes.starts_with(b".env.")
    }
    #[cfg(not(unix))]
    {
        name.to_str().is_some_and(is_dotenv_name)
    }
}

/// Recursively discovers project dotenv files (`SET-003`).
///
/// Ignored and untracked files are included deliberately: a credential is just
/// as reachable whether or not version control tracks it.
pub fn project_dotenv_files(project_root: &Path) -> Vec<Discovered> {
    project_files(project_root).dotenv
}

/// Collects dotenv and narrowly anchored Known Source paths in one walk.
pub fn project_files(project_root: &Path) -> ProjectFiles {
    let mut found = ProjectFiles::default();
    walk(project_root, project_root, &mut found);
    found
        .dotenv
        .sort_by(|left, right| left.path.cmp(&right.path));
    found.claude_settings.sort();
    found.claude_mcp.sort();
    found
}

fn walk(root: &Path, directory: &Path, found: &mut ProjectFiles) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `symlink_metadata` never follows the link, so a symlinked file or
        // directory is skipped rather than traversed (`SET-003`).
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let name = entry.file_name();
            let excluded = name
                .to_str()
                .is_some_and(|name| EXCLUDED_DIRECTORIES.contains(&name));
            if !excluded {
                walk(root, &path, found);
            }
            continue;
        }
        if !metadata.is_file() {
            // FIFOs, devices, sockets, and other special files are never read.
            continue;
        }
        if is_dotenv_file_name(&entry.file_name()) {
            found
                .dotenv
                .push(inspect(&path, relative_entry(root, &path)));
        } else if entry.file_name() == "settings.json"
            && path.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new(".claude"))
        {
            found.claude_settings.push(path);
        } else if entry.file_name() == ".mcp.json" {
            found.claude_mcp.push(path);
        }
    }
}

/// Probes the bounded global locations in `SET-004`.
///
/// The home directory and the supported harness configuration directories are
/// inspected directly; neither is crawled recursively.
pub fn global_dotenv_files(home: &Path) -> Vec<Discovered> {
    let mut directories = vec![home.to_path_buf()];
    for harness in [".claude", ".codex", ".copilot"] {
        directories.push(home.join(harness));
    }
    for config in ["opencode", "contextveil"] {
        directories.push(home.join(".config").join(config));
    }

    let mut found = Vec::new();
    for directory in directories {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                continue;
            }
            if !is_dotenv_file_name(&entry.file_name()) {
                continue;
            }
            found.push(inspect(&path, home_entry(home, &path)));
        }
    }
    found.sort_by(|left, right| left.path.cmp(&right.path));
    found
}

/// Reads and parses one discovered file (`SET-013`).
pub fn inspect(path: &Path, entered: Option<String>) -> Discovered {
    let display = sanitize::path(path);
    if entered.is_none() {
        return Discovered {
            path: path.to_path_buf(),
            display,
            entered,
            state: State::Unavailable(Unavailable::NonUtf8Path),
        };
    }

    let state = match std::fs::read(path) {
        Err(_) => State::Unavailable(Unavailable::Unreadable),
        Ok(bytes) => match String::from_utf8(bytes) {
            Err(_) => State::Unavailable(Unavailable::NotUtf8),
            Ok(text) => match dotenv::parse(&text) {
                Ok(parsed) => State::Available(parsed),
                Err(error) => State::Unavailable(Unavailable::Malformed {
                    line: error.line,
                    kind: error.kind,
                }),
            },
        },
    };

    Discovered {
        path: path.to_path_buf(),
        display,
        entered,
        state,
    }
}

/// Project-relative path to store in configuration, when it is valid UTF-8.
fn relative_entry(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    relative.to_str().map(str::to_string)
}

/// Home-relative path in the `~/` form the specification uses (`CFG-010`).
fn home_entry(home: &Path, path: &Path) -> Option<String> {
    match path.strip_prefix(home) {
        Ok(relative) => relative.to_str().map(|tail| format!("~/{tail}")),
        Err(_) => path.to_str().map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Canary;

    struct Tree {
        root: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "contextveil-discovery-{}-{}",
                std::process::id(),
                Canary::generate("TREE").token()
            ));
            std::fs::create_dir_all(&root).expect("fixture root");
            Self { root }
        }

        fn file(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("fixture directories");
            }
            std::fs::write(&path, contents).expect("write fixture file");
            path
        }

        fn directory(&self, relative: &str) -> PathBuf {
            let path = self.root.join(relative);
            std::fs::create_dir_all(&path).expect("fixture directory");
            path
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn entries(found: &[Discovered]) -> Vec<String> {
        found
            .iter()
            .map(|item| item.entered.clone().unwrap_or_default())
            .collect()
    }

    #[test]
    fn discovery_is_recursive_and_includes_untracked_files() {
        let tree = Tree::new();
        tree.file(".env", "A=1\n");
        tree.file(".env.local", "B=2\n");
        tree.file("packages/app/.env.production", "C=3\n");
        tree.file(".gitignore", ".env*\n");
        tree.file("README.md", "not a dotenv\n");
        tree.file("env", "not a dotenv\n");
        tree.file(".environment", "not a dotenv\n");

        let found = project_dotenv_files(&tree.root);
        let names = entries(&found);
        assert!(names.contains(&".env".to_string()));
        assert!(names.contains(&".env.local".to_string()));
        assert!(names.iter().any(|name| name.ends_with(".env.production")));
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn one_project_walk_collects_only_anchored_known_source_json() {
        let tree = Tree::new();
        tree.file("app/.claude/settings.json", "{}");
        tree.file("app/.mcp.json", "{}");
        tree.file("app/settings.json", "{}");
        tree.file("app/auth.json", "{}");
        tree.file("app/.claude/nested/settings.json", "{}");

        let found = project_files(&tree.root);
        assert_eq!(
            found.claude_settings,
            vec![tree.root.join("app/.claude/settings.json")]
        );
        assert_eq!(found.claude_mcp, vec![tree.root.join("app/.mcp.json")]);
        assert!(found.dotenv.is_empty());
    }

    #[test]
    fn excluded_directories_are_never_entered() {
        let tree = Tree::new();
        tree.file(".env", "A=1\n");
        tree.file(".git/.env", "LEAK=1\n");
        tree.file("node_modules/pkg/.env", "LEAK=1\n");
        tree.file("target/debug/.env", "LEAK=1\n");
        tree.file("vendor/.env", "LEAK=1\n");

        let found = project_dotenv_files(&tree.root);
        assert_eq!(entries(&found), vec![".env".to_string()]);
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_and_special_files_are_skipped() {
        let tree = Tree::new();
        tree.file("real/.env", "A=1\n");
        let outside = tree.directory("outside");
        std::fs::write(outside.join(".env.secret"), "B=2\n").expect("write outside file");

        std::os::unix::fs::symlink(outside.join(".env.secret"), tree.root.join(".env.link"))
            .expect("file symlink");
        std::os::unix::fs::symlink(&outside, tree.root.join("linked-dir")).expect("dir symlink");

        let found = project_dotenv_files(&tree.root.join("real"));
        assert_eq!(entries(&found), vec![".env".to_string()]);

        let all = project_dotenv_files(&tree.root);
        // The symlinked file and the symlinked directory are both skipped; the
        // real file inside `outside/` is still found because it is a real child.
        assert!(!entries(&all).iter().any(|name| name.contains("link")));
    }

    #[test]
    #[cfg(unix)]
    fn a_fifo_named_like_a_dotenv_file_is_never_read() {
        let tree = Tree::new();
        let fifo = tree.root.join(".env.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(status.success());
        // Reading this path would block forever, so discovery must skip it.
        assert!(project_dotenv_files(&tree.root).is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn non_utf8_paths_are_reported_as_unavailable() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let tree = Tree::new();
        let name = OsString::from_vec(vec![b'.', b'e', b'n', b'v', b'.', 0xff]);
        let path = tree.root.join(&name);

        // Reporting such a path never reads it, so this half holds even where the
        // filesystem cannot hold the name at all.
        let inspected = inspect(&path, None);
        assert_eq!(
            inspected.state,
            State::Unavailable(Unavailable::NonUtf8Path)
        );
        assert!(inspected.display.contains("\\xff"));
        assert!(!inspected.display.contains('\u{fffd}'));

        // `LIM-022`: APFS rejects file names that are not valid UTF-8, so the
        // discovery half only runs on a filesystem that accepts one.
        if std::fs::write(&path, "A=1\n").is_err() {
            return;
        }

        let found = project_dotenv_files(&tree.root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entered, None);
        assert_eq!(found[0].state, State::Unavailable(Unavailable::NonUtf8Path));
        assert!(found[0].display.contains("\\xff"));
        assert!(!found[0].display.contains('\u{fffd}'));
    }

    #[test]
    fn malformed_and_unreadable_files_are_marked_unavailable() {
        let tree = Tree::new();
        tree.file(".env", "A=1\n");
        tree.file(".env.broken", "A=1\nnot an assignment\n");
        let binary = tree.root.join(".env.binary");
        std::fs::write(&binary, [b'A', b'=', 0xff, b'\n']).expect("write binary file");

        let found = project_dotenv_files(&tree.root);
        let broken = found
            .iter()
            .find(|item| item.path.ends_with(".env.broken"))
            .expect("the malformed file is listed");
        assert!(matches!(
            broken.state,
            State::Unavailable(Unavailable::Malformed { line: 2, .. })
        ));
        let binary = found
            .iter()
            .find(|item| item.path.ends_with(".env.binary"))
            .expect("the binary file is listed");
        assert_eq!(binary.state, State::Unavailable(Unavailable::NotUtf8));
        // Discovery continues past an unavailable file.
        assert!(
            found
                .iter()
                .any(|item| matches!(item.state, State::Available(_)))
        );
    }

    #[test]
    fn unavailable_reasons_never_quote_file_content() {
        let tree = Tree::new();
        tree.file(".env.broken", "SECRET_LOOKING_LINE\n");
        let found = project_dotenv_files(&tree.root);
        let reason = match &found[0].state {
            State::Unavailable(why) => why.reason(),
            State::Available(_) => panic!("expected an unavailable file"),
        };
        assert!(!reason.contains("SECRET_LOOKING_LINE"));
    }

    #[test]
    fn global_probing_is_bounded_to_the_documented_locations() {
        let tree = Tree::new();
        let home = tree.directory("home");
        std::fs::write(home.join(".env"), "A=1\n").expect("home dotenv");
        std::fs::create_dir_all(home.join(".claude")).expect("claude directory");
        std::fs::write(home.join(".claude").join(".env.local"), "B=2\n").expect("claude dotenv");
        std::fs::create_dir_all(home.join(".config").join("opencode")).expect("opencode directory");
        std::fs::write(home.join(".config").join("opencode").join(".env"), "C=3\n")
            .expect("opencode dotenv");
        // Not probed: a nested project directory under home.
        std::fs::create_dir_all(home.join("projects").join("app")).expect("nested directory");
        std::fs::write(home.join("projects").join("app").join(".env"), "D=4\n")
            .expect("nested dotenv");

        let found = global_dotenv_files(&home);
        let names = entries(&found);
        assert!(names.contains(&"~/.env".to_string()));
        assert!(names.contains(&"~/.claude/.env.local".to_string()));
        assert!(names.contains(&"~/.config/opencode/.env".to_string()));
        assert!(!names.iter().any(|name| name.contains("projects")));
    }

    #[test]
    fn dotenv_name_matching_follows_the_specification() {
        assert!(is_dotenv_name(".env"));
        assert!(is_dotenv_name(".env.local"));
        assert!(is_dotenv_name(".env."));
        assert!(!is_dotenv_name("env"));
        assert!(!is_dotenv_name(".environment"));
        assert!(!is_dotenv_name("local.env"));
        assert!(!is_dotenv_name(".ENV"));
    }
}
