//! Collision analysis for setup candidates.
//!
//! `SET-011`: search readable regular-file bytes under the current selected
//! project root using the discovery exclusions, include ignored files, exclude
//! every equal-value alias source file, never follow symlinks, and skip
//! special files. Occurrences are counted as non-overlapping exact byte matches
//! from left to right, including inside binary or non-UTF-8 files.
//!
//! `SET-012`: report counts and sanitized relative filenames only, never values,
//! matched lines, or snippets. Findings are advisory (`DIA-004`), so skipped
//! files need not be reported.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::sanitize;
use crate::setup::discovery::EXCLUDED_DIRECTORIES;

/// Where a candidate value also occurs inside the project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collisions {
    pub total: usize,
    /// Sanitized project-relative filenames with their occurrence counts.
    pub files: Vec<(String, usize)>,
}

impl Collisions {
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// One-line advisory summary. It contains no value or matched text.
    pub fn describe(&self) -> String {
        let files: Vec<String> = self
            .files
            .iter()
            .take(3)
            .map(|(name, count)| format!("{name} x{count}"))
            .collect();
        let more = self.files.len().saturating_sub(files.len());
        let suffix = if more > 0 {
            format!(", and {more} more")
        } else {
            String::new()
        };
        format!(
            "{} occurrence(s) elsewhere in this project ({}{suffix})",
            self.total,
            files.join(", ")
        )
    }
}

/// One value to search for, with the files that must be excluded from its search.
pub struct Subject<'a> {
    pub value: &'a str,
    /// Every known equal-value source file, excluded in full (`SET-011`).
    pub source_files: &'a [PathBuf],
}

/// Counts occurrences of every subject under `project_root`.
///
/// The tree is walked once and each readable regular file is scanned for all
/// subjects, so cost stays proportional to project size rather than to the
/// number of candidates.
pub fn analyze(project_root: &Path, subjects: &[Subject<'_>]) -> Vec<Collisions> {
    let mut results = vec![Collisions::default(); subjects.len()];
    if subjects.is_empty() {
        return results;
    }
    let canonical_sources: Vec<Vec<PathBuf>> = subjects
        .iter()
        .map(|subject| {
            subject
                .source_files
                .iter()
                .filter_map(|path| path.canonicalize().ok())
                .collect()
        })
        .collect();
    scan(
        project_root,
        project_root,
        subjects,
        &canonical_sources,
        &mut results,
    );
    for collisions in &mut results {
        collisions
            .files
            .sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    }
    results
}

fn scan(
    root: &Path,
    directory: &Path,
    subjects: &[Subject<'_>],
    canonical_sources: &[Vec<PathBuf>],
    results: &mut [Collisions],
) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let excluded = entry
                .file_name()
                .to_str()
                .is_some_and(|name| EXCLUDED_DIRECTORIES.contains(&name));
            if !excluded {
                scan(root, &path, subjects, canonical_sources, results);
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let Ok(mut file) = std::fs::File::open(&path) else {
            // Unreadable files are skipped; analysis is advisory.
            continue;
        };
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        let mut bytes = Vec::new();
        if file.read_to_end(&mut bytes).is_err() {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        let canonical_path = path.canonicalize().ok();
        for (index, subject) in subjects.iter().enumerate() {
            if subject.source_files.iter().any(|source| source == &path)
                || canonical_path
                    .as_ref()
                    .is_some_and(|path| canonical_sources[index].contains(path))
            {
                continue;
            }
            let count = count_occurrences(&bytes, subject.value.as_bytes());
            if count > 0 {
                results[index].total += count;
                results[index]
                    .files
                    .push((sanitize::path(&relative), count));
            }
        }
    }
}

/// Counts non-overlapping occurrences from left to right.
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > haystack.len() {
        return 0;
    }
    let mut count = 0;
    let mut position = 0;
    while position + needle.len() <= haystack.len() {
        if &haystack[position..position + needle.len()] == needle {
            count += 1;
            position += needle.len();
        } else {
            position += 1;
        }
    }
    count
}

/// Convenience wrapper for one value.
pub fn analyze_one(project_root: &Path, value: &str, source_file: Option<&Path>) -> Collisions {
    let source_files: Vec<PathBuf> = source_file.map(Path::to_path_buf).into_iter().collect();
    analyze(
        project_root,
        &[Subject {
            value,
            source_files: &source_files,
        }],
    )
    .pop()
    .unwrap_or_default()
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
                "contextveil-collision-{}-{}",
                std::process::id(),
                Canary::generate("TREE").token()
            ));
            std::fs::create_dir_all(&root).expect("fixture root");
            Self { root }
        }

        fn file(&self, relative: &str, contents: &[u8]) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("fixture directories");
            }
            std::fs::write(&path, contents).expect("write fixture file");
            path
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn occurrences_are_counted_across_the_project() {
        let tree = Tree::new();
        tree.file("a.txt", b"value value");
        tree.file("nested/b.txt", b"prefix-value");
        tree.file("c.txt", b"nothing here");

        let collisions = analyze_one(&tree.root, "value", None);
        assert_eq!(collisions.total, 3);
        assert_eq!(collisions.files.len(), 2);
    }

    #[test]
    fn counting_is_non_overlapping_and_left_to_right() {
        assert_eq!(count_occurrences(b"aaaa", b"aa"), 2);
        assert_eq!(count_occurrences(b"aaaaa", b"aa"), 2);
        assert_eq!(count_occurrences(b"abcabc", b"abc"), 2);
        assert_eq!(count_occurrences(b"", b"a"), 0);
        assert_eq!(count_occurrences(b"a", b""), 0);
    }

    #[test]
    fn the_candidates_own_source_file_is_excluded_entirely() {
        let tree = Tree::new();
        let source = tree.file(".env", b"TOKEN=value\nOTHER=value\n");
        tree.file("elsewhere.txt", b"value");

        let with_exclusion = analyze_one(&tree.root, "value", Some(&source));
        assert_eq!(with_exclusion.total, 1);

        let without_exclusion = analyze_one(&tree.root, "value", None);
        assert_eq!(without_exclusion.total, 3);
    }

    #[test]
    fn every_equal_value_alias_file_is_excluded() {
        let tree = Tree::new();
        let first = tree.file(".env", b"TOKEN=value\n");
        let second = tree.file("config/auth.json", br#"{"token":"value"}"#);
        tree.file("README.md", b"value");
        let source_files = vec![first, second];

        let collisions = analyze(
            &tree.root,
            &[Subject {
                value: "value",
                source_files: &source_files,
            }],
        );

        assert_eq!(collisions[0].total, 1);
        assert_eq!(collisions[0].files[0].0, "README.md");
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_source_excludes_its_regular_project_target() {
        let tree = Tree::new();
        let target = tree.file("config/auth.json", br#"{"token":"value"}"#);
        let source = tree.root.join("machine-auth.json");
        std::os::unix::fs::symlink(&target, &source).expect("source symlink");

        let collisions = analyze_one(&tree.root, "value", Some(&source));

        assert!(collisions.is_empty());
    }

    #[test]
    fn binary_and_non_utf8_files_are_included() {
        let tree = Tree::new();
        tree.file("blob.bin", &[0x00, 0xff, b'v', b'a', b'l', 0xfe]);
        let collisions = analyze_one(&tree.root, "val", None);
        assert_eq!(collisions.total, 1);
    }

    #[test]
    fn excluded_directories_are_not_searched() {
        let tree = Tree::new();
        tree.file("node_modules/pkg/index.js", b"value");
        tree.file(".git/objects/x", b"value");
        tree.file("kept.txt", b"value");

        let collisions = analyze_one(&tree.root, "value", None);
        assert_eq!(collisions.total, 1);
        assert_eq!(collisions.files[0].0, "kept.txt");
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_and_special_files_are_skipped() {
        let tree = Tree::new();
        let target = tree.file("target.txt", b"value");
        std::os::unix::fs::symlink(&target, tree.root.join("link.txt")).expect("symlink");
        let fifo = tree.root.join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("mkfifo runs")
                .success()
        );

        let collisions = analyze_one(&tree.root, "value", None);
        assert_eq!(collisions.total, 1);
        assert_eq!(collisions.files[0].0, "target.txt");
    }

    #[test]
    fn reports_contain_filenames_and_counts_but_never_values() {
        let canary = Canary::generate("COLLIDING");
        let tree = Tree::new();
        tree.file("config/settings.json", canary.value().as_bytes());

        let collisions = analyze_one(&tree.root, canary.value(), None);
        let description = collisions.describe();
        crate::testing::assert_canary_absent("collision report", description.as_bytes(), &canary);
        assert!(description.contains("config/settings.json"));
        assert!(description.contains('1'));
    }

    #[test]
    fn filenames_are_sanitized_for_the_terminal() {
        let tree = Tree::new();
        tree.file("weird\u{1b}[31mname.txt", b"value");
        let collisions = analyze_one(&tree.root, "value", None);
        assert!(!collisions.files[0].0.contains('\u{1b}'));
        assert!(collisions.files[0].0.contains("\\e[31m"));
    }

    #[test]
    fn several_subjects_share_one_walk() {
        let tree = Tree::new();
        tree.file("a.txt", b"alpha beta beta");
        let results = analyze(
            &tree.root,
            &[
                Subject {
                    value: "alpha",
                    source_files: &[],
                },
                Subject {
                    value: "beta",
                    source_files: &[],
                },
                Subject {
                    value: "gamma",
                    source_files: &[],
                },
            ],
        );
        assert_eq!(results[0].total, 1);
        assert_eq!(results[1].total, 2);
        assert!(results[2].is_empty());
    }
}
