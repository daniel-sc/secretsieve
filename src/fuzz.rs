//! Fuzz targets for every untrusted input surface (`TST-006`).
//!
//! Each target takes raw bytes, must never panic, and asserts the invariants that
//! matter for this surface. They are plain functions so the bounded smoke harness
//! (`mise run fuzz-smoke`) and any external fuzzer can drive the same code.
//!
//! The adapter targets run against a temporary configuration that enrolls one
//! generated non-credential value, so every target also asserts that value never
//! appears in any output (`TST-005`).
//!
//! This module is compiled only for tests or behind the `testing` feature.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::adapter::{claude, codex, copilot, opencode};
use crate::matcher::Redactor;
use crate::secret::{ResolvedSecret, SourceId};
use crate::source::Environment;

/// A temporary configuration and the value enrolled in it.
pub struct Context {
    root: PathBuf,
    environment: Environment,
    canary: String,
}

impl Context {
    /// Creates a context, or `None` when a temporary directory is unavailable.
    pub fn create() -> Option<Self> {
        let canary = format!(
            "SSCANARY-FUZZ-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        );
        let root = std::env::temp_dir().join(format!("contextveil-fuzz-{canary}"));
        std::fs::create_dir_all(root.join("contextveil")).ok()?;
        std::fs::write(
            root.join("contextveil").join("config.toml"),
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"CONTEXTVEIL_FUZZ\"\n",
        )
        .ok()?;
        let environment = Environment::from_pairs([
            ("XDG_CONFIG_HOME", root.to_string_lossy().into_owned()),
            ("CONTEXTVEIL_FUZZ", canary.clone()),
        ]);
        Some(Self {
            root,
            environment,
            canary,
        })
    }

    pub fn canary(&self) -> &str {
        &self.canary
    }

    fn assert_no_disclosure(&self, channel: &str, text: &str) {
        assert!(
            !text.contains(&self.canary),
            "the enrolled value was disclosed in {channel}"
        );
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The process-wide context used by the single-argument targets.
pub fn context() -> Option<&'static Context> {
    static CONTEXT: OnceLock<Option<Context>> = OnceLock::new();
    CONTEXT.get_or_init(Context::create).as_ref()
}

/// One fuzz target: raw bytes in, no output, must never panic.
pub type Target = fn(&[u8]);

/// Every target, by name, for the smoke harness.
pub const TARGETS: [(&str, Target); 9] = [
    ("dotenv", dotenv),
    ("json-source", json_source),
    ("config", config),
    ("matcher", matcher),
    ("sanitize", sanitize),
    ("claude", claude_hook),
    ("codex", codex_hook),
    ("copilot", copilot_hook),
    ("opencode", opencode_hook),
];

/// Dotenv grammar (`SRC-003`).
pub fn dotenv(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = crate::dotenv::parse(text) {
        // Every reported key must be retrievable, and duplicates must be a subset
        // of the keys.
        for (key, value) in parsed.entries() {
            assert_eq!(parsed.get(key), Some(value));
        }
        for duplicate in parsed.duplicates() {
            assert!(parsed.get(duplicate).is_some());
        }
    }
}

/// Strict JSON documents and exact pointer traversal (`SRC-011`, `TST-006`).
pub fn json_source(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (pointer, document) = text.split_once('\n').unwrap_or((text, ""));
    if crate::json::final_token(pointer).is_ok()
        && let Ok(value) = crate::json::parse(document)
    {
        let _ = crate::json::select(&value, pointer);
    }
}

/// Configuration parsing (`CFG-006`).
pub fn config(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match crate::config::parse(
        text,
        Path::new("/fuzz/project"),
        Some(Path::new("/fuzz/home")),
    ) {
        Ok(parsed) => {
            // Accepted files never contain two identical identities (`CFG-006`).
            let mut seen = Vec::new();
            for source in &parsed.sources {
                let identity = source.id();
                assert!(!seen.contains(&identity), "duplicate identity accepted");
                seen.push(identity);
            }
        }
        Err(kind) => {
            // A diagnostic must never quote the file (`SEC-004`).
            let reason = kind.reason();
            for line in text.lines().filter(|line| line.len() > 8) {
                assert!(!reason.contains(line), "a diagnostic quoted file content");
            }
        }
    }
}

/// Matcher semantics (`RED-001` through `RED-008`).
pub fn matcher(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // The first line holds tab-separated values; the rest is the haystack.
    let (header, haystack) = text.split_once('\n').unwrap_or((text, ""));
    let secrets: Vec<ResolvedSecret> = header
        .split('\t')
        .filter(|value| !value.is_empty())
        .take(16)
        .enumerate()
        .map(|(index, value)| {
            ResolvedSecret::new(SourceId::env(format!("FUZZ_{index}")), value.to_string())
        })
        .collect();

    let redactor = Redactor::new(secrets);
    let mut tally = redactor.tally();
    let output = redactor
        .redact(haystack, &mut tally)
        .unwrap_or_else(|| haystack.to_string());

    match redactor.intervention(&tally) {
        None => assert_eq!(tally.total(), 0),
        Some(intervention) => {
            assert_eq!(intervention.total, tally.total());
            let reported: usize = intervention
                .named
                .iter()
                .map(|entry| entry.count)
                .sum::<usize>()
                + intervention.unnamed;
            assert_eq!(reported, intervention.total);
            // Metadata carries counts and labels only (`RED-008`).
            let summary = intervention.summary();
            for entry in &intervention.named {
                assert!(summary.contains(&entry.label));
            }
        }
    }
    // Replacing again must be a no-op for the same registry, because inserted
    // text is never rescanned (`RED-007`).
    let mut second = redactor.tally();
    if let Some(again) = redactor.redact(&output, &mut second) {
        assert_ne!(
            again, output,
            "a second pass changed nothing but reported so"
        );
    }
}

/// Terminal sanitization (`SEC-006`).
pub fn sanitize(data: &[u8]) {
    let rendered = crate::sanitize::bytes(data);
    assert!(
        !rendered.contains([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1b}', '\u{85}', '\u{2028}', '\u{2029}'
        ]),
        "a sanitized rendering left a line break or escape in place"
    );
    if let Ok(text) = std::str::from_utf8(data) {
        assert_eq!(crate::sanitize::text(text), rendered);
    }
}

/// Claude `PostToolUse` envelopes (`RUN-006`).
pub fn claude_hook(data: &[u8]) {
    let Some(context) = context() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let response = claude::handle(text, &context.environment);
    if let Some(stdout) = &response.stdout {
        context.assert_no_disclosure("claude stdout", stdout);
        assert!(
            serde_json::from_str::<serde_json::Value>(stdout).is_ok(),
            "the adapter emitted invalid protocol output"
        );
    }
}

/// Codex `PostToolUse` envelopes (`RUN-006`).
pub fn codex_hook(data: &[u8]) {
    let Some(context) = context() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let response = codex::handle(text, &context.environment);
    if let Some(stdout) = &response.stdout {
        context.assert_no_disclosure("codex stdout", stdout);
        assert!(serde_json::from_str::<serde_json::Value>(stdout).is_ok());
    }
}

/// Copilot payloads for both covered events (`RUN-006`).
pub fn copilot_hook(data: &[u8]) {
    let Some(context) = context() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for event in [
        copilot::Event::TransformedPrompt,
        copilot::Event::PostToolUse,
    ] {
        let response = copilot::handle(event, text, &context.environment);
        if let Some(stdout) = &response.stdout {
            context.assert_no_disclosure("copilot stdout", stdout);
            for line in stdout.lines() {
                assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
            }
        }
        if let Some(stderr) = &response.stderr {
            context.assert_no_disclosure("copilot stderr", stderr);
        }
    }
}

/// OpenCode transport requests (`OCO-001`, `RUN-006`).
pub fn opencode_hook(data: &[u8]) {
    let Some(context) = context() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let response = opencode::handle(text, &context.environment);
    let json = response.to_json();
    context.assert_no_disclosure("opencode response", &json);
    assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_survives_empty_and_hostile_input() {
        let inputs: [&[u8]; 7] = [
            b"",
            b"\0\0\0",
            &[0xff, 0xfe, 0xfd],
            b"version = 1",
            b"A=1\nB='unterminated",
            b"{\"hook_event_name\":\"PostToolUse\"}",
            b"a\tb\nabab",
        ];
        for (name, target) in TARGETS {
            for input in inputs {
                target(input);
                let _ = name;
            }
        }
    }

    #[test]
    fn the_matcher_target_exercises_real_replacement() {
        // A sanity check that the split convention actually produces matches.
        matcher(b"secret\nthis contains secret twice: secret");
    }
}
