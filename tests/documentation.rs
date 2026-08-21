//! Structural checks for shipped documentation.

use std::collections::HashSet;
use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{} could not be read: {error}", path.display());
    })
}

fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let (_, rest) = text
        .split_once(heading)
        .unwrap_or_else(|| panic!("document has no `{heading}` section"));
    rest.split("\n## ").next().unwrap_or(rest)
}

#[test]
fn public_support_matrices_have_the_required_tiers() {
    for (document, heading) in [
        ("README.md", "## Support and Security Limits"),
        ("vision.md", "## V1 Support Posture"),
        ("docs/release-notes-template.md", "## Support matrix"),
    ] {
        let text = read(document);
        let matrix = section(&text, heading);
        for (integration, expected) in [
            ("Claude Code", "Production"),
            ("OpenAI Codex CLI", "Experimental"),
            ("GitHub Copilot CLI", "Experimental"),
            ("OpenCode", "Experimental"),
        ] {
            let row = matrix
                .lines()
                .filter(|line| line.trim_start().starts_with('|'))
                .find_map(|line| {
                    let mut columns = line
                        .split('|')
                        .skip(1)
                        .map(|column| column.trim().trim_matches('*'));
                    let name = columns.next()?;
                    let tier = columns.next()?;
                    (name == integration).then_some(tier)
                })
                .unwrap_or_else(|| panic!("{document} has no support row for {integration}"));

            assert!(
                row.to_ascii_lowercase()
                    .starts_with(&expected.to_ascii_lowercase()),
                "{document} labels {integration} as `{row}`, expected {expected}"
            );
        }
    }
}

#[test]
fn release_notes_link_the_boundary_and_reporting_documents() {
    let text = read("docs/release-notes-template.md");
    for link in ["(../limitations.md)", "(../SECURITY.md)"] {
        assert!(text.contains(link), "release notes omit the `{link}` link");
    }
}

#[test]
fn public_known_source_matrices_match_the_v1_boundary() {
    for (document, heading) in [
        ("README.md", "### Known Source Discovery"),
        (
            "docs/release-notes-template.md",
            "## Known Source discovery",
        ),
    ] {
        let text = read(document);
        let matrix = section(&text, heading);
        let normalized = matrix.split_whitespace().collect::<Vec<_>>().join(" ");
        for (integration, markers) in [
            (
                "Claude Code",
                &["CLAUDE_CONFIG_DIR", ".credentials.json", ".mcp.json"][..],
            ),
            (
                "OpenAI Codex CLI",
                &["CODEX_HOME", "auth.json", ".credentials.json"][..],
            ),
            (
                "GitHub Copilot CLI",
                &[
                    "COPILOT_HOME",
                    "copilotTokens",
                    "64-lowercase-hex",
                    "JSONC",
                    ".secret",
                    ".verifier",
                    "mcp-secrets",
                ][..],
            ),
            (
                "OpenCode",
                &[
                    "XDG_DATA_HOME",
                    "auth.json",
                    "mcp-auth.json",
                    "OPENCODE_AUTH_CONTENT",
                ][..],
            ),
        ] {
            let row = matrix
                .lines()
                .find(|line| line.starts_with(&format!("| {integration} |")))
                .unwrap_or_else(|| panic!("{document} has no Known Source row for {integration}"));
            for marker in markers {
                assert!(
                    row.contains(marker),
                    "{document}'s {integration} Known Source row omits `{marker}`"
                );
            }
        }

        for boundary in [
            "advisory",
            "not an adapter coverage guarantee",
            "strict JSON",
            "silently no-match",
            "unavailable",
            "keychains",
            "credential helpers",
            "invocation directory",
            "rerun",
            "no shell or tilde expansion",
        ] {
            assert!(
                normalized.contains(boundary),
                "{document}'s Known Source section omits `{boundary}`"
            );
        }
        assert!(matrix.contains("known-sources.md"));
        assert!(matrix.contains("lim-023-known-source-discovery-is-advisory"));
    }
}

#[test]
fn known_source_inventory_pins_all_evidence() {
    let text = read("docs/known-sources.md");
    for link in [
        "https://github.com/openai/codex/commit/ff0e95007cca1edfc0877bbbbfaeb9eb77ed92b3",
        "https://github.com/openai/codex/commit/d9fd91edab298c2423c0c82526513e4e000284cf",
        "https://github.com/anomalyco/opencode/commit/31406ccc51b4bd2a4e1e086b2bcaa5f7f804f26d",
        "https://github.com/github/copilot-cli/commit/ef627e1baad937d3c8da45f8a5541c6fc3c97b6a",
        "https://github.com/github/docs/commit/838d18789ba2c51cfe5544b3e5bf1ca3168c2795",
        "https://github.com/anthropics/claude-code/commit/8a8e81d098cbd0fae4ee5b9c853542945fe87016",
    ] {
        assert!(text.contains(link), "Known Source inventory omits `{link}`");
    }
    for disclosure in [
        "artifact, not represented as public source-code contracts",
        "advisory and version-sensitive",
        "not a guarantee that",
        "an adapter covers a host",
        "there is no runtime `KnownSource` source type",
        "Empty names and `*`",
    ] {
        assert!(
            text.contains(disclosure),
            "Known Source inventory omits `{disclosure}`"
        );
    }
}

#[test]
fn completed_known_source_work_has_no_temporary_gap_entries() {
    let limitations = read("limitations.md");
    assert!(!limitations.contains("### LIM-011:"));
    assert!(!limitations.contains("### DEV-003:"));

    let traceability = read("docs/traceability.md");
    for requirement in [
        "SET-002", "SET-006", "SET-018", "SET-019", "SET-020", "TST-003",
    ] {
        let row = traceability
            .lines()
            .find(|line| line.starts_with(&format!("| {requirement} |")))
            .unwrap_or_else(|| panic!("traceability has no row for {requirement}"));
        assert!(
            row.ends_with("| covered |"),
            "{requirement} remains open: {row}"
        );
    }
}

#[test]
fn limitation_and_deviation_entries_are_well_formed() {
    let text = read("limitations.md");
    let mut identifiers = HashSet::new();

    for block in text.split("\n### ").skip(1) {
        let heading = block.lines().next().unwrap_or_default();
        let identifier = heading.split(':').next().unwrap_or_default();
        if identifier.ends_with("NNN") {
            continue;
        }

        let sections: &[&str] = if identifier.starts_with("LIM-") {
            &[
                "**Reality:**",
                "**Impact:**",
                "**Workaround:**",
                "**Verification:**",
            ]
        } else if identifier.starts_with("DEV-") {
            &[
                "Contract:",
                "**Observed behavior:**",
                "**Impact:**",
                "**Workaround:**",
                "**Verification:**",
            ]
        } else {
            continue;
        };

        let number = identifier
            .split_once('-')
            .map(|(_, number)| number)
            .unwrap_or_default();
        assert!(
            number.len() == 3 && number.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid limitation identifier `{identifier}`"
        );
        assert!(
            identifiers.insert(identifier),
            "duplicate limitation identifier `{identifier}`"
        );
        for section in sections {
            assert!(block.contains(section), "{heading} is missing {section}");
        }
    }
}
