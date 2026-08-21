# ContextVeil __VERSION__

ContextVeil keeps enrolled local secrets out of coding-agent model context
through deterministic local redaction. Runtime resolution and redaction make no
network calls, and no value is ever written into ContextVeil configuration.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/daniel-sc/contextveil/v__VERSION__/install.sh | bash
```

The installer verifies the release checksum before replacing anything, installs
into `~/.local/bin/contextveil` by default, and never runs setup or changes
coding-agent configuration. Rerunning it upgrades within the installed major
version; crossing a major version needs `--allow-major-upgrade`.

Then, in a project:

```bash
contextveil setup
contextveil doctor
```

Setup guides enrollment from environment variables, dotenv files, manual exact
JSON fields, and the bounded Known Sources below. Known Source discovery is
advisory and version-sensitive, not an adapter coverage guarantee.

## Support matrix

| Integration | Tier | Covered model-bound content | Failure behavior |
| --- | --- | --- | --- |
| Claude Code | Production | String values in successful, replaceable `PostToolUse` tool responses | Fail open |
| OpenAI Codex CLI | EXPERIMENTAL | Supported `PostToolUse` results, replaced as sanitized text with possible loss of structure | Fail open |
| GitHub Copilot CLI | EXPERIMENTAL | `userPromptTransformed` and successful `textResultForLlm` text | Fail open |
| OpenCode | EXPERIMENTAL | New V1 `chat.message` user text and successful standard `tool.execute.after` text | Abort when the executing plugin detects a covered malfunction |

Experimental integrations are functional and fixture-tested, but outside the
production support promise, and always require an affirmative choice during
setup. Coverage applies only where a local harness loads and honors the installed
integration.

## Known Source discovery

This discovery is advisory and version-sensitive, not an adapter coverage
guarantee.

| Coding agent | V1 Known Source locations | Important exclusions |
| --- | --- | --- |
| Claude Code | `CLAUDE_CONFIG_DIR` or `~/.claude`: non-macOS `.credentials.json`, `settings.json`, and override-root `.claude.json`; default `~/.claude.json`; project `.claude/settings.json` and `.mcp.json` | macOS primary credentials are keychain-backed and not queried |
| OpenAI Codex CLI | `CODEX_HOME` or `~/.codex`: `auth.json` and `.credentials.json` | Unknown schemas silently no-match |
| GitHub Copilot CLI | `COPILOT_HOME` or `~/.copilot`: strict-JSON `config.json` `copilotTokens` and immediate 64-lowercase-hex `mcp-oauth-config` `.tokens.json`/`.json` files | Common JSONC `config.json`, raw `.secret`/`.verifier`, and `mcp-secrets` fallback files are not supported |
| OpenCode | `${XDG_DATA_HOME:-~/.local/share}/opencode`: `auth.json` and `mcp-auth.json`; whole `OPENCODE_AUTH_CONTENT` | The environment value is enrolled whole, not parsed |

Only strict JSON is parsed. Valid unknown schemas silently no-match; malformed
matched strict JSON is shown as unavailable. Override values resolve during
setup, relative overrides use the invocation directory, changes require a rerun,
and no shell or tilde expansion occurs. OS keychains and credential helpers are not
queried. See the [exact field matrix and pinned evidence](known-sources.md) and
[`LIM-023`](../limitations.md#lim-023-known-source-discovery-is-advisory).

## Tested host versions

Protocol behavior was verified against these host versions. V1 performs no host
version checks (`LIM-018`), so these are evidence rather than a supported range:
run `contextveil doctor` after upgrading a coding agent.

| Host | Verified against |
| --- | --- |
| Claude Code | Adapter: 2.1.233 live qualification. Known Sources: 2.1.238, public release commit `8a8e81d098cbd0fae4ee5b9c853542945fe87016` plus shipped-artifact-derived private structures |
| OpenAI Codex CLI | Adapter: `openai/codex` commit `c6058cca`. Known Sources: `ff0e95007cca1edfc0877bbbbfaeb9eb77ed92b3` (also issue-time `d9fd91edab298c2423c0c82526513e4e000284cf`) |
| GitHub Copilot CLI | Adapter and Known Sources: 1.0.80 release commit `ef627e1baad937d3c8da45f8a5541c6fc3c97b6a`, official docs commit `838d18789ba2c51cfe5544b3e5bf1ca3168c2795`, plus shipped-artifact-derived private structures |
| OpenCode | Adapter and Known Sources: 1.18.18 commit `31406ccc51b4bd2a4e1e086b2bcaa5f7f804f26d` |

## Platforms

Linux and macOS on x86_64 and arm64. Each asset is listed in
`contextveil-__VERSION__-SHA256SUMS`.

## Known boundaries

ContextVeil is a model-context safety primitive, not a guarantee that credentials
cannot leave the machine. Read [limitations.md](../limitations.md) before relying on it. The
most important entries:

- [`LIM-001`](../limitations.md#lim-001-model-context-not-credential-use): model
  context only, not credential use or egress.
- [`LIM-002`](../limitations.md#lim-002-unknown-and-transformed-values): unknown
  and transformed values are not recognized.
- [`LIM-003`](../limitations.md#lim-003-string-values-only): string values only,
  not object keys or binary content.
- [`LIM-004`](../limitations.md#lim-004-common-values-can-be-destructive):
  enrolling a short or common value can replace unrelated text.
- [`LIM-012`](../limitations.md#lim-012-process-hooks-fail-open): process hooks
  fail open when a host crashes, times out, disables, or bypasses them.
- [`LIM-013`](../limitations.md#lim-013-claude-coverage-gaps) through
  [`LIM-016`](../limitations.md#lim-016-opencode-v1-api-only): per-host coverage
  gaps.
- [`LIM-023`](../limitations.md#lim-023-known-source-discovery-is-advisory):
  strict-JSON Known Source discovery is advisory and excludes JSONC, raw
  sidecars, keychains, helpers, and unknown or changed schemas.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md). Never include a real credential in a report.
