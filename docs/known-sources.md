# Known Source Discovery

Known Source discovery is setup-time assistance for recognized coding-agent
credential stores. It is advisory and version-sensitive, not a guarantee that
an adapter covers a host or that every host credential will be enrolled. Review
the candidates and the [adapter support matrix](../README.md#support-and-security-limits)
separately.

ContextVeil reads only the paths and strict-JSON fields listed below. A selected
candidate is persisted as an ordinary environment or exact JSON source
reference; there is no runtime `KnownSource` source type. Valid JSON with no
recognized schema silently produces no candidate. A recognized file that is
malformed, non-UTF-8, or unreadable is shown as unavailable during setup.

## Discovery Semantics

- `CODEX_HOME`, `COPILOT_HOME`, `CLAUDE_CONFIG_DIR`, and `XDG_DATA_HOME` are
  resolved when setup runs. Changing one requires rerunning setup.
- A relative override is relative to setup's invocation directory. Overrides
  receive lexical `.`/`..` normalization, but no shell, environment-variable,
  glob, or tilde expansion.
- An empty override uses the default. A non-UTF-8 override is shown as
  unavailable and does not fall back to the default.
- Default machine paths are persisted using `~/...`; override paths are
  persisted as resolved explicit paths.
- Exact machine file paths may be symlinks when the target is a regular file.
  The one bounded project traversal does not follow file or directory symlinks
  and applies the normal project discovery exclusions.
- Only strict UTF-8 JSON without duplicate object members is accepted. JSONC,
  comments, wildcard field searches, interpolation, decoding, and generic
  secret-name matching are not supported.
- Recognized dynamic object members produce candidates only when every member
  name is representable by an exact `CFG-016` JSON Pointer. Empty names and `*`
  are unrepresentable and silently produce no candidate.

## Codex

Root: `CODEX_HOME`, or `~/.codex` when it is unset or empty.

| File | Exact recognized JSON fields |
| --- | --- |
| `auth.json` | `/OPENAI_API_KEY`; `/tokens/id_token`; `/tokens/access_token`; `/tokens/refresh_token`; `/personal_access_token`; `/bedrock_api_key/api_key`; and either a string `/agent_identity` or `/agent_identity/agent_private_key` |
| `.credentials.json` | For each immediate object member: `access_token` and optional string `refresh_token`, only when `server_name`, `server_url`, `client_id`, and `access_token` are strings and `refresh_token` is absent, null, or a string |

Evidence is pinned to [`openai/codex@ff0e95007cca1edfc0877bbbbfaeb9eb77ed92b3`](https://github.com/openai/codex/commit/ff0e95007cca1edfc0877bbbbfaeb9eb77ed92b3).
The issue-time behavior was also checked at
[`openai/codex@d9fd91edab298c2423c0c82526513e4e000284cf`](https://github.com/openai/codex/commit/d9fd91edab298c2423c0c82526513e4e000284cf).

## OpenCode

Root: `${XDG_DATA_HOME}/opencode`, or `~/.local/share/opencode` when
`XDG_DATA_HOME` is unset or empty. A non-empty `OPENCODE_AUTH_CONTENT` is also
offered as one whole environment source; ContextVeil does not parse it into
derived references.

| File | Exact recognized JSON fields |
| --- | --- |
| `auth.json` | For each immediate provider object: `key` when `type` is `api`; `access` and `refresh` when `type` is `oauth`; `token` when `type` is `wellknown` |
| `mcp-auth.json` | For each immediate server object: `tokens.accessToken`, `tokens.refreshToken`, `clientInfo.clientSecret`, and `codeVerifier` |

Evidence is pinned to OpenCode 1.18.18 at
[`anomalyco/opencode@31406ccc51b4bd2a4e1e086b2bcaa5f7f804f26d`](https://github.com/anomalyco/opencode/commit/31406ccc51b4bd2a4e1e086b2bcaa5f7f804f26d).

## GitHub Copilot CLI

Root: `COPILOT_HOME`, or `~/.copilot` when it is unset or empty.

| File | Exact recognized JSON fields |
| --- | --- |
| `config.json` | Every non-empty string value in the immediate `copilotTokens` object |
| `mcp-oauth-config/<hash>.tokens.json` | Top-level `access_token`, `refresh_token`, and `id_token`, where `<hash>` is exactly 64 lowercase hexadecimal characters |
| `mcp-oauth-config/<hash>.json` | Top-level `client_secret`, with the same exact filename rule |

Only immediate regular files with those exact names are inspected. Copilot CLI
1.0.80 commonly writes a comment-bearing JSONC `config.json`; the V1 strict-JSON
resolver cannot enroll fields from that file and setup shows it as unavailable.
Raw `.secret` and `.verifier` files and `mcp-secrets` fallback files cannot be
represented by V1 environment, dotenv, or exact-JSON source references and are
not discovered.

Release behavior is pinned to GitHub Copilot CLI 1.0.80 at
[`github/copilot-cli@ef627e1baad937d3c8da45f8a5541c6fc3c97b6a`](https://github.com/github/copilot-cli/commit/ef627e1baad937d3c8da45f8a5541c6fc3c97b6a),
with official documentation pinned at
[`github/docs@838d18789ba2c51cfe5544b3e5bf1ca3168c2795`](https://github.com/github/docs/commit/838d18789ba2c51cfe5544b3e5bf1ca3168c2795).
The private `copilotTokens` and MCP file structures are derived from the shipped
1.0.80 artifact, not represented as public source-code contracts.

## Claude Code

Machine root: `CLAUDE_CONFIG_DIR`, or `~/.claude` when it is unset or empty.
With an override, the user-state file is `<root>/.claude.json`; without one, it
is `~/.claude.json` alongside the default `~/.claude` directory.

| Scope and file | Exact recognized JSON fields |
| --- | --- |
| Non-macOS machine `.credentials.json` | `/claudeAiOauth/accessToken`; `/claudeAiOauth/refreshToken`; each immediate entry's `accessToken`, `refreshToken`, and `clientSecret` under `/mcpOAuth`; each immediate entry's `clientSecret` under `/mcpOAuthClientConfig` |
| Machine `settings.json` | Immediate `/env` strings named `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_AWS_API_KEY`, `ANTHROPIC_FOUNDRY_API_KEY`, `ANTHROPIC_FOUNDRY_AUTH_TOKEN`, `AWS_BEARER_TOKEN_BEDROCK`, `CLAUDE_CODE_OAUTH_TOKEN`, or `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE` |
| Machine `.claude.json` | The `mcpOAuth` and `mcpOAuthClientConfig` fields above, plus the exact MCP server fields below |
| Project `.claude/settings.json` at any depth | The exact `/env` names listed for machine `settings.json` |
| Project `.mcp.json` at any depth | The exact MCP server fields below |

For each immediate `mcpServers` member, discovery recognizes string header
values whose names case-insensitively equal `authorization`,
`proxy-authorization`, `x-api-key`, `api-key`, `x-auth-token`, or
`x-subscription-token`. It recognizes string environment values whose names
exactly equal `API_KEY`, `ACCESS_TOKEN`, `AUTH_TOKEN`, `BEARER_TOKEN`,
`CLIENT_SECRET`, `PASSWORD`, `SECRET`, `TOKEN`, or one of the eight Claude names
listed in the table. Other settings, headers, and environment names do not
match.

On macOS, Claude's primary credentials are keychain-backed. ContextVeil does not
query the keychain, so primary `.credentials.json` discovery is non-macOS only.
Public release evidence is pinned to Claude Code 2.1.238 at
[`anthropics/claude-code@8a8e81d098cbd0fae4ee5b9c853542945fe87016`](https://github.com/anthropics/claude-code/commit/8a8e81d098cbd0fae4ee5b9c853542945fe87016).
The private credential structures are derived from the shipped 2.1.238 artifact,
not represented as public source-code contracts.

## Permanent Boundary

Known Source discovery does not query OS keychains, execute credential helpers,
read raw credential sidecars, parse JSONC, or promise coverage for a future host
version. These are source-format and discovery boundaries, not unimplemented
parts of the listed V1 contract. Manually enroll a supported environment,
dotenv, or strict-JSON source when possible, and rerun setup after host or path
changes. See [`LIM-023`](../limitations.md#lim-023-known-source-discovery-is-advisory).
