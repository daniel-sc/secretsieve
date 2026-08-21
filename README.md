# ContextVeil

**A small, local safety net for secrets used around coding agents.**

ContextVeil replaces secret values you choose before supported coding-agent text
reaches the LLM:

```text
GITHUB_TOKEN=ghp_example  ->  GITHUB_TOKEN=<SECRET:GITHUB_TOKEN>
```

> **You choose what counts as secret. Automatically replace exact matches. Keep working. No magic.**

It only replaces exact values from sources you choose.
It is an extra safety net, not a promise to cover every
way a secret can be exposed or used.

> **Status:** Pre-release. `v1.0.0-alpha.2` is available, but stable V1 has not
> been published yet. See [Quick Start](#quick-start) for the current install
> command.

## Why Use It?

Imagine asking a coding agent to debug your app. It reads `.env` or runs a command
such as `printenv`. Most of the output is useful, but it also contains an API key.
That key may become part of the next request to the model (LLM).

ContextVeil does not block the file read or command. The local operation still
happens. On a supported integration path, ContextVeil changes the text headed to
the model and leaves the rest useful:

```text
DATABASE_URL=postgres://localhost/my_app
API_TOKEN=<SECRET:API_TOKEN>
LOG_LEVEL=debug
```

This is deliberately a small tool. It is not trying to recognize every possible
secret or control everything an agent can do.

## Guided Setup, Boring Runtime

`contextveil setup` does the thoughtful part: it suggests likely environment
variables and entries in `.env` files, recognizes a bounded set of coding-agent
Known Sources, lets you manually add an exact JSON field, shows only masked
previews, lets you choose what to protect, and installs the integrations you
select. It does not scan arbitrary JSON files or keys.

Daily use is boring on purpose: ContextVeil reads the current values, performs
local exact-text replacement, and exits. There is no daemon, no network request,
no account, no hosted service and no LLM deciding what looks secret. Clean events are
silent.

And of course it is fast. You won't notice it, promise!

```mermaid
flowchart TD
    subgraph setup [Setup: run once, rerun when needed]
        direction LR
        A[Find likely environment, .env, and Known Source entries]
        B[You choose what to protect]
        C[Install selected coding-agent integrations]
        D[Store where values live, not the values]
        A --> B --> C --> D
    end


    subgraph persistence [Persistence: configuration files]
      direction LR
      X[Global<br>~/.config/contextveil/config.toml]
      Y[Project<br>.contextveil.toml]
      X ~~~ Y
    end

    subgraph runtime [Runtime: for each supported event]
        direction LR
        E[Coding agent produces model-bound text]
        F[Read current values from enrolled sources]
        G{Exact value found?}
        H[Pass text through unchanged]
        I[Replace value with a placeholder]
        J[Cleaned text continues to the LLM]
        E --> F --> G
        G -- No --> H --> J
        G -- Yes --> I --> J
    end

    setup -. Stored in .-> persistence
    persistence -. Used by .-> runtime
```

ContextVeil stores where to find each value, such as “the `API_TOKEN` environment
variable,” “the `STRIPE_KEY` entry in `.env.local`,” or “the exact
`/tokens/access_token` field in `auth.json`.” It does not copy the value into its
configuration. Changes to `.env` and JSON files apply on the next supported
event. Environment changes apply after you restart the coding agent.

### Known Source Discovery

Known Sources are advisory setup shortcuts, not an adapter coverage guarantee.
They inspect strict JSON at maintained paths and persist the selected exact
environment or JSON references. Valid unknown schemas silently produce no
candidate; malformed matched strict JSON is shown as unavailable.

| Coding agent | V1 Known Source locations | Important exclusions |
| --- | --- | --- |
| Claude Code | `CLAUDE_CONFIG_DIR` or `~/.claude`: non-macOS `.credentials.json`, `settings.json`, and override-root `.claude.json`; default `~/.claude.json`; project `.claude/settings.json` and `.mcp.json` | macOS primary credentials are keychain-backed and not queried |
| OpenAI Codex CLI | `CODEX_HOME` or `~/.codex`: `auth.json` and `.credentials.json` | Unknown schemas silently no-match |
| GitHub Copilot CLI | `COPILOT_HOME` or `~/.copilot`: strict-JSON `config.json` `copilotTokens` and immediate 64-lowercase-hex `mcp-oauth-config` `.tokens.json`/`.json` files | Common JSONC `config.json`, raw `.secret`/`.verifier`, and `mcp-secrets` fallback files are not supported |
| OpenCode | `${XDG_DATA_HOME:-~/.local/share}/opencode`: `auth.json` and `mcp-auth.json`; whole `OPENCODE_AUTH_CONTENT` | The environment value is enrolled whole, not parsed |

Override values are resolved when setup runs, so changes require a rerun.
Relative overrides are relative to the setup invocation directory; there is no
shell or tilde expansion. ContextVeil does not query keychains or execute
credential helpers. See the [exact field matrix and pinned evidence](docs/known-sources.md)
and [`LIM-023`](limitations.md#lim-023-known-source-discovery-is-advisory).

## Quick Start

### 1. Install

While ContextVeil is in pre-release, install the published alpha explicitly:

```bash
curl -fsSL https://raw.githubusercontent.com/daniel-sc/contextveil/main/install.sh |
  bash -s -- --version 1.0.0-alpha.2
```

After stable V1 is published, the shorter command will install the latest stable
release:

```bash
curl -fsSL https://raw.githubusercontent.com/daniel-sc/contextveil/main/install.sh | bash
```

The binary is installed to `~/.local/bin/contextveil` by default. Make sure that
directory is on your `PATH`.

### 2. Set Up A Project

Run this from the project where you use your coding agent:

```bash
contextveil setup
```

Setup is interactive and safe to rerun. It walks through:

1. secrets you use across projects;
2. secrets from the current project;
3. coding-agent integrations;
4. an offline check that the selected integrations work.

Complete secret values are never displayed. Suggestions are only suggestions;
you make the final choices. Rerun setup after changing a Known Source path
override or upgrading a host whose credential schema changed.

### 3. Check It

```bash
contextveil status
```

Then work normally. ContextVeil stays quiet unless it replaces something - then it notifies you via the agent harness.

## What It Is Good At

- **Keeping useful output.** Commands and file reads still happen. Only enrolled
  values are replaced on supported model-bound paths.
- **Being predictable.** Matching is literal, case-sensitive, and deterministic.
  There is no runtime guess about whether arbitrary text looks sensitive.
- **Handling private token formats.** A value does not need to match a known API
  key pattern. If you enroll its source, its current exact value can be matched.
- **Following rotation.** ContextVeil reads the selected environment variables,
  `.env` entries, and exact JSON fields for each supported event instead of
  keeping copied values.
- **Guiding source enrollment.** Setup recognizes pinned strict-JSON credential
  fields for Claude Code, Codex CLI, GitHub Copilot CLI, and OpenCode without
  turning runtime into a generic credential scanner.
- **Staying small and local.** Runtime has no network calls, telemetry, account,
  subscription, or persistent logging. Safe and fast by design.

## Support and Security Limits

V1 supports Linux (including WSL on Windows) and macOS on x86_64 and arm64.

| Coding agent | Support | Text ContextVeil can replace | If ContextVeil fails |
| --- | --- | --- | --- |
| Claude Code | **Production** | String values in successful tool results that Claude allows hooks to replace | Claude continues with the original content: fail open |
| OpenAI Codex CLI | **EXPERIMENTAL** | Supported successful tool results; replacement becomes plain text and may lose structure | Codex continues with the original content: fail open |
| GitHub Copilot CLI | **EXPERIMENTAL** | Transformed user prompts and successful text tool results | Copilot continues with the original content: fail open |
| OpenCode | **EXPERIMENTAL** | New user text and successful standard tool output on the V1 plugin API | A detected problem stops that covered operation while the plugin is running |

Experimental integrations are functional and fixture-tested, but they are not
part of the production support promise. 

ContextVeil is a guardrail for accidental exposure, not a general security
boundary:

- It protects only current, exact values from sources you enroll. Unknown,
  encoded, split, normalized, hashed, or otherwise transformed values are not
  detected.
- Coverage applies only when the coding-agent application loads and honors the
  installed integration. Cloud, remote, container, and company-managed setups
  need their own working installation.
- Claude, Codex, and Copilot fail open. If their hook crashes, times out, is
  disabled, or is bypassed, the coding agent may continue with the original text.
  OpenCode can stop a covered operation only after its plugin has loaded.
- ContextVeil does not stop local processes from reading or using credentials,
  and other coding-agent hooks may see the original content before redaction.
- Short or common enrolled values can also match and replace ordinary text. (This is shown during setup as a warning.)
- Known Source discovery is version-sensitive setup advice, not an adapter
  coverage guarantee. It excludes JSONC, unsupported raw sidecars, keychains,
  helpers, and unknown schemas as detailed in `LIM-023`.

See [limitations.md](limitations.md) for the complete security boundary and
coding-agent-specific gaps.

## Commands

```bash
# find sources, record your choices, and install integrations. It is interactive and safe to rerun:
contextveil setup

# give a quick view of current sources and integrations:
contextveil status

# It can optionally offer a confirmed, paid/networked Claude test.
contextveil doctor

contextveil --help
contextveil --version
```

## Configuration

ContextVeil keeps source references in:

- `${XDG_CONFIG_HOME:-~/.config}/contextveil/config.toml` for sources used across
  projects;
- `.contextveil.toml` at the selected project root for project sources.

The two files are additive. Review `.contextveil.toml` before using an untrusted
project: it can refer to environment variables, `.env` files, or JSON files outside the
project. If a selected config is invalid or unreadable,
ContextVeil uses none of the sources for that event instead of applying partial redaction.

## Installation Details

You can download a checksummed binary directly from
[GitHub Releases](https://github.com/daniel-sc/contextveil/releases), extract and place it
at `~/.local/bin/contextveil`.

Alteratively, the install script detects your platform and architecture, downloads the matching
release, verifies its SHA-256 checksum, and replaces the binary atomically:

```text
install.sh [--install-dir DIR] [--version VERSION] [--allow-major-upgrade]
```

It never runs setup or changes ContextVeil or coding-agent configuration.
Rerunning it upgrades within the installed major version. A major-version upgrade
requires `--allow-major-upgrade`, and a prerelease is installed only when you name
its exact version.

To build the current source instead:

```bash
mise install
mise run build
```

The binary will be at `target/release/contextveil`.

## Development

[mise](https://mise.jdx.dev) is the supported entry point. It pins the Rust
toolchain, so no globally installed Rust utility is required. You still need a
system C linker: `cc` from `build-essential` on Linux or the Xcode command line
tools on macOS.

```bash
mise install         # install the pinned toolchain
mise run check       # formatting, Clippy with warnings denied, and tests
mise run build       # release binary
mise run fuzz-smoke  # bounded fuzz smoke run
mise run bench       # representative runtime workload
mise run package     # build and package a release artifact
mise run release-check
```

## More Detail

- [Specification](specification.md): authoritative V1 behavior
- [Limitations](limitations.md): complete security and coding-agent boundaries
- [Vision](vision.md): product intent and non-goals
- [Architecture](architecture.md): implementation boundaries
- [Known Source inventory](docs/known-sources.md): exact discovered fields,
  source-format boundaries, and pinned upstream evidence

ContextVeil is free and open source under MIT OR Apache-2.0. It needs no account
or hosted runtime.
