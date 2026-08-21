# ContextVeil Architecture

This document defines mandatory technical boundaries for ContextVeil V1. It is
authoritative for implementation structure; [specification.md](specification.md)
is authoritative for observable behavior. A conflict between the two must be
resolved explicitly before implementation continues.

## Architectural Goals

- Keep the security-critical runtime small and auditable.
- Use one native implementation for source resolution and matching.
- Keep harness-specific code limited to protocol and presentation concerns.
- Resolve current source values without persisting plaintext.
- Avoid long-lived processes and hidden state.
- Make host coverage and failure behavior observable through diagnostics.
- Support additional source formats and adapters without creating a general
  plugin framework in V1.

## System Shape

```text
                         ContextVeil Rust binary
┌──────────────────────────────────────────────────────────────────┐
│ CLI                                                              │
│ setup | status | doctor                                          │
├──────────────────────────────────────────────────────────────────┤
│ enrollment | Known Source discovery | collision analysis         │
├──────────────────────────────────────────────────────────────────┤
│ config loading | registry composition | source resolution        │
├──────────────────────────────────────────────────────────────────┤
│ exact matcher | structured value redaction | interventions        │
├──────────────────────────────────────────────────────────────────┤
│ Claude | Codex | Copilot native hook protocol adapters           │
└──────────────────────────────────┬───────────────────────────────┘
                                   │ one JSON request/response
                                   │ over stdin/stdout per event
                                   ▼
                     OpenCode TypeScript adapter
```

The Rust binary is both the CLI and process-hook executable. Process-based
harnesses invoke it directly; they do not spawn an intermediate core process.
The OpenCode plugin is the only V1 in-process adapter and invokes the Rust binary
once for each covered event.

## Mandatory Boundaries

### Core

The core owns:

- config validation and project selection;
- global and project registry composition;
- environment, dotenv, and exact-pointer JSON source resolution;
- candidate grouping, scoring, and collision analysis;
- canonicalization of duplicate resolved values;
- exact matching and placeholder selection;
- structured string-value traversal;
- intervention metadata and secret-safe diagnostics.

The core emits semantics such as `secret-replaced(label, count)` and
`registry-malfunction(kind)`. It does not emit harness UI concepts such as a
toast, progress event, or `systemMessage`.

### Adapters

An adapter may only:

- parse and validate its host protocol;
- select the host-defined model-visible fields;
- invoke shared resolution and redaction behavior;
- map sanitized results back to the host protocol;
- map semantic events to host UI;
- implement the host-specific failure policy in the specification.

An adapter must not implement separate matching, source resolution, candidate
classification, placeholder rules, or registry precedence.

### Setup And Installers

Setup owns deterministic enrollment and integration installation. Harness
plugins or hooks must never download the Rust binary, alter enrollment, or ask
an LLM to interpret policy.

Installers operate through documented host configuration surfaces. They must
identify their exact managed artifact and preserve unrelated user configuration.
Observed state, not persisted lifecycle flags, determines whether an adapter is
installed or functioning. Persisted fingerprints or acknowledgements may be used
only to establish ownership and user intent.

## Dependency Direction

Dependencies flow inward:

```text
CLI and adapters
       ↓
application operations
       ↓
registry, resolver, matcher, intervention domain
       ↓
small parsing and filesystem primitives
```

The core must not import harness protocol types. The first Claude vertical slice
may use direct functions and enums; traits or general adapter frameworks should
be extracted only after a second concrete use demonstrates the need.

One Rust package containing a library and binary is the default starting point.
A workspace or additional crates require a concrete build, ownership, or release
need rather than anticipated reuse.

## Runtime Data Flow

For each covered event:

```text
host payload on stdin
        ↓
adapter protocol validation
        ↓
project-root selection
        ↓
strict global/project config loading
        ↓
fresh source resolution
        ↓
effective registry canonicalization
        ↓
leftmost-longest exact replacement in selected string values
        ↓
sanitized host response + intervention metadata
```

Runtime is one-shot and stateless. There is no daemon, registry cache, source
snapshot, persistent value history, or cross-event session store. Config writes
must be atomic enough that readers observe a complete old or new file; the exact
writer-locking mechanism is tactical.

## Domain Model

The minimum conceptual types are:

- `SourceReference`: environment, one dotenv key, all keys in a dotenv file, or
  one exact JSON file pointer;
- `KnownSource`: setup-time knowledge of bounded paths and credential fields that
  produces explicit source references but is absent from runtime policy;
- `Registry`: ordered source references from one config scope;
- `ResolvedSecret`: a non-empty UTF-8 value plus source identity and safe label;
- `EffectiveRegistry`: project entries followed by global entries for canonical
  label selection, while preserving additive protection;
- `Intervention`: replacement counts with optional emit-safe canonical labels;
- `Diagnostic`: stable internal classification plus secret-safe presentation
  data.

These names are conceptual, not required Rust identifiers. The canonical domain
language is in [CONTEXT.md](CONTEXT.md).

## Configuration Architecture

Global and project TOML use the same versioned source model. The global file is
trusted machine/user policy. The project file is committable project policy and
is automatically selected according to the specification.

V1 deliberately allows project config to name environment sources and arbitrary
supported source paths. Therefore project config can cause host-file reads or
disable the effective registry by being invalid. This is an accepted boundary
documented in [limitations.md](limitations.md), not an invitation for adapters to
weaken validation.

Integration ownership metadata may live in a separate file under the global
ContextVeil config directory so policy TOML remains comprehensible. It must not
contain resolved values or be treated as proof of health.

Config parsing is strict and versioned. Within major version 1, newer binaries
must continue reading earlier V1 files and managed hook state. Runtime protection
must not depend on setup having performed a migration.

## Source Resolvers

The current source expansion has three concrete resolver families:

- environment variables inherited by the hook process;
- dotenv files parsed without interpolation or execution;
- JSON files selected by exact RFC 6901 pointer, parsed without duplicate object
  members or transformations.

Resolvers return resolved, unresolved, or malfunction. They do not decide
whether a value looks secret. A dotenv file referenced by multiple entries must
be read and parsed once per event where practical, but caching must not survive
the process.

Additional file formats should be implemented as explicit source variants behind
the same registry operation. The next planned variants are exact INI fields and
npmrc entries. Do not expose a public plugin API or dynamic resolver loading in
anticipation.

## Known Source Discovery

Known Sources belong to setup, not runtime. Their maintained path and schema
knowledge yields ordinary environment, dotenv, or JSON source references. The
persisted policy never names a Known Source, so changing a definition cannot
silently change runtime reads; see
[`ADR-0001`](docs/adr/0001-persist-explicit-source-references.md).

The closed definitions and strict field vocabularies live in
`src/setup/known_source.rs`. `src/setup/discovery.rs` performs one shared bounded
project traversal for dotenv files and the anchored Claude
`.claude/settings.json` and `.mcp.json` patterns. There is no runtime
`KnownSource` variant: discovery emits existing `SourceReference` variants only.

The first implementation is a closed list of direct discovery functions with
small shared helpers. It is not a trait registry, manifest language, plugin API,
or generic structured-file scanner. Machine stores use exact standard or
setup-time environment-resolved paths. Project discovery performs one bounded
walk and recognizes only source-specific anchored patterns. Valid unmatched
structures are ordinary no-match results.

Codex, OpenCode, Copilot, and Claude representable primary and MCP plaintext
stores form the first Known Source release. Source-visible schemas use exact
structural fields. Private schemas use per-tool exact vocabularies and pinned
fixtures; they never authorize generic recursive secret-name matching in
unrelated JSON. The maintained matrix and evidence are in
[`docs/known-sources.md`](docs/known-sources.md). JSONC, raw sidecar formats,
keychains, helper execution, decoded representations, and other transformations
remain outside this discovery layer.

## Matcher

The matcher works on UTF-8 string values and implements the exact semantics in
the specification. A straightforward algorithm is acceptable for small
registries. Aho-Corasick is an optimization, not part of the security model.

The implementation must keep source values out of diagnostics. Avoiding all
in-memory copies, zeroizing memory, or locking pages is not an architectural
requirement. The process lifetime is intentionally short.

## Adapter Architecture

### Claude Code

Claude is the production adapter and the first vertical slice. The binary parses
native synchronous `PostToolUse` JSON and returns an `updatedToolOutput` with the
same key/type shape. Only string values are transformed. The installer edits
the documented user settings file using an absolute executable path and direct
arguments, not shell interpolation.

Production quality means protocol fixtures, safe shared-settings editing,
ownership-aware removal, conflict handling, synthetic verification, and manual
release qualification. It does not imply coverage beyond the host's mutable
event.

### Codex CLI

Codex is experimental. Its process adapter consumes supported `PostToolUse`
events. On intervention it suppresses the original model-facing result and
returns a sanitized textual rendering because the host does not provide
shape-preserving result replacement. This semantic degradation must remain
visible in setup and documentation.

### GitHub Copilot CLI

Copilot is experimental. Its process adapter handles transformed prompt text
and successful textual tool results. It owns a dedicated user hook file, avoiding
mutation of unrelated files where the host supports file-based aggregation.

### OpenCode

OpenCode is experimental. A small managed TypeScript file uses the documented V1
plugin API and `Bun.spawn` with explicit argv, piped stdin/stdout, and a timeout.
It supports `chat.message` and `tool.execute.after` only. Security semantics stay
in Rust. No V2 plugin API, provider wrapper, or experimental full-context hook is
part of V1.

## Failure Boundaries

The core distinguishes unresolved sources from malfunctions before adapter
translation. It never partially uses an effective registry after a malfunction.

| Boundary | Required architectural response |
| --- | --- |
| Optional source absent/unset/empty | Omit that source and continue |
| Config or enrolled source malformed/unreadable | Return malfunction; no partial matcher |
| Process adapter diagnoses malfunction | Emit host warning and no mutation |
| Process adapter crashes/times out | Host behavior governs; documented as fail-open |
| OpenCode malfunction detected by an executing plugin | Throw from the covered mutation hook |
| Host rejects a replacement | Surface through diagnostics where detectable |

Adapters must not claim fail-closed behavior where the host can ignore, time out,
or bypass them.

## Security Constraints

- Runtime source resolution and matching perform no network calls.
- Hook payloads use stdin and structured stdout, never argv or shell expansion.
- Stdout contains only host protocol output.
- No telemetry or persistent runtime logs are permitted.
- Errors, debug output, snapshots, and fixtures must not contain resolved values,
  source contents, matching lines, or deterministic value hashes. Setup UI may
  show only the masked previews required by `SET-010`.
- Untrusted labels and paths must be terminal-sanitized.
- Secret-bearing fixtures use generated canaries and assert canary absence from
  every output channel after intervention.
- Unsafe code is unnecessary for the expected implementation. Any future use
  requires a documented invariant and focused tests.

## Tooling

`mise` is the canonical entry point for development, CI, and release tasks.
Bootstrap must pin the Rust toolchain and supporting tools and provide:

```text
mise install
mise run format
mise run lint
mise run test
mise run check
mise run build
mise run fuzz-smoke
mise run release-check
```

`check` should compose the routine local quality gate. Routine CI invokes the
applicable format, lint, test, check, and build mise tasks. Fuzz and release jobs
invoke `fuzz-smoke` and `release-check` respectively. CI must not duplicate the
commands hidden behind those task names. Cargo remains the Rust build tool
underneath mise; committed lockfiles and explicit toolchain versions are required
for reproducibility.

## Test Architecture

- Unit and property tests cover registry and matcher invariants.
- Filesystem tests use isolated homes/projects for config, discovery, setup, and
  permissions.
- Protocol fixtures cover every supported path and failure mapping for every
  shipped adapter.
- Integration tests invoke the binary over stdin/stdout rather than bypassing
  adapter boundaries.
- Leak-regression tests assert canaries are absent from stdout, stderr,
  diagnostics, and returned model content.
- Fuzz targets cover untrusted JSON, TOML, dotenv, and matcher inputs.
- Live networked tests are optional; Claude resume behavior is a manual release
  qualification.

## Release Architecture

V1 produces checksummed standalone artifacts for Linux and macOS on x86_64 and
arm64. A maintained installer verifies the checksum and atomically places the
binary at a user-selected location, defaulting to `~/.local/bin/contextveil`.
The installer does not run setup or edit harness configuration.

Ordinary upgrades stay within the installed major version. Incompatible major
upgrades require affirmative opt-in. Release checks include clean installation,
upgrade, binary version, checksum, and setup-free invocation tests.

## Tactical Discretion

Implementers may choose module layout, parser and terminal libraries, matcher
implementation, writer locking, scoring weights, directory exclusion details,
and output wording where the specification is intentionally non-exact.

Prefer a smaller maintainable design over machinery added solely to satisfy an
internal shape imagined by these documents. A tactical choice that preserves
observable behavior and product intent needs no limitation entry. A known
behavioral deviation or security gap must be recorded in
[limitations.md](limitations.md) with impact, workaround, and verification.
