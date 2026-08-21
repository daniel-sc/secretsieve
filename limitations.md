# ContextVeil V1 Limitations

This document records accepted product gaps and implementation deviations. It is
not normative and does not authorize violating [specification.md](specification.md).
New deviations must include impact, workaround, and verification. Broad gaps
belong here; code comments should explain only local, non-obvious consequences
and may link to a limitation ID.

## Product Boundary

### LIM-001: Model Context, Not Credential Use

**Reality:** ContextVeil intervenes only at supported model-bound harness paths.
A process can read a credential and send it directly over the network without
that value entering model context.

**Impact:** ContextVeil is not an egress control, sandbox, capability broker, or
DLP boundary.

**Workaround:** Use environment isolation, least-privilege credentials, sandboxing,
and network policy when credential use itself must be controlled.

**Verification:** Release review compares public claims with `SEC-002` and rejects
claims that secrets can never leave the machine.

### LIM-002: Unknown And Transformed Values

**Reality:** Runtime matches only current exact values from enrolled sources.
Unknown credentials and encoded, hashed, split, normalized, partially revealed,
or otherwise transformed values are not recognized.

**Impact:** A model or tool can receive a semantically equivalent representation
that has no exact enrolled byte sequence.

**Workaround:** Enroll all relevant sources and use a separate secret scanner or
stronger execution boundary for unknown/adversarial disclosure.

**Verification:** Negative conformance fixtures demonstrate that transformed and
cross-field values are intentionally unchanged.

### LIM-003: String Values Only

**Reality:** Structured redaction processes decoded string values independently.
JSON object keys, binary data, images, attachment bytes, and values split across
fields or message parts are not covered.

**Impact:** A secret represented in an object key or non-text content may remain
model-visible on a host that forwards it.

**Workaround:** Avoid secret-bearing keys and binary embedding; use host-specific
controls for attachments.

**Verification:** Adapter fixtures preserve keys and non-string values and mark
these paths unsupported.

### LIM-004: Common Values Can Be Destructive

**Reality:** The user may enroll any non-empty UTF-8 value. Runtime has no minimum
length or collision heuristic. Wildcard files automatically enroll future keys.

**Impact:** A value such as `foo` can replace unrelated text extensively and
degrade tool semantics. Future wildcard values receive no enrollment-time review.

**Workaround:** Heed setup and doctor collision warnings; avoid wildcard policies
for files containing non-secret settings.

**Verification:** Setup requires explicit wildcard confirmation and unselects
currently colliding candidates by default.

### LIM-005: No Automatic Rehydration

**Reality:** A placeholder is a display marker, not a credential handle.
ContextVeil never restores a value inside a later tool call.

**Impact:** Tasks that require literal credentials may need the user to arrange
symbolic environment access or perform the operation outside the agent.

**Workaround:** Reference credentials symbolically through the tool environment
where appropriate; do not paste them back into prompts.

**Verification:** No public or internal adapter path maps placeholders to sources.

## Source And Configuration Limits

### LIM-006: Resolution Race

**Reality:** A tool may emit a dotenv value and rotate or delete its source before
the post-tool hook resolves current values.

**Impact:** The old emitted value is not matched.

**Workaround:** Restart/retry after rotation and avoid commands that print and
rotate a credential in one operation.

**Verification:** A regression fixture documents the accepted miss; no previous
value history is persisted.

### LIM-007: Environment Rotation Requires Restart

**Reality:** Hooks inherit the harness process environment. Changing a parent
shell does not modify an already-running harness environment.

**Impact:** Rotated environment values become active only in a newly launched
harness process. Dotenv values remain per-event fresh.

**Workaround:** Restart the coding-agent harness after rotating an enrolled
environment variable.

**Verification:** Status and documentation distinguish environment and dotenv
rotation behavior.

### LIM-008: Project Config Is Trusted To Read Host Paths

**Reality:** Automatically loaded project config may reference arbitrary dotenv
paths and environment names, including paths outside the project.

**Impact:** A cloned project can cause local host-file reads, influence redaction,
or act as a limited presence/equality oracle. Source values are still never
returned in diagnostics.

**Workaround:** Review `.contextveil.toml` before working in an untrusted project
and prefer global config for machine-specific external paths.

**Verification:** Security tests assert external paths resolve as specified while
diagnostics remain value-free.

### LIM-009: Invalid Project Config Disables Global Protection

**Reality:** Registry use is all-or-nothing. Invalid or unreadable selected
project policy disables otherwise valid global redaction for that event.

**Impact:** Project-controlled config can cause denial of protection. Process-hook
hosts may then pass original content.

**Workaround:** Run `contextveil doctor`, repair/remove the invalid file, and
review project policy before starting the harness.

**Verification:** Conformance tests assert no partial global fallback occurs.

### LIM-010: Unbounded Input Size

**Reality:** V1 imposes no ContextVeil-specific size cap on dotenv files or
intercepted payloads.

Setup's collision analysis also reads every readable regular file under the
project root, so it scales with project size rather than with the number of
candidates.

**Impact:** Very large files or payloads can consume excessive memory or exceed
the five-second host timeout, causing fail-open behavior in process-hook hosts.
Setup can take a noticeable moment on a very large repository.

**Workaround:** Keep credential files small and rely on normal harness output
limits. Diagnose slow paths with `contextveil doctor` and benchmarks.

**Verification:** Large-input tests measure behavior without promising a fixed
maximum: a 4 MiB dotenv file with about 90,000 wildcard keys, a 2 MiB tool
result, and 201 active values over a 512 KiB payload all complete well inside the
five-second host bound, and runtime cost is linear in input size rather than
quadratic.

## Host Integration Limits

### LIM-012: Process Hooks Fail Open

**Reality:** Claude, Codex, and Copilot continue with original content when the
hook crashes, times out, is disabled, is not trusted, emits malformed output, or
is bypassed by the host. Diagnosed ContextVeil malfunctions also pass original
content with a warning by product choice.

**Impact:** These integrations are safety guardrails, not reliable fail-closed
security boundaries.

**Workaround:** Use `status` and `doctor`, keep the configured executable path
valid, and address every host warning before continuing sensitive work.

**Verification:** Adapter failure fixtures assert warning and original-content
behavior; support material uses fail-open wording.

### LIM-013: Claude Coverage Gaps

**Reality:** Claude V1 rewrites successful `PostToolUse` results only. Failed
tool-result text cannot be replaced through the documented failure event. Tool
execution and host telemetry see the original result before intervention, and
replacement schema rejection can expose the original.

**Impact:** A secret printed by a failing command, unsupported result shape, or
host telemetry path may remain visible outside the covered model result.

**Workaround:** Treat command failures as uncovered, inspect doctor output, and
avoid tools that emit credentials before failing.

**Verification:** Protocol fixtures cover successful replacement and explicitly
negative failed-result cases. Manual release qualification checks resume replay.

### LIM-014: Codex Textual Replacement

**Reality:** Codex does not provide shape-preserving `tool_response` replacement.
Its `updatedMCPToolOutput` field is rejected by the host, so the only mechanism
that changes what the model sees is a block decision whose `reason` becomes the
model-facing text. On intervention, ContextVeil therefore blocks the original
model-facing result and supplies a sanitized textual rendering for supported
`PostToolUse` events.

Three further host-specific limits apply, verified against the Codex source:

- a newly installed or changed hook stays untrusted, and untrusted hooks do not
  run, until the user accepts it in Codex's own hook-review screen;
- Codex also accepts hooks declared inline in `config.toml`. ContextVeil neither
  writes nor inspects that form, so a competing mutating hook declared there is
  not reported as a conflict;
- a tool call that fails outright emits no `PostToolUse` event at all, while a
  shell command that merely exits non-zero does emit one and is covered.

**Impact:** A successful or typed result may appear error-like and lose structure,
images, or code-mode semantics. Protection does not start until the user trusts
the hook. Hosted or specialized tools may not emit the event, and failed-result
coverage is not universal.

**Workaround:** Complete Codex's hook-review step after setup, declare competing
hooks in `~/.codex/hooks.json` so they are visible to `contextveil doctor`, and
retry with narrower text-producing tools when the sanitized replacement no longer
gives Codex enough structure.

**Verification:** Experimental protocol fixtures assert original suppression,
cover the non-zero-exit and structured-result paths, and document semantic
degradation. Setup prints the trust step, and the offline synthetic check
requires the block decision to carry the placeholder.

### LIM-015: Copilot Coverage Gaps

**Reality:** Copilot V1 covers transformed prompt text and successful textual
tool results. Failed errors, non-text attachments, other context injection paths,
and the original prompt displayed in the local timeline are not rewritten. A
failed tool result arrives on a separate host event that offers no result
replacement at all.

Two further host-specific limits apply:

- Copilot merges hooks from repository files and from inline `settings.json`
  sections as well as from `~/.copilot/hooks/`. ContextVeil owns one file in that
  directory and inspects only that directory for competing hooks, so a mutating
  hook declared elsewhere is not reported as a conflict.
- The host documents that rewrites do not compose across multiple hooks on some
  events, and does not document composition for the two covered events. Another
  hook that also rewrites the same content may therefore win, regardless of
  order.

**Impact:** Enrolled values may remain in uncovered model paths or local UI, and
a competing rewrite outside the inspected directory is neither reported nor
prevented.

**Workaround:** Avoid pasting credentials into attachments, treat failed tool
output as uncovered, and keep competing hooks in `~/.copilot/hooks/` so
`contextveil doctor` can report them.

**Verification:** Fixtures cover both mutable paths, the failed-result negative
case, clean and malformed input, the progress summary, and the warning channel.
Installation and removal tests assert that unrelated hook files are untouched.

### LIM-016: OpenCode V1 API Only

**Reality:** The adapter uses documented V1 `chat.message` and
`tool.execute.after` hooks. It does not use the V2 plugin API, experimental full
context transforms, provider wrappers, generic MCP special cases, failed-tool
paths, attachments, existing history, or auxiliary model requests. Throw/abort
behavior applies only after the plugin has loaded and is executing; load failure,
disablement, and host bypass cannot be made fail-closed by the plugin.

Two further host-specific limits apply, verified against OpenCode 1.18.18:

- `tool.execute.after` runs only after a tool returns successfully, so a tool that
  throws is not covered at all;
- OpenCode discovers plugins one level deep in `plugin/` and `plugins/`, and gives
  no static way to tell which hooks another plugin registers. Setup therefore lists
  every other plugin file for approval by name rather than by behavior, and cannot
  tell whether one of them also rewrites the same content.

`Bun.spawn` inherits a snapshot of the environment taken when the host process
started rather than the live environment, so the plugin forwards the current
environment explicitly. Environment rotation still requires restarting the
harness (`LIM-007`).

**Impact:** OpenCode coverage is broad enough to be useful but incomplete and
version-sensitive. A malfunction detected by an executing plugin aborts the
covered operation; a plugin that never loads cannot intervene.

**Workaround:** Keep the integration explicitly experimental and rerun doctor
after OpenCode upgrades.

**Verification:** Tests target only the two documented hook paths and assert
abort-on-malfunction behavior.

### LIM-017: Hook Composition Is Not A Security Boundary

**Reality:** Hosts may run multiple hooks concurrently or with undocumented
mutation ordering. Other hooks can see original content before ContextVeil and
may replace its result.

**Impact:** Installing ContextVeil cannot prevent another hook from logging,
exfiltrating, or reintroducing a value. User-approved Claude conflicts are still
reported as healthy by product choice.

**Workaround:** Review every competing hook presented by setup and remove
untrusted mutators.

**Verification:** Doctor continues listing approved conflicts; installers never
delete or reorder unrelated hooks.

### LIM-018: No Harness Version Gate

**Reality:** V1 performs no minimum or maximum host version checks despite hook
APIs evolving independently.

**Impact:** A host upgrade can change behavior before ContextVeil's compatibility
fixtures are updated.

**Workaround:** Run doctor after upgrades and use optional Claude live canary when
assurance is needed.

**Verification:** Health relies on configuration and synthetic checks, never a
version-range certificate. The host versions each protocol was verified against
are recorded in the release notes as evidence, not as a supported range.

### LIM-019: Project Roots And Multi-Root Sessions

**Reality:** Each event uses one project registry. Claude and OpenCode use stable
roots where available; Codex and Copilot may fall back to event `cwd`. Added or
multi-root workspaces are not merged.

**Impact:** A secondary workspace's project enrollment may be absent, or an
experimental adapter may select a different config after a directory change.

**Workaround:** Put universally required references in global config or launch a
separate session from the secondary project.

**Verification:** Project-selection tests cover nearest-config and cwd fallback.

## Operational Limits

### LIM-020: No Memory-Erasure Guarantee

**Reality:** V1 uses ordinary process memory. It does not guarantee zeroization,
locked pages, core-dump exclusion, swap exclusion, or resistance to same-user
debugging.

**Impact:** Resolved values may transiently exist in process or operating-system
memory outside ContextVeil's model-context claim.

**Workaround:** Apply operating-system hardening where local memory disclosure is
in scope.

**Verification:** Documentation avoids memory-protection claims.

### LIM-021: Interactive Configuration Only

**Reality:** Setup requires a TTY, and status/doctor expose no stable JSON output
contract.

**Impact:** Fully unattended enrollment and structured fleet diagnostics are not
supported in V1.

**Workaround:** Manage the documented TOML and host configuration through
external automation, then run human-readable diagnostics.

**Verification:** Non-TTY setup fails without writes.

### LIM-022: Non-UTF-8 Source Paths

**Reality:** TOML can represent only UTF-8 strings. Automatic discovery skips
dotenv files whose project-relative path contains non-UTF-8 bytes, although it
renders the unavailable path safely in setup.

**Impact:** A dotenv source at such a path cannot be enrolled directly in V1.

**Workaround:** Rename the file or an ancestor directory to a UTF-8 name, or
expose the credential through an enrolled environment variable.

**Verification:** A Unix test asserts such a path is safely reported, not parsed
or persisted. Its discovery half additionally creates the file, which runs only
where the filesystem accepts a non-UTF-8 name; APFS rejects one, so macOS covers
the reporting half alone.

### LIM-023: Known Source Discovery Is Advisory

**Reality:** Known Source discovery is setup-time, advisory, and version-sensitive;
it is not an adapter coverage guarantee or a promise to find every host
credential. It inspects only the exact machine paths and bounded project patterns
in [`docs/known-sources.md`](docs/known-sources.md), then persists ordinary
environment or exact JSON references. It accepts strict JSON only. Valid unknown
schemas silently no-match; malformed matched JSON, including JSONC, is shown as
unavailable. Recognized dynamic object members are candidates only when their
names are representable as exact JSON Pointers under `CFG-016`; empty names and
`*` silently no-match. Keychains and credential helpers are not queried.

Copilot CLI 1.0.80 commonly writes a comment-bearing JSONC `config.json` that the
V1 strict JSON resolver cannot enroll. Its raw `.secret` and `.verifier` files
and `mcp-secrets` fallback files are not representable by V1 environment, dotenv,
or JSON source references and are not discovered. On macOS, Claude's primary
credentials are keychain-backed, so `.credentials.json` primary discovery is
non-macOS only. Path overrides are resolved during setup; changes require a
rerun. Relative overrides are invocation-directory relative and receive no
shell, environment-variable, glob, or tilde expansion. These are source-format
boundaries, not an implementation-not-present deviation.

**Impact:** Setup may show a matched strict-JSON path as unavailable or silently
omit a valid but unknown schema or an otherwise recognized dynamic member whose
name cannot be represented by `CFG-016`. Credentials in Copilot's common
JSONC/raw fallback stores, the macOS Claude keychain, a new third-party schema,
an unusual path, or a changed override are not automatically suggested.
Installing an adapter does not change this source-discovery boundary.

**Workaround:** Review setup candidates, rerun setup after host or override
changes, and manually enroll a supported environment, dotenv, or exact strict-JSON
reference when one represents the value. Use host diagnostics and separate
keychain controls for keychain- or helper-backed credentials. Copilot raw/JSONC
stores require a future source format or another representable source.

**Verification:** Unit fixtures pin every recognized field vocabulary and host
version; filesystem and setup tests cover exact and anchored paths, override
resolution, strict-JSON unavailability, silent unknown-schema no-match, symlink
rules, explicit-reference persistence, and canary-free output. Documentation
tests require the public matrices and pinned evidence links.

## Implementation Deviations

### DEV-001: The Live Claude Canary Has No Automated Coverage

Contract: `DIA-005`, `TST-008`, `REL-008`

**Observed behavior:** `contextveil doctor` offers the optional Claude live
canary, and the code path that runs it is shipped, but no automated test starts
the request. How its reply is classified is a pure function covered by unit
tests; only the paid, networked request itself is uncovered. Every other doctor
check, including the offline synthetic protocol check, is covered by tests.

**Reason:** The canary starts a paid, networked Claude Code request and needs
host credentials. `TST-008` forbids gating routine CI on paid or networked tests,
so covering it automatically is not permitted.

**Impact:** A regression in the live-canary invocation itself, for example a host
CLI flag changing, would be caught by the manual release qualification rather
than by CI. The check fails loudly rather than silently passing: a host that
cannot be started, a non-zero exit, a timeout, or a disclosed value are all
reported as a failure.

**Workaround:** Run `contextveil doctor` on a terminal and confirm the canary
before relying on it, and treat `REL-008` as the gate for release.

**Verification:** The manual live qualification in `REL-008` exercises this path
against the tested host version, and its result is recorded as release evidence
in `docs/qualification.md`. The run of 2026-08-17 against Claude Code 2.1.233
passed and found that the canary's own pass condition was too weak; that is
recorded in the same file, along with the fact that the run was performed by an
automated session and still needs human sign-off.

### DEV-002: Copilot Prompt Coverage Rests On An Inferred Host Rule

Contract: `COP-002`, `SUP-004`

**Observed behavior:** The Copilot adapter redacts `userPromptTransformed` text by
returning `modifiedTransformedPrompt`. The host documentation states explicitly
that the neighboring `userPromptSubmitted` event honors its `modifiedPrompt` only
for SDK hooks, not for command hooks, and it states explicitly that `postToolUse`
honors `modifiedResult` for command hooks. It makes no such statement either way
for `userPromptTransformed`.

**Reason:** Copilot CLI is experimental in V1 (`SUP-003`) and `SUP-004` forbids
host version gates, so coverage is derived from the documented schema plus offline
synthetic verification rather than from a live host run.

**Impact:** If Copilot ignores `modifiedTransformedPrompt` for command hooks, the
prompt path is silently uncovered while the tool-result path still works. The
offline synthetic check cannot detect this, because it exercises ContextVeil's
side of the protocol only.

**Workaround:** Treat Copilot prompt coverage as unproven until a live check is
performed, and rely on the Claude production integration where prompt-path
assurance matters.

**Verification:** Protocol fixtures assert ContextVeil emits exactly the
documented response shape for both events. Confirming that the host honors the
prompt mutation requires a live Copilot run, which is out of scope for automated
tests (`TST-008`).

Add future deviations using this template:

```text
### DEV-NNN: Short title

Contract: requirement IDs
Observed behavior:
Reason:
Impact:
Workaround:
Verification:
Resolution or accepted status:
```
