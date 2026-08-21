# ContextVeil Vision

This document describes why ContextVeil exists and the product direction. It is
not the normative behavior contract. See [specification.md](specification.md) for
requirements and [architecture.md](architecture.md) for technical boundaries.

## Product Promise

ContextVeil keeps enrolled local secrets out of supported coding-agent model
context by deterministically redacting exact, locally resolved values before the
model sees them.

The concise positioning is:

> ContextVeil keeps enrolled local secrets out of coding-agent model context
> through deterministic local redaction.

This statement is always accompanied by the current support matrix and its
host-specific limits. ContextVeil is a safety primitive, not a claim that
credentials can never leave the machine.

ContextVeil is free and open source under MIT OR Apache-2.0. It requires no
account, subscription, hosted service, or paid runtime component.

## Problem

Coding agents legitimately read files and run tools whose output can
incidentally contain credentials. Commands such as `printenv`, `cat .env`,
configuration inspection, debugging, stack traces, and MCP tools can place a
local credential into the next remote model request even when neither the user
nor agent intended to disclose it.

ContextVeil changes the model-bound result:

```text
GITHUB_TOKEN=ghp_example
```

into:

```text
GITHUB_TOKEN=<SECRET:GITHUB_TOKEN>
```

The local operation has still happened. ContextVeil intervenes only at a
supported model-context boundary.

## Defining Choice

Most secret scanners ask at runtime whether arbitrary text looks secret.
ContextVeil instead asks the user during setup which local sources should be
enrolled, using bounded Known Source knowledge where it improves discovery,
then performs literal matching against their current values at runtime and
redacts matches before covered content enters model context.

```text
smart enrollment
+ deterministic runtime
+ honest host-specific coverage
```

This choice favors predictability, arbitrary private credential formats, low
false-positive rates, auditability, and a small implementation. It deliberately
gives up automatic protection for unknown or transformed secrets.

## Why ContextVeil

- **Less disruptive redaction.** ContextVeil does not broadly block file reads,
  tool execution, or access to configuration files. Covered operations continue
  normally; only enrolled values in model-bound content are redacted.
- **Predictable behavior.** The user decides which sources are sensitive, and
  runtime matching is literal and deterministic. There is no changing classifier
  deciding whether arbitrary text looks secret on every event.
- **Low runtime overhead.** After initial setup, runtime performs local
  exact-value matching without network calls, provider lookups, or LLM
  classification. Clean events remain silent.
- **Private formats work.** Redaction does not depend on a provider-specific
  regex or recognizable token format. Any enrolled textual credential can be
  protected.
- **Rotation without re-enrollment.** ContextVeil stores source references rather
  than copied values, so file-backed changes are picked up on subsequent events
  and environment changes after restarting the harness.
- **Inspectable and independently useful.** The small shared Rust core, explicit
  host coverage, permissive open-source licensing, and lack of a hosted runtime
  make behavior independently auditable.

Unlike controls that block access to sensitive files or classify every result
heuristically, ContextVeil preserves useful tool output and redacts only exact
enrolled values at covered model boundaries.

## User Experience

The normal journey is:

1. Install the standalone binary.
2. Run `contextveil setup` from a project directory.
3. Review global and project candidates from environment, dotenv, and supported
   Known Sources without exposing complete plaintext values.
4. Select supported coding-agent integrations.
5. Work normally; clean events are silent.
6. See a concise notification only when ContextVeil redacts a value.
7. Use `contextveil status` or `contextveil doctor` when inspecting coverage.

The same setup command is safe to rerun as sources, projects, or integrations
change.

## Principles

- **Local by default.** Runtime resolution and redaction make no network calls.
- **User-authorized enrollment.** Heuristics suggest; the user decides.
- **Boring runtime.** Matching is literal, case-sensitive, and deterministic.
- **Source references over snapshots.** Values are resolved from explicit local
  source references rather than copied into ContextVeil configuration.
- **Known sources, not generic crawling.** Setup recognizes bounded secret-bearing
  stores and schemas. It does not recursively inspect arbitrary JSON, YAML, XML,
  TOML, or similarly named files for secret-like fields.
- **One security core.** Harness adapters translate protocols but do not
  reimplement source resolution or matching.
- **Silent success.** Runtime produces UI only for intervention or malfunction.
- **Honest coverage.** Installation is not a certificate, and each host's gaps
  remain visible.
- **Small and inspectable.** Prefer the smallest maintainable implementation
  that preserves the security claim.
- **Free and open source.** Keep the entire protection path inspectable under
  permissive licenses, without an account or hosted dependency.
- **Pragmatic evolution.** Tactical implementation choices may vary when they
  preserve intent and observable behavior. Known gaps belong in
  [limitations.md](limitations.md).

## V1 Support Posture

| Harness | V1 status | Intended coverage |
| --- | --- | --- |
| Claude Code | Production | Successful `PostToolUse` string values |
| OpenAI Codex CLI | Experimental, opt-in | Supported `PostToolUse` results via sanitized textual replacement |
| GitHub Copilot CLI | Experimental, opt-in | Transformed user prompts and successful textual tool results |
| OpenCode | Experimental, opt-in | Documented V1 `chat.message` and `tool.execute.after` text paths |

Experimental means functional and tested against protocol fixtures, but not part
of the production support promise. Experimental installation always requires an
affirmative choice.

## Success

V1 succeeds when:

- an enrolled credential in a covered path is absent from model-visible content;
- source rotation is picked up according to the source's process/filesystem
  semantics without copying plaintext into config;
- users can understand whether a registry and adapter are active, inactive, or
  impaired;
- clean tool use remains unobtrusive and fast;
- adapters cannot silently broaden the core security semantics;
- failures and coverage gaps are documented without inflated claims;
- the implementation remains small enough to audit and maintain.

## Non-Goals

ContextVeil V1 is not a:

- secret manager or vault;
- sandbox, capability system, or environment isolator;
- network proxy, egress firewall, or DLP platform;
- general prompt-injection or behavioral defense;
- runtime regex, entropy, provider-pattern, or LLM classifier;
- detector for secrets that were never enrolled;
- command analyzer or credential-use policy engine;
- credential broker that rehydrates placeholders into tool calls.

Direct flows such as `environment -> local process -> network` do not need to
enter model context and are outside the product boundary. See
[limitations.md](limitations.md) for the complete current boundary.

## Evolution

Future work may add source formats, additional Known Sources, stronger host
integrations, environment controls, or explicit credential grants. Semantic
decoding and other derived representations remain separate from exact-value
redaction unless the product security model is deliberately revised.
