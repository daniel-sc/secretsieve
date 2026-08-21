# ContextVeil

ContextVeil is a local redaction primitive that keeps user-enrolled secrets out
of supported coding-agent model-context boundaries.

## Language

**Source Reference**:
A durable pointer naming where a protected value can be resolved without storing
the value itself.
_Avoid_: Secret snapshot, stored secret

**Known Source**:
A recognized class of secret-bearing local store that ContextVeil knows how to
discover and interpret.
_Avoid_: Named source, source adapter

**Enrolled Source**:
A source reference or file policy the user has chosen to protect.
_Avoid_: Detected secret, scanned secret

**Candidate**:
A source that setup presents for possible enrollment based on discovery and
advisory heuristics.
_Avoid_: Detected secret, confirmed secret

**Candidate Group**:
A setup choice within one enrollment scope containing candidate source references
whose currently resolved values are equal. Selecting the group enrolls every
represented source.
_Avoid_: Duplicate secret, merged source

**Resolved Secret**:
The current non-empty textual value obtained from an enrolled source.
_Avoid_: Credential record, stored secret

**Global Registry**:
The user's machine-scoped collection of enrolled sources.
_Avoid_: Global vault, system policy

**Project Registry**:
The project-scoped collection of enrolled sources described by the project's
`.contextveil.toml`.
_Avoid_: Repository vault, project secrets

**Effective Registry**:
The additive combination of the global registry and the one selected project
registry for a runtime event.
_Avoid_: Merged config, override policy

**Unresolved Source**:
An enrolled source that currently has no usable value because it is absent,
unset, empty, or is a non-UTF-8 environment value. Failure to decode or parse a
required textual source is a malfunction instead.
_Avoid_: Failure, invalid secret

**Malfunction**:
A configuration, source, protocol, or execution error that prevents trustworthy
use of the effective registry.
_Avoid_: Unresolved source, missing optional secret

**Match**:
An occurrence of a resolved secret inside one model-visible string value.
_Avoid_: Finding, heuristic detection

**Redaction**:
The deterministic replacement of a match before covered content reaches a
model.
_Avoid_: Encryption, masking, deletion

**Placeholder**:
The non-secret marker inserted by a redaction when a safe marker can be emitted.
_Avoid_: Token, grant, secret handle

**Intervention**:
The semantic result that one or more redactions occurred, including counts and
optional emit-safe labels but never matched values.
_Avoid_: Alert, policy violation

**Adapter**:
A harness-specific translator between a coding agent's extension protocol and
the shared ContextVeil behavior.
_Avoid_: Security core, provider proxy

**Coverage**:
The model-bound content paths a particular adapter can demonstrably mutate
before model consumption.
_Avoid_: Protection certificate, universal support

**Collision**:
An occurrence of a candidate value elsewhere in the current project that warns
the user the value may be too common for useful literal redaction.
_Avoid_: Match, duplicate source
