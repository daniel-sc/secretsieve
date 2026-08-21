# Security Policy

ContextVeil is a local model-context redaction primitive. Please read
[limitations.md](limitations.md) before reporting: several gaps are deliberate,
documented parts of the V1 boundary rather than vulnerabilities.

## Reporting A Vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories:

<https://github.com/daniel-sc/contextveil/security/advisories/new>

Please do not open a public issue for an unfixed vulnerability.

Include:

- affected version (`contextveil --version`) and platform;
- the coding-agent harness and integration involved, if any;
- reproduction steps and observed versus expected behavior;
- the impact you believe the issue has.

**Never include a real credential.** Reproduce with a generated placeholder
value such as `SSCANARY_EXAMPLE_0123456789abcdef`. Reports containing real
credentials will be deleted and you will be asked to rotate the value and resend
the report.

## Response Expectations

- Acknowledgement within 5 working days.
- An assessment, including whether the report describes a documented limitation,
  within 15 working days.
- Coordinated disclosure once a fix or documented mitigation is available.

## In Scope

- Disclosure of a resolved source value through diagnostics, logs, snapshots,
  configuration, error output, or intervention metadata.
- Failure to redact an enrolled value on a covered adapter path that the support
  matrix presents as protected.
- Terminal escape, path, or label injection through ContextVeil output.
- Configuration or integration installation that corrupts unrelated user or
  harness configuration.
- Execution of untrusted content by the configuration, dotenv, or JSON parsers.

## Out Of Scope

Everything documented in [limitations.md](limitations.md), in particular:

- direct credential use or network exfiltration by a local process (`LIM-001`);
- unknown, transformed, or encoded values (`LIM-002`);
- content outside string values, such as object keys or binary data (`LIM-003`);
- destructive replacement caused by deliberately enrolling common values
  (`LIM-004`);
- fail-open behavior of hosts that crash, disable, time out, or bypass a hook
  (`LIM-012`);
- memory-residency of resolved values in ordinary process memory (`LIM-020`).

## Supported Versions

The latest release in the current major version receives security fixes.
