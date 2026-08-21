# Requirement-To-Test Traceability Audit

This document maps every normative requirement ID in
[specification.md](../specification.md) to its implementation and its test or
check evidence. `specification.md` is authoritative for observable behavior;
this audit does not change it and records no new requirements.

Each row gives one requirement ID, a one-line paraphrase (not a substitute for
the normative text), where the behavior lives in the source tree, the test or
check that would fail if the behavior regressed, and a status:

- `covered` — implemented, with a test or check that would fail on regression.
- `covered-by-design` — nothing to implement (typically a prohibition satisfied
  by the absence of code); the reason is given in the same clause.
- `manual` — verifiable only by a human or a paid/networked run.
- `gap` — no implementation or evidence was found.

Findings were produced by reading the cited source and test files directly,
not by trusting requirement-ID comments alone. To regenerate this mapping,
re-run `grep -rn "<ID>"` across `src/` and `tests/` for each ID in
specification.md, read the matched code and its nearest test, and re-classify.
Every row was checked against the repository as of the point this document was
written; at that point `mise run check` (format, lint, test, and the OpenCode
plugin suite) passed in full, with no failing test.

## 1. Security Claim (`SEC-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| SEC-001 | Help prevent resolved values reaching model context via covered adapter paths | src/matcher.rs (`Redactor`), src/redact.rs, src/adapter/{claude,codex,copilot,opencode}.rs | tests/leaks.rs::no_adapter_discloses_an_enrolled_value; per-adapter protocol fixtures in tests/claude_hook.rs, tests/codex_hook.rs, tests/copilot_hook.rs, tests/opencode/plugin.test.ts | covered |
| SEC-002 | Must not claim protection beyond the support matrix | Public documentation; limitations.md LIM-001/LIM-002 | Manual release review compares public claims with the requirement; prose meaning is not inferred from keywords | manual |
| SEC-003 | Runtime resolution/redaction make no network calls; install and the Claude live canary are the only network-capable workflows | Cargo.toml dependencies (`serde`, `serde_json`, `toml` only — no HTTP client in the binary); src/integration/claude.rs:223 (live canary is the one exception) | tests/diagnose.rs (comment-anchored assertion that nothing else reaches the network, ~line 298); tests/diagnose.rs::doctor_is_not_offered_the_live_canary_without_a_terminal | covered |
| SEC-004 | Must not persist, configure, or diagnose with resolved values | src/setup/write.rs (only source references are ever written); src/matcher.rs intervention metadata (counts/labels only); src/source.rs malfunction reasons never quote content | tests/leaks.rs::a_complete_setup_run_writes_no_value_anywhere, ::no_adapter_discloses_an_enrolled_value, ::diagnostics_never_disclose_an_enrolled_value, ::a_malfunction_on_every_adapter_discloses_nothing | covered |
| SEC-005 | No telemetry, crash upload, analytics, or persistent runtime logging | Absence of any such dependency (Cargo.toml lists only `serde`, `serde_json`, `toml`) or code path | tests/leaks.rs::runtime_writes_no_log_or_telemetry_file (walks the isolated home before/after every adapter, status, and doctor run and asserts no new file appears) | covered |
| SEC-006 | Untrusted terminal strings render as one visible-escaped logical line; non-UTF-8 path bytes render as `\xNN` | src/sanitize.rs::text, ::path, ::bytes | src/sanitize.rs unit tests (`control_characters_become_visible_escapes`, `escape_sequences_cannot_reach_the_terminal`, `bidi_and_separator_controls_are_escaped`, `every_rendering_occupies_one_logical_line`, `invalid_utf8_bytes_are_escaped`, `non_utf8_paths_are_rendered_without_raw_bytes`); tests/leaks.rs::terminal_hostile_names_and_paths_are_escaped_in_diagnostics; tests/setup.rs::terminal_escapes_in_names_and_paths_are_neutralized | covered |

## 2. Supported Platforms And Integrations (`SUP-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| SUP-001 | Support Linux and macOS on x86_64 and arm64 | .github/workflows/release.yml (package matrix: x86_64/aarch64-linux-gnu, aarch64/x86_64-apple-darwin); install.sh platform detection | scripts/release-check.sh (native artifact + checksum verification); .github/workflows/ci.yml matrix (ubuntu-latest x86_64, macos-latest arm64) | covered |
| SUP-002 | Claude is production; Codex, Copilot, OpenCode are experimental | src/integration/mod.rs (`Tier` enum) | src/integration/mod.rs::only_claude_is_production; tests/documentation.rs::public_support_matrices_have_the_required_tiers | covered |
| SUP-003 | Experimental integrations labeled EXPERIMENTAL everywhere; opt-in only; not counted as production health | src/diagnose.rs:534 (`Tier::Experimental => " (EXPERIMENTAL)"`); src/setup/integrations.rs:171-174 (affirmative installation only) | tests/diagnose.rs (asserts output contains "EXPERIMENTAL", ~line 884); tests/setup.rs::an_experimental_integration_requires_an_affirmative_choice; tests/documentation.rs::public_support_matrices_have_the_required_tiers | covered |
| SUP-004 | No host version checks; health from configuration and synthetic checks | No version-detection code exists anywhere in src/; doc comment in src/integration/mod.rs states this explicitly | covered-by-design — a prohibition satisfied by the absence of any version-comparison code; DIA-003/DIA-006 evidence the config+synthetic-check alternative | covered-by-design |
| SUP-005 | Coverage applies to local harness modes honoring the integration; cloud/remote/container modes need separate install | README.md and release-note support-matrix scoping text | Manual release review compares the coverage statements with the requirement | manual |

## 3. CLI (`CLI-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| CLI-001 | `setup` is the only configuration workflow; no `init`/install/remove/slash commands | src/cli.rs::parse (rejects `init`, `install`, `uninstall`, `enroll`; only `setup`/`status`/`doctor` plus the hidden `hook` entry point) | src/cli.rs::v1_rejects_removed_and_unknown_commands, ::help_lists_only_public_commands, tests/cli.rs::help_hides_harness_protocol_entry_points | covered |
| CLI-002 | `setup` requires an interactive TTY; fails clearly without changing files otherwise | src/cli.rs::run_setup (`is_terminal()` check on stdin/stdout) | tests/cli.rs::setup_refuses_to_run_without_a_terminal | covered |
| CLI-003 | Public commands are human-readable only; no stable JSON contract | src/cli.rs::parse (only `-h/--help`, `-V/--version` accepted; any other flag is `UnknownOption`); limitations.md LIM-021 | src/cli.rs (flag-rejection tests); output is asserted as plain text throughout tests/diagnose.rs and tests/setup.rs | covered |
| CLI-004 | `setup` returns zero only when every write/action/verification completes | src/setup/mod.rs (cancellation and phase-failure handling) | tests/setup.rs::cancelling_the_first_phase_writes_nothing, ::a_project_phase_failure_keeps_the_committed_global_phase, ::a_malformed_settings_file_fails_the_integration_phase_without_changing_it | covered |
| CLI-005 | `status` returns zero whenever inspection completes, nonzero only if inspection itself fails | src/diagnose.rs (status exit logic) | tests/diagnose.rs::a_healthy_machine_exits_zero_for_both_commands, ::a_partially_unresolved_registry_is_healthy, ::an_inspection_that_cannot_complete_exits_two | covered |
| CLI-006 | `doctor` exit codes 0/1/2 per the documented health-failure rules | src/diagnose.rs (exit-code derivation) | tests/diagnose.rs::a_fully_inactive_registry_is_a_health_failure, ::a_partially_unresolved_registry_is_healthy, ::an_approved_conflict_stays_healthy_but_visible, ::an_inspection_that_cannot_complete_exits_two | covered |
| CLI-007 | Diagnosed process-hook failures exit zero after emitting valid host protocol output | src/cli.rs::run_claude_hook and equivalents; src/adapter/claude.rs (malformed-input handling) | src/adapter/claude.rs::malformed_input_is_diagnosed_without_echoing_the_payload (asserts `Exit::Ok`); equivalent malformed-input tests in tests/codex_hook.rs, tests/copilot_hook.rs | covered |

## 4. Configuration Locations And Selection (`CFG-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| CFG-001 | Global config path is XDG-based; directory/file are user-only | src/config.rs (`global_config_path`); src/setup/write.rs (0o700/0o600 permissions) | config.rs unit test on the XDG path; write.rs permission-mode test | covered |
| CFG-002 | Project config filename is `.contextveil.toml` | src/paths.rs (`PROJECT_CONFIG_FILENAME`) | tests/setup.rs (literal filename used throughout) | covered |
| CFG-003 | Setup project root: nearest `.contextveil.toml`, else Git worktree root, else cwd | src/paths.rs (`setup_project_root`) | paths.rs::project_root_selection_prefers_the_nearest_config, ::project_root_falls_back_to_the_git_worktree_then_the_directory, ::a_git_file_marks_a_worktree_root; tests/setup.rs::the_project_root_is_selected_from_the_working_directory | covered |
| CFG-004 | Runtime uses at most one, nearest-ancestor project registry; no merging | src/paths.rs (`runtime_project_config`); src/registry.rs (`build`) | registry.rs fixture asserting exactly one project registry is used | covered |
| CFG-005 | Per-adapter project root selection (Claude/OpenCode stable root; Codex/Copilot may use cwd) | src/adapter/claude.rs (project root from host field); src/adapter/opencode.rs (`Request.project_root`); Codex/Copilot adapters use event `cwd` | claude.rs::the_project_registry_is_selected_from_the_host_project_directory; tests/codex_hook.rs and tests/copilot_hook.rs::a_project_registry_is_selected_from_the_event_cwd | covered |
| CFG-006 | `version = 1` required; unknown fields/types/malformed entries/duplicate identities invalidate the file, including JSON identities | src/config.rs (`parse`, `parse_entry`); src/source.rs (`SourceRef::id`) | config.rs strict-field and normalized-identity tests for env, dotenv, and JSON | covered |
| CFG-007 | An env entry needs `source = "env"` plus non-empty `name`, no dotenv fields | src/config.rs (`parse_entry`, "env" arm) | config.rs::environment_entries_reject_dotenv_fields | covered |
| CFG-008 | A dotenv entry needs `file` plus exactly one of `key`/`all` | src/config.rs (`parse_entry`, "dotenv" arm) | config.rs::dotenv_entries_require_exactly_one_of_key_or_all | covered |
| CFG-009 | Global/project may share identity; project may reference external files/env names | src/config.rs (no cross-file identity check); src/registry.rs (`build`) | config.rs::project_config_may_reference_external_paths_and_environment_names; registry.rs::cross_scope_duplicate_identities_are_allowed | covered |
| CFG-010 | Paths stored as entered; `~/` expands to home; relative paths resolve against the config file; no env/glob/shell expansion | src/paths.rs (`expand`); src/config.rs (stores the entered string) | paths.rs::relative_paths_resolve_against_the_config_directory, ::a_leading_tilde_expands_to_the_home_directory, ::other_expansions_never_happen; config.rs::paths_are_stored_as_entered | covered |
| CFG-011 | Effective enrollment is additive (global + project); no negation/override | src/registry.rs (`build`) | registry.rs fixtures combining global and project registries | covered |
| CFG-012 | Invalid/unreadable config disables the entire effective registry, all-or-nothing | src/registry.rs (`Outcome::Malfunction`); src/config.rs (`Load::Invalid`) | registry.rs::an_invalid_project_config_disables_global_redaction, ::an_invalid_global_config_disables_project_redaction | covered |
| CFG-013 | Missing global config warns but keeps valid project redaction; missing project config is normal | src/registry.rs (`Warning::GlobalConfigMissing`); src/config.rs (`Load::Missing`) | registry.rs::a_missing_global_config_warns_but_keeps_project_redaction, ::a_missing_project_config_leaves_project_enrollment_empty | covered |
| CFG-014 | Setup must not overwrite invalid existing config; shows sanitized path/reason | src/setup/mod.rs (preflight, invalid-config reporting) | tests/setup.rs::an_invalid_existing_config_is_preserved_byte_for_byte, ::an_invalid_project_config_stops_setup_before_the_global_phase | covered |
| CFG-015 | Setup preserves existing valid enrollment by default; permits deliberate removal; never auto-removes unresolved entries | src/setup/mod.rs (enrollment-preservation logic) | tests/setup.rs::existing_enrollment_survives_a_rerun_even_when_unresolved, ::an_enrolled_entry_can_be_removed_deliberately | covered |
| CFG-016 | JSON entries require an explicit file and non-empty plain RFC 6901 pointer, with no wildcards or cross-source fields | src/config.rs (`parse_entry`, JSON arm); src/json.rs (`final_token`) | config.rs::json_entries_are_strict_and_require_a_supported_pointer; json.rs pointer-validation tests | covered |

## 5. Configuration Schema

Schema requirements are numbered under `CFG-*` above (`CFG-006` through
`CFG-010` and `CFG-016` cover the schema itself); there is no separate ID range
for section 5.

## 6. Source Resolution (`SRC-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| SRC-001 | Env reference resolves case-sensitively from the inherited environment | src/source.rs (`resolve_environment`) | source.rs::environment_names_are_case_sensitive_and_empty_values_are_unresolved | covered |
| SRC-002 | Unset/empty/non-UTF-8 env value is unresolved, never enters the matcher | src/source.rs (`Unresolved::NonUtf8`) | source.rs::non_utf8_environment_values_never_enter_the_matcher | covered |
| SRC-003 | Deterministic dotenv grammar (export, quoting, CRLF, comments, escapes) | src/dotenv.rs (`parse`, `Parser`) | src/dotenv.rs unit tests covering every grammar clause; fuzz/regressions/dotenv/{bom-and-trailing-comment,crlf-inside-quotes,export-space-is-malformed,unterminated-single-quote} | covered |
| SRC-004 | Last dotenv assignment wins; setup/doctor warn without showing values | src/dotenv.rs (last-key-wins); src/setup/mod.rs (duplicate warning) | dotenv.rs::the_last_assignment_wins_and_duplicates_are_reported; tests/setup.rs::duplicate_dotenv_keys_are_warned_about_without_values | covered |
| SRC-005 | Absent file/key or empty value is unresolved, not a malfunction | src/source.rs (`Resolution::Unresolved`) | source.rs::absent_files_keys_and_empty_values_are_unresolved | covered |
| SRC-006 | Permission denial, malformed dotenv, invalid UTF-8, or I/O failure disables the whole effective registry | src/source.rs (`SourceMalfunction`) | source.rs::malformed_and_invalid_utf8_files_are_malfunctions, ::an_unreadable_file_is_a_malfunction; src/registry.rs all-or-nothing tests | covered |
| SRC-007 | A wildcard entry resolves every current non-empty key without another setup run | src/source.rs (`Resolver::resolve`, `DotenvAll` arm) | source.rs::a_wildcard_entry_resolves_every_current_non_empty_key | covered |
| SRC-008 | No ContextVeil-specific dotenv size cap | src/dotenv.rs (linear parser, no size check) | tests/limits.rs (large-dotenv-file case); covered-by-design: absence of any cap-checking code | covered |
| SRC-009 | Sources resolved afresh per event; no cross-process cache or rotation history | src/source.rs (`Resolver` constructed per event; a file is read once per event only) | source.rs::a_file_is_read_once_per_event_and_duplicates_are_recorded | covered |
| SRC-010 | Dotenv changes observable next event; env changes need a harness restart | src/source.rs (doc comment tying this to SRC-009's per-event `Resolver`) | covered-by-design: an architectural consequence of a fresh `Resolver` per event plus process-immutable `Environment::from_process()`; not independently testable in-process (would require spawning a new harness process) | covered-by-design |
| SRC-011 | JSON resolver uses one exact pointer, rejects duplicate members, and performs no transformation | src/json.rs (strict visitor, `select`); src/source.rs (`JsonFileState`) | json.rs exact-selection and nested-duplicate tests; source.rs JSON resolver tests | covered |
| SRC-012 | Non-empty selected JSON strings resolve; missing/empty/non-string targets are unresolved | src/source.rs (`SourceRef::Json` resolution) | source.rs::a_json_pointer_resolves_only_a_non_empty_string | covered |
| SRC-013 | Missing JSON files are unresolved; malformed/unreadable/non-UTF-8/duplicate-member files malfunction | src/source.rs (`read_json`) | source.rs::missing_malformed_non_utf8_and_duplicate_json_are_classified; tests/diagnose.rs::duplicate_json_members_are_a_secret_safe_doctor_failure | covered |
| SRC-014 | JSON files are parsed once per event where practical and never cached across hook processes | src/source.rs (`Resolver::json_files`, constructed per event) | source.rs::a_json_file_is_parsed_once_per_event_and_fresh_next_event | covered |

## 7. Setup Discovery And Enrollment (`SET-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| SET-001 | Setup presents four phases in order after preflight parse of both config files | src/setup/mod.rs (`run`, preflight) | tests/setup.rs::an_invalid_project_config_stops_setup_before_the_global_phase, ::a_project_phase_failure_keeps_the_committed_global_phase | covered |
| SET-002 | Setup auto-inspects the process environment for vocabulary, URL, and Known Source candidates | src/setup/mod.rs (`environment_candidates`, `build_items`); src/setup/known_source.rs (`machine`, override and `OPENCODE_AUTH_CONTENT` inspection) | tests/setup.rs::a_gated_environment_candidate_is_enrolled_by_default, ::a_database_url_candidate_is_enrolled_as_its_environment_source, ::relative_known_source_overrides_use_the_setup_invocation_directory; src/setup/known_source.rs::claude_schema_matrix_recognizes_platform_primary_and_mcp_fields_only | covered |
| SET-003 | Recursive project dotenv discovery with documented exclusions; no symlinks/special files | src/setup/discovery.rs (`project_dotenv_files`, `walk`) | discovery.rs::discovery_is_recursive_and_includes_untracked_files, ::excluded_directories_are_never_entered, ::symlinks_and_special_files_are_skipped, ::a_fifo_named_like_a_dotenv_file_is_never_read, ::non_utf8_paths_are_reported_as_unavailable | covered |
| SET-004 | Global dotenv probing bounded to home + harness config directories, non-recursive | src/setup/discovery.rs (`global_dotenv_files`) | discovery.rs::global_probing_is_bounded_to_the_documented_locations; tests/setup.rs::global_dotenv_probing_covers_the_documented_locations | covered |
| SET-005 | Manual paths/keys/wildcard/env names and JSON pointers allowed; absent manual sources savable after confirmation | src/setup/mod.rs (`add_manual`) | tests/setup.rs::an_unresolved_manual_source_requires_confirmation, ::exact_json_fields_can_be_enrolled_manually_in_both_scopes, ::unresolved_json_may_be_confirmed_but_malformed_json_cannot | covered |
| SET-006 | Vocabulary remains the default gate, with bounded URL and Known Source exceptions | src/setup/vocabulary.rs (`Signal::KnownSource`); src/setup/credential_url.rs; src/setup/mod.rs (`build_items`, `rank_of`) | vocabulary.rs unit tests; credential_url.rs positive/negative fixtures; tests/setup.rs::non_credential_url_shapes_do_not_bypass_name_gating, ::known_sources_persist_explicit_refs_and_bypass_name_gating | covered |
| SET-007 | Automatic candidates selected by default unless colliding; enrolled groups stay selected | src/setup/mod.rs (`annotate_collisions`, grouped selection state) | tests/setup.rs::a_colliding_candidate_is_visible_but_unselected, ::a_partially_enrolled_group_saves_all_aliases_but_skip_is_exact, ::wildcard_values_exclude_their_file_for_other_candidate_groups | covered |
| SET-008 | User is authoritative: enrollment allowed after a collision warning; no minimum length | src/setup/mod.rs (no length gate anywhere in setup or matcher) | tests/setup.rs::a_collision_can_be_overridden_by_the_user; absence of a length check corroborated by REG-001 | covered |
| SET-009 | Wildcard enrollment requires an additional explicit confirmation | src/setup/mod.rs (`add_manual`, wildcard branch) | tests/setup.rs::wildcard_enrollment_requires_an_extra_confirmation | covered |
| SET-010 | Preview masking table by Unicode scalar length; no fingerprint shown | src/setup/preview.rs (`mask`, `describe`) | preview.rs unit tests, including `boundaries_follow_the_specified_table`, `length_is_counted_in_unicode_scalar_values`, `no_fingerprint_is_derived_from_the_value` | covered |
| SET-011 | Collision analysis is byte-exact and excludes every whole equal-value alias file | src/setup/collision.rs (`Subject::source_files`, `analyze`); src/setup/mod.rs (`alias_inventory`) | collision.rs::every_equal_value_alias_file_is_excluded; tests/setup.rs::every_alias_file_is_excluded_but_an_unrelated_collision_remains, ::equal_values_in_different_phases_remain_separate_choices | covered |
| SET-012 | Collision output shows counts and sanitized filenames only, never values/snippets | src/setup/collision.rs (`Collisions::describe`) | collision.rs::reports_contain_filenames_and_counts_but_never_values, ::filenames_are_sanitized_for_the_terminal | covered |
| SET-013 | Unavailable non-enrolled files excluded without aborting discovery; enrolled malformed sources must be repaired or removed | src/setup/discovery.rs (`inspect`); src/setup/mod.rs (blocking on enrolled malformed sources) | discovery.rs::malformed_and_unreadable_files_are_marked_unavailable; tests/setup.rs::an_enrolled_malformed_source_must_be_repaired_or_removed, ::an_unavailable_discovered_file_does_not_stop_discovery | covered |
| SET-014 | Atomic writes; independent phase commits; resumable, rollback-capable integration actions | src/setup/write.rs (`write`); src/setup/integrations.rs (phase commit/rollback) | tests/setup.rs::a_project_phase_failure_keeps_the_committed_global_phase, ::cancelling_the_first_phase_writes_nothing, ::rerunning_setup_with_no_changes_is_idempotent, ::rerunning_setup_leaves_an_installed_integration_byte_identical | covered |
| SET-015 | Multiline menus list all actions, including manual JSON, and repeat after loop actions | src/setup/mod.rs (`render_actions`) | tests/setup.rs::setup_lists_number_toggle_and_other_actions_separately, ::setup_repeats_the_action_menu_after_a_toggle | covered |
| SET-016 | Equal current values form phase-local Candidate Groups with all-alias selection, wildcard handling, and stable canonical order | src/setup/mod.rs (`merge_item`, grouped `Item`, `update_suppression`, `selected_sources`) | tests/setup.rs::equal_environment_candidates_are_one_group_and_enroll_every_alias, ::equal_values_in_different_phases_remain_separate_choices, ::a_partially_enrolled_group_saves_all_aliases_but_skip_is_exact, ::resolvable_manual_sources_merge_into_an_existing_group, ::a_selected_wildcard_suppresses_redundant_keyed_candidates, ::aliases_split_into_separate_rows_after_their_values_diverge | covered |
| SET-017 | Credential-bearing absolute URL values from env/dotenv become whole-value candidates | src/setup/credential_url.rs (`is_credential_bearing`); src/setup/mod.rs (`environment_candidates`, `file_candidates`, normal Candidate Group/collision pipeline) | credential_url.rs::database_registry_and_proxy_urls_are_recognized, ::non_credential_url_shapes_are_rejected; tests/setup.rs::a_database_url_candidate_is_enrolled_as_its_environment_source, ::registry_and_proxy_urls_are_discovered_in_dotenv_files, ::equal_url_candidates_use_the_normal_candidate_group, ::a_colliding_url_candidate_is_visible_but_unselected, ::url_looking_json_fields_are_not_automatic_candidates | covered |
| SET-018 | Known Sources are discovery-only, use bounded paths, resolve overrides at setup, and persist explicit references | src/setup/known_source.rs (`machine`, `project`, `path_override`); src/setup/discovery.rs (`project_files`); no runtime source variant exists in src/source.rs | tests/setup.rs::known_sources_persist_explicit_refs_and_bypass_name_gating, ::known_source_override_reruns_are_idempotent_and_pick_up_changes, ::relative_known_source_overrides_use_the_setup_invocation_directory, ::setup_follows_exact_machine_file_symlinks_but_not_project_symlinks; known_source.rs::exact_machine_fifo_and_symlink_to_fifo_are_skipped_promptly, ::copilot_mcp_oauth_directory_symlink_is_not_traversed | covered |
| SET-019 | Valid unmatched Known Source strict JSON is silent; malformed matched JSON is unavailable; fields are source-specific and CFG-016-representable | src/setup/known_source.rs (`inspect` plus exact per-host discovery functions); src/json.rs (`parse`, `final_token`) | known_source.rs::valid_no_match_is_silent_but_invalid_matched_json_is_noticed, ::unrepresentable_dynamic_pointer_tokens_are_skipped_without_panicking, and the four independently named `*_filesystem_matrix_covers_*` tests; tests/setup.rs::malformed_and_non_utf8_known_sources_are_visible_and_secret_safe | covered |
| SET-020 | Initial Known Sources cover the explicitly representable Codex, OpenCode, Copilot, and Claude primary/MCP stores without keychain/helper/raw-file claims | src/setup/known_source.rs (`codex`, `opencode`, `copilot`, `claude_machine`, `project`); docs/known-sources.md pins the support/evidence inventory | known_source.rs::codex_filesystem_matrix_covers_primary_mcp_override_and_failure_boundaries, ::opencode_filesystem_matrix_covers_primary_mcp_override_and_failure_boundaries, ::copilot_filesystem_matrix_covers_primary_mcp_override_and_failure_boundaries, ::claude_filesystem_matrix_covers_platform_primary_mcp_override_and_failure_boundaries, ::claude_schema_matrix_recognizes_platform_primary_and_mcp_fields_only; tests/documentation.rs::public_known_source_matrices_match_the_v1_boundary | covered |

## 8. Effective Registry (`REG-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| REG-001 | Every non-empty UTF-8 resolved value is an exact match pattern; no heuristics apply at runtime | src/matcher.rs (`Redactor::new`) | src/matcher.rs::matching_is_case_sensitive_and_byte_exact, ::matching_is_substring_matching | covered |
| REG-002 | Duplicate resolved values collapse to one canonical pattern (first project entry, else first global entry, in file order) | src/matcher.rs (value dedup); src/registry.rs (canonical ordering) | src/matcher.rs::duplicate_values_collapse_to_the_canonical_source; src/registry.rs::equal_values_canonicalize_to_the_first_project_entry; src/diagnose.rs alias-warning test | covered |
| REG-003 | Source/key names are case-sensitive; labels derive from env name, dotenv key, or final JSON pointer token, never a file path | src/secret.rs (`SourceId::key`, `label`); src/json.rs (`final_token`) | secret.rs::labels_derive_from_the_key_only; source.rs JSON-label test; config.rs case-sensitive JSON identity test | covered |
| REG-004 | Labels keep ASCII word characters, collapse other runs to `_` | src/secret.rs (`safe_label`) | src/secret.rs::labels_keep_only_the_allowed_character_set, ::labels_collapse_control_and_escape_sequences | covered |

## 9. Redaction Semantics (`RED-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| RED-001 | Matching is case-sensitive UTF-8 byte comparison; no normalization | src/matcher.rs (`match_at`, `redact`) | src/matcher.rs::matching_is_case_sensitive_and_byte_exact, ::utf8_values_match_without_normalization; tests/matcher_property.rs | covered |
| RED-002 | Matching operates independently per selected string value; fields are never joined | src/redact.rs (`redact_in_place`) | src/redact.rs::values_are_matched_independently_across_fields; tests/claude_hook.rs (split-value case) | covered |
| RED-003 | Leftmost-longest match selection with canonical-source tie-break | src/matcher.rs (`build_index`, `match_at`) | src/matcher.rs::same_start_overlap_prefers_the_longest_value, ::different_start_overlap_prefers_the_earliest_start; tests/matcher_property.rs::the_matcher_agrees_with_the_reference_model | covered |
| RED-004 | Substring matching; no token/word boundaries | src/matcher.rs (`redact`) | src/matcher.rs::matching_is_substring_matching | covered |
| RED-005 | Only decoded string values are transformed; keys, numbers, booleans, nulls untouched | src/redact.rs (`redact_in_place`) | src/redact.rs::object_keys_are_never_transformed, ::numbers_and_booleans_that_look_like_values_are_left_alone | covered |
| RED-006 | Placeholder fallback: `<SECRET:LABEL>` then `<SECRET>` then empty string | src/matcher.rs (`Redactor::new` decision logic) | src/matcher.rs::a_value_inside_the_named_placeholder_forces_the_generic_form, ::a_value_inside_every_placeholder_forces_deletion, ::a_placeholder_that_reproduces_a_value_is_rejected_before_insertion | covered |
| RED-007 | Generated placeholders are never rescanned/fed back through the matcher | src/matcher.rs (`redact`, cursor advances past a replacement) | src/matcher.rs::replacements_are_never_rescanned; tests/matcher_property.rs::no_active_value_survives_when_placeholders_cannot_be_reconstructed | covered |
| RED-008 | Intervention metadata carries counts/labels only, never values/hashes/content | src/matcher.rs (`Intervention`, `intervention`) | src/matcher.rs::intervention_summary_is_canary_free, ::unsafe_labels_are_aggregated_without_names; tests/leaks.rs::no_adapter_discloses_an_enrolled_value, ::diagnostics_never_disclose_an_enrolled_value | covered |
| RED-009 | Clean events are silent; unresolved sources produce no runtime UI | src/matcher.rs (`redact` returns `None` on no match); adapter call sites | src/matcher.rs::clean_input_is_unchanged_and_silent; tests/claude_hook.rs::a_clean_event_produces_no_output_at_all, ::an_unresolved_source_is_silent_and_does_not_fail_the_event | covered |
| RED-010 | No path replaces a placeholder with a source value later | No reverse-mapping code exists anywhere in src/; documented in src/redact.rs and README.md | covered-by-design — satisfied by the absence of any placeholder-to-source lookup path | covered-by-design |

## 10. Runtime Failure Policy (`RUN-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| RUN-001 | Malfunction/invalid config yields no partial redaction; original content passed with a warning | src/registry.rs (`Outcome::Malfunction`); adapter call sites in src/adapter/{claude,codex,copilot}.rs | tests/claude_hook.rs::an_invalid_global_config_disables_redaction_and_warns; src/registry.rs::an_invalid_project_config_disables_global_redaction | covered |
| RUN-002 | Claude, Codex, and Copilot are documented as fail-open | README.md support matrix; limitations.md LIM-012 | Manual release review verifies the documented failure behavior | manual |
| RUN-003 | The OpenCode plugin aborts the covered operation on subprocess failure; a notify failure does not undo the mutation | assets/opencode/plugin.ts (throws on crash/timeout/invalid protocol/malfunction; notify-failure guard) | tests/opencode/plugin.test.ts (subprocess-failure, invalid-protocol-output, reported-malfunction, and notify-failure-ignored cases) | covered |
| RUN-004 | Every installed hook/subprocess invocation uses a 5-second timeout | src/integration/{claude,codex,copilot}.rs (`TIMEOUT_SECONDS = 5`); assets/opencode/plugin.ts (`TIMEOUT_MS = 5000`) | src/integration/{claude,codex,copilot}.rs timeout-in-config tests; tests/{claude,codex,copilot}_hook.rs timeout-mapping tests | covered |
| RUN-005 | Runtime should target p95 below 100 ms for the documented workload (engineering benchmark, not a pass/fail gate) | benches/redaction.rs | `mise run bench` (`cargo bench --bench redaction`); tests/limits.rs::many_enrolled_values_stay_inside_the_host_timeout (loose 5-second wiring check only) | manual |
| RUN-006 | Malformed envelope/unknown event is a diagnosed malfunction; adapter warns without echoing the payload; OpenCode throws; uncovered-but-valid content is preserved | src/adapter/{claude,codex,copilot}.rs (malformed-envelope handling); src/adapter/opencode.rs (throw path) | tests/claude_hook.rs::invalid_input_is_diagnosed_without_echoing_the_payload, ::uncovered_fields_and_non_string_content_are_preserved_exactly; tests/opencode/plugin.test.ts (invalid-protocol-output case) | covered |

## 11. Integration Installation (`INT-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| INT-001 | Detect all four harnesses; Claude selected by default; experimental integrations unselected unless already ContextVeil-installed | src/setup/integrations.rs (default-selection logic); src/integration/mod.rs (`Tier`) | src/integration/mod.rs::only_claude_is_production; tests/setup.rs::an_experimental_integration_requires_an_affirmative_choice | covered |
| INT-002 | A user may install an undetected harness; setup discloses limited verification | src/setup/integrations.rs (undetected-harness path) | tests/setup.rs::an_undetected_harness_discloses_limited_verification | covered |
| INT-003 | Absolute binary path, direct argument arrays, stdin/stdout, no shell interpolation | src/integration/mod.rs (`current_executable`, `shell_quote`); src/integration/hooks_json.rs (`managed_command`) | src/integration/mod.rs::plain_paths_are_not_quoted, ::awkward_paths_are_quoted_so_the_shell_cannot_split_or_expand_them; tests/claude_hook.rs, tests/codex_hook.rs (spawn the real binary, feed stdin, read stdout) | covered |
| INT-004 | No duplicate managed entries; removal only when ownership/identity is established; modified/user-owned entries preserved with a warning | src/integration/hooks_json.rs (`Installed::Modified`, classification); src/integration/opencode.rs, src/integration/copilot.rs (`classify`) | src/integration/claude.rs::malformed_settings_are_never_overwritten, ::removal_by_deselection_removes_only_the_managed_entry; tests/setup.rs::rerunning_setup_leaves_an_installed_integration_byte_identical, ::deselecting_the_integration_removes_only_the_managed_hook | covered |
| INT-005 | Competing mutating hooks shown for individual approval; an approved conflict is not a health failure but stays visible | src/integration/hooks_json.rs (`Conflict`); src/setup/integrations.rs (`approve_conflicts`) | tests/setup.rs::a_competing_mutating_hook_is_offered_for_approval; src/integration/claude.rs::other_post_tool_use_command_hooks_are_reported_as_conflicts; tests/diagnose.rs::an_approved_conflict_stays_healthy_but_visible, ::an_unapproved_conflict_is_a_health_failure | covered |
| INT-006 | Installation success is not permanent proof; status/doctor derive current state from config/host artifacts | src/integration/mod.rs (`inspect` re-derives state on every call; no cached "installed" flag) | tests/diagnose.rs::a_missing_integration_is_a_health_failure, ::an_uninstalled_integration_reports_no_timeout | covered |

## 12. Claude Code Adapter (`CLA-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| CLA-001 | One managed synchronous wildcard `PostToolUse` hook in `~/.claude/settings.json`, 5-second timeout | src/integration/claude.rs (`SPEC`, `settings_path`, `install`) | src/integration/claude.rs (installation test asserting timeout=5, single hook group) | covered |
| CLA-002 | Recursively redact `tool_response` strings, preserve keys/non-strings/shape, return via `hookSpecificOutput.updatedToolOutput` | src/adapter/claude.rs (`handle`, `finish`) | src/adapter/claude.rs (shape-preservation test); tests/claude_hook.rs::every_supported_result_shape_is_redacted_without_changing_its_shape | covered |
| CLA-003 | On intervention, one safe `systemMessage` with count/labels; never `additionalContext` | src/adapter/claude.rs (`finish`) | src/adapter/claude.rs (intervention test asserting `systemMessage` present, no `additionalContext`) | covered |
| CLA-004 | Must not claim coverage for failed results, prompts, outgoing args, telemetry, local artifacts, or non-replaceable successes | Absence of such handling in src/adapter/claude.rs; limitations.md LIM-013 documents the gap explicitly | tests/claude_hook.rs::a_failed_tool_result_event_is_not_claimed_as_covered | covered |
| CLA-005 | Other matching `PostToolUse` hooks trigger INT-005 approval; once approved, they do not block healthy status | Shared conflict logic in src/integration/hooks_json.rs (see INT-005) | tests/diagnose.rs::an_approved_conflict_stays_healthy_but_visible | covered |

## 13. Codex CLI Adapter (`COD-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| COD-001 | One managed synchronous wildcard `PostToolUse` hook in `~/.codex/hooks.json`, 5-second timeout, host trust workflow | src/integration/codex.rs (`SPEC`, `hooks_path`, `install`, trust-note) | src/integration/codex.rs::installation_writes_the_documented_codex_shape, ::codex_is_experimental_and_carries_a_trust_note | covered |
| COD-002 | On a match, redact strings, block the original, provide sanitized text via the blocking mechanism | src/adapter/codex.rs (`handle`, `render`, `finish`) | src/adapter/codex.rs::a_match_blocks_the_original_and_supplies_sanitized_text, ::a_string_result_is_rendered_directly, ::structured_results_keep_their_shape_inside_the_rendering | covered |
| COD-003 | Disclose that intervention may turn a successful/structured result into error-like text and lose structure/images/types | src/adapter/codex.rs (`render` embeds the disclosure text); limitations.md LIM-014 | src/adapter/codex.rs::a_match_blocks_the_original_and_supplies_sanitized_text (asserts the disclosure wording) | covered |
| COD-004 | Must not claim every tool emits the event, that MCP results are shape-preserving, or full failed-result coverage | limitations.md LIM-014 documents all three explicitly | src/adapter/codex.rs::a_non_zero_exit_result_is_still_covered (documents the boundary) | covered |

## 14. GitHub Copilot CLI Adapter (`COP-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| COP-001 | Dedicated ContextVeil hook file under `~/.copilot/hooks/`, 5-second timeout, unrelated files untouched | src/integration/copilot.rs (`hook_file`, `install`, `managed_file`) | src/integration/copilot.rs::copilot_installs_one_dedicated_file_and_leaves_others_alone | covered |
| COP-002 | Redact `userPromptTransformed` and successful `postToolUse.toolResult.textResultForLlm`, preserve host result shape | src/adapter/copilot.rs (`handle`) | src/adapter/copilot.rs::a_transformed_prompt_is_redacted_with_one_progress_line, ::a_successful_tool_result_keeps_its_shape, ::extra_result_fields_are_preserved | covered |
| COP-003 | On intervention, one safe persistent progress summary before the final mutation object | src/adapter/copilot.rs (`redact_one` pushes the progress line) | src/adapter/copilot.rs::a_transformed_prompt_is_redacted_with_one_progress_line (asserts exactly one progress line) | covered |
| COP-004 | Must not claim coverage for failed tool errors, non-text attachments, other injection paths, or the local timeline prompt | limitations.md LIM-015 documents the gaps explicitly | src/adapter/copilot.rs::a_failed_tool_result_is_not_covered | covered |

## 15. OpenCode Adapter (`OCO-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| OCO-001 | One ContextVeil-owned TypeScript plugin file under `~/.config/opencode/plugins/`; JSON stdin/stdout to the absolute Rust binary | src/integration/opencode.rs (`plugin_file`, `install`, `render`) | src/integration/opencode.rs::installation_writes_one_owned_plugin_file; tests/opencode/plugin.test.ts (spawns the real plugin) | covered |
| OCO-002 | Use `chat.message` for new textual user parts and `tool.execute.after` for successful standard textual tool output | assets/opencode/plugin.ts (both handlers); src/adapter/opencode.rs (`Event`) | tests/opencode/plugin.test.ts ("new user text is redacted in place and announced", "successful standard tool output is redacted in place") | covered |
| OCO-003 | One safe named/count TUI notification when redaction occurs and the API is available | assets/opencode/plugin.ts (`announce`/`notify`) | tests/opencode/plugin.test.ts ("new user text is redacted...", "a notification failure does not undo the mutation") | covered |
| OCO-004 | Must not implement V2 APIs, provider wrappers, full-history/system transforms, tool-definition rewriting, or claim wider coverage | assets/opencode/plugin.ts (only the two documented hooks, no matcher logic); limitations.md LIM-016 | src/integration/opencode.rs::the_plugin_carries_no_matcher_or_resolver_logic; tests/opencode/plugin.test.ts ("explicitly unsupported paths are left alone without spawning") | covered |

## 16. Status And Doctor (`DIA-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| DIA-001 | Status inspects config, resolves sources, reports active/unresolved counts without adapter protocol tests; both select project root via CFG-003 from cwd | src/diagnose.rs (status implementation, project-root selection) | tests/diagnose.rs::status_runs_no_adapter_protocol_test, ::the_project_root_follows_the_working_directory | covered |
| DIA-002 | Registry and integration health are independent facets; zero active values shown as `INACTIVE` | src/diagnose.rs (registry/integration facets kept separate) | tests/diagnose.rs::a_partially_unresolved_registry_is_healthy, ::a_fully_inactive_registry_is_a_health_failure | covered |
| DIA-003 | Doctor additionally checks permissions, source errors, aliases, collisions, ownership, disabled hooks, conflicts, executables, timeouts, synthetic protocol behavior | src/diagnose.rs (`inspect` and permission/timeout/synthetic-check helpers, ~line 502, 720) | tests/diagnose.rs::malformed_configuration_fails_doctor_but_not_status, ::status_recognizes_a_hook_that_points_at_the_running_binary, ::an_uninstalled_integration_reports_no_timeout | covered |
| DIA-004 | Collision findings remain advisory and doctor applies grouped alias-file exclusions | src/diagnose.rs (`collision_findings` grouped subjects); src/setup/collision.rs | tests/diagnose.rs::doctor_groups_aliases_and_excludes_all_of_their_source_files | covered |
| DIA-005 | Optional paid/networked Claude live canary, disabled by default, requires confirmation, uses a random non-credential value, and passes only on a present placeholder | src/diagnose.rs (`LiveCanary` enum, `run_live_canary`); src/cli.rs (`run_doctor` gating); src/integration/claude.rs (`classify_canary`) | tests/diagnose.rs::doctor_is_not_offered_the_live_canary_without_a_terminal; src/integration/claude.rs::tests (reply classification: placeholder, inconclusive, disclosure, bytes, empty value); only the network request itself is exercised by a human (see limitations.md DEV-001) | manual |
| DIA-006 | Codex, Copilot, OpenCode have offline synthetic verification only; passing it does not remove the experimental label | src/diagnose.rs (`verify_offline` call, ~line 611-628) | src/integration/{codex,copilot,opencode}.rs offline-verification tests; tests/diagnose.rs (experimental label persists after a passing check) | covered |
| DIA-007 | A previous successful verification is never a permanent certificate | src/integration/state.rs (`Managed` stores only command + approved conflicts, no pass/fail history); src/diagnose.rs (re-derives every check on every run) | covered-by-design — no field anywhere persists a "verified" or "last passed" state, so a stale pass cannot be represented; doctor re-runs synthetic checks from scratch on every invocation | covered-by-design |
| DIA-008 | Doctor returns one for any diagnosed protection-preventing condition, two only for usage/internal failures | src/diagnose.rs (exit-code derivation) | tests/diagnose.rs::a_fully_inactive_registry_is_a_health_failure, ::a_missing_integration_is_a_health_failure, ::an_unapproved_conflict_is_a_health_failure, ::an_inspection_that_cannot_complete_exits_two | covered |

## 17. Installation And Release (`REL-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| REL-001 | Standalone checksummed GitHub Release artifacts for all four platform/arch targets | .github/workflows/release.yml (`package` job matrix: 4 targets); scripts/package.sh | scripts/release-check.sh (checksum-match assertion); release.yml `publish` job (merges and verifies `SHA256SUMS`) | covered |
| REL-002 | Maintained install script: detects platform/arch, downloads, verifies checksum, atomically installs, overridable default destination; a prerelease is never selected automatically and only `--version` may name one | install.sh (`--install-dir`, `--version`, `--allow-major-upgrade`; platform detection, checksum verification; `list_versions stable\|any`) | scripts/release-check.sh (clean-install, `--install-dir`, unknown-option rejection, and prerelease-selection cases, the last asserting a default run refuses a prerelease-only index and that naming the version installs it) | covered |
| REL-003 | Install script installs/upgrades the binary only; never runs setup, edits config, installs adapters, or accepts enrollment defaults | install.sh (doc comment: "never runs setup... never touches coding-agent configuration") | scripts/release-check.sh ("no configuration or harness file created" case) | covered |
| REL-004 | Rerunning the script upgrades within the installed major; crossing a major needs explicit opt-in | install.sh (version-selection logic) | scripts/release-check.sh (upgrade-same-major, major-gating, explicit-major-upgrade cases) | covered |
| REL-005 | Hooks and plugins never download/install/update the Rust binary | src/integration/mod.rs (doc comment: "no installer, hook, or plugin downloads or updates the binary. The only component that fetches anything is `install.sh`") | covered-by-design — no networking dependency exists in the hook/adapter code paths (Cargo.toml has no HTTP client); install.sh is the sole fetcher | covered-by-design |
| REL-006 | MIT OR Apache-2.0 license plus a public security-reporting policy | Cargo.toml (`license = "MIT OR Apache-2.0"`); LICENSE-MIT, LICENSE-APACHE | SECURITY.md (reporting instructions, response expectations) | covered |
| REL-007 | Every V1 release reads earlier V1 config/managed state without requiring setup to run first | scripts/release-check.sh (installs an older release, writes a V1 config, upgrades, reads the config with the new binary) | scripts/release-check.sh (upgrade case, ~line 118-151: "an existing V1 configuration still runtime-readable afterwards") | covered |
| REL-008 | Release qualification includes a manual live Claude test proving redaction survives session resume | Not automatable by design; run per release and recorded in docs/qualification.md | Run and passed 2026-08-17 against Claude Code 2.1.233 by an automated session: placeholder survived `claude -r`, value absent from the reply and the stored transcript. Human sign-off remains outstanding per docs/qualification.md. No automated test exists or should exist (`TST-008`); limitations.md DEV-001 records the automation gap | manual |

## 18. Testing And Acceptance (`TST-*`)

| ID | Requirement | Implementation | Evidence | Status |
| --- | --- | --- | --- | --- |
| TST-001 | Matcher tests cover empty/UTF-8/case/substrings/adjacent/overlap/duplicates/canonical labels/multiline/placeholder-fallback/no-recursion | src/matcher.rs unit tests (the named vectors); tests/matcher_property.rs (the same rules over generated input) | src/matcher.rs test module; tests/matcher_property.rs::the_matcher_agrees_with_the_reference_model | covered |
| TST-002 | Config/source tests include JSON strictness, pointers, duplicate members, and wrong-type targets in addition to existing coverage | src/config.rs, src/json.rs, src/source.rs, src/registry.rs test modules | Strict JSON config, pointer escaping, wrong-type, duplicate-member, freshness, and all-or-nothing tests cited above | covered |
| TST-003 | Filesystem tests include Known Source exact/anchored paths, traversal and symlink rules, and grouped collision exclusions | src/setup/discovery.rs and src/setup/known_source.rs filesystem test modules; tests/setup.rs end-to-end setup fixtures | discovery.rs::one_project_walk_collects_only_anchored_known_source_json, ::excluded_directories_are_never_entered, ::symlinks_and_special_files_are_skipped; known_source.rs four independently named host filesystem matrices, ::exact_machine_fifo_and_symlink_to_fifo_are_skipped_promptly, ::copilot_mcp_oauth_directory_symlink_is_not_traversed; tests/setup.rs::a_known_source_group_with_an_external_collision_defaults_unselected, ::exact_machine_symlink_target_inside_project_is_excluded_from_collisions; tests/diagnose.rs::doctor_groups_aliases_and_excludes_all_of_their_source_files | covered |
| TST-004 | Every shipped adapter path has protocol fixtures for clean, intervened, unresolved, malformed-input, diagnosed-malfunction, timeout mapping, and conflicting-installation states | tests/claude_hook.rs, tests/codex_hook.rs, tests/copilot_hook.rs, tests/opencode/plugin.test.ts | tests/claude_hook.rs doc comment cites this explicitly; timeout-mapping tests cited under RUN-004; conflict tests cited under INT-005 | covered |
| TST-005 | Tests use generated canaries and assert absence from stdout/stderr/diagnostics/snapshots/model-visible content | src/testing.rs (`Canary`, `assert_canary_absent`) | tests/leaks.rs (entire suite); src/fuzz.rs (canary-absence check for every fuzz target) | covered |
| TST-006 | Fuzz targets cover the matcher and untrusted JSON/TOML/dotenv input; a bounded smoke task runs through mise | src/fuzz.rs (`TARGETS`, `json_source`); src/bin/fuzz_smoke.rs; fuzz/regressions/{json-source,matcher,config,dotenv,claude,codex,copilot,opencode,sanitize}/* | scripts/fuzz-smoke.sh; mise.toml `fuzz-smoke` task; .github/workflows/fuzz.yml | covered |
| TST-007 | Routine CI runs format/lint/test/build through mise; release checks exercise artifacts, checksums, install, upgrade | mise.toml (`format-check`, `lint`, `test`, `build`, `check` tasks) | .github/workflows/ci.yml (`mise run check`, `mise run build`); .github/workflows/release.yml (`mise run release-check`) | covered |
| TST-008 | Optional paid/networked tests do not gate routine CI; REL-008 gates a release only | Routine workflows invoke offline mise tasks; the live qualification is a documented manual release step | Covered by workflow design and review, not a keyword blacklist | covered-by-design |

## Gaps and manual items

No implementation or test-evidence gaps remain in the Known Source requirements
closed by issue #11. `LIM-023` records the permanent source-format and
version-sensitivity boundary rather than an implementation deviation.

**Manual (verifiable only by a human or a paid/networked run):**

- **SEC-002, SUP-005, RUN-002** — release review checks the meaning of public
  security-boundary and failure-policy claims; keyword tests cannot establish it.
- **RUN-005** — the p95-latency benchmark is an engineering target, not a
  pass/fail gate; a human must run `mise run bench` and read the result.
- **DIA-005** — the gating, confirmation, random-value, and reply-classification
  logic around the Claude live canary is tested, but the live network request
  itself is made only when a human runs `contextveil doctor` and opts in
  (`limitations.md` DEV-001).
- **REL-008** — release qualification requires a manual live Claude test proving
  redaction survives session resume. It is deliberately outside automated CI
  (`TST-008`). It was run and passed on 2026-08-17 against Claude Code 2.1.233,
  but by an automated session rather than by a human at the terminal, so a
  release manager must still repeat or confirm it. `docs/qualification.md`
  records the procedure, the host's own transcript records, the result, and the
  scope of what one run proves, and must be rerun for each release.

**Covered-by-design (nothing to implement; satisfied by an absence):**

- **SUP-004** — no host-version-comparison code exists anywhere in the tree.
- **SRC-010** — the environment-restart half follows structurally from
  process-immutable `Environment::from_process()`; not independently
  testable without spawning a new harness process.
- **RED-010** — no placeholder-to-source reverse mapping exists anywhere.
- **REL-005** — no hook or adapter path has network capability; only
  `install.sh` fetches anything.
- **DIA-007** — no code path persists a "previously verified" flag, so a
  stale pass cannot be shown as a certificate.

**Noted caveat on otherwise-covered rows:**

- **SUP-001, REL-001** — implemented for all four targets, and the release
  workflow builds and packages each of them, but only
  `x86_64-unknown-linux-gnu` has been built and exercised in the development
  environment used so far. The other three need their CI runners.

At the point this document was written, `mise run check` (format, lint, test,
and the OpenCode plugin suite) passed in full with no failing test or Clippy
warning.
