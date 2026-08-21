//! `status` and `doctor`.
//!
//! `DIA-001`: status inspects the selected configuration, resolves current
//! sources, and reports counts without running any adapter protocol test.
//! `DIA-002`: registry and integration health are independent facets, and zero
//! active values is shown as `INACTIVE`. `DIA-003` adds doctor's deeper checks,
//! and `DIA-004` keeps collision findings advisory.
//!
//! `DIA-007`: a passing check is never presented as a permanent certificate;
//! both commands re-derive everything from current configuration and artifacts,
//! and say so.
//!
//! Output is human-readable only; V1 provides no stable machine-readable
//! contract (`CLI-003`, `LIM-021`). Every untrusted path, key, and command is
//! rendered through `crate::sanitize` (`SEC-006`), and no diagnostic contains a
//! resolved value, source content, or a value fingerprint (`SEC-004`).

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::Exit;
use crate::config::{self, Load};
use crate::integration::claude::CanaryOutcome;
use crate::integration::hooks_json::Installed;
use crate::integration::{self as integration, Detection, HARNESSES, Inspection, Tier, state};
use crate::matcher::Redactor;
use crate::paths;
use crate::sanitize;
use crate::secret::SourceId;
use crate::setup::collision;
use crate::source::{Environment, Resolution, Resolver, SourceMalfunction, SourceRef, Unresolved};

/// Every installed runtime hook uses this timeout (`RUN-004`).
const EXPECTED_TIMEOUT_SECONDS: u64 = 5;

/// Severity of one reported finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    /// Visible, but not a health failure (`CLI-006`, `DIA-004`).
    Warning,
    /// A diagnosed condition that prevents effective protection (`DIA-008`).
    Failure,
}

impl Level {
    fn marker(self) -> &'static str {
        match self {
            Level::Ok => "ok  ",
            Level::Warning => "warn",
            Level::Failure => "fail",
        }
    }
}

/// Whether doctor should run the optional paid, networked Claude canary.
///
/// `DIA-005`: disabled by default and only ever enabled by explicit
/// confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveCanary {
    Skip,
    Run,
}

/// Runs `status` (`CLI-005`).
///
/// `executable` is the running binary, so an installed hook that points at it is
/// reported as current rather than as outdated.
pub fn status(
    out: &mut dyn Write,
    environment: &Environment,
    current_directory: &Path,
    executable: Option<&Path>,
) -> Exit {
    let Some(snapshot) = Snapshot::take(environment, current_directory, executable) else {
        let _ = writeln!(
            out,
            "contextveil: the configuration location could not be determined. Set HOME or \
             XDG_CONFIG_HOME."
        );
        // Inspection itself could not complete.
        return Exit::Usage;
    };

    let _ = writeln!(out, "ContextVeil status");
    snapshot.render_registry(out);
    snapshot.render_integrations(out);
    let _ = writeln!(
        out,
        "\nInstallation is not proof of protection. Run `contextveil doctor` for deeper checks."
    );
    // `CLI-005`: zero whenever inspection completes, whatever it found.
    Exit::Ok
}

/// Runs `doctor` (`CLI-006`, `DIA-008`).
pub fn doctor(
    out: &mut dyn Write,
    environment: &Environment,
    current_directory: &Path,
    executable: Option<&Path>,
    live: LiveCanary,
) -> Exit {
    let Some(snapshot) = Snapshot::take(environment, current_directory, executable) else {
        let _ = writeln!(
            out,
            "contextveil: the configuration location could not be determined. Set HOME or \
             XDG_CONFIG_HOME."
        );
        // `CLI-006`: two only for usage or an inspection that cannot complete.
        return Exit::Usage;
    };

    let _ = writeln!(out, "ContextVeil doctor");
    snapshot.render_registry(out);
    snapshot.render_integrations(out);

    let mut findings = snapshot.registry_findings();
    findings.extend(snapshot.integration_findings());

    if live == LiveCanary::Run {
        findings.push(snapshot.run_live_canary(out));
    }

    let _ = writeln!(out, "\nChecks");
    for finding in &findings {
        let _ = writeln!(out, "  [{}] {}", finding.level.marker(), finding.text);
    }

    let worst = findings
        .iter()
        .map(|finding| finding.level)
        .max()
        .unwrap_or(Level::Ok);
    match worst {
        Level::Failure => {
            let _ = writeln!(
                out,
                "\nProtection is not effective right now. Address every `fail` line above."
            );
            Exit::Failure
        }
        _ => {
            let _ = writeln!(out, "\nNo condition preventing protection was found.");
            Exit::Ok
        }
    }
}

/// One reported line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub text: String,
}

impl Finding {
    fn ok(text: impl Into<String>) -> Self {
        Self {
            level: Level::Ok,
            text: text.into(),
        }
    }

    fn warning(text: impl Into<String>) -> Self {
        Self {
            level: Level::Warning,
            text: text.into(),
        }
    }

    fn failure(text: impl Into<String>) -> Self {
        Self {
            level: Level::Failure,
            text: text.into(),
        }
    }
}

/// Everything both commands inspect, gathered once.
struct Snapshot {
    global_path: PathBuf,
    global: Load,
    project_root: PathBuf,
    project_path: Option<PathBuf>,
    project: Load,
    /// Every enrolled source with its current resolution.
    resolutions: Vec<(SourceRef, Resolution)>,
    /// Dotenv files with repeated keys (`SRC-004`).
    duplicate_keys: Vec<(PathBuf, Vec<String>)>,
    redactor: Redactor,
    /// One entry per supported harness, empty when the home directory is
    /// unknown.
    integrations: Vec<Inspection>,
    executable: Option<PathBuf>,
    home: Option<PathBuf>,
}

impl Snapshot {
    fn take(
        environment: &Environment,
        current_directory: &Path,
        executable: Option<&Path>,
    ) -> Option<Self> {
        let home = environment.home();
        let global_path = config::global_config_path(environment)?;
        // `DIA-001`: status and doctor select their project root with `CFG-003`
        // from the current working directory.
        let project_root = paths::setup_project_root(current_directory);
        let project_path = paths::runtime_project_config(&project_root);

        let global = config::load(&global_path, home.as_deref());
        let project = match &project_path {
            Some(path) => config::load(path, home.as_deref()),
            None => Load::Missing,
        };

        let mut resolver = Resolver::new();
        let mut resolutions = Vec::new();
        let mut resolved = Vec::new();
        for source in sources_of(&project)
            .iter()
            .chain(sources_of(&global).iter())
        {
            let resolution = resolver.resolve(source, environment);
            if let Resolution::Resolved(secrets) = &resolution {
                resolved.extend(secrets.clone());
            }
            resolutions.push((source.clone(), resolution));
        }

        let mut duplicate_keys: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for (source, _) in &resolutions {
            if let Some(path) = source.dotenv_file() {
                let duplicates = resolver.duplicate_keys(path);
                if !duplicates.is_empty() && !duplicate_keys.iter().any(|(known, _)| known == path)
                {
                    duplicate_keys.push((path.to_path_buf(), duplicates.to_vec()));
                }
            }
        }

        // A malfunction disables the whole registry for a runtime event
        // (`CFG-012`, `SRC-006`), so the reported active count must reflect that.
        let disabled = matches!(global, Load::Invalid(_))
            || matches!(project, Load::Invalid(_))
            || resolutions
                .iter()
                .any(|(_, resolution)| matches!(resolution, Resolution::Malfunction { .. }));
        let redactor = if disabled {
            Redactor::default()
        } else {
            Redactor::new(resolved)
        };

        let integrations = match home.as_deref() {
            None => Vec::new(),
            Some(home) => {
                let recorded = state::load(&state::path(&global_path));
                HARNESSES
                    .iter()
                    .map(|harness| {
                        integration::inspect(*harness, environment, home, executable, &recorded)
                    })
                    .collect()
            }
        };

        Some(Self {
            global_path,
            global,
            project_root,
            project_path,
            project,
            resolutions,
            duplicate_keys,
            redactor,
            integrations,
            executable: executable.map(Path::to_path_buf),
            home,
        })
    }

    fn enrolled(&self) -> usize {
        self.resolutions.len()
    }

    fn unresolved(&self) -> usize {
        self.resolutions
            .iter()
            .filter(|(_, resolution)| matches!(resolution, Resolution::Unresolved { .. }))
            .count()
    }

    /// The registry facet (`DIA-002`).
    fn render_registry(&self, out: &mut dyn Write) {
        let _ = writeln!(out, "\nRegistry");
        let _ = writeln!(
            out,
            "  global config   {} ({})",
            sanitize::path(&self.global_path),
            describe_load(&self.global)
        );
        match &self.project_path {
            Some(path) => {
                let _ = writeln!(
                    out,
                    "  project config  {} ({})",
                    sanitize::path(path),
                    describe_load(&self.project)
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "  project config  none under {}",
                    sanitize::path(&self.project_root)
                );
            }
        }
        let _ = writeln!(
            out,
            "  enrolled        {}",
            count(self.enrolled(), "source", "sources")
        );
        let active = self.redactor.active_count();
        if active == 0 {
            // `DIA-002`: zero active values is shown as INACTIVE.
            let _ = writeln!(out, "  active          0 values - INACTIVE");
        } else {
            let _ = writeln!(
                out,
                "  active          {}",
                count(active, "value", "values")
            );
        }
        let _ = writeln!(
            out,
            "  unresolved      {}",
            count(self.unresolved(), "source", "sources")
        );
    }

    /// The integration facet, kept independent of registry health (`DIA-002`).
    fn render_integrations(&self, out: &mut dyn Write) {
        let _ = writeln!(out, "\nIntegrations");
        if self.integrations.is_empty() {
            let _ = writeln!(out, "  unknown: the home directory could not be determined");
            return;
        }
        for inspection in &self.integrations {
            let harness = inspection.harness;
            // `SUP-003`: the experimental label follows the integration
            // everywhere it appears.
            let _ = writeln!(
                out,
                "  {} ({})  {}, {}",
                harness.label(),
                harness.tier_label(),
                match inspection.detection {
                    Detection::Detected => "detected",
                    Detection::NotDetected => "not detected",
                },
                describe_installed(&inspection.installed)
            );
            let _ = writeln!(
                out,
                "      file {}",
                sanitize::path(&inspection.artifact_path)
            );
            for conflict in &inspection.conflicts {
                let _ = writeln!(
                    out,
                    "      other hook on the same event: {} ({})",
                    conflict.command,
                    if conflict.approved {
                        "approved"
                    } else {
                        "not approved"
                    }
                );
            }
        }
    }

    /// Configuration, source, permission, duplicate, and collision checks.
    fn registry_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (label, load, path) in [
            ("global", &self.global, Some(&self.global_path)),
            ("project", &self.project, self.project_path.as_ref()),
        ] {
            match load {
                Load::Valid(_) => {}
                Load::Missing if label == "global" => {
                    // `CFG-013`: incomplete machine setup, not malformed config.
                    findings.push(Finding::warning(
                        "global configuration is missing; run `contextveil setup`",
                    ));
                }
                Load::Missing => {}
                Load::Invalid(error) => findings.push(Finding::failure(format!(
                    "{label} configuration is unusable: {}",
                    error.kind.reason()
                ))),
            }
            if let Some(path) = path {
                findings.extend(permission_finding(path, label));
            }
        }

        for (source, resolution) in &self.resolutions {
            match resolution {
                Resolution::Resolved(_) => {}
                Resolution::Unresolved { source: id, why } => {
                    // `DIA-002`: individual unresolved sources are not failures.
                    findings.push(Finding::warning(format!(
                        "{} {}",
                        describe_source(id),
                        unresolved_text(*why)
                    )));
                }
                Resolution::Malfunction {
                    source: id, why, ..
                } => {
                    findings.push(Finding::failure(format!(
                        "{} {}",
                        describe_source(id),
                        malfunction_text(*why)
                    )));
                }
            }
            let _ = source;
        }

        for (path, keys) in &self.duplicate_keys {
            findings.push(Finding::warning(format!(
                "{} assigns {} more than once; the last assignment wins",
                sanitize::path(path),
                count(keys.len(), "key", "keys")
            )));
        }

        // `REG-002`: report aliases without values.
        for (canonical, aliases) in self.redactor.aliases() {
            findings.push(Finding::warning(format!(
                "{} has {} resolving to the same value",
                describe_source(canonical),
                count(aliases.len(), "alias", "aliases")
            )));
        }

        if self.redactor.is_empty() {
            // `CLI-006`: a registry with zero currently resolved values is a
            // health failure.
            findings.push(Finding::failure(
                "no enrolled source resolves to a value, so nothing would be redacted",
            ));
        } else {
            findings.push(Finding::ok(format!(
                "{} would be redacted right now",
                count(self.redactor.active_count(), "value", "values")
            )));
        }

        findings.extend(self.collision_findings());
        findings
    }

    /// Current project collisions, always advisory (`DIA-003`, `DIA-004`).
    fn collision_findings(&self) -> Vec<Finding> {
        struct Group<'a> {
            value: &'a str,
            label: String,
            source_files: Vec<PathBuf>,
        }
        let mut groups: Vec<Group<'_>> = Vec::new();
        for (source, resolution) in &self.resolutions {
            if let Resolution::Resolved(secrets) = resolution {
                for secret in secrets {
                    if let Some(group) = groups.iter_mut().find(|group| group.value == secret.value)
                    {
                        if let Some(file) = source.file()
                            && !group.source_files.iter().any(|known| known == file)
                        {
                            group.source_files.push(file.to_path_buf());
                        }
                    } else {
                        groups.push(Group {
                            value: &secret.value,
                            label: describe_source(&secret.source),
                            source_files: source
                                .file()
                                .map(Path::to_path_buf)
                                .into_iter()
                                .collect(),
                        });
                    }
                }
            }
        }
        if groups.is_empty() {
            return Vec::new();
        }
        let subjects: Vec<collision::Subject<'_>> = groups
            .iter()
            .map(|group| collision::Subject {
                value: group.value,
                source_files: &group.source_files,
            })
            .collect();
        collision::analyze(&self.project_root, &subjects)
            .into_iter()
            .zip(groups)
            .filter(|(collisions, _)| !collisions.is_empty())
            .map(|(collisions, group)| {
                Finding::warning(format!(
                    "{} also occurs in this project: {}",
                    group.label,
                    collisions.describe()
                ))
            })
            .collect()
    }

    /// Ownership, policy, executable, timeout, and synthetic protocol checks.
    fn integration_findings(&self) -> Vec<Finding> {
        if self.integrations.is_empty() {
            return vec![Finding::failure(
                "integration state is unknown because the home directory could not be determined",
            )];
        }

        let mut findings = Vec::new();
        let installed_count = self
            .integrations
            .iter()
            .filter(|inspection| inspection.is_installed())
            .count();
        if installed_count == 0 {
            // `DIA-008`: no installed integration is a health failure. An absent
            // unselected integration on its own is only informational.
            findings.push(Finding::failure(
                "no coding-agent integration is installed; run `contextveil setup`",
            ));
        }

        for inspection in &self.integrations {
            findings.extend(self.findings_for(inspection));
        }
        findings
    }

    fn findings_for(&self, inspection: &Inspection) -> Vec<Finding> {
        let label = inspection.harness.label();
        let experimental = match inspection.harness.tier() {
            Tier::Production => "",
            Tier::Experimental => " (EXPERIMENTAL)",
        };
        let mut findings = Vec::new();

        match &inspection.installed {
            Installed::Current => findings.push(Finding::ok(format!(
                "the {label}{experimental} integration is installed and owned by ContextVeil"
            ))),
            Installed::Outdated { .. } => findings.push(Finding::warning(format!(
                "the {label} integration points at a different ContextVeil binary; rerun \
                 `contextveil setup`"
            ))),
            Installed::Modified { command } => findings.push(Finding::warning(format!(
                "the {label} integration was modified by hand ({command}); ContextVeil will not \
                 change it"
            ))),
            // Absent is informational per integration; the aggregate check above
            // decides whether that is a failure.
            Installed::Absent => {}
            Installed::Unreadable => findings.push(Finding::failure(format!(
                "the {label} host file is not valid JSON, so the integration cannot be verified"
            ))),
            Installed::Unexpected => findings.push(Finding::failure(format!(
                "the {label} host file has an unexpected shape"
            ))),
        }

        if inspection.disabled_by_policy {
            findings.push(Finding::failure(format!(
                "a managed policy on this machine disables all {label} hooks"
            )));
        }

        if let Some(path) = &inspection.hook_executable {
            if path.is_file() {
                findings.push(Finding::ok(format!(
                    "the {label} configured executable exists: {}",
                    sanitize::path(path)
                )));
            } else {
                findings.push(Finding::failure(format!(
                    "the {label} configured executable is missing: {}",
                    sanitize::path(path)
                )));
            }
        }

        match inspection.hook_timeout {
            Some(timeout) if timeout == EXPECTED_TIMEOUT_SECONDS => findings.push(Finding::ok(
                format!("the {label} hook timeout is {timeout} seconds"),
            )),
            Some(timeout) => findings.push(Finding::warning(format!(
                "the {label} hook timeout is {timeout} seconds instead of \
                 {EXPECTED_TIMEOUT_SECONDS}"
            ))),
            None if matches!(inspection.installed, Installed::Absent) => {}
            None => findings.push(Finding::warning(format!(
                "the {label} hook has no timeout, so the host default applies"
            ))),
        }

        for conflict in &inspection.conflicts {
            if conflict.approved {
                // `INT-005`: an approved conflict stays visible but healthy.
                findings.push(Finding::warning(format!(
                    "an approved {label} hook can also change the same content: {}",
                    conflict.command
                )));
            } else {
                findings.push(Finding::failure(format!(
                    "an unapproved {label} hook can also change the same content: {}; rerun \
                     `contextveil setup`",
                    conflict.command
                )));
            }
        }

        // The synthetic protocol check runs the real hook path offline
        // (`DIA-006`: experimental integrations have offline verification only).
        if !matches!(inspection.installed, Installed::Absent) {
            let candidate = inspection
                .hook_executable
                .clone()
                .or_else(|| self.executable.clone());
            match candidate {
                None => findings.push(Finding::warning(format!(
                    "the {label} synthetic protocol check was skipped because no executable is \
                     known"
                ))),
                Some(path) => match integration::verify_offline(inspection.harness, &path) {
                    integration::Verification::Passed => findings.push(Finding::ok(format!(
                        "the {label} synthetic protocol check passed"
                    ))),
                    integration::Verification::Failed(reason) => findings.push(Finding::failure(
                        format!("the {label} synthetic protocol check failed: {reason}"),
                    )),
                },
            }
        }

        findings
    }

    /// The optional paid, networked Claude canary (`DIA-005`).
    fn run_live_canary(&self, out: &mut dyn Write) -> Finding {
        let Some(home) = &self.home else {
            return Finding::failure("the live canary needs a known home directory");
        };
        let _ = writeln!(
            out,
            "\nRunning the live Claude canary. It starts one paid, networked Claude Code request \
             that reads a generated non-credential value through the installed hook."
        );
        match integration::claude::live_canary(home) {
            Ok(outcome) => live_canary_finding(outcome),
            Err(reason) => Finding::failure(format!("the live canary failed: {reason}")),
        }
    }
}

/// Severity of one live-canary outcome (`DIA-005`, `DIA-008`).
///
/// Kept out of `run_live_canary` so the mapping that drives doctor's exit code
/// is covered without a paid, networked request (`TST-008`, `DEV-001`).
///
/// An inconclusive reply is a warning rather than a failure on purpose: it is not
/// a diagnosed condition that prevents protection, which is what `DIA-008`
/// reserves exit one for, and the failure summary states that protection is not
/// effective right now, which would be untrue when the hook may be healthy and
/// the offline synthetic check passed. It is still never reported as a pass.
fn live_canary_finding(outcome: CanaryOutcome) -> Finding {
    match outcome {
        CanaryOutcome::Redacted => Finding::ok(
            "the live canary placeholder reached Claude's reply and the generated value did not; \
             this tested one successful Bash PostToolUse result only",
        ),
        CanaryOutcome::Inconclusive => Finding::warning(
            "the live canary proved nothing: Claude's reply carried neither the generated value \
             nor its placeholder, so the covered path was not exercised",
        ),
        CanaryOutcome::Disclosed => Finding::failure(
            "the generated value reached Claude's reply, so the covered path did not redact it",
        ),
    }
}

/// Renders a count with a correctly pluralized noun.
fn count(number: usize, singular: &str, plural: &str) -> String {
    if number == 1 {
        format!("{number} {singular}")
    } else {
        format!("{number} {plural}")
    }
}

fn sources_of(load: &Load) -> Vec<SourceRef> {
    match load {
        Load::Valid(config) => config.sources.clone(),
        Load::Missing | Load::Invalid(_) => Vec::new(),
    }
}

fn describe_load(load: &Load) -> String {
    match load {
        Load::Valid(config) => count(config.sources.len(), "entry", "entries"),
        Load::Missing => "missing".to_string(),
        Load::Invalid(error) => format!("invalid: {}", error.kind.reason()),
    }
}

fn describe_installed(installed: &Installed) -> &'static str {
    match installed {
        Installed::Absent => "not installed",
        Installed::Current => "installed",
        Installed::Outdated { .. } => "installed, pointing at another binary",
        Installed::Modified { .. } => "installed entry modified by hand",
        Installed::Unreadable => "host file is not valid JSON",
        Installed::Unexpected => "host file has an unexpected shape",
    }
}

/// Sanitized, value-free description of one source.
fn describe_source(id: &SourceId) -> String {
    match id {
        SourceId::Env { name } => format!("env {}", sanitize::text(name)),
        SourceId::DotenvKey { path, key } => {
            format!(
                "dotenv {} key {}",
                sanitize::path(path),
                sanitize::text(key)
            )
        }
        SourceId::DotenvAll { path } => {
            format!("dotenv {} (every key)", sanitize::path(path))
        }
        SourceId::Json { path, pointer, .. } => format!(
            "json {} pointer {}",
            sanitize::path(path),
            sanitize::text(pointer)
        ),
    }
}

fn unresolved_text(why: Unresolved) -> String {
    format!("is enrolled but {}", why.reason())
}

fn malfunction_text(why: SourceMalfunction) -> String {
    format!(
        "{}, which disables all redaction for every event",
        why.reason()
    )
}

/// Config permission check (`DIA-003`, `CFG-001`).
fn permission_finding(path: &Path, label: &str) -> Option<Finding> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
        if label == "global" && mode & 0o077 != 0 {
            return Some(Finding::warning(format!(
                "{} is readable by other users (mode {:o}); global configuration should be \
                 user-only",
                sanitize::path(path),
                mode
            )));
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = (path, label);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Canary;

    /// The mapping that decides doctor's exit code for the paid canary. A
    /// disclosure must stay a failure and an inconclusive reply must never be
    /// reported as a pass (`DIA-005`, `DIA-008`).
    #[test]
    fn a_live_canary_outcome_maps_to_the_intended_severity() {
        assert_eq!(
            live_canary_finding(CanaryOutcome::Redacted).level,
            Level::Ok
        );
        assert_eq!(
            live_canary_finding(CanaryOutcome::Inconclusive).level,
            Level::Warning
        );
        assert_eq!(
            live_canary_finding(CanaryOutcome::Disclosed).level,
            Level::Failure
        );
    }

    /// Only a disclosure may make doctor exit non-zero, and only a redaction may
    /// leave the report free of a qualifying line.
    #[test]
    fn only_a_disclosed_live_canary_is_a_health_failure() {
        for outcome in [CanaryOutcome::Redacted, CanaryOutcome::Inconclusive] {
            assert_ne!(
                live_canary_finding(outcome).level,
                Level::Failure,
                "{outcome:?} does not diagnose a condition that prevents protection"
            );
        }
        assert_ne!(
            live_canary_finding(CanaryOutcome::Inconclusive).level,
            Level::Ok,
            "a reply that proved nothing must not read as a pass"
        );
    }

    /// No live-canary line may carry a value, source content, or a fingerprint
    /// (`SEC-004`).
    #[test]
    fn no_live_canary_line_quotes_what_it_saw() {
        for outcome in [
            CanaryOutcome::Redacted,
            CanaryOutcome::Inconclusive,
            CanaryOutcome::Disclosed,
        ] {
            let text = live_canary_finding(outcome).text;
            assert!(
                !text.contains("SSCANARY")
                    && !text.contains(crate::integration::SYNTHETIC_VARIABLE),
                "{outcome:?} quoted the value it inspected: {text}"
            );
        }
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "contextveil-diagnose-{}-{}",
                std::process::id(),
                Canary::generate("DIAG").token()
            ));
            std::fs::create_dir_all(root.join("home").join("project")).expect("project");
            std::fs::create_dir_all(root.join("home").join(".config").join("contextveil"))
                .expect("config directory");
            Self { root }
        }

        fn home(&self) -> PathBuf {
            self.root.join("home")
        }

        fn project(&self) -> PathBuf {
            self.home().join("project")
        }

        fn write_global(&self, contents: &str) {
            std::fs::write(
                self.home()
                    .join(".config")
                    .join("contextveil")
                    .join("config.toml"),
                contents,
            )
            .expect("write global config");
        }

        fn write_project(&self, contents: &str) {
            std::fs::write(self.project().join(".contextveil.toml"), contents)
                .expect("write project config");
        }

        fn environment(&self, pairs: &[(&str, &str)]) -> Environment {
            let mut variables = vec![(
                "HOME".to_string(),
                self.home().to_string_lossy().into_owned(),
            )];
            variables.extend(
                pairs
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string())),
            );
            Environment::from_pairs(variables)
        }

        fn status(&self, pairs: &[(&str, &str)]) -> (Exit, String) {
            let mut out = Vec::new();
            let exit = status(&mut out, &self.environment(pairs), &self.project(), None);
            (exit, String::from_utf8(out).expect("UTF-8 output"))
        }

        fn doctor(&self, pairs: &[(&str, &str)]) -> (Exit, String) {
            let mut out = Vec::new();
            let exit = doctor(
                &mut out,
                &self.environment(pairs),
                &self.project(),
                None,
                LiveCanary::Skip,
            );
            (exit, String::from_utf8(out).expect("UTF-8 output"))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn status_reports_counts_and_exits_zero() {
        let canary = Canary::generate("GITHUB_TOKEN");
        let fixture = Fixture::new();
        fixture.write_global(
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"GITHUB_TOKEN\"\n\n[[secret]]\nsource = \"env\"\nname = \"ABSENT_TOKEN\"\n",
        );

        let (exit, output) = fixture.status(&[("GITHUB_TOKEN", canary.value())]);
        assert_eq!(exit, Exit::Ok);
        assert!(output.contains("enrolled        2 sources"));
        assert!(output.contains("active          1 value"));
        assert!(output.contains("unresolved      1 source"));
        crate::testing::assert_canary_absent("status output", output.as_bytes(), &canary);
    }

    #[test]
    fn status_shows_inactive_when_nothing_resolves() {
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"ABSENT\"\n");
        let (exit, output) = fixture.status(&[]);
        assert_eq!(exit, Exit::Ok);
        assert!(output.contains("INACTIVE"));
    }

    #[test]
    fn status_exits_zero_even_with_invalid_configuration() {
        // `CLI-005`: inspection completed, so the exit code is zero.
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"nope\"\n");
        let (exit, output) = fixture.status(&[]);
        assert_eq!(exit, Exit::Ok);
        assert!(output.contains("invalid:"));
        assert!(output.contains("INACTIVE"));
    }

    #[test]
    fn status_cannot_complete_without_a_configuration_location() {
        let mut out = Vec::new();
        let exit = status(
            &mut out,
            &Environment::from_pairs([("HOME", "")]),
            Path::new("/tmp"),
            None,
        );
        assert_eq!(exit, Exit::Usage);
    }

    #[test]
    fn status_facets_are_independent() {
        // `DIA-002`: an unresolved source does not change integration state.
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"ABSENT\"\n");
        let (_, output) = fixture.status(&[]);
        let registry = output.find("Registry").expect("registry facet");
        let integrations = output.find("Integrations").expect("integration facet");
        assert!(registry < integrations);
        assert!(output.contains("EXPERIMENTAL"));
    }

    #[test]
    fn doctor_fails_when_no_value_resolves() {
        // `CLI-006`: zero active values is a health failure.
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"ABSENT\"\n");
        let (exit, output) = fixture.doctor(&[]);
        assert_eq!(exit, Exit::Failure);
        assert!(output.contains("no enrolled source resolves"));
        assert!(output.contains("[warn] env ABSENT is enrolled but is not present"));
    }

    #[test]
    fn doctor_fails_on_an_enrolled_source_malfunction() {
        let fixture = Fixture::new();
        std::fs::write(fixture.project().join(".env.broken"), "A=1\nbroken line\n")
            .expect("write dotenv");
        fixture.write_global("version = 1\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env.broken\"\nkey = \"A\"\n",
        );

        let (exit, output) = fixture.doctor(&[]);
        assert_eq!(exit, Exit::Failure);
        assert!(output.contains("disables all redaction"));
        assert!(!output.contains("broken line"));
    }

    #[test]
    fn doctor_reports_collisions_as_warnings_only() {
        // `DIA-004`: collisions never change the exit status.
        let canary = Canary::generate("SHARED_TOKEN");
        let fixture = Fixture::new();
        fixture
            .write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"SHARED_TOKEN\"\n");
        std::fs::write(fixture.project().join("notes.txt"), canary.value()).expect("write file");
        std::fs::create_dir_all(fixture.home().join(".claude")).expect("claude directory");
        std::fs::write(
            fixture.home().join(".claude").join("settings.json"),
            "{\"hooks\": {\"PostToolUse\": []}}",
        )
        .expect("write settings");

        let (_, output) = fixture.doctor(&[("SHARED_TOKEN", canary.value())]);
        assert!(output.contains("also occurs in this project"));
        assert!(output.contains("notes.txt"));
        crate::testing::assert_canary_absent("doctor output", output.as_bytes(), &canary);
    }

    #[test]
    fn doctor_fails_when_no_integration_is_installed() {
        let canary = Canary::generate("TOKEN");
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        let (exit, output) = fixture.doctor(&[("TOKEN", canary.value())]);
        assert_eq!(exit, Exit::Failure);
        assert!(output.contains("no coding-agent integration is installed"));
    }

    #[test]
    fn doctor_fails_on_an_unapproved_conflict_and_a_missing_executable() {
        let canary = Canary::generate("TOKEN");
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        std::fs::create_dir_all(fixture.home().join(".claude")).expect("claude directory");
        std::fs::write(
            fixture.home().join(".claude").join("settings.json"),
            r#"{"hooks": {"PostToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": "/gone/contextveil hook claude", "timeout": 5}]},
                {"matcher": "*", "hooks": [{"type": "command", "command": "/other/mutator"}]}
            ]}}"#,
        )
        .expect("write settings");

        let (exit, output) = fixture.doctor(&[("TOKEN", canary.value())]);
        assert_eq!(exit, Exit::Failure);
        assert!(output.contains("configured executable is missing"));
        assert!(output.contains("unapproved Claude Code hook can also change"));
    }

    #[test]
    fn doctor_warns_about_a_wrong_timeout_without_failing_on_it_alone() {
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n");
        std::fs::create_dir_all(fixture.home().join(".claude")).expect("claude directory");
        std::fs::write(
            fixture.home().join(".claude").join("settings.json"),
            r#"{"hooks": {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "/gone/contextveil hook claude", "timeout": 30}]}]}}"#,
        )
        .expect("write settings");

        let (_, output) = fixture.doctor(&[]);
        assert!(output.contains("hook timeout is 30 seconds instead of 5"));
    }

    #[test]
    fn doctor_warns_about_duplicate_keys_and_aliases_without_values() {
        let canary = Canary::generate("DOUBLE");
        let fixture = Fixture::new();
        std::fs::write(
            fixture.project().join(".env"),
            format!("DOUBLE=first\nDOUBLE={}\n", canary.value()),
        )
        .expect("write dotenv");
        fixture
            .write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"ALSO_DOUBLE\"\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nkey = \"DOUBLE\"\n",
        );

        let (_, output) = fixture.doctor(&[("ALSO_DOUBLE", canary.value())]);
        assert!(output.contains("more than once"));
        assert!(output.contains("1 alias resolving"));
        crate::testing::assert_canary_absent("doctor output", output.as_bytes(), &canary);
    }

    #[test]
    fn doctor_performs_no_network_call_unless_the_canary_is_selected() {
        // The default is `LiveCanary::Skip`, and nothing else in doctor reaches
        // the network (`SEC-003`, `DIA-005`).
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n");
        let (_, output) = fixture.doctor(&[]);
        assert!(!output.contains("live canary"));
    }

    #[test]
    fn diagnostics_sanitize_untrusted_names_and_paths() {
        let fixture = Fixture::new();
        fixture.write_global(
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"\\u001b[31mEVIL_TOKEN\"\n",
        );
        let (_, output) = fixture.doctor(&[]);
        assert!(!output.contains('\u{1b}'));
        assert!(output.contains("\\e[31mEVIL_TOKEN"));
    }
}
