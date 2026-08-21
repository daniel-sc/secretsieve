//! Effective registry composition for one runtime event.
//!
//! Effective enrollment is additive (`CFG-011`): all valid global references
//! plus all valid references from the one selected project registry. There is
//! no negation, disable, or override semantics.
//!
//! Use of the effective registry is all-or-nothing (`CFG-012`, `SRC-006`,
//! `RUN-001`): an invalid or unreadable configuration file, or any enrolled
//! source malfunction, disables every redaction for the event instead of
//! producing a partial matcher. A missing global file is a non-clean
//! configuration state that warns without discarding valid project redaction
//! (`CFG-013`).

use std::path::{Path, PathBuf};

use crate::config::{self, ConfigError, Load};
use crate::matcher::Redactor;
use crate::paths;
use crate::secret::SourceId;
use crate::source::{Environment, Resolution, Resolver, SourceMalfunction, SourceRef, Unresolved};

/// A registry that may be used for the current event.
#[derive(Debug, Clone, Default)]
pub struct EffectiveRegistry {
    pub redactor: Redactor,
    /// Enrolled sources that currently have no usable value. These stay silent
    /// during normal runtime (`RED-009`).
    pub unresolved: Vec<(SourceId, Unresolved)>,
    pub warnings: Vec<Warning>,
    /// Dotenv files with repeated keys, for `SRC-004` reporting.
    pub duplicate_keys: Vec<(PathBuf, Vec<String>)>,
    /// The selected project configuration file, when one exists (`CFG-004`).
    pub project_config: Option<PathBuf>,
}

/// A non-fatal configuration state worth reporting where the host permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// No global configuration file exists, so machine setup is incomplete.
    GlobalConfigMissing,
}

impl Warning {
    pub fn message(&self) -> &'static str {
        match self {
            Warning::GlobalConfigMissing => {
                "ContextVeil global setup is incomplete: no global configuration file was found. \
                 Run `contextveil setup`."
            }
        }
    }
}

/// A condition that prevents trustworthy use of the effective registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malfunction {
    /// A configuration file could not be read or parsed (`CFG-012`).
    Config(ConfigError),
    /// An enrolled source could not be read or parsed (`SRC-006`).
    Source {
        source: SourceId,
        path: PathBuf,
        why: SourceMalfunction,
    },
    /// The global configuration location cannot be determined.
    NoConfigLocation,
}

impl Malfunction {
    /// Emit-safe warning text for a host that permits one.
    ///
    /// It names neither the file nor its content: paths are untrusted terminal
    /// input (`SEC-006`) and configuration or source text must never be echoed
    /// (`SEC-004`).
    pub fn message(&self) -> String {
        let detail = match self {
            Malfunction::Config(error) => {
                format!("configuration is unusable ({})", error.kind.reason())
            }
            Malfunction::Source { why, .. } => format!("an enrolled source {}", why.reason()),
            Malfunction::NoConfigLocation => {
                "the configuration location could not be determined".to_string()
            }
        };
        format!(
            "ContextVeil disabled redaction for this event: {detail}. Run `contextveil doctor`."
        )
    }
}

/// Result of composing the effective registry.
#[derive(Debug, Clone)]
pub enum Outcome {
    Ready(EffectiveRegistry),
    Malfunction(Malfunction),
}

/// Builds the effective registry for one event.
///
/// `project_root` is the adapter-provided root for the event (`CFG-005`); the
/// nearest ancestor project config below or at that root is selected
/// (`CFG-004`).
pub fn build(environment: &Environment, project_root: Option<&Path>) -> Outcome {
    let home = environment.home();
    let Some(global_path) = config::global_config_path(environment) else {
        return Outcome::Malfunction(Malfunction::NoConfigLocation);
    };

    let mut warnings = Vec::new();
    let global = match config::load(&global_path, home.as_deref()) {
        Load::Valid(config) => config,
        Load::Missing => {
            warnings.push(Warning::GlobalConfigMissing);
            config::Config::default()
        }
        Load::Invalid(error) => return Outcome::Malfunction(Malfunction::Config(error)),
    };

    let project_config = project_root.and_then(paths::runtime_project_config);
    let project = match &project_config {
        None => config::Config::default(),
        Some(path) => match config::load(path, home.as_deref()) {
            Load::Valid(config) => config,
            // The file disappeared between selection and reading; treat it the
            // same as an absent project registry.
            Load::Missing => config::Config::default(),
            Load::Invalid(error) => return Outcome::Malfunction(Malfunction::Config(error)),
        },
    };

    // Project entries come first so equal values canonicalize to a project
    // source (`REG-002`); protection itself stays additive.
    let ordered: Vec<&SourceRef> = project
        .sources
        .iter()
        .chain(global.sources.iter())
        .collect();

    let mut resolver = Resolver::new();
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for reference in &ordered {
        match resolver.resolve(reference, environment) {
            Resolution::Resolved(secrets) => resolved.extend(secrets),
            Resolution::Unresolved { source, why } => unresolved.push((source, why)),
            Resolution::Malfunction { source, path, why } => {
                return Outcome::Malfunction(Malfunction::Source { source, path, why });
            }
        }
    }

    let mut duplicate_keys = Vec::new();
    for reference in &ordered {
        if let Some(path) = reference.dotenv_file() {
            let duplicates = resolver.duplicate_keys(path);
            if !duplicates.is_empty()
                && !duplicate_keys
                    .iter()
                    .any(|(known, _): &(PathBuf, Vec<String>)| known == path)
            {
                duplicate_keys.push((path.to_path_buf(), duplicates.to_vec()));
            }
        }
    }

    Outcome::Ready(EffectiveRegistry {
        redactor: Redactor::new(resolved),
        unresolved,
        warnings,
        duplicate_keys,
        project_config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Canary;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "contextveil-registry-{}-{}",
                std::process::id(),
                Canary::generate("FIXTURE").token()
            ));
            std::fs::create_dir_all(root.join("config").join("contextveil"))
                .expect("global config directory");
            std::fs::create_dir_all(root.join("project").join("nested"))
                .expect("project directories");
            Self { root }
        }

        fn write_global(&self, contents: &str) {
            std::fs::write(
                self.root
                    .join("config")
                    .join("contextveil")
                    .join("config.toml"),
                contents,
            )
            .expect("write global config");
        }

        fn write_project(&self, contents: &str) {
            std::fs::write(
                self.root.join("project").join(".contextveil.toml"),
                contents,
            )
            .expect("write project config");
        }

        fn write_file(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.root.join("project").join(relative);
            std::fs::write(&path, contents).expect("write project file");
            path
        }

        fn project_root(&self) -> PathBuf {
            self.root.join("project")
        }

        fn environment(&self, pairs: &[(&str, &str)]) -> Environment {
            let mut variables = vec![
                (
                    "XDG_CONFIG_HOME".to_string(),
                    self.root.join("config").to_string_lossy().into_owned(),
                ),
                ("HOME".to_string(), self.root.to_string_lossy().into_owned()),
            ];
            variables.extend(
                pairs
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string())),
            );
            Environment::from_pairs(variables)
        }

        fn build(&self, pairs: &[(&str, &str)]) -> Outcome {
            let root = self.project_root();
            build(&self.environment(pairs), Some(&root))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn ready(outcome: Outcome) -> EffectiveRegistry {
        match outcome {
            Outcome::Ready(registry) => registry,
            Outcome::Malfunction(malfunction) => panic!("unexpected malfunction: {malfunction:?}"),
        }
    }

    fn malfunction(outcome: Outcome) -> Malfunction {
        match outcome {
            Outcome::Malfunction(malfunction) => malfunction,
            Outcome::Ready(_) => panic!("expected a malfunction"),
        }
    }

    #[test]
    fn global_and_project_enrollment_are_additive() {
        let global_canary = Canary::generate("GLOBAL_TOKEN");
        let project_canary = Canary::generate("PROJECT_KEY");
        let fixture = Fixture::new();
        fixture
            .write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"GLOBAL_TOKEN\"\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env.local\"\nkey = \"PROJECT_KEY\"\n",
        );
        fixture.write_file(
            ".env.local",
            &format!("PROJECT_KEY={}\n", project_canary.value()),
        );

        let registry = ready(fixture.build(&[("GLOBAL_TOKEN", global_canary.value())]));
        assert_eq!(registry.redactor.active_count(), 2);
        assert!(registry.warnings.is_empty());
        assert_eq!(
            registry.project_config,
            Some(fixture.project_root().join(".contextveil.toml"))
        );
    }

    #[test]
    fn equal_values_canonicalize_to_the_first_project_entry() {
        let canary = Canary::generate("SHARED");
        let fixture = Fixture::new();
        fixture
            .write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"GLOBAL_NAME\"\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"PROJECT_NAME\"\n",
        );

        let registry = ready(fixture.build(&[
            ("GLOBAL_NAME", canary.value()),
            ("PROJECT_NAME", canary.value()),
        ]));
        assert_eq!(registry.redactor.active_count(), 1);

        let mut tally = registry.redactor.tally();
        let output = registry
            .redactor
            .redact(canary.value(), &mut tally)
            .expect("the value is redacted");
        assert_eq!(output, "<SECRET:PROJECT_NAME>");
    }

    #[test]
    fn the_nearest_ancestor_project_config_is_selected() {
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n");
        fixture.write_project("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"OUTER\"\n");
        std::fs::write(
            fixture
                .root
                .join("project")
                .join("nested")
                .join(".contextveil.toml"),
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"INNER\"\n",
        )
        .expect("write nested config");

        let nested = fixture.root.join("project").join("nested");
        let registry = ready(build(
            &fixture.environment(&[("INNER", "inner-value"), ("OUTER", "outer-value")]),
            Some(&nested),
        ));
        // `CFG-004`: exactly one project registry, never merged with a parent.
        assert_eq!(registry.redactor.active_count(), 1);
        let mut tally = registry.redactor.tally();
        assert_eq!(
            registry
                .redactor
                .redact("inner-value", &mut tally)
                .as_deref(),
            Some("<SECRET:INNER>")
        );
    }

    #[test]
    fn a_missing_project_config_leaves_project_enrollment_empty() {
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        let registry = ready(fixture.build(&[("TOKEN", "value")]));
        assert_eq!(registry.redactor.active_count(), 1);
        assert_eq!(registry.project_config, None);
    }

    #[test]
    fn a_missing_global_config_warns_but_keeps_project_redaction() {
        // `CFG-013`: incomplete machine setup does not discard valid project
        // enrollment.
        let fixture = Fixture::new();
        fixture.write_project("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        let registry = ready(fixture.build(&[("TOKEN", "value")]));
        assert_eq!(registry.redactor.active_count(), 1);
        assert_eq!(registry.warnings, vec![Warning::GlobalConfigMissing]);
    }

    #[test]
    fn an_invalid_project_config_disables_global_redaction() {
        // `LIM-009`: registry use is all-or-nothing, in both directions.
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        fixture.write_project("version = 1\n\n[[secret]]\nsource = \"nope\"\n");
        assert!(matches!(
            malfunction(fixture.build(&[("TOKEN", "value")])),
            Malfunction::Config(_)
        ));
    }

    #[test]
    fn an_invalid_global_config_disables_project_redaction() {
        let fixture = Fixture::new();
        fixture.write_global("version = 3\n");
        fixture.write_project("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        assert!(matches!(
            malfunction(fixture.build(&[("TOKEN", "value")])),
            Malfunction::Config(_)
        ));
    }

    #[test]
    fn a_malformed_enrolled_source_disables_the_whole_registry() {
        // `SRC-006`: no partial matcher after a source malfunction.
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env.broken\"\nkey = \"A\"\n",
        );
        fixture.write_file(".env.broken", "A=1\nnot an assignment\n");

        assert!(matches!(
            malfunction(fixture.build(&[("TOKEN", "value")])),
            Malfunction::Source {
                why: SourceMalfunction::Malformed { .. },
                ..
            }
        ));
    }

    #[test]
    fn json_sources_are_active_and_malformed_json_disables_every_pattern() {
        let canary = Canary::generate("JSON_ACCESS_TOKEN");
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"json\"\nfile = \"auth.json\"\npointer = \"/tokens/access_token\"\n",
        );
        fixture.write_file(
            "auth.json",
            &format!(r#"{{"tokens":{{"access_token":"{}"}}}}"#, canary.value()),
        );

        let registry = ready(fixture.build(&[("TOKEN", "other-value")]));
        assert_eq!(registry.redactor.active_count(), 2);
        let mut tally = registry.redactor.tally();
        assert_eq!(
            registry
                .redactor
                .redact(canary.value(), &mut tally)
                .as_deref(),
            Some("<SECRET:access_token>")
        );

        fixture.write_file("auth.json", r#"{"token":"a","token":"b"}"#);
        assert!(matches!(
            malfunction(fixture.build(&[("TOKEN", "other-value")])),
            Malfunction::Source {
                why: SourceMalfunction::DuplicateJsonMember,
                ..
            }
        ));
    }

    #[test]
    fn unresolved_sources_do_not_fail_the_event() {
        let fixture = Fixture::new();
        fixture.write_global(
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"PRESENT\"\n\n[[secret]]\nsource = \"env\"\nname = \"ABSENT\"\n",
        );
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env.missing\"\nall = true\n",
        );

        let registry = ready(fixture.build(&[("PRESENT", "value")]));
        assert_eq!(registry.redactor.active_count(), 1);
        assert_eq!(registry.unresolved.len(), 2);
    }

    #[test]
    fn wildcard_entries_pick_up_keys_added_later() {
        // `SRC-007`: no further setup run is needed for a new key.
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nall = true\n",
        );
        fixture.write_file(".env", "FIRST=one\n");
        assert_eq!(ready(fixture.build(&[])).redactor.active_count(), 1);

        fixture.write_file(".env", "FIRST=one\nSECOND=two\nEMPTY=\n");
        assert_eq!(ready(fixture.build(&[])).redactor.active_count(), 2);
    }

    #[test]
    fn duplicate_dotenv_keys_are_reported_without_values() {
        let canary = Canary::generate("DUPLICATE");
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nkey = \"DUPLICATE\"\n",
        );
        fixture.write_file(
            ".env",
            &format!("DUPLICATE=first\nDUPLICATE={}\n", canary.value()),
        );

        let registry = ready(fixture.build(&[]));
        assert_eq!(registry.duplicate_keys.len(), 1);
        assert_eq!(registry.duplicate_keys[0].1, ["DUPLICATE"]);
    }

    #[test]
    fn cross_scope_duplicate_identities_are_allowed() {
        // `CFG-009`: the same identity may appear in both scopes.
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        fixture.write_project("version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"TOKEN\"\n");
        let registry = ready(fixture.build(&[("TOKEN", "value")]));
        assert_eq!(registry.redactor.active_count(), 1);
        assert_eq!(registry.redactor.aliases().count(), 1);
    }

    #[test]
    fn malfunction_messages_contain_no_path_or_file_text() {
        let canary = Canary::generate("LEAK");
        let fixture = Fixture::new();
        fixture.write_global("version = 1\n");
        fixture.write_project(
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env.broken\"\nkey = \"A\"\n",
        );
        fixture.write_file(
            ".env.broken",
            &format!("A={}\nbroken line\n", canary.value()),
        );

        let message = malfunction(fixture.build(&[])).message();
        crate::testing::assert_canary_absent("malfunction message", message.as_bytes(), &canary);
        assert!(!message.contains(".env.broken"));
        assert!(!message.contains("broken line"));
    }
}
