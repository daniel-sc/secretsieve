//! The unified interactive setup workflow.
//!
//! `CLI-001` makes `setup` the only configuration workflow and `SET-001` fixes
//! its phases: global enrollment, project enrollment, integration selection and
//! removal, then offline verification. Each configuration phase presents
//! existing entries as selected, offers a no-change path, and commits only after
//! its own explicit confirmation (`SET-014`).
//!
//! Nothing here prints a complete candidate value (`SET-010`) or persists one
//! (`SEC-004`), and every untrusted path, key, and preview is rendered through
//! `crate::sanitize` (`SEC-006`).

pub mod collision;
pub mod credential_url;
pub mod discovery;
pub mod integrations;
pub mod known_source;
pub mod preview;
pub mod ui;
pub mod vocabulary;
pub mod write;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::cli::Exit;
use crate::config::{self, Config, ConfigError, Load};
use crate::paths::{self, PROJECT_CONFIG_FILENAME};
use crate::sanitize;
use crate::secret::SourceId;
use crate::source::{Environment, Resolution, Resolver, SourceRef, Unresolved};

use collision::Collisions;
use discovery::{Discovered, State};
use ui::{Cancelled, Terminal};
use vocabulary::Signal;

/// Which registry a phase edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Global,
    Project,
}

impl Scope {
    fn title(self) -> &'static str {
        match self {
            Scope::Global => "Global sources (this machine)",
            Scope::Project => "Project sources (this project)",
        }
    }
}

/// Runs the complete setup workflow.
///
/// `current_directory` is where the user invoked the command; the project root
/// is selected from it by `CFG-003`.
pub fn run(
    terminal: &mut Terminal<'_>,
    environment: &Environment,
    current_directory: &Path,
    executable: Option<&Path>,
) -> Exit {
    let home = environment.home();
    let Some(global_path) = config::global_config_path(environment) else {
        terminal.line(
            "contextveil: the configuration location could not be determined. Set HOME or \
             XDG_CONFIG_HOME.",
        );
        return Exit::Failure;
    };
    let project_root = paths::setup_project_root(current_directory);
    let project_path = project_root.join(PROJECT_CONFIG_FILENAME);

    terminal.line("ContextVeil setup");
    terminal.line("Complete values are never shown, stored, or sent anywhere.");
    terminal.blank();

    // `SET-001`: both files are parsed before any phase runs, so an invalid file
    // stops setup before it can change anything (`CFG-014`).
    let global = match preflight(terminal, &global_path, home.as_deref()) {
        Ok(config) => config,
        Err(exit) => return exit,
    };
    let project = match preflight(terminal, &project_path, home.as_deref()) {
        Ok(config) => config,
        Err(exit) => return exit,
    };

    let project_files = discovery::project_files(&project_root);

    // Discover both scopes before presenting either phase. Candidate Groups stay
    // phase-local, while collision exclusions can account for aliases in both
    // scopes (`SET-011`, `SET-016`).
    let (global_items, global_notices) = build_items(
        Scope::Global,
        &global,
        &project_root,
        environment,
        home.as_deref(),
        current_directory,
        &project_files,
    );
    let (project_items, project_notices) = build_items(
        Scope::Project,
        &project,
        &project_root,
        environment,
        home.as_deref(),
        current_directory,
        &project_files,
    );
    let mut aliases = alias_inventory([
        (Scope::Global, global_items.as_slice()),
        (Scope::Project, project_items.as_slice()),
    ]);

    let global_result = enrollment_phase(
        terminal,
        Scope::Global,
        &global,
        global_items,
        global_notices,
        EnrollmentContext {
            config_path: &global_path,
            project_root: &project_root,
            environment,
            home: home.as_deref(),
            aliases: &mut aliases,
        },
    );
    let global_sources = match global_result {
        PhaseResult::Kept(sources) | PhaseResult::Saved(sources) => sources,
        PhaseResult::Stopped(exit) => return exit,
    };

    let project_result = enrollment_phase(
        terminal,
        Scope::Project,
        &project,
        project_items,
        project_notices,
        EnrollmentContext {
            config_path: &project_path,
            project_root: &project_root,
            environment,
            home: home.as_deref(),
            aliases: &mut aliases,
        },
    );
    let project_sources = match project_result {
        PhaseResult::Kept(sources) | PhaseResult::Saved(sources) => sources,
        // `SET-014`: a completed global phase stays committed.
        PhaseResult::Stopped(exit) => return exit,
    };

    // `CFG-003`: the project file always exists after setup, even when empty.
    if !project_path.exists()
        && let Err(error) = write::write(&project_path, &project_sources, false)
    {
        terminal.line(&format!(
            "contextveil: `{}` could not be written because {}.",
            sanitize::path(&project_path),
            error.reason()
        ));
        return Exit::Failure;
    }

    match integrations::phase(
        terminal,
        environment,
        home.as_deref(),
        &global_path,
        executable,
    ) {
        Ok(()) => {}
        Err(exit) => return exit,
    }

    verification_phase(
        terminal,
        environment,
        &project_root,
        &global_sources,
        &project_sources,
    )
}

/// Loads one configuration file before any phase runs.
fn preflight(
    terminal: &mut Terminal<'_>,
    path: &Path,
    home: Option<&Path>,
) -> Result<Config, Exit> {
    match config::load(path, home) {
        Load::Valid(config) => Ok(config),
        Load::Missing => Ok(Config::default()),
        Load::Invalid(error) => {
            report_invalid(terminal, &error);
            Err(Exit::Failure)
        }
    }
}

/// `CFG-014`: show where the problem is and change nothing.
fn report_invalid(terminal: &mut Terminal<'_>, error: &ConfigError) {
    terminal.line(&format!(
        "contextveil: `{}` is not a valid ContextVeil configuration: {}.",
        sanitize::path(&error.path),
        error.kind.reason()
    ));
    terminal.line("Setup made no change. Repair or remove the file and run setup again.");
}

enum PhaseResult {
    /// The user chose the no-change path.
    Kept(Vec<SourceRef>),
    Saved(Vec<SourceRef>),
    Stopped(Exit),
}

struct EnrollmentContext<'a> {
    config_path: &'a Path,
    project_root: &'a Path,
    environment: &'a Environment,
    home: Option<&'a Path>,
    aliases: &'a mut AliasInventory,
}

/// One enrollment phase.
fn enrollment_phase(
    terminal: &mut Terminal<'_>,
    scope: Scope,
    existing: &Config,
    mut items: Vec<Item>,
    notices: Vec<known_source::Notice>,
    mut context: EnrollmentContext<'_>,
) -> PhaseResult {
    refresh_items(scope, &mut items, &mut context);

    terminal.line(scope.title());
    terminal.line(&format!("  file: {}", sanitize::path(context.config_path)));
    for notice in notices {
        terminal.line(&format!(
            "  unavailable: {} ({})",
            notice.display, notice.reason
        ));
    }
    loop {
        render(terminal, &items);
        render_actions(terminal, visible_count(&items));
        let answer = match terminal.ask(">") {
            Ok(answer) => answer,
            Err(Cancelled) => return cancelled(terminal),
        };

        match answer.trim() {
            "" => {
                if let Some(blocker) = blocking_item(&items) {
                    terminal.line(&format!(
                        "Cannot save: {blocker} must be repaired or deselected first."
                    ));
                    continue;
                }
                let selected = selected_sources(&items);
                return match write::write(context.config_path, &selected, scope == Scope::Global) {
                    Ok(changed) => {
                        terminal.line(if changed {
                            "Saved."
                        } else {
                            "No change; the file already matches."
                        });
                        terminal.blank();
                        PhaseResult::Saved(selected)
                    }
                    Err(error) => {
                        terminal.line(&format!(
                            "contextveil: `{}` could not be written because {}.",
                            sanitize::path(context.config_path),
                            error.reason()
                        ));
                        PhaseResult::Stopped(Exit::Failure)
                    }
                };
            }
            "s" => {
                terminal.line("Skipped; this file is unchanged.");
                terminal.blank();
                return PhaseResult::Kept(existing.sources.clone());
            }
            "q" => return cancelled(terminal),
            "a" => {
                for item in &mut items {
                    if item.problem.is_none() {
                        item.selected = true;
                        item.selection_touched = true;
                    }
                }
                refresh_items(scope, &mut items, &mut context);
            }
            "n" => {
                for item in &mut items {
                    item.selected = false;
                    item.selection_touched = true;
                }
                refresh_items(scope, &mut items, &mut context);
            }
            "e" | "k" | "w" | "j" => {
                match add_manual(terminal, answer.trim(), scope, &mut items, &mut context) {
                    Ok(()) => {}
                    Err(Cancelled) => return cancelled(terminal),
                }
            }
            selection => {
                toggle(terminal, &mut items, selection);
                refresh_items(scope, &mut items, &mut context);
            }
        }
    }
}

fn cancelled(terminal: &mut Terminal<'_>) -> PhaseResult {
    // `CLI-004`: cancellation returns nonzero. Phases already committed stay.
    terminal.line("Setup cancelled. Nothing further was changed.");
    PhaseResult::Stopped(Exit::Failure)
}

struct Member {
    source: SourceRef,
    enrolled: bool,
    suppressed: bool,
}

/// One selectable row in a phase. Singular equal-value references share a row;
/// unresolved references and wildcard policies remain standalone (`SET-016`).
struct Item {
    members: Vec<Member>,
    enrolled: bool,
    selected: bool,
    /// Masked preview and explanatory signals, when the source resolves.
    detail: String,
    /// Why the source cannot be used, when it currently cannot.
    problem: Option<String>,
    /// The resolved value, kept only in memory for collision analysis.
    value: Option<String>,
    resolved: bool,
    /// Current values from a wildcard policy. They never make the wildcard a
    /// Candidate Group member, but can exclude its file for other groups.
    wildcard_values: Vec<String>,
    collisions: Option<Collisions>,
    /// Whether the user explicitly chose this row rather than accepting setup's
    /// collision-derived default.
    selection_touched: bool,
    known_source: bool,
}

impl Item {
    fn description(&self) -> String {
        let visible: Vec<&Member> = self
            .members
            .iter()
            .filter(|member| !member.suppressed)
            .collect();
        if visible.len() == 1 {
            describe(&visible[0].source)
        } else {
            format!("Candidate group ({} sources)", visible.len())
        }
    }

    fn is_wildcard(&self) -> bool {
        matches!(self.members[0].source, SourceRef::DotenvAll { .. })
    }

    fn visible(&self) -> bool {
        self.is_wildcard() || self.members.iter().any(|member| !member.suppressed)
    }
}

#[derive(Default)]
struct AliasInventory {
    sources: HashMap<String, Vec<PathBuf>>,
    wildcards: Vec<WildcardAliases>,
}

struct WildcardAliases {
    scope: Scope,
    path: PathBuf,
    values: Vec<String>,
}

/// Renders a count with a correctly pluralized noun.
fn count(number: usize, singular: &str, plural: &str) -> String {
    if number == 1 {
        format!("{number} {singular}")
    } else {
        format!("{number} {plural}")
    }
}

/// Sanitized, value-free description of a source reference.
fn describe(source: &SourceRef) -> String {
    match source {
        SourceRef::Env { name } => format!("env {}", sanitize::text(name)),
        SourceRef::DotenvKey { entered, key, .. } => format!(
            "dotenv {} key {}",
            sanitize::text(entered),
            sanitize::text(key)
        ),
        SourceRef::DotenvAll { entered, .. } => {
            format!("dotenv {} (every key)", sanitize::text(entered))
        }
        SourceRef::Json {
            entered, pointer, ..
        } => format!(
            "json {} pointer {}",
            sanitize::text(entered),
            sanitize::text(pointer)
        ),
    }
}

fn build_items(
    scope: Scope,
    existing: &Config,
    project_root: &Path,
    environment: &Environment,
    home: Option<&Path>,
    invocation_directory: &Path,
    project_files: &discovery::ProjectFiles,
) -> (Vec<Item>, Vec<known_source::Notice>) {
    let mut resolver = Resolver::new();
    let mut items: Vec<Item> = Vec::new();

    // `CFG-015`: existing valid enrollment is preserved by default, including
    // sources that are merely unresolved right now.
    for source in &existing.sources {
        merge_item(
            &mut items,
            item_for(source.clone(), true, false, &mut resolver, environment),
        );
    }

    let mut known: HashSet<SourceId> = items
        .iter()
        .flat_map(|item| &item.members)
        .map(|member| member.source.id())
        .collect();
    let mut candidates: Vec<Item> = Vec::new();

    let discovered_known = match scope {
        Scope::Global => known_source::machine(environment, home, invocation_directory),
        Scope::Project => known_source::project(project_root, project_files),
    };
    for source in discovered_known.sources {
        if known.insert(source.id()) {
            candidates.push(item_for(source, false, true, &mut resolver, environment));
        }
    }

    if scope == Scope::Global {
        // `SET-002`: the current process environment is inspected automatically.
        for name in environment_candidates(environment) {
            let source = SourceRef::Env { name };
            if known.insert(source.id()) {
                candidates.push(item_for(source, false, false, &mut resolver, environment));
            }
        }
    }

    let discovered = match scope {
        // `SET-004`: bounded probe locations only.
        Scope::Global => home.map(discovery::global_dotenv_files).unwrap_or_default(),
        // `SET-003`: recursive project discovery.
        Scope::Project => project_files.dotenv.clone(),
    };
    for file in &discovered {
        for candidate in file_candidates(file, &known, &mut resolver, environment) {
            known.insert(candidate.members[0].source.id());
            candidates.push(candidate);
        }
    }

    // Rank suggestions by their admission and advisory signals (`SET-006`,
    // `SET-017`).
    candidates.sort_by(|left, right| {
        rank_of(right).cmp(&rank_of(left)).then_with(|| {
            left.members[0]
                .source
                .id()
                .cmp(&right.members[0].source.id())
        })
    });
    for candidate in candidates {
        merge_item(&mut items, candidate);
    }
    (items, discovered_known.notices)
}

fn rank_of(item: &Item) -> u32 {
    match &item.value {
        None => 0,
        Some(value) => {
            let mut signals = vocabulary::value_signals(value);
            if item.known_source {
                signals.push(Signal::KnownSource);
            }
            if let Some(signal) = admission_signal(&item.members[0].source, value) {
                signals.push(signal);
            }
            vocabulary::rank(&signals)
        }
    }
}

/// Name-gated and credential-bearing URL environment variables, in stable order.
fn environment_candidates(environment: &Environment) -> Vec<String> {
    let mut names: Vec<String> = environment
        .names()
        .filter(|name| {
            vocabulary::gating_term(name).is_some()
                || environment
                    .get_str(name)
                    .is_some_and(credential_url::is_credential_bearing)
        })
        .map(str::to_string)
        .collect();
    names.sort();
    names
}

/// Candidates offered for one discovered dotenv file.
fn file_candidates(
    file: &Discovered,
    known: &HashSet<SourceId>,
    resolver: &mut Resolver,
    environment: &Environment,
) -> Vec<Item> {
    let (Some(entered), State::Available(dotenv)) = (&file.entered, &file.state) else {
        return Vec::new();
    };
    dotenv
        .entries()
        .filter(|(key, value)| {
            !value.is_empty()
                && (vocabulary::gating_term(key).is_some()
                    || credential_url::is_credential_bearing(value))
        })
        .map(|(key, _)| SourceRef::DotenvKey {
            entered: entered.clone(),
            path: file.path.clone(),
            key: key.to_string(),
        })
        .filter(|source| !known.contains(&source.id()))
        .map(|source| item_for(source, false, false, resolver, environment))
        .collect()
}

fn item_for(
    source: SourceRef,
    enrolled: bool,
    known_source: bool,
    resolver: &mut Resolver,
    environment: &Environment,
) -> Item {
    let mut item = Item {
        members: vec![Member {
            source: source.clone(),
            enrolled,
            suppressed: false,
        }],
        enrolled,
        // `SET-007`: automatic candidates are selected by default; collision
        // analysis may unselect them afterwards.
        selected: true,
        detail: String::new(),
        problem: None,
        value: None,
        resolved: false,
        wildcard_values: Vec::new(),
        collisions: None,
        selection_touched: false,
        known_source,
    };

    match resolver.resolve(&source, environment) {
        Resolution::Resolved(secrets) => {
            item.resolved = true;
            let value = if matches!(source, SourceRef::DotenvAll { .. }) {
                None
            } else {
                secrets.first().map(|secret| secret.value.clone())
            };
            item.detail = match &value {
                Some(value) => {
                    let mut signals: Vec<Signal> =
                        admission_signal(&source, value).into_iter().collect();
                    if known_source {
                        signals.push(Signal::KnownSource);
                    }
                    signals.extend(vocabulary::value_signals(value));
                    let described: Vec<String> = signals.iter().map(Signal::describe).collect();
                    if described.is_empty() {
                        preview::describe(value)
                    } else {
                        format!("{}; {}", preview::describe(value), described.join(", "))
                    }
                }
                None => format!("{} current keys", secrets.len()),
            };
            if matches!(source, SourceRef::DotenvAll { .. }) {
                item.detail = format!("{} current key(s)", secrets.len());
                item.wildcard_values = secrets.into_iter().map(|secret| secret.value).collect();
            }
            item.value = value;
        }
        Resolution::Unresolved { why, .. } => {
            item.detail = format!("unresolved: {}", unresolved_reason(why));
            // An unresolved source is not an error; it is simply not selected by
            // default unless it is already enrolled (`CFG-015`).
            item.selected = enrolled;
        }
        Resolution::Malfunction { why, .. } => {
            // `SET-013`: an enrolled malformed or unreadable source must be
            // repaired or removed before setup can complete, so it stays
            // selected and blocks saving until the user deselects it.
            item.problem = Some(why.reason());
            item.detail = format!("unavailable: {}", why.reason());
            item.selected = enrolled;
        }
    }
    item
}

fn admission_signal(source: &SourceRef, value: &str) -> Option<Signal> {
    source
        .id()
        .key()
        .and_then(vocabulary::gating_term)
        .map(Signal::NameMatches)
        .or_else(|| {
            credential_url::is_credential_bearing(value).then_some(Signal::CredentialBearingUrl)
        })
}

fn merge_item(items: &mut Vec<Item>, mut incoming: Item) {
    if let Some(value) = incoming.value.as_ref()
        && let Some(existing) = items
            .iter_mut()
            .find(|item| item.value.as_ref() == Some(value))
    {
        existing.enrolled |= incoming.enrolled;
        existing.selected |= incoming.selected;
        existing.selection_touched |= incoming.selection_touched;
        existing.known_source |= incoming.known_source;
        existing.members.append(&mut incoming.members);
        return;
    }
    items.push(incoming);
}

fn alias_inventory<'a>(phases: impl IntoIterator<Item = (Scope, &'a [Item])>) -> AliasInventory {
    let mut aliases = AliasInventory::default();
    for (scope, items) in phases {
        for item in items {
            if let Some(value) = &item.value {
                for member in &item.members {
                    add_alias(&mut aliases.sources, value, member.source.file());
                }
            }
            if item.selected && item.is_wildcard() {
                aliases.wildcards.push(WildcardAliases {
                    scope,
                    path: item.members[0]
                        .source
                        .file()
                        .expect("a wildcard always has a file")
                        .to_path_buf(),
                    values: item.wildcard_values.clone(),
                });
            }
        }
    }
    aliases
}

impl AliasInventory {
    fn sync_wildcards(&mut self, scope: Scope, items: &[Item]) {
        self.wildcards.retain(|wildcard| wildcard.scope != scope);
        self.wildcards.extend(
            items
                .iter()
                .filter(|item| item.selected && item.is_wildcard())
                .map(|item| WildcardAliases {
                    scope,
                    path: item.members[0]
                        .source
                        .file()
                        .expect("a wildcard always has a file")
                        .to_path_buf(),
                    values: item.wildcard_values.clone(),
                }),
        );
    }

    fn source_files(&self, value: &str) -> Vec<PathBuf> {
        let mut files = self.sources.get(value).cloned().unwrap_or_default();
        for wildcard in &self.wildcards {
            if wildcard.values.iter().any(|known| known == value)
                && !files.iter().any(|known| known == &wildcard.path)
            {
                files.push(wildcard.path.clone());
            }
        }
        files
    }
}

fn add_alias(aliases: &mut HashMap<String, Vec<PathBuf>>, value: &str, file: Option<&Path>) {
    let Some(file) = file else { return };
    let files = aliases.entry(value.to_string()).or_default();
    if !files.iter().any(|known| known == file) {
        files.push(file.to_path_buf());
    }
}

fn unresolved_reason(why: Unresolved) -> &'static str {
    why.reason()
}

/// Runs collision analysis for every resolvable candidate (`SET-011`).
fn annotate_collisions(items: &mut [Item], project_root: &Path, aliases: &AliasInventory) {
    let values: Vec<&str> = items
        .iter()
        .filter_map(|item| item.value.as_deref())
        .collect();
    let source_files: Vec<Vec<PathBuf>> = values
        .iter()
        .map(|value| aliases.source_files(value))
        .collect();
    let subjects: Vec<collision::Subject<'_>> = values
        .iter()
        .zip(&source_files)
        .map(|(value, source_files)| collision::Subject {
            value,
            source_files,
        })
        .collect();
    if subjects.is_empty() {
        return;
    }
    let reports = collision::analyze(project_root, &subjects);

    let mut report = reports.into_iter();
    for item in items.iter_mut() {
        if item.value.is_none() {
            continue;
        }
        let Some(collisions) = report.next() else {
            break;
        };
        item.collisions = None;
        if !collisions.is_empty() {
            // `SET-007`: a colliding candidate stays visible but unselected,
            // unless it is already enrolled (`CFG-015`).
            if !item.enrolled && !item.selection_touched {
                item.selected = false;
            }
            item.collisions = Some(collisions);
        } else if !item.enrolled && !item.selection_touched {
            item.selected = true;
        }
    }
}

fn render(terminal: &mut Terminal<'_>, items: &[Item]) {
    terminal.blank();
    if visible_count(items) == 0 {
        terminal.line("  (no candidates found)");
        return;
    }
    for (index, item) in items.iter().filter(|item| item.visible()).enumerate() {
        let marker = match (&item.problem, item.selected) {
            (Some(_), _) => "!",
            (None, true) => "x",
            (None, false) => " ",
        };
        let enrolled = if item.enrolled { " (enrolled)" } else { "" };
        terminal.line(&format!(
            "  {:>2} [{marker}] {}{enrolled}",
            index + 1,
            item.description()
        ));
        if item
            .members
            .iter()
            .filter(|member| !member.suppressed)
            .count()
            > 1
        {
            for member in item.members.iter().filter(|member| !member.suppressed) {
                let enrolled = if member.enrolled { " (enrolled)" } else { "" };
                terminal.line(&format!("        - {}{enrolled}", describe(&member.source)));
            }
        }
        if !item.detail.is_empty() {
            terminal.line(&format!("        {}", item.detail));
        }
        if let Some(collisions) = &item.collisions {
            terminal.line(&format!("        collision: {}", collisions.describe()));
        }
    }
}

fn render_actions(terminal: &mut Terminal<'_>, item_count: usize) {
    terminal.line("Choose an action:");
    if item_count > 0 {
        terminal.line("  [1 3]   toggle row(s)");
        terminal.line("  [a]     select all");
        terminal.line("  [n]     select none");
    }
    terminal.line("  [e]     add env");
    terminal.line("  [k]     add dotenv key");
    terminal.line("  [w]     add wildcard file");
    terminal.line("  [j]     add JSON field");
    terminal.line("  [Enter] save");
    terminal.line("  [s]     skip");
    terminal.line("  [q]     quit");
}

/// The first selected source that blocks saving (`SET-013`).
fn blocking_item(items: &[Item]) -> Option<String> {
    items
        .iter()
        .find(|item| item.visible() && item.selected && item.problem.is_some())
        .map(|item| item.description())
}

fn selected_sources(items: &[Item]) -> Vec<SourceRef> {
    items
        .iter()
        .filter(|item| item.selected && item.visible())
        .flat_map(|item| {
            item.members
                .iter()
                .filter(|member| !member.suppressed)
                .map(|member| member.source.clone())
        })
        .collect()
}

fn toggle(terminal: &mut Terminal<'_>, items: &mut [Item], selection: &str) {
    let visible: Vec<usize> = items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| item.visible().then_some(index))
        .collect();
    let mut unknown = Vec::new();
    for token in selection.split_whitespace() {
        match token.parse::<usize>() {
            Ok(number) if number >= 1 && number <= visible.len() => {
                let item = &mut items[visible[number - 1]];
                if item.problem.is_some() && !item.selected {
                    terminal.line(&format!(
                        "  {} is unavailable and cannot be selected.",
                        item.description()
                    ));
                    continue;
                }
                item.selected = !item.selected;
                item.selection_touched = true;
            }
            _ => unknown.push(sanitize::text(token)),
        }
    }
    if !unknown.is_empty() {
        terminal.line(&format!("  Not a choice: {}", unknown.join(", ")));
    }
}

fn visible_count(items: &[Item]) -> usize {
    items.iter().filter(|item| item.visible()).count()
}

fn update_suppression(items: &mut [Item], aliases: &AliasInventory) {
    let selected_wildcards: Vec<&Path> = aliases
        .wildcards
        .iter()
        .map(|wildcard| wildcard.path.as_path())
        .collect();
    for item in items {
        if item.is_wildcard() {
            continue;
        }
        for member in &mut item.members {
            member.suppressed = !member.enrolled
                && matches!(
                    &member.source,
                    SourceRef::DotenvKey { path, .. }
                        if selected_wildcards.iter().any(|wildcard| *wildcard == path)
                );
        }
    }
}

fn refresh_items(scope: Scope, items: &mut [Item], context: &mut EnrollmentContext<'_>) {
    context.aliases.sync_wildcards(scope, items);
    update_suppression(items, context.aliases);
    annotate_collisions(items, context.project_root, context.aliases);
}

/// Manual entry of a source (`SET-005`).
fn add_manual(
    terminal: &mut Terminal<'_>,
    kind: &str,
    scope: Scope,
    items: &mut Vec<Item>,
    context: &mut EnrollmentContext<'_>,
) -> Result<(), Cancelled> {
    let base = context.config_path.parent().unwrap_or(Path::new("."));
    let source = match kind {
        "e" => {
            let name = terminal.ask("Environment variable name:")?;
            if name.trim().is_empty() {
                terminal.line("  No name entered.");
                return Ok(());
            }
            SourceRef::Env {
                name: name.trim().to_string(),
            }
        }
        "k" | "w" => {
            let entered = terminal.ask("Dotenv file path:")?;
            let entered = entered.trim().to_string();
            if entered.is_empty() {
                terminal.line("  No path entered.");
                return Ok(());
            }
            let path = match paths::expand(&entered, base, context.home) {
                Ok(path) => path,
                Err(problem) => {
                    terminal.line(&format!("  That path {}.", problem.reason()));
                    return Ok(());
                }
            };
            if kind == "k" {
                let key = terminal.ask("Key name:")?;
                if key.trim().is_empty() {
                    terminal.line("  No key entered.");
                    return Ok(());
                }
                SourceRef::DotenvKey {
                    entered,
                    path,
                    key: key.trim().to_string(),
                }
            } else {
                // `SET-009`: wildcard enrollment needs its own confirmation.
                terminal.line(
                    "  Wildcard enrollment protects every current and future key in that file.",
                );
                terminal.line(
                    "  Short, common, and future values are enrolled without individual review, \
                     and a common value can replace unrelated text.",
                );
                if !terminal.confirm("  Enroll every key in this file?", false)? {
                    terminal.line("  Not added.");
                    return Ok(());
                }
                SourceRef::DotenvAll { entered, path }
            }
        }
        "j" => {
            let entered = terminal.ask("JSON file path:")?;
            let entered = entered.trim().to_string();
            if entered.is_empty() {
                terminal.line("  No path entered.");
                return Ok(());
            }
            let path = match paths::expand(&entered, base, context.home) {
                Ok(path) => path,
                Err(problem) => {
                    terminal.line(&format!("  That path {}.", problem.reason()));
                    return Ok(());
                }
            };
            let pointer = terminal.ask("JSON Pointer:")?;
            if pointer.trim().is_empty() {
                terminal.line("  No pointer entered.");
                return Ok(());
            }
            let token = match crate::json::final_token(&pointer) {
                Ok(token) => token,
                Err(_) => {
                    terminal.line(
                        "  Enter a plain RFC 6901 pointer beginning with `/`, with a non-empty final token and no wildcards.",
                    );
                    return Ok(());
                }
            };
            SourceRef::Json {
                entered,
                path,
                pointer,
                token,
            }
        }
        _ => return Ok(()),
    };

    if items
        .iter()
        .flat_map(|item| &item.members)
        .any(|member| member.source.id() == source.id())
    {
        terminal.line("  That source is already listed.");
        return Ok(());
    }

    let mut resolver = Resolver::new();
    let mut item = item_for(source, false, false, &mut resolver, context.environment);
    if item.problem.is_some() {
        terminal.line(&format!("  This source is currently {}.", item.detail));
        terminal.line("  Not added; repair the source and try again.");
        return Ok(());
    }
    if !item.resolved {
        // `SET-005`: a currently absent manual source may be saved after an
        // explicit confirmation.
        terminal.line(&format!("  This source is currently {}.", item.detail));
        if !terminal.confirm("  Save it anyway?", false)? {
            terminal.line("  Not added.");
            return Ok(());
        }
    }
    item.selected = true;
    // Manual entry is itself an affirmative enrollment choice. Collisions stay
    // visible but do not reverse that choice (`SET-008`).
    item.selection_touched = true;
    if let Some(value) = &item.value {
        add_alias(
            &mut context.aliases.sources,
            value,
            item.members[0].source.file(),
        );
    }
    merge_item(items, item);
    refresh_items(scope, items, context);
    Ok(())
}

/// Offline verification (`SET-001` phase four).
fn verification_phase(
    terminal: &mut Terminal<'_>,
    environment: &Environment,
    project_root: &Path,
    global_sources: &[SourceRef],
    project_sources: &[SourceRef],
) -> Exit {
    terminal.line("Verification");
    match crate::registry::build(environment, Some(project_root)) {
        crate::registry::Outcome::Ready(registry) => {
            let enrolled = global_sources.len() + project_sources.len();
            terminal.line(&format!(
                "  {} enrolled: {} active, {} unresolved.",
                count(enrolled, "source", "sources"),
                registry.redactor.active_count(),
                registry.unresolved.len()
            ));
            for (path, keys) in &registry.duplicate_keys {
                // `SRC-004`: warn about duplicates without showing either value.
                terminal.line(&format!(
                    "  warning: {} assigns {} more than once; the last assignment wins.",
                    sanitize::path(path),
                    keys.len()
                ));
            }
            if registry.redactor.is_empty() {
                terminal.line("  INACTIVE: no source resolves to a value right now.");
            }
            terminal.line("Setup complete.");
            Exit::Ok
        }
        crate::registry::Outcome::Malfunction(malfunction) => {
            terminal.line(&format!("  verification failed: {}", malfunction.message()));
            Exit::Failure
        }
    }
}
