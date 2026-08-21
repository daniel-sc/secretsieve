//! Leak regression suite (`TST-005`, `SEC-004`).
//!
//! One generated canary is enrolled and then pushed through every shipped path:
//! all four adapters, `status`, `doctor`, and a complete `setup` run. After each,
//! the canary must be absent from stdout, stderr, every file ContextVeil wrote,
//! and every diagnostic it produced.
//!
//! This is deliberately end to end through the built binary, so it also covers
//! the wiring between the CLI, the adapters, and the installers.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use contextveil::testing::{Canary, assert_canary_absent};
use serde_json::json;

struct Machine {
    root: PathBuf,
    canary: Canary,
}

impl Machine {
    /// A machine with the canary enrolled through environment, dotenv, and JSON
    /// references, so every source kind is exercised.
    fn new() -> Self {
        let canary = Canary::generate("LEAK_TOKEN");
        // The directory name must not contain any part of the canary: paths are
        // printed by design, and a fixture-shaped false positive would hide a
        // real leak.
        let root = std::env::temp_dir().join(format!(
            "contextveil-leaks-{}-{}",
            std::process::id(),
            Canary::generate("FIXTURE").token()
        ));
        let home = root.join("home");
        let project = home.join("project");
        std::fs::create_dir_all(project.join("nested")).expect("project");
        std::fs::create_dir_all(home.join(".config").join("contextveil")).expect("config");
        std::fs::create_dir_all(home.join(".claude")).expect("claude");
        std::fs::create_dir_all(home.join(".codex")).expect("codex");

        std::fs::write(
            home.join(".config").join("contextveil").join("config.toml"),
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"LEAK_TOKEN\"\n",
        )
        .expect("global config");
        std::fs::write(
            project.join(".contextveil.toml"),
            "version = 1\n\n[[secret]]\nsource = \"json\"\nfile = \"auth.json\"\npointer = \"/tokens/access_token\"\n\n[[secret]]\nsource = \"dotenv\"\nfile = \".env\"\nall = true\n",
        )
        .expect("project config");
        std::fs::write(
            project.join("auth.json"),
            format!(r#"{{"tokens":{{"access_token":"{}"}}}}"#, canary.value()),
        )
        .expect("JSON source");
        std::fs::write(
            home.join(".codex").join("auth.json"),
            format!(r#"{{"OPENAI_API_KEY":"{}"}}"#, canary.value()),
        )
        .expect("Known Source JSON");
        std::fs::write(
            project.join(".env"),
            format!(
                "PROJECT_TOKEN={}\nDUPLICATE={}\nDUPLICATE=other\n",
                canary.value(),
                canary.value()
            ),
        )
        .expect("dotenv");
        // A file that also contains the value, so collision analysis reports it.
        std::fs::write(project.join("nested").join("notes.txt"), canary.value())
            .expect("colliding file");

        Self { root, canary }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn project(&self) -> PathBuf {
        self.home().join("project")
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_contextveil"));
        command
            .args(arguments)
            .current_dir(self.project())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.home())
            .env("LEAK_TOKEN", self.canary.value())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.command(arguments)
            .stdin(Stdio::null())
            .output()
            .expect("the binary runs")
    }

    fn run_with_payload(&self, arguments: &[&str], payload: &str) -> Output {
        let mut child = self
            .command(arguments)
            .stdin(Stdio::piped())
            .spawn()
            .expect("the binary runs");
        child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(payload.as_bytes())
            .expect("write the payload");
        child.wait_with_output().expect("the hook finishes")
    }

    /// Asserts the canary is absent from both channels.
    fn assert_clean(&self, label: &str, output: &Output) {
        assert_canary_absent(&format!("{label} stdout"), &output.stdout, &self.canary);
        assert_canary_absent(&format!("{label} stderr"), &output.stderr, &self.canary);
    }

    /// Asserts the canary is absent from every file under the isolated home,
    /// except the dotenv source that legitimately holds it.
    fn assert_files_clean(&self) {
        let dotenv = self.project().join(".env");
        let json = self.project().join("auth.json");
        let known_source = self.home().join(".codex").join("auth.json");
        let notes = self.project().join("nested").join("notes.txt");
        let mut checked = 0;
        for path in walk(&self.home()) {
            if path == dotenv || path == json || path == known_source || path == notes {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            assert_canary_absent(&path.to_string_lossy(), &bytes, &self.canary);
            checked += 1;
        }
        assert!(checked > 0, "no files were inspected");
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}

#[test]
fn no_adapter_discloses_an_enrolled_value() {
    let machine = Machine::new();
    let value = machine.canary.value().to_string();
    let project = machine.project().to_string_lossy().into_owned();

    let cases: Vec<(&str, Vec<&str>, String)> = vec![
        (
            "claude",
            vec!["hook", "claude"],
            json!({
                "hook_event_name": "PostToolUse",
                "cwd": project,
                "tool_name": "Bash",
                "tool_response": {"stdout": value, "stderr": value, "nested": [{"text": value}]},
            })
            .to_string(),
        ),
        (
            "codex",
            vec!["hook", "codex"],
            json!({
                "hook_event_name": "PostToolUse",
                "cwd": project,
                "tool_name": "shell",
                "tool_response": {"output": value, "exit_code": 0},
            })
            .to_string(),
        ),
        (
            "copilot prompt",
            vec!["hook", "copilot", "prompt"],
            json!({
                "cwd": project,
                "prompt": value,
                "transformedPrompt": value,
            })
            .to_string(),
        ),
        (
            "copilot tool",
            vec!["hook", "copilot", "tool"],
            json!({
                "cwd": project,
                "toolName": "shell",
                "toolResult": {"resultType": "success", "textResultForLlm": value},
            })
            .to_string(),
        ),
        (
            "opencode",
            vec!["hook", "opencode"],
            json!({
                "version": 1,
                "event": "tool.execute.after",
                "project_root": project,
                "texts": [value],
            })
            .to_string(),
        ),
    ];

    for (label, arguments, payload) in cases {
        let output = machine.run_with_payload(&arguments, &payload);
        machine.assert_clean(label, &output);
        assert!(
            !output.stdout.is_empty(),
            "{label} produced no output, so the fixture proves nothing"
        );
        // The replacement really happened, so absence is not vacuous.
        let text = String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout");
        assert!(
            text.contains("<SECRET:"),
            "{label} did not redact anything: {text}"
        );
    }
}

#[test]
fn diagnostics_never_disclose_an_enrolled_value() {
    let machine = Machine::new();
    for command in ["status", "doctor"] {
        let output = machine.run(&[command]);
        machine.assert_clean(command, &output);
        let text = String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout");
        // Doctor really did inspect the sources and the collision.
        if command == "doctor" {
            assert!(text.contains("also occurs in this project"));
            assert!(text.contains("more than once"));
        }
    }
}

#[test]
fn a_complete_setup_run_writes_no_value_anywhere() {
    // Setup is driven through the library so a scripted transcript can answer it;
    // the process-level surface is covered by the other tests here.
    use contextveil::setup;
    use contextveil::setup::ui::Terminal;
    use contextveil::source::Environment;

    let machine = Machine::new();
    let environment = Environment::from_pairs([
        (
            "HOME".to_string(),
            machine.home().to_string_lossy().into_owned(),
        ),
        ("LEAK_TOKEN".to_string(), machine.canary.value().to_string()),
    ]);

    let mut transcript: Vec<u8> = Vec::new();
    let exit = {
        let mut terminal = Terminal::new(
            std::io::Cursor::new(String::from("\n\n\n")),
            &mut transcript,
        );
        setup::run(
            &mut terminal,
            &environment,
            &machine.project(),
            Some(Path::new(env!("CARGO_BIN_EXE_contextveil"))),
        )
    };
    assert_eq!(
        exit,
        contextveil::cli::Exit::Ok,
        "{}",
        String::from_utf8_lossy(&transcript)
    );

    assert_canary_absent("setup transcript", &transcript, &machine.canary);
    let global = std::fs::read_to_string(
        machine
            .home()
            .join(".config")
            .join("contextveil")
            .join("config.toml"),
    )
    .expect("global config");
    assert!(
        global.contains("~/.codex/auth.json"),
        "the setup leak check must exercise Known Source persistence"
    );
    // Every file ContextVeil wrote, including the installed hook and the
    // integration record, is value-free.
    machine.assert_files_clean();
}

#[test]
fn a_malfunction_on_every_adapter_discloses_nothing() {
    let machine = Machine::new();
    // Break the global config so every adapter takes its malfunction path.
    std::fs::write(
        machine
            .home()
            .join(".config")
            .join("contextveil")
            .join("config.toml"),
        "version = 1\n\n[[secret]]\nsource = \"unknown\"\n",
    )
    .expect("write invalid config");

    let value = machine.canary.value().to_string();
    let cases: Vec<(&str, Vec<&str>, String)> = vec![
        (
            "claude",
            vec!["hook", "claude"],
            json!({"hook_event_name": "PostToolUse", "tool_response": {"stdout": value}})
                .to_string(),
        ),
        (
            "codex",
            vec!["hook", "codex"],
            json!({"hook_event_name": "PostToolUse", "tool_response": {"output": value}})
                .to_string(),
        ),
        (
            "copilot",
            vec!["hook", "copilot", "tool"],
            json!({"toolResult": {"resultType": "success", "textResultForLlm": value}}).to_string(),
        ),
        (
            "opencode",
            vec!["hook", "opencode"],
            json!({"version": 1, "event": "chat.message", "texts": [value]}).to_string(),
        ),
    ];

    for (label, arguments, payload) in cases {
        let output = machine.run_with_payload(&arguments, &payload);
        machine.assert_clean(label, &output);
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains("doctor"),
            "{label} did not warn about the malfunction"
        );
    }
}

#[test]
fn runtime_writes_no_log_or_telemetry_file() {
    // `SEC-005`: no telemetry, crash upload, analytics, or persistent runtime
    // logging. Every covered path is exercised, then the file tree is compared
    // with what existed before.
    let machine = Machine::new();
    let value = machine.canary.value().to_string();
    let project = machine.project().to_string_lossy().into_owned();
    let before: Vec<PathBuf> = walk(&machine.home());

    let payloads: Vec<(Vec<&str>, String)> = vec![
        (
            vec!["hook", "claude"],
            json!({"hook_event_name": "PostToolUse", "cwd": project, "tool_response": {"stdout": value}})
                .to_string(),
        ),
        (
            vec!["hook", "codex"],
            json!({"hook_event_name": "PostToolUse", "cwd": project, "tool_response": {"output": value}})
                .to_string(),
        ),
        (
            vec!["hook", "copilot", "tool"],
            json!({"cwd": project, "toolResult": {"resultType": "success", "textResultForLlm": value}})
                .to_string(),
        ),
        (
            vec!["hook", "opencode"],
            json!({"version": 1, "event": "chat.message", "project_root": project, "texts": [value]})
                .to_string(),
        ),
    ];
    for (arguments, payload) in payloads {
        machine.run_with_payload(&arguments, &payload);
    }
    machine.run(&["status"]);
    machine.run(&["doctor"]);

    let after: Vec<PathBuf> = walk(&machine.home());
    let created: Vec<&PathBuf> = after.iter().filter(|path| !before.contains(path)).collect();
    assert!(created.is_empty(), "runtime created files: {created:?}");
}

#[test]
fn terminal_hostile_names_and_paths_are_escaped_in_diagnostics() {
    // `SEC-006`: everything untrusted reaching a terminal is escaped.
    let machine = Machine::new();
    std::fs::write(
        machine
            .home()
            .join(".config")
            .join("contextveil")
            .join("config.toml"),
        "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"\\u001b[31mLEAK_TOKEN\"\n",
    )
    .expect("write global config");
    std::fs::write(
        machine.project().join(".contextveil.toml"),
        "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \"weird\\u001b[31mname.env\"\nkey = \"A\"\n",
    )
    .expect("write project config");

    for command in ["status", "doctor"] {
        let output = machine.run(&[command]);
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
        assert!(!stdout.contains('\u{1b}'), "{command} emitted a raw escape");
    }
    // Only doctor names individual sources, so only doctor renders the escape.
    let doctor = machine.run(&["doctor"]);
    let stdout = String::from_utf8(doctor.stdout).expect("UTF-8 stdout");
    assert!(
        stdout.contains("\\e[31m"),
        "doctor did not escape the name: {stdout}"
    );
}
