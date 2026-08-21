//! Bounded fuzz smoke run over every untrusted input surface (`TST-006`).
//!
//! It replays the committed regression corpus first, then mutates seed inputs with
//! a deterministic generator until its iteration or time budget runs out. A target
//! that panics fails the run and its input is written to
//! `fuzz/regressions/<target>/` so it can be committed as a permanent seed.
//!
//! Determinism is deliberate: the same command reproduces the same inputs, so a
//! failure is investigable and CI never depends on luck. Raise `CONTEXTVEIL_FUZZ_
//! ITERATIONS` or `CONTEXTVEIL_FUZZ_SECONDS` for a longer run.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use contextveil::fuzz;

/// Seed inputs per target, chosen to be valid or nearly valid so mutation
/// explores interesting states rather than mostly rejecting garbage.
const SEEDS: [(&str, &[&str]); 9] = [
    (
        "dotenv",
        &[
            "A=1\nB=two\n",
            "export TOKEN=abc # comment\nQUOTED=\"line1\\nline2\"\n",
            "\u{feff}A='multi\nline'\r\nDUP=1\nDUP=2\n",
            "malformed line\n",
        ],
    ),
    (
        "json-source",
        &[
            "/tokens/access_token\n{\"tokens\":{\"access_token\":\"value\"}}",
            "/a~1b/~0key\n{\"a/b\":{\"~key\":\"value\"}}",
            "/token\n{\"token\":\"first\",\"token\":\"second\"}",
            "/missing\n[null,true,1,{},[]]",
        ],
    ),
    (
        "config",
        &[
            "version = 1\n",
            "version = 1\n\n[[secret]]\nsource = \"env\"\nname = \"A\"\n",
            "version = 1\n\n[[secret]]\nsource = \"dotenv\"\nfile = \"~/.env\"\nall = true\n",
            "version = 1\n\n[[secret]]\nsource = \"json\"\nfile = \"~/auth.json\"\npointer = \"/tokens/access_token\"\n",
            "version = 2\nunknown = true\n",
        ],
    ),
    (
        "matcher",
        &[
            "abc\tabcd\nzabcd",
            "TOKEN\n[TOKEN]",
            "\u{e4}\u{f6}\t\u{fc}\nsome \u{e4}\u{f6} text",
            "\t\n",
        ],
    ),
    (
        "sanitize",
        &[
            "plain text",
            "a\u{1b}[31mb",
            "a\nb\rc\td",
            "\u{202e}reversed",
        ],
    ),
    (
        "claude",
        &[
            r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"x"}}"#,
            r#"{"hook_event_name":"PostToolUse","tool_response":[{"type":"text","text":"x"}]}"#,
            r#"{"hook_event_name":"SessionStart"}"#,
        ],
    ),
    (
        "codex",
        &[
            r#"{"hook_event_name":"PostToolUse","cwd":"/tmp","tool_response":{"output":"x","exit_code":0}}"#,
            r#"{"hook_event_name":"PostToolUse","tool_response":"plain"}"#,
        ],
    ),
    (
        "copilot",
        &[
            r#"{"cwd":"/tmp","prompt":"p","transformedPrompt":"p"}"#,
            r#"{"cwd":"/tmp","toolName":"shell","toolResult":{"resultType":"success","textResultForLlm":"x"}}"#,
            r#"{"cwd":"/tmp","toolName":"shell","toolResult":{"resultType":"failure"}}"#,
        ],
    ),
    (
        "opencode",
        &[
            r#"{"version":1,"event":"chat.message","project_root":"/tmp","texts":["a","b"]}"#,
            r#"{"version":1,"event":"tool.execute.after","texts":["a"]}"#,
            r#"{"version":2,"event":"chat.message","texts":[]}"#,
        ],
    ),
];

fn main() {
    let iterations: usize = read_budget("CONTEXTVEIL_FUZZ_ITERATIONS", 4000);
    let seconds = read_budget("CONTEXTVEIL_FUZZ_SECONDS", 30) as u64;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let regressions = PathBuf::from("fuzz/regressions");

    println!("ContextVeil fuzz smoke");
    println!("  targets     {}", fuzz::TARGETS.len());
    println!("  iterations  {iterations} per target (budget {seconds}s)");
    if fuzz::context().is_none() {
        eprintln!("fuzz-smoke: a temporary configuration could not be created");
        std::process::exit(1);
    }

    let mut executed = 0usize;
    let mut failures = 0usize;
    for (name, target) in fuzz::TARGETS {
        let seeds = SEEDS
            .iter()
            .find(|(target_name, _)| *target_name == name)
            .map(|(_, seeds)| *seeds)
            .unwrap_or(&[]);

        // Committed regressions run first and always, budget or not.
        for (label, input) in replay(&regressions, name) {
            executed += 1;
            if !run(target, &input) {
                failures += 1;
                eprintln!("fuzz-smoke: {name} failed on committed regression {label}");
            }
        }

        let mut rng = Rng::new(seed_for(name));
        for iteration in 0..iterations {
            if Instant::now() >= deadline {
                println!("  {name}: stopped at iteration {iteration} (time budget)");
                break;
            }
            let input = mutate(&mut rng, seeds);
            executed += 1;
            if !run(target, &input) {
                failures += 1;
                let path = promote(&regressions, name, &input);
                eprintln!(
                    "fuzz-smoke: {name} failed on a generated input; saved to {}",
                    path.display()
                );
                eprintln!("fuzz-smoke: commit that file so the case is replayed from now on");
                break;
            }
        }
    }

    println!("  executed    {executed} inputs");
    if failures > 0 {
        eprintln!("fuzz-smoke: {failures} target(s) failed");
        std::process::exit(1);
    }
    println!("  result      no panic, no unbounded recursion, no disclosure");
}

fn read_budget(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Runs one target, catching a panic so the harness can report and continue.
fn run(target: fuzz::Target, input: &[u8]) -> bool {
    let input = input.to_vec();
    // The default panic hook would print the payload; the harness reports the
    // saved file instead, so the hook is silenced for the call.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(move || target(&input));
    std::panic::set_hook(previous);
    outcome.is_ok()
}

/// Committed regression inputs for one target.
fn replay(root: &Path, target: &str) -> Vec<(String, Vec<u8>)> {
    let directory = root.join(target);
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut inputs: Vec<(String, Vec<u8>)> = entries
        .flatten()
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            std::fs::read(entry.path()).ok().map(|bytes| (name, bytes))
        })
        .collect();
    inputs.sort_by(|left, right| left.0.cmp(&right.0));
    inputs
}

/// Writes a failing input so it can be committed as a permanent seed.
fn promote(root: &Path, target: &str, input: &[u8]) -> PathBuf {
    let directory = root.join(target);
    let _ = std::fs::create_dir_all(&directory);
    let path = directory.join(format!("{:016x}", fingerprint(input)));
    if let Ok(mut file) = std::fs::File::create(&path) {
        let _ = file.write_all(input);
    }
    path
}

fn fingerprint(input: &[u8]) -> u64 {
    // A stable name for the same input, so a rerun overwrites rather than piles up.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in input {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn seed_for(target: &str) -> u64 {
    fingerprint(target.as_bytes()) | 1
}

/// Builds one input by mutating a seed, or by generating random bytes.
fn mutate(rng: &mut Rng, seeds: &[&str]) -> Vec<u8> {
    if seeds.is_empty() || rng.below(8) == 0 {
        let length = rng.below(64);
        return (0..length).map(|_| rng.below(256) as u8).collect();
    }
    let mut bytes = seeds[rng.below(seeds.len())].as_bytes().to_vec();
    let edits = 1 + rng.below(4);
    for _ in 0..edits {
        if bytes.is_empty() {
            bytes.push(rng.below(256) as u8);
            continue;
        }
        let position = rng.below(bytes.len());
        match rng.below(4) {
            0 => bytes[position] = rng.below(256) as u8,
            1 => bytes.insert(position, INTERESTING[rng.below(INTERESTING.len())]),
            2 => {
                bytes.remove(position);
            }
            _ => {
                let slice = bytes[position..].to_vec();
                bytes.extend_from_slice(&slice);
            }
        }
    }
    bytes.truncate(4096);
    bytes
}

/// Bytes that carry meaning in the grammars under test.
const INTERESTING: [u8; 16] = [
    b'"', b'\'', b'\\', b'\n', b'\r', b'\t', b'#', b'=', b'{', b'}', b'[', b']', b':', b',', 0x00,
    0xff,
];

/// A small xorshift generator. Deterministic and dependency-free.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.0 = state;
        state
    }

    fn below(&mut self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        (self.next() % limit as u64) as usize
    }
}
