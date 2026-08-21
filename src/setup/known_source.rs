//! Closed, setup-time discovery for supported coding-agent credential stores.
//!
//! Every match becomes an ordinary environment or exact JSON reference. JSONC,
//! transformed values, keychains, helpers, and broad directory recursion are
//! deliberately outside this module.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::json;
use crate::paths;
use crate::sanitize;
use crate::source::{Environment, SourceRef};

use super::discovery::ProjectFiles;

const CLAUDE_ENV: [&str; 8] = [
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_AWS_API_KEY",
    "ANTHROPIC_FOUNDRY_API_KEY",
    "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
];
const MCP_ENV: [&str; 8] = [
    "API_KEY",
    "ACCESS_TOKEN",
    "AUTH_TOKEN",
    "BEARER_TOKEN",
    "CLIENT_SECRET",
    "PASSWORD",
    "SECRET",
    "TOKEN",
];
const MCP_HEADERS: [&str; 6] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-subscription-token",
];

#[derive(Debug, Default)]
pub struct Found {
    pub sources: Vec<SourceRef>,
    pub notices: Vec<Notice>,
}

#[derive(Debug)]
pub struct Notice {
    pub display: String,
    pub reason: &'static str,
}

pub fn machine(environment: &Environment, home: Option<&Path>, base: &Path) -> Found {
    let mut found = Found::default();
    codex(&mut found, environment, home, base);
    opencode(&mut found, environment, home, base);
    copilot(&mut found, environment, home, base);
    claude_machine(&mut found, environment, home, base);
    if environment
        .get_str("OPENCODE_AUTH_CONTENT")
        .is_some_and(|value| !value.is_empty())
    {
        found.sources.push(SourceRef::Env {
            name: "OPENCODE_AUTH_CONTENT".into(),
        });
    }
    deduplicate(&mut found.sources);
    found
}

pub fn project(project_root: &Path, files: &ProjectFiles) -> Found {
    let mut found = Found::default();
    for path in &files.claude_settings {
        inspect(
            &mut found,
            path,
            project_entry(project_root, path),
            settings_sources,
        );
    }
    for path in &files.claude_mcp {
        inspect(
            &mut found,
            path,
            project_entry(project_root, path),
            mcp_server_sources,
        );
    }
    deduplicate(&mut found.sources);
    found
}

fn codex(found: &mut Found, environment: &Environment, home: Option<&Path>, base: &Path) {
    let Some((root, default)) = rooted(found, environment, "CODEX_HOME", home, ".codex", base)
    else {
        return;
    };
    inspect_at(
        found,
        &root.join("auth.json"),
        home,
        default,
        |value, path, entered, out| {
            for pointer in [
                "/OPENAI_API_KEY",
                "/tokens/id_token",
                "/tokens/access_token",
                "/tokens/refresh_token",
                "/personal_access_token",
                "/bedrock_api_key/api_key",
            ] {
                add_if_string(value, path, entered, pointer, out);
            }
            if value
                .pointer("/agent_identity")
                .is_some_and(Value::is_string)
            {
                add_if_string(value, path, entered, "/agent_identity", out);
            } else {
                add_if_string(
                    value,
                    path,
                    entered,
                    "/agent_identity/agent_private_key",
                    out,
                );
            }
        },
    );
    inspect_at(
        found,
        &root.join(".credentials.json"),
        home,
        default,
        |value, path, entered, out| {
            let Some(entries) = value.as_object() else {
                return;
            };
            for (name, entry) in entries {
                let Some(entry) = entry.as_object() else {
                    continue;
                };
                if !["server_name", "server_url", "client_id", "access_token"]
                    .iter()
                    .all(|field| entry.get(*field).is_some_and(Value::is_string))
                    || !matches!(
                        entry.get("refresh_token"),
                        None | Some(Value::Null) | Some(Value::String(_))
                    )
                {
                    continue;
                }
                add_dynamic(
                    entry.get("access_token"),
                    path,
                    entered,
                    &[name, "access_token"],
                    out,
                );
                add_dynamic(
                    entry.get("refresh_token"),
                    path,
                    entered,
                    &[name, "refresh_token"],
                    out,
                );
            }
        },
    );
}

fn opencode(found: &mut Found, environment: &Environment, home: Option<&Path>, base: &Path) {
    let root = match path_override(found, environment, "XDG_DATA_HOME", base) {
        Override::Path(path) => (path.join("opencode"), false),
        Override::Absent => match home {
            Some(home) => (home.join(".local/share/opencode"), true),
            None => return,
        },
        Override::Unavailable => return,
    };
    inspect_at(
        found,
        &root.0.join("auth.json"),
        home,
        root.1,
        opencode_auth_sources,
    );
    inspect_at(
        found,
        &root.0.join("mcp-auth.json"),
        home,
        root.1,
        opencode_mcp_auth_sources,
    );
}

fn opencode_auth_sources(value: &Value, path: &Path, entered: &str, out: &mut Vec<SourceRef>) {
    let Some(providers) = value.as_object() else {
        return;
    };
    for (provider, entry) in providers {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let fields: &[&str] = match entry.get("type").and_then(Value::as_str) {
            Some("api")
                if has_nonempty_string(entry, "key") && optional_string_map(entry, "metadata") =>
            {
                &["key"]
            }
            Some("oauth")
                if has_string(entry, "refresh")
                    && has_string(entry, "access")
                    && entry.get("expires").and_then(Value::as_u64).is_some()
                    && optional_string(entry, "accountId")
                    && optional_string(entry, "enterpriseUrl") =>
            {
                &["refresh", "access"]
            }
            Some("wellknown") if has_string(entry, "key") && has_string(entry, "token") => {
                &["token"]
            }
            _ => continue,
        };
        for field in fields {
            add_dynamic(entry.get(*field), path, entered, &[provider, field], out);
        }
    }
}

fn opencode_mcp_auth_sources(value: &Value, path: &Path, entered: &str, out: &mut Vec<SourceRef>) {
    let Some(entries) = value.as_object() else {
        return;
    };
    if !entries.values().all(|entry| {
        let Some(entry) = entry.as_object() else {
            return false;
        };
        optional_object(entry, "tokens", |tokens| {
            has_string(tokens, "accessToken") && optional_string(tokens, "refreshToken")
        }) && optional_object(entry, "clientInfo", |client| {
            has_string(client, "clientId") && optional_string(client, "clientSecret")
        }) && optional_string(entry, "codeVerifier")
            && optional_string(entry, "oauthState")
            && optional_string(entry, "serverUrl")
    }) {
        return;
    }
    direct_paths(
        value,
        path,
        entered,
        &[
            &["tokens", "accessToken"],
            &["tokens", "refreshToken"],
            &["clientInfo", "clientSecret"],
            &["codeVerifier"],
        ],
        out,
    );
}

fn copilot(found: &mut Found, environment: &Environment, home: Option<&Path>, base: &Path) {
    let Some((root, default)) = rooted(found, environment, "COPILOT_HOME", home, ".copilot", base)
    else {
        return;
    };
    inspect_at(
        found,
        &root.join("config.json"),
        home,
        default,
        |value, path, entered, out| {
            let Some(tokens) = value.get("copilotTokens").and_then(Value::as_object) else {
                return;
            };
            for (name, value) in tokens {
                add_dynamic(Some(value), path, entered, &["copilotTokens", name], out);
            }
        },
    );
    let directory = root.join("mcp-oauth-config");
    if !std::fs::symlink_metadata(&directory).is_ok_and(|metadata| metadata.is_dir()) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let discover = if name.strip_suffix(".tokens.json").is_some_and(is_hex64) {
            copilot_mcp_tokens_sources as fn(&Value, &Path, &str, &mut Vec<SourceRef>)
        } else if name.strip_suffix(".json").is_some_and(is_hex64) {
            copilot_mcp_client_sources
        } else {
            continue;
        };
        inspect_at(found, &path, home, default, discover);
    }
}

fn copilot_mcp_tokens_sources(value: &Value, path: &Path, entered: &str, out: &mut Vec<SourceRef>) {
    let Some(tokens) = value.as_object() else {
        return;
    };
    if !has_string(tokens, "access_token")
        || !optional_string(tokens, "refresh_token")
        || !optional_string(tokens, "id_token")
    {
        return;
    }
    for field in ["access_token", "refresh_token", "id_token"] {
        add_if_string(value, path, entered, &format!("/{field}"), out);
    }
}

fn copilot_mcp_client_sources(value: &Value, path: &Path, entered: &str, out: &mut Vec<SourceRef>) {
    let Some(client) = value.as_object() else {
        return;
    };
    if !has_string(client, "client_id") || !optional_string(client, "client_secret") {
        return;
    }
    add_if_string(value, path, entered, "/client_secret", out);
}

fn has_string(object: &serde_json::Map<String, Value>, field: &str) -> bool {
    object.get(field).is_some_and(Value::is_string)
}

fn has_nonempty_string(object: &serde_json::Map<String, Value>, field: &str) -> bool {
    object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
}

fn optional_string(object: &serde_json::Map<String, Value>, field: &str) -> bool {
    object.get(field).is_none_or(Value::is_string)
}

fn optional_string_map(object: &serde_json::Map<String, Value>, field: &str) -> bool {
    object.get(field).is_none_or(|value| {
        value
            .as_object()
            .is_some_and(|values| values.values().all(Value::is_string))
    })
}

fn optional_object(
    object: &serde_json::Map<String, Value>,
    field: &str,
    valid: impl FnOnce(&serde_json::Map<String, Value>) -> bool,
) -> bool {
    object
        .get(field)
        .is_none_or(|value| value.as_object().is_some_and(valid))
}

fn claude_machine(found: &mut Found, environment: &Environment, home: Option<&Path>, base: &Path) {
    let override_root = match path_override(found, environment, "CLAUDE_CONFIG_DIR", base) {
        Override::Path(path) => Some(path),
        Override::Absent => None,
        Override::Unavailable => return,
    };
    let Some(root) = override_root
        .clone()
        .or_else(|| home.map(|home| home.join(".claude")))
    else {
        return;
    };
    let default = override_root.is_none();
    #[cfg(not(target_os = "macos"))]
    inspect_at(
        found,
        &root.join(".credentials.json"),
        home,
        default,
        |value, path, entered, out| {
            for pointer in ["/claudeAiOauth/accessToken", "/claudeAiOauth/refreshToken"] {
                add_if_string(value, path, entered, pointer, out);
            }
            direct_fields(
                value,
                path,
                entered,
                "/mcpOAuth",
                &["accessToken", "refreshToken", "clientSecret"],
                out,
            );
            direct_fields(
                value,
                path,
                entered,
                "/mcpOAuthClientConfig",
                &["clientSecret"],
                out,
            );
        },
    );
    inspect_at(
        found,
        &root.join("settings.json"),
        home,
        default,
        settings_sources,
    );
    let state = override_root.map_or_else(
        || home.expect("root required home").join(".claude.json"),
        |root| root.join(".claude.json"),
    );
    inspect_at(found, &state, home, default, |value, path, entered, out| {
        direct_fields(
            value,
            path,
            entered,
            "/mcpOAuth",
            &["accessToken", "refreshToken", "clientSecret"],
            out,
        );
        direct_fields(
            value,
            path,
            entered,
            "/mcpOAuthClientConfig",
            &["clientSecret"],
            out,
        );
        mcp_server_sources(value, path, entered, out);
    });
}

fn settings_sources(value: &Value, path: &Path, entered: &str, out: &mut Vec<SourceRef>) {
    for name in CLAUDE_ENV {
        add_if_string(value, path, entered, &format!("/env/{name}"), out);
    }
}

fn mcp_server_sources(value: &Value, path: &Path, entered: &str, out: &mut Vec<SourceRef>) {
    let Some(servers) = value.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (server_name, server) in servers {
        if let Some(headers) = server.get("headers").and_then(Value::as_object) {
            for (name, value) in headers {
                if MCP_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                    add_dynamic(
                        Some(value),
                        path,
                        entered,
                        &["mcpServers", server_name, "headers", name],
                        out,
                    );
                }
            }
        }
        if let Some(env) = server.get("env").and_then(Value::as_object) {
            for name in MCP_ENV {
                add_dynamic(
                    env.get(name),
                    path,
                    entered,
                    &["mcpServers", server_name, "env", name],
                    out,
                );
            }
            for name in CLAUDE_ENV {
                add_dynamic(
                    env.get(name),
                    path,
                    entered,
                    &["mcpServers", server_name, "env", name],
                    out,
                );
            }
        }
    }
}

fn direct_fields(
    value: &Value,
    path: &Path,
    entered: &str,
    prefix: &str,
    fields: &[&str],
    out: &mut Vec<SourceRef>,
) {
    let selected = if prefix.is_empty() {
        Some(value)
    } else {
        value.pointer(prefix)
    };
    let Some(entries) = selected.and_then(Value::as_object) else {
        return;
    };
    for (name, entry) in entries {
        for field in fields {
            let mut tokens = Vec::new();
            if !prefix.is_empty() {
                tokens.extend(prefix[1..].split('/'));
            }
            tokens.extend([name.as_str(), *field]);
            add_dynamic(entry.get(*field), path, entered, &tokens, out);
        }
    }
}

fn direct_paths(
    value: &Value,
    path: &Path,
    entered: &str,
    fields: &[&[&str]],
    out: &mut Vec<SourceRef>,
) {
    let Some(entries) = value.as_object() else {
        return;
    };
    for (name, entry) in entries {
        for suffix in fields {
            let mut tokens = vec![name.as_str()];
            tokens.extend_from_slice(suffix);
            let selected = suffix
                .iter()
                .try_fold(entry, |current, token| current.get(*token));
            add_dynamic(selected, path, entered, &tokens, out);
        }
    }
}

fn add_if_string(
    value: &Value,
    path: &Path,
    entered: &str,
    pointer: &str,
    out: &mut Vec<SourceRef>,
) {
    if value
        .pointer(pointer)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        add_source(path, entered, pointer.to_string(), out);
    }
}

fn add_dynamic(
    value: Option<&Value>,
    path: &Path,
    entered: &str,
    tokens: &[&str],
    out: &mut Vec<SourceRef>,
) {
    if !value
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        return;
    }
    let pointer = tokens
        .iter()
        .map(|token| json::encode_token(token))
        .collect::<Vec<_>>()
        .join("/");
    add_source(path, entered, format!("/{pointer}"), out);
}

fn add_source(path: &Path, entered: &str, pointer: String, out: &mut Vec<SourceRef>) {
    let Ok(token) = json::final_token(&pointer) else {
        return;
    };
    out.push(SourceRef::Json {
        entered: entered.into(),
        path: path.to_path_buf(),
        pointer,
        token,
    });
}

fn inspect_at<F>(found: &mut Found, path: &Path, home: Option<&Path>, default: bool, discover: F)
where
    F: FnOnce(&Value, &Path, &str, &mut Vec<SourceRef>),
{
    let entered = if default {
        home_entry(home, path)
    } else {
        path.to_str().map(str::to_string)
    };
    inspect(found, path, entered, discover);
}

fn inspect<F>(found: &mut Found, path: &Path, entered: Option<String>, discover: F)
where
    F: FnOnce(&Value, &Path, &str, &mut Vec<SourceRef>),
{
    let Some(entered) = entered else {
        found.notices.push(Notice {
            display: sanitize::path(path),
            reason: "its path is not valid UTF-8",
        });
        return;
    };
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            found.notices.push(Notice {
                display: sanitize::path(path),
                reason: "it could not be read",
            });
            return;
        }
    }
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            found.notices.push(Notice {
                display: sanitize::path(path),
                reason: "it could not be read",
            });
            return;
        }
    };
    match file.metadata() {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            found.notices.push(Notice {
                display: sanitize::path(path),
                reason: "it could not be read",
            });
            return;
        }
    }
    let mut bytes = Vec::new();
    match file.read_to_end(&mut bytes) {
        Ok(_) => {}
        Err(_) => {
            found.notices.push(Notice {
                display: sanitize::path(path),
                reason: "it could not be read",
            });
            return;
        }
    }
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            found.notices.push(Notice {
                display: sanitize::path(path),
                reason: "it is not valid UTF-8",
            });
            return;
        }
    };
    match json::parse(&text) {
        Ok(value) => discover(&value, path, &entered, &mut found.sources),
        Err(_) => found.notices.push(Notice {
            display: sanitize::path(path),
            reason: "it is malformed JSON",
        }),
    }
}

fn rooted(
    found: &mut Found,
    environment: &Environment,
    variable: &str,
    home: Option<&Path>,
    fallback: &str,
    base: &Path,
) -> Option<(PathBuf, bool)> {
    match path_override(found, environment, variable, base) {
        Override::Path(path) => Some((path, false)),
        Override::Absent => home.map(|home| (home.join(fallback), true)),
        Override::Unavailable => None,
    }
}

enum Override {
    Absent,
    Path(PathBuf),
    Unavailable,
}

fn path_override(
    found: &mut Found,
    environment: &Environment,
    name: &str,
    base: &Path,
) -> Override {
    match environment.get(name) {
        None => Override::Absent,
        Some(value) => match value.to_str() {
            Some("") => Override::Absent,
            Some(value) => Override::Path(explicit_path(value, base)),
            None => {
                found.notices.push(Notice {
                    display: name.to_string(),
                    reason: "its override is not valid UTF-8",
                });
                Override::Unavailable
            }
        },
    }
}

fn explicit_path(value: &str, base: &Path) -> PathBuf {
    let path = Path::new(value);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    paths::normalize(&absolute)
}

fn home_entry(home: Option<&Path>, path: &Path) -> Option<String> {
    let home = home?;
    path.strip_prefix(home)
        .ok()?
        .to_str()
        .map(|tail| format!("~/{tail}"))
}

fn project_entry(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root).ok()?.to_str().map(str::to_string)
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn deduplicate(sources: &mut Vec<SourceRef>) {
    let mut seen = HashSet::new();
    sources.retain(|source| seen.insert(source.id()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Canary, assert_canary_absent};

    struct Tree(PathBuf);

    impl Tree {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "contextveil-known-source-{}-{}",
                std::process::id(),
                crate::testing::Canary::generate("KNOWN").token()
            ));
            std::fs::create_dir_all(&path).expect("fixture root");
            Self(path)
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("directories");
            std::fs::write(&path, contents).expect("fixture file");
            path
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pointers(found: &Found) -> Vec<String> {
        found
            .sources
            .iter()
            .filter_map(|source| match source {
                SourceRef::Json { pointer, .. } => Some(pointer.clone()),
                SourceRef::Env { name } => Some(format!("env:{name}")),
                _ => None,
            })
            .collect()
    }

    fn machine_pointers(tree: &Tree) -> Vec<String> {
        let home = tree.0.join("home");
        let environment = Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
        pointers(&machine(&environment, Some(&home), &tree.0))
    }

    fn assert_found_is_canary_free(found: &Found, canary: &Canary) {
        let source_metadata = format!("{:?}", found.sources);
        assert_canary_absent(
            "Known Source SourceRef metadata",
            source_metadata.as_bytes(),
            canary,
        );
        let source_ids = found.sources.iter().map(SourceRef::id).collect::<Vec<_>>();
        let config_metadata = format!("{source_ids:?}");
        assert_canary_absent(
            "Known Source config-facing identities",
            config_metadata.as_bytes(),
            canary,
        );
        for notice in &found.notices {
            assert_canary_absent(
                "Known Source notice path",
                notice.display.as_bytes(),
                canary,
            );
            assert_canary_absent(
                "Known Source notice reason",
                notice.reason.as_bytes(),
                canary,
            );
        }
    }

    fn default_environment(tree: &Tree) -> (PathBuf, Environment) {
        let home = tree.0.join("home");
        let environment = Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
        (home, environment)
    }

    #[test]
    fn lowercase_hash_names_are_pinned() {
        assert!(is_hex64(&"a".repeat(64)));
        assert!(!is_hex64(&"A".repeat(64)));
        assert!(!is_hex64(&"a".repeat(63)));
    }

    #[test]
    fn explicit_overrides_are_literal_normalized_paths() {
        assert_eq!(
            explicit_path("~/../stores", Path::new("/project")),
            PathBuf::from("/project/stores")
        );
        assert_eq!(
            explicit_path("sub/../stores", Path::new("/project")),
            PathBuf::from("/project/stores")
        );
    }

    #[test]
    fn codex_schema_matrix_recognizes_primary_and_fallback_tokens_only() {
        let tree = Tree::new();
        tree.write("home/.codex/auth.json", r#"{"OPENAI_API_KEY":"a","tokens":{"access_token":"b"},"agent_identity":{"agent_private_key":"c"},"ignored":"d"}"#);
        tree.write(
            "home/.codex/.credentials.json",
            r#"{
                "valid":{"server_name":"server","server_url":"https://example.test","client_id":"client","access_token":"d","refresh_token":"e","metadata":{"ignored":true}},
                "without_refresh":{"server_name":"server","server_url":"https://example.test","client_id":"client","access_token":"f"},
                "null_refresh":{"server_name":"server","server_url":"https://example.test","client_id":"client","access_token":"g","refresh_token":null},
                "incomplete":{"server_name":"server","access_token":"h"},
                "wrong_type":{"server_name":"server","server_url":"https://example.test","client_id":7,"access_token":"i"},
                "bad_refresh":{"server_name":"server","server_url":"https://example.test","client_id":"client","access_token":"j","refresh_token":7}
            }"#,
        );
        let home = tree.0.join("home");
        let environment = Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
        let found = machine(&environment, Some(&home), &tree.0);
        let pointers = pointers(&found);
        for expected in [
            "/OPENAI_API_KEY",
            "/tokens/access_token",
            "/agent_identity/agent_private_key",
            "/valid/access_token",
            "/valid/refresh_token",
            "/without_refresh/access_token",
            "/null_refresh/access_token",
        ] {
            assert!(
                pointers.iter().any(|pointer| pointer == expected),
                "missing {expected}: {pointers:?}"
            );
        }
        for rejected in [
            "/ignored",
            "/incomplete/access_token",
            "/wrong_type/access_token",
            "/bad_refresh/access_token",
        ] {
            assert!(
                !pointers.iter().any(|pointer| pointer == rejected),
                "accepted {rejected}"
            );
        }
        assert!(found.notices.is_empty());
    }

    #[test]
    fn opencode_auth_schema_matrix_is_pinned() {
        let tree = Tree::new();
        tree.write(
            "home/.local/share/opencode/auth.json",
            r#"{
                "api":{"type":"api","key":"api-canary","metadata":{"region":"test"},"nearbySecret":"ignored"},
                "oauth":{"type":"oauth","refresh":"refresh-canary","access":"access-canary","expires":0,"accountId":"account","enterpriseUrl":"https://example.test","token":"ignored"},
                "wellknown":{"type":"wellknown","key":"identifier","token":"token-canary","access":"ignored"},
                "incomplete_api":{"type":"api"},
                "empty_api":{"type":"api","key":""},
                "incomplete_oauth":{"type":"oauth","refresh":"refresh-canary","access":"access-canary"},
                "incomplete_wellknown":{"type":"wellknown","token":"token-canary"},
                "wrong_metadata":{"type":"api","key":"api-canary","metadata":{"region":7}},
                "wrong_expires":{"type":"oauth","refresh":"refresh-canary","access":"access-canary","expires":-1},
                "wrong_optional":{"type":"oauth","refresh":"refresh-canary","access":"access-canary","expires":1,"accountId":7},
                "unknown":{"type":"future","key":"ignored","token":"ignored"}
            }"#,
        );
        assert_eq!(
            machine_pointers(&tree),
            vec![
                "/api/key",
                "/oauth/refresh",
                "/oauth/access",
                "/wellknown/token",
            ]
        );
    }

    #[test]
    fn opencode_auth_valid_no_match_and_unknown_fields_do_not_match() {
        let tree = Tree::new();
        tree.write(
            "home/.local/share/opencode/auth.json",
            r#"{
                "oauth":{"type":"oauth","refresh":"","access":"","expires":12,"extraToken":"ignored"},
                "wellknown":{"type":"wellknown","key":"identifier","token":"","secret":"ignored"},
                "unknown":{"type":"future","key":"ignored"}
            }"#,
        );
        assert!(machine_pointers(&tree).is_empty());
    }

    #[test]
    fn opencode_mcp_auth_schema_matrix_is_all_or_nothing() {
        let tree = Tree::new();
        let path = "home/.local/share/opencode/mcp-auth.json";
        tree.write(
            path,
            r#"{
                "srv/name":{"tokens":{"accessToken":"access-canary","refreshToken":"refresh-canary","nearby":"ignored"},"clientInfo":{"clientId":"client","clientSecret":"secret-canary","nearby":"ignored"},"codeVerifier":"verifier-canary","oauthState":"state-is-not-a-credential","serverUrl":"https://example.test","accessToken":"ignored"},
                "optional":{"unknown":{"clientSecret":"ignored"}}
            }"#,
        );
        assert_eq!(
            machine_pointers(&tree),
            vec![
                "/srv~1name/tokens/accessToken",
                "/srv~1name/tokens/refreshToken",
                "/srv~1name/clientInfo/clientSecret",
                "/srv~1name/codeVerifier",
            ]
        );

        tree.write(
            path,
            r#"{"valid":{"tokens":{"accessToken":"access-canary"}},"incomplete":{"tokens":{"refreshToken":"refresh-canary"}}}"#,
        );
        assert!(machine_pointers(&tree).is_empty());

        tree.write(
            path,
            r#"{"valid":{"tokens":{"accessToken":"access-canary"}},"wrong":{"clientInfo":{"clientId":7}}}"#,
        );
        assert!(machine_pointers(&tree).is_empty());

        tree.write(
            path,
            r#"{"no-match":{"oauthState":"state","serverUrl":"https://example.test","unknown":{"accessToken":"ignored"}}}"#,
        );
        assert!(machine_pointers(&tree).is_empty());

        tree.write(path, r#"[{"tokens":{"accessToken":"access-canary"}}]"#);
        assert!(machine_pointers(&tree).is_empty());
    }

    #[test]
    fn copilot_schema_matrix_recognizes_primary_and_hashed_mcp_fields_only() {
        let tree = Tree::new();
        tree.write(
            "home/.copilot/config.json",
            r#"{"copilotTokens":{"github.com":"n"},"token":"o"}"#,
        );
        let hash = "a".repeat(64);
        tree.write(
            &format!("home/.copilot/mcp-oauth-config/{hash}.tokens.json"),
            r#"{"access_token":"p","unknown":"q"}"#,
        );
        tree.write(
            "home/.copilot/mcp-oauth-config/not-a-hash.tokens.json",
            r#"{"access_token":"rejected"}"#,
        );
        let home = tree.0.join("home");
        let environment = Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
        assert_eq!(
            pointers(&machine(&environment, Some(&home), &tree.0)),
            vec!["/copilotTokens/github.com", "/access_token"]
        );
    }

    #[test]
    fn copilot_mcp_tokens_schema_matrix_rejects_the_whole_file() {
        let tree = Tree::new();
        let hash = "b".repeat(64);
        let path = format!("home/.copilot/mcp-oauth-config/{hash}.tokens.json");
        tree.write(
            &path,
            r#"{"access_token":"access-canary","refresh_token":"refresh-canary","id_token":"id-canary","nearby_secret":"ignored"}"#,
        );
        assert_eq!(
            machine_pointers(&tree),
            vec!["/access_token", "/refresh_token", "/id_token"]
        );

        tree.write(&path, r#"{"refresh_token":"refresh-canary"}"#);
        assert!(machine_pointers(&tree).is_empty());

        tree.write(
            &path,
            r#"{"access_token":"access-canary","refresh_token":7}"#,
        );
        assert!(machine_pointers(&tree).is_empty());

        tree.write(
            &path,
            r#"{"access_token":"","refresh_token":"","id_token":"","token":"ignored"}"#,
        );
        assert!(machine_pointers(&tree).is_empty());

        tree.write(&path, r#"["access-canary"]"#);
        assert!(machine_pointers(&tree).is_empty());
    }

    #[test]
    fn copilot_mcp_client_schema_matrix_recognizes_only_client_secret() {
        let tree = Tree::new();
        let hash = "c".repeat(64);
        let path = format!("home/.copilot/mcp-oauth-config/{hash}.json");
        tree.write(
            &path,
            r#"{"client_id":"client-canary","client_secret":"secret-canary","access_token":"ignored"}"#,
        );
        assert_eq!(machine_pointers(&tree), vec!["/client_secret"]);

        tree.write(&path, r#"{"client_secret":"secret-canary"}"#);
        assert!(machine_pointers(&tree).is_empty());

        tree.write(&path, r#"{"client_id":"client-canary","client_secret":7}"#);
        assert!(machine_pointers(&tree).is_empty());

        tree.write(
            &path,
            r#"{"client_id":"client-canary","nearby_secret":"ignored"}"#,
        );
        assert!(machine_pointers(&tree).is_empty());

        tree.write(&path, r#"["client-canary"]"#);
        assert!(machine_pointers(&tree).is_empty());
    }

    #[test]
    fn claude_schema_matrix_recognizes_platform_primary_and_mcp_fields_only() {
        let tree = Tree::new();
        tree.write(
            "home/.claude/.credentials.json",
            r#"{"claudeAiOauth":{"accessToken":"r"},"mcpOAuth":{"srv":{"clientSecret":"s"}}}"#,
        );
        tree.write(
            "home/.claude/settings.json",
            r#"{"env":{"ANTHROPIC_API_KEY":"t","RANDOM_TOKEN":"u"}}"#,
        );
        tree.write(
            "home/.claude.json",
            r#"{"mcpOAuthClientConfig":{"srv":{"clientSecret":"v"}}}"#,
        );
        let environment = Environment::from_pairs([
            ("HOME", tree.0.join("home").to_string_lossy().into_owned()),
            ("OPENCODE_AUTH_CONTENT", "whole".to_string()),
        ]);
        let found = machine(&environment, Some(&tree.0.join("home")), &tree.0);
        let pointers = pointers(&found);
        for expected in [
            "/env/ANTHROPIC_API_KEY",
            "/mcpOAuthClientConfig/srv/clientSecret",
            "env:OPENCODE_AUTH_CONTENT",
        ] {
            assert!(
                pointers.iter().any(|pointer| pointer == expected),
                "missing {expected}: {pointers:?}"
            );
        }
        #[cfg(not(target_os = "macos"))]
        for expected in ["/claudeAiOauth/accessToken", "/mcpOAuth/srv/clientSecret"] {
            assert!(
                pointers.iter().any(|pointer| pointer == expected),
                "missing {expected}: {pointers:?}"
            );
        }
        #[cfg(target_os = "macos")]
        for keychain_only in ["/claudeAiOauth/accessToken", "/mcpOAuth/srv/clientSecret"] {
            assert!(
                !pointers.iter().any(|pointer| pointer == keychain_only),
                "macOS must not discover keychain-backed primary fields: {pointers:?}"
            );
        }
        assert!(
            !pointers
                .iter()
                .any(|pointer| pointer == "/env/RANDOM_TOKEN")
        );
        assert!(found.notices.is_empty());
    }

    #[test]
    fn unrepresentable_dynamic_pointer_tokens_are_skipped_without_panicking() {
        let tree = Tree::new();
        tree.write(
            "home/.copilot/config.json",
            r#"{"copilotTokens":{"*":"value","":"value"}}"#,
        );
        let home = tree.0.join("home");
        let environment = Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
        let found = machine(&environment, Some(&home), &tree.0);
        assert!(found.sources.is_empty());
        assert!(found.notices.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn codex_filesystem_matrix_covers_primary_mcp_override_and_failure_boundaries() {
        let tree = Tree::new();
        let canary = Canary::generate("CODEX_MATRIX");
        let target = tree.write(
            "targets/codex-auth.json",
            &format!(
                r#"{{"OPENAI_API_KEY":"{}","unrelated":"ignored"}}"#,
                canary.value()
            ),
        );
        std::fs::create_dir_all(tree.0.join("home/.codex")).expect("Codex root");
        std::os::unix::fs::symlink(&target, tree.0.join("home/.codex/auth.json"))
            .expect("Codex exact-file symlink");
        tree.write(
            "home/.codex/.credentials.json",
            &format!(
                r#"{{"server":{{"server_name":"server","server_url":"https://example.test","client_id":"client","access_token":"{}"}}}}"#,
                canary.value()
            ),
        );
        tree.write(
            "home/unrelated/auth.json",
            &format!(r#"{{"OPENAI_API_KEY":"{}"}}"#, canary.value()),
        );
        let (home, environment) = default_environment(&tree);
        let found = machine(&environment, Some(&home), &tree.0);
        assert_eq!(
            pointers(&found),
            vec!["/OPENAI_API_KEY", "/server/access_token"]
        );
        assert!(found.notices.is_empty());
        assert_found_is_canary_free(&found, &canary);

        std::fs::remove_file(tree.0.join("home/.codex/auth.json")).expect("remove symlink");
        tree.write("home/.codex/auth.json", r#"{"ordinary":"value"}"#);
        tree.write("home/.codex/.credentials.json", "{");
        let found = machine(&environment, Some(&home), &tree.0);
        assert!(found.sources.is_empty());
        assert_eq!(found.notices.len(), 1);
        assert_found_is_canary_free(&found, &canary);

        tree.write(
            "override/codex/auth.json",
            &format!(r#"{{"tokens":{{"access_token":"{}"}}}}"#, canary.value()),
        );
        let override_environment = Environment::from_pairs([
            ("HOME", home.to_string_lossy().into_owned()),
            (
                "CODEX_HOME",
                tree.0.join("override/codex").to_string_lossy().into_owned(),
            ),
        ]);
        let found = machine(&override_environment, Some(&home), &tree.0);
        assert!(pointers(&found).contains(&"/tokens/access_token".to_string()));
        assert_found_is_canary_free(&found, &canary);
    }

    #[test]
    #[cfg(unix)]
    fn opencode_filesystem_matrix_covers_primary_mcp_override_and_failure_boundaries() {
        let tree = Tree::new();
        let canary = Canary::generate("OPENCODE_MATRIX");
        let target = tree.write(
            "targets/opencode-auth.json",
            &format!(
                r#"{{"provider":{{"type":"api","key":"{}","ignored":"nearby"}}}}"#,
                canary.value()
            ),
        );
        std::fs::create_dir_all(tree.0.join("home/.local/share/opencode")).expect("OpenCode root");
        std::os::unix::fs::symlink(&target, tree.0.join("home/.local/share/opencode/auth.json"))
            .expect("OpenCode exact-file symlink");
        tree.write(
            "home/.local/share/opencode/mcp-auth.json",
            &format!(
                r#"{{"server":{{"tokens":{{"accessToken":"{}"}}}}}}"#,
                canary.value()
            ),
        );
        tree.write(
            "home/unrelated/mcp-auth.json",
            &format!(
                r#"{{"server":{{"tokens":{{"accessToken":"{}"}}}}}}"#,
                canary.value()
            ),
        );
        let (home, environment) = default_environment(&tree);
        let found = machine(&environment, Some(&home), &tree.0);
        assert_eq!(
            pointers(&found),
            vec!["/provider/key", "/server/tokens/accessToken"]
        );
        assert!(found.notices.is_empty());
        assert_found_is_canary_free(&found, &canary);

        std::fs::remove_file(tree.0.join("home/.local/share/opencode/auth.json"))
            .expect("remove symlink");
        tree.write(
            "home/.local/share/opencode/auth.json",
            r#"{"provider":{"type":"future","key":"value"}}"#,
        );
        tree.write("home/.local/share/opencode/mcp-auth.json", "{");
        let found = machine(&environment, Some(&home), &tree.0);
        assert!(found.sources.is_empty());
        assert_eq!(found.notices.len(), 1);
        assert_found_is_canary_free(&found, &canary);

        tree.write(
            "override/data/opencode/auth.json",
            &format!(
                r#"{{"provider":{{"type":"api","key":"{}"}}}}"#,
                canary.value()
            ),
        );
        let override_environment = Environment::from_pairs([
            ("HOME", home.to_string_lossy().into_owned()),
            (
                "XDG_DATA_HOME",
                tree.0.join("override/data").to_string_lossy().into_owned(),
            ),
        ]);
        let found = machine(&override_environment, Some(&home), &tree.0);
        assert!(pointers(&found).contains(&"/provider/key".to_string()));
        assert_found_is_canary_free(&found, &canary);
    }

    #[test]
    #[cfg(unix)]
    fn copilot_filesystem_matrix_covers_primary_mcp_override_and_failure_boundaries() {
        let tree = Tree::new();
        let canary = Canary::generate("COPILOT_MATRIX");
        let target = tree.write(
            "targets/copilot-config.json",
            &format!(
                r#"{{"copilotTokens":{{"github.com":"{}"}},"unrelated":"ignored"}}"#,
                canary.value()
            ),
        );
        std::fs::create_dir_all(tree.0.join("home/.copilot/mcp-oauth-config"))
            .expect("Copilot MCP root");
        std::os::unix::fs::symlink(&target, tree.0.join("home/.copilot/config.json"))
            .expect("Copilot exact-file symlink");
        let hash = "a".repeat(64);
        tree.write(
            &format!("home/.copilot/mcp-oauth-config/{hash}.tokens.json"),
            &format!(
                r#"{{"access_token":"{}","unrelated":"ignored"}}"#,
                canary.value()
            ),
        );
        tree.write(
            "home/unrelated/config.json",
            &format!(
                r#"{{"copilotTokens":{{"github.com":"{}"}}}}"#,
                canary.value()
            ),
        );
        let (home, environment) = default_environment(&tree);
        let found = machine(&environment, Some(&home), &tree.0);
        assert_eq!(
            pointers(&found),
            vec!["/copilotTokens/github.com", "/access_token"]
        );
        assert!(found.notices.is_empty());
        assert_found_is_canary_free(&found, &canary);

        std::fs::remove_file(tree.0.join("home/.copilot/config.json")).expect("remove symlink");
        tree.write(
            "home/.copilot/config.json",
            r#"{"copilotTokens":{"github.com":7}}"#,
        );
        tree.write(
            &format!("home/.copilot/mcp-oauth-config/{hash}.tokens.json"),
            "{",
        );
        let found = machine(&environment, Some(&home), &tree.0);
        assert!(found.sources.is_empty());
        assert_eq!(found.notices.len(), 1);
        assert_found_is_canary_free(&found, &canary);

        tree.write(
            "override/copilot/config.json",
            &format!(
                r#"{{"copilotTokens":{{"github.com":"{}"}}}}"#,
                canary.value()
            ),
        );
        let override_environment = Environment::from_pairs([
            ("HOME", home.to_string_lossy().into_owned()),
            (
                "COPILOT_HOME",
                tree.0
                    .join("override/copilot")
                    .to_string_lossy()
                    .into_owned(),
            ),
        ]);
        let found = machine(&override_environment, Some(&home), &tree.0);
        assert!(pointers(&found).contains(&"/copilotTokens/github.com".to_string()));
        assert_found_is_canary_free(&found, &canary);
    }

    #[test]
    #[cfg(unix)]
    fn claude_filesystem_matrix_covers_platform_primary_mcp_override_and_failure_boundaries() {
        let tree = Tree::new();
        let canary = Canary::generate("CLAUDE_MATRIX");
        let settings_target = tree.write(
            "targets/claude-settings.json",
            &format!(
                r#"{{"env":{{"ANTHROPIC_API_KEY":"{}","UNRELATED":"ignored"}}}}"#,
                canary.value()
            ),
        );
        std::fs::create_dir_all(tree.0.join("home/.claude")).expect("Claude root");
        std::os::unix::fs::symlink(&settings_target, tree.0.join("home/.claude/settings.json"))
            .expect("Claude exact-file symlink");
        tree.write(
            "home/.claude/.credentials.json",
            &format!(
                r#"{{"claudeAiOauth":{{"accessToken":"{}"}}}}"#,
                canary.value()
            ),
        );
        tree.write(
            "home/.claude.json",
            &format!(
                r#"{{"mcpOAuth":{{"server":{{"clientSecret":"{}"}}}},"unrelated":"ignored"}}"#,
                canary.value()
            ),
        );
        tree.write(
            "home/unrelated/settings.json",
            &format!(r#"{{"env":{{"ANTHROPIC_API_KEY":"{}"}}}}"#, canary.value()),
        );
        let (home, environment) = default_environment(&tree);
        let found = machine(&environment, Some(&home), &tree.0);
        let found_pointers = pointers(&found);
        assert!(found_pointers.contains(&"/env/ANTHROPIC_API_KEY".to_string()));
        assert!(found_pointers.contains(&"/mcpOAuth/server/clientSecret".to_string()));
        #[cfg(not(target_os = "macos"))]
        assert!(found_pointers.contains(&"/claudeAiOauth/accessToken".to_string()));
        #[cfg(target_os = "macos")]
        assert!(!found_pointers.contains(&"/claudeAiOauth/accessToken".to_string()));
        assert!(found.notices.is_empty());
        assert_found_is_canary_free(&found, &canary);

        std::fs::remove_file(tree.0.join("home/.claude/settings.json")).expect("remove symlink");
        tree.write(
            "home/.claude/settings.json",
            r#"{"env":{"UNRELATED":"value"}}"#,
        );
        tree.write("home/.claude.json", "{");
        let found = machine(&environment, Some(&home), &tree.0);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(pointers(&found), vec!["/claudeAiOauth/accessToken"]);
        #[cfg(target_os = "macos")]
        assert!(found.sources.is_empty());
        assert_eq!(found.notices.len(), 1);
        assert_found_is_canary_free(&found, &canary);

        tree.write(
            "override/claude/settings.json",
            &format!(
                r#"{{"env":{{"ANTHROPIC_AUTH_TOKEN":"{}"}}}}"#,
                canary.value()
            ),
        );
        let override_environment = Environment::from_pairs([
            ("HOME", home.to_string_lossy().into_owned()),
            (
                "CLAUDE_CONFIG_DIR",
                tree.0
                    .join("override/claude")
                    .to_string_lossy()
                    .into_owned(),
            ),
        ]);
        let found = machine(&override_environment, Some(&home), &tree.0);
        assert!(pointers(&found).contains(&"/env/ANTHROPIC_AUTH_TOKEN".to_string()));
        assert_found_is_canary_free(&found, &canary);
    }

    #[test]
    fn overrides_are_resolved_at_discovery_time_and_persist_explicit_paths() {
        let tree = Tree::new();
        tree.write(
            "project/stores/codex/auth.json",
            r#"{"OPENAI_API_KEY":"value"}"#,
        );
        tree.write(
            "project/stores/open/opencode/auth.json",
            r#"{"p":{"type":"api","key":"value"}}"#,
        );
        tree.write(
            "project/stores/copilot/config.json",
            r#"{"copilotTokens":{"p":"value"}}"#,
        );
        tree.write(
            "project/stores/claude/settings.json",
            r#"{"env":{"ANTHROPIC_API_KEY":"value"}}"#,
        );
        let environment = Environment::from_pairs([
            ("CODEX_HOME", "stores/codex"),
            ("XDG_DATA_HOME", "stores/open"),
            ("COPILOT_HOME", "stores/copilot"),
            ("CLAUDE_CONFIG_DIR", "stores/claude"),
        ]);
        let found = machine(&environment, None, &tree.0.join("project"));
        assert_eq!(found.sources.len(), 4);
        assert!(found.sources.iter().all(|source| match source {
            SourceRef::Json { entered, path, .. } => {
                entered == &path.to_string_lossy()
                    && path.starts_with(tree.0.join("project/stores"))
                    && !entered.contains('~')
            }
            _ => false,
        }));
    }

    #[test]
    fn valid_no_match_is_silent_but_invalid_matched_json_is_noticed() {
        let tree = Tree::new();
        tree.write("home/.codex/auth.json", r#"{"unrelated":"value"}"#);
        tree.write("home/.local/share/opencode/auth.json", "{");
        tree.write("home/.copilot/config.json", r#"{"copilotTokens":{"x":1}}"#);
        let home = tree.0.join("home");
        let environment = Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
        let found = machine(&environment, Some(&home), &tree.0);
        assert!(found.sources.is_empty());
        assert_eq!(found.notices.len(), 1);
        assert!(found.notices[0].display.ends_with("opencode/auth.json"));
        assert_eq!(found.notices[0].reason, "it is malformed JSON");
    }

    #[test]
    fn project_matches_use_relative_paths_and_exact_mcp_names() {
        let tree = Tree::new();
        let settings = tree.write(
            "project/app/.claude/settings.json",
            r#"{"env":{"CLAUDE_CODE_OAUTH_TOKEN":"a","OTHER_TOKEN":"b"}}"#,
        );
        let mcp = tree.write("project/app/.mcp.json", r#"{"mcpServers":{"srv/a":{"headers":{"authorization":"c","Cookie":"d"},"env":{"TOKEN":"e","TOKEN_FILE":"f"}}}}"#);
        let files = ProjectFiles {
            dotenv: vec![],
            claude_settings: vec![settings],
            claude_mcp: vec![mcp],
        };
        let found = project(&tree.0.join("project"), &files);
        let pointers = pointers(&found);
        assert_eq!(
            pointers,
            vec![
                "/env/CLAUDE_CODE_OAUTH_TOKEN",
                "/mcpServers/srv~1a/headers/authorization",
                "/mcpServers/srv~1a/env/TOKEN",
            ]
        );
        assert!(found.sources.iter().all(|source| match source {
            SourceRef::Json { entered, .. } => entered.starts_with("app/"),
            _ => false,
        }));
    }

    #[test]
    fn claude_user_state_uses_the_same_narrow_mcp_server_fields() {
        let tree = Tree::new();
        tree.write("home/.claude.json", r#"{"mcpServers":{"srv":{"headers":{"X-Api-Key":"a","Cookie":"b"},"env":{"CLIENT_SECRET":"c","CLIENT_ID":"d"}}}}"#);
        let home = tree.0.join("home");
        let environment = Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
        assert_eq!(
            pointers(&machine(&environment, Some(&home), &tree.0)),
            vec![
                "/mcpServers/srv/headers/X-Api-Key",
                "/mcpServers/srv/env/CLIENT_SECRET",
            ]
        );
    }

    #[test]
    #[cfg(unix)]
    fn unreadable_matched_json_produces_a_safe_notice() {
        use std::os::unix::fs::PermissionsExt;
        let tree = Tree::new();
        let path = tree.write(
            "home/.codex/auth.json",
            r#"{"OPENAI_API_KEY":"never reported"}"#,
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("permissions");
        if std::fs::read(&path).is_err() {
            let home = tree.0.join("home");
            let environment =
                Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
            let found = machine(&environment, Some(&home), &tree.0);
            assert!(found.sources.is_empty());
            assert_eq!(found.notices.len(), 1);
            assert_eq!(found.notices[0].reason, "it could not be read");
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    #[test]
    #[cfg(unix)]
    fn exact_machine_fifo_and_symlink_to_fifo_are_skipped_promptly() {
        let tree = Tree::new();
        let fifo = tree.0.join("home/.codex/auth.json");
        std::fs::create_dir_all(fifo.parent().expect("FIFO parent")).expect("Codex root");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(status.success());

        let symlink = tree.0.join("home/.local/share/opencode/auth.json");
        std::fs::create_dir_all(symlink.parent().expect("symlink parent")).expect("OpenCode root");
        std::os::unix::fs::symlink(&fifo, &symlink).expect("symlink to FIFO");

        let (home, environment) = default_environment(&tree);
        let started = std::time::Instant::now();
        let found = machine(&environment, Some(&home), &tree.0);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "Known Source discovery attempted to open a FIFO"
        );
        assert!(found.sources.is_empty());
        assert!(found.notices.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn copilot_mcp_oauth_directory_symlink_is_not_traversed() {
        let tree = Tree::new();
        let canary = Canary::generate("COPILOT_DIRECTORY_SYMLINK");
        let hash = "d".repeat(64);
        tree.write(
            &format!("outside/{hash}.tokens.json"),
            &format!(r#"{{"access_token":"{}"}}"#, canary.value()),
        );
        std::fs::create_dir_all(tree.0.join("home/.copilot")).expect("Copilot root");
        std::os::unix::fs::symlink(
            tree.0.join("outside"),
            tree.0.join("home/.copilot/mcp-oauth-config"),
        )
        .expect("directory symlink");

        let (home, environment) = default_environment(&tree);
        let found = machine(&environment, Some(&home), &tree.0);
        assert!(found.sources.is_empty());
        assert!(found.notices.is_empty());
        assert_found_is_canary_free(&found, &canary);
    }

    #[test]
    #[cfg(unix)]
    fn exact_machine_symlinks_are_followed_but_project_symlinks_are_not_walked() {
        let tree = Tree::new();
        let target = tree.write("target.json", r#"{"OPENAI_API_KEY":"value"}"#);
        std::fs::create_dir_all(tree.0.join("home/.codex")).expect("codex directory");
        std::os::unix::fs::symlink(target, tree.0.join("home/.codex/auth.json"))
            .expect("file symlink");
        let home = tree.0.join("home");
        let environment = Environment::from_pairs([("HOME", home.to_string_lossy().into_owned())]);
        assert_eq!(machine(&environment, Some(&home), &tree.0).sources.len(), 1);

        tree.write(
            "outside/.claude/settings.json",
            r#"{"env":{"ANTHROPIC_API_KEY":"value"}}"#,
        );
        std::fs::create_dir_all(tree.0.join("project")).expect("project");
        std::os::unix::fs::symlink(tree.0.join("outside"), tree.0.join("project/linked"))
            .expect("directory symlink");
        let walked = super::super::discovery::project_files(&tree.0.join("project"));
        assert!(walked.claude_settings.is_empty());
    }
}
