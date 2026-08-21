//! Name gating and advisory ranking for setup candidates.
//!
//! `SET-006` fixes the V1 vocabulary exactly. Format, entropy, length, and source
//! type may rank or explain a name-gated candidate but must never introduce one.
//! Credential-bearing URLs are the bounded value-shape exception in `SET-017`.
//! Vocabulary changes are observable setup behavior and must update the
//! specification and its fixtures in the same change.

/// Whole tokens that gate a name.
const EXACT_TOKENS: [&str; 8] = [
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "key",
    "credential",
    "credentials",
];

/// Suffixes of the compact form that gate a name.
const COMPACT_SUFFIXES: [&str; 13] = [
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "credentials",
    "apikey",
    "accesskey",
    "privatekey",
    "clientsecret",
    "authtoken",
    "refreshtoken",
];

/// Why a candidate is shown or ranked, in user-facing wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// The ordinary gating reason.
    NameMatches(&'static str),
    /// The bounded whole-value exception in `SET-017`.
    CredentialBearingUrl,
    /// Admission by one of the closed coding-agent Known Source definitions.
    KnownSource,
    /// Advisory only (`SET-006`).
    LongValue,
    HighVariety,
    LooksEncoded,
}

impl Signal {
    pub fn describe(&self) -> String {
        match self {
            Signal::NameMatches(term) => format!("name contains `{term}`"),
            Signal::CredentialBearingUrl => "credential-bearing URL".to_string(),
            Signal::KnownSource => "Known Source".to_string(),
            Signal::LongValue => "long value".to_string(),
            Signal::HighVariety => "mixed character classes".to_string(),
            Signal::LooksEncoded => "encoded-looking value".to_string(),
        }
    }
}

/// Returns the vocabulary term that gates `name`, if any.
///
/// Matching uses ASCII case folding. The name is split into tokens at every run
/// of non-ASCII-alphanumeric characters, and a compact form is built by removing
/// those separators. Characters outside ASCII are preserved for display but do
/// not match the vocabulary.
pub fn gating_term(name: &str) -> Option<&'static str> {
    let folded: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();

    let mut tokens: Vec<String> = Vec::new();
    let mut compact = String::new();
    let mut current = String::new();
    for character in folded {
        if character.is_ascii_alphanumeric() {
            current.push(character);
            compact.push(character);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    for term in EXACT_TOKENS {
        if tokens.iter().any(|token| token == term) {
            return Some(term);
        }
    }
    // Longest suffix first so `refreshtoken` explains itself rather than
    // reporting the shorter `token`.
    let mut suffixes = COMPACT_SUFFIXES;
    suffixes.sort_by_key(|suffix| std::cmp::Reverse(suffix.len()));
    suffixes
        .into_iter()
        .find(|suffix| compact.ends_with(suffix))
}

/// Advisory signals used to rank an already-gated candidate.
pub fn value_signals(value: &str) -> Vec<Signal> {
    let mut signals = Vec::new();
    let length = value.chars().count();
    if length >= 24 {
        signals.push(Signal::LongValue);
    }

    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let classes = [has_lower, has_upper, has_digit]
        .into_iter()
        .filter(|present| *present)
        .count();
    if classes >= 3 {
        signals.push(Signal::HighVariety);
    }

    let encoded_shape = length >= 16
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_' | '.'));
    if encoded_shape {
        signals.push(Signal::LooksEncoded);
    }
    signals
}

/// Ranking score for an admitted candidate. Higher sorts first.
pub fn rank(signals: &[Signal]) -> u32 {
    signals
        .iter()
        .map(|signal| match signal {
            Signal::NameMatches(_) => 4,
            Signal::CredentialBearingUrl => 4,
            Signal::KnownSource => 4,
            Signal::LongValue => 2,
            Signal::HighVariety => 2,
            Signal::LooksEncoded => 1,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_tokens_gate_a_name() {
        for name in [
            "GITHUB_TOKEN",
            "api-key",
            "MY.SECRET.VALUE",
            "db password",
            "PASSWD_FILE",
            "user_passphrase_1",
            "AWS_CREDENTIAL",
            "credentials",
            "KEY",
        ] {
            assert!(gating_term(name).is_some(), "`{name}` should be gated");
        }
    }

    #[test]
    fn compact_suffixes_gate_a_name() {
        for (name, expected) in [
            ("GITHUBAPIKEY", "apikey"),
            ("myAccessKey", "accesskey"),
            ("service_private_key", "key"),
            ("SomePrivateKey", "privatekey"),
            ("client-secret", "secret"),
            ("OAUTH_REFRESH_TOKEN", "token"),
        ] {
            assert_eq!(gating_term(name), Some(expected), "for `{name}`");
        }
        // A compact suffix with no separate token still gates.
        assert_eq!(gating_term("stripeapikey"), Some("apikey"));
        assert_eq!(gating_term("myrefreshtoken"), Some("refreshtoken"));
        assert_eq!(gating_term("appclientsecret"), Some("clientsecret"));
    }

    #[test]
    fn unrelated_names_are_not_gated() {
        for name in [
            "PATH",
            "HOME",
            "EDITOR",
            "DATABASE_URL",
            "keyboard_layout",
            "TOKENIZER",
            "monkey",
            "keys",
        ] {
            assert_eq!(gating_term(name), None, "`{name}` should not be gated");
        }
    }

    #[test]
    fn gating_is_ascii_case_insensitive_only() {
        assert_eq!(gating_term("Github_Token"), Some("token"));
        assert_eq!(gating_term("gitHUB_tOkEn"), Some("token"));
        // Non-ASCII characters act as separators and never match themselves.
        assert_eq!(gating_term("TÖKEN"), None);
        assert_eq!(gating_term("secret✓"), Some("secret"));
        assert_eq!(gating_term("prefix✓token"), Some("token"));
    }

    #[test]
    fn advisory_value_shape_does_not_change_name_gating() {
        // Bounded exceptions such as SET-017 are applied outside the vocabulary.
        assert_eq!(gating_term("DATABASE_URL"), None);
        assert!(!value_signals("aGVsbG8gd29ybGQgZXhhbXBsZQ==").is_empty());
    }

    #[test]
    fn signals_describe_why_a_candidate_ranks_higher() {
        let signals = value_signals("aB3aB3aB3aB3aB3aB3aB3aB3aB3");
        assert!(signals.contains(&Signal::LongValue));
        assert!(signals.contains(&Signal::HighVariety));
        assert!(signals.contains(&Signal::LooksEncoded));
        assert!(rank(&signals) > rank(&value_signals("short")));
    }

    #[test]
    fn signal_descriptions_never_include_the_value() {
        for signal in value_signals("aB3aB3aB3aB3aB3aB3aB3aB3aB3") {
            assert!(!signal.describe().contains("aB3"));
        }
    }
}
