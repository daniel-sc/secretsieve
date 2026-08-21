//! Setup-only recognition of credential-bearing URL values (`SET-017`).

use url::Url;

/// Whether the complete value is an absolute hierarchical URL with an
/// authority and a non-empty password in userinfo.
pub fn is_credential_bearing(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    !url.cannot_be_a_base()
        && url.has_authority()
        && url.password().is_some_and(|password| !password.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Canary;

    #[test]
    fn database_registry_and_proxy_urls_are_recognized() {
        let canary = Canary::generate("URL_PASSWORD");
        for value in [
            format!("postgresql://app:{}@db.example.test/app", canary.value()),
            format!(
                "https://publisher:{}@registry.example.test/package",
                canary.value()
            ),
            format!(
                "http://proxy-user:{}@proxy.example.test:8080",
                canary.value()
            ),
        ] {
            assert!(is_credential_bearing(&value), "URL should qualify");
        }
    }

    #[test]
    fn non_credential_url_shapes_are_rejected() {
        let canary = Canary::generate("URL_PASSWORD");
        for value in [
            format!("//user:{}@example.test/path", canary.value()),
            format!("scheme:user:{}@example.test", canary.value()),
            "https://example.test/path".to_string(),
            "https://user@example.test/path".to_string(),
            "https://user:@example.test/path".to_string(),
        ] {
            assert!(!is_credential_bearing(&value), "URL should not qualify");
        }
    }
}
