//! Strict JSON parsing and exact RFC 6901 pointer selection (`SRC-011`).
//!
//! Object members are checked while deserializing because parsing directly into
//! `serde_json::Value` would discard duplicate names before they can be rejected.

use std::collections::HashSet;
use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

const DUPLICATE_MARKER: &str = "contextveil duplicate object member";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Malformed,
    DuplicateMember,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerError {
    Invalid,
    EmptyFinalToken,
    Wildcard,
}

/// Encodes one object member name as an RFC 6901 reference token.
pub fn encode_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Validates a plain RFC 6901 pointer and returns its decoded final token.
pub fn final_token(pointer: &str) -> Result<String, PointerError> {
    if !pointer.starts_with('/') {
        return Err(PointerError::Invalid);
    }

    let mut final_token = None;
    for encoded in pointer[1..].split('/') {
        let token = decode_token(encoded)?;
        if token == "*" {
            return Err(PointerError::Wildcard);
        }
        final_token = Some(token);
    }

    match final_token {
        Some(token) if !token.is_empty() => Ok(token),
        _ => Err(PointerError::EmptyFinalToken),
    }
}

/// Parses one complete JSON document, rejecting duplicate members at any depth.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    serde_json::from_str::<StrictValue>(text)
        .map(|value| value.0)
        .map_err(|error| {
            if error.to_string().contains(DUPLICATE_MARKER) {
                ParseError::DuplicateMember
            } else {
                ParseError::Malformed
            }
        })
}

/// Selects exactly one value using an already validated pointer.
pub fn select<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    let mut selected = value;
    for encoded in pointer[1..].split('/') {
        let token = decode_token(encoded).ok()?;
        selected = match selected {
            Value::Object(object) => object.get(&token)?,
            Value::Array(array) => {
                let bytes = token.as_bytes();
                let valid_index = token == "0"
                    || (matches!(bytes.first(), Some(b'1'..=b'9'))
                        && bytes[1..].iter().all(u8::is_ascii_digit));
                if !valid_index {
                    return None;
                }
                array.get(token.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(selected)
}

fn decode_token(encoded: &str) -> Result<String, PointerError> {
    let mut decoded = String::with_capacity(encoded.len());
    let mut characters = encoded.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => return Err(PointerError::Invalid),
        }
    }
    Ok(decoded)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = HashSet::new();
        let mut values = Map::new();
        while let Some(name) = object.next_key::<String>()? {
            if !names.insert(name.clone()) {
                return Err(serde::de::Error::custom(DUPLICATE_MARKER));
            }
            values.insert(name, object.next_value::<StrictValue>()?.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointers_are_validated_and_final_tokens_are_decoded() {
        assert_eq!(
            final_token("/tokens/access_token"),
            Ok("access_token".into())
        );
        assert_eq!(final_token("/a~1b/~0key"), Ok("~key".into()));
        for pointer in ["", "#/*", "a/b", "/", "/a/", "/a/~2b"] {
            assert!(final_token(pointer).is_err(), "accepted {pointer:?}");
        }
        assert_eq!(final_token("/tokens/*"), Err(PointerError::Wildcard));
    }

    #[test]
    fn reference_tokens_are_encoded_in_rfc6901_order() {
        assert_eq!(encode_token("plain"), "plain");
        assert_eq!(encode_token("a/b"), "a~1b");
        assert_eq!(encode_token("a~b/c"), "a~0b~1c");
        assert_eq!(
            final_token(&format!("/{}", encode_token("a~b/c"))),
            Ok("a~b/c".into())
        );
    }

    #[test]
    fn exact_selection_handles_objects_arrays_and_escaping() {
        let value = parse(r#"{"a/b":{"~key":["zero","one"]}}"#).expect("valid JSON");
        assert_eq!(
            select(&value, "/a~1b/~0key/1"),
            Some(&Value::String("one".into()))
        );
        for token in ["01", "+1", "+01", "-1", "-", "", "999999999999999999999"] {
            assert_eq!(select(&value, &format!("/a~1b/~0key/{token}")), None);
        }
        assert_eq!(
            select(&value, "/a~1b/~0key/0"),
            Some(&Value::String("zero".into()))
        );
        assert_eq!(select(&value, "/missing"), None);
    }

    #[test]
    fn duplicate_members_at_every_depth_are_rejected() {
        assert_eq!(parse(r#"{"a":1,"a":2}"#), Err(ParseError::DuplicateMember));
        assert_eq!(
            parse(r#"{"selected":"ok","other":{"x":1,"x":2}}"#),
            Err(ParseError::DuplicateMember)
        );
    }

    #[test]
    fn malformed_and_trailing_input_are_rejected() {
        assert_eq!(parse("{"), Err(ParseError::Malformed));
        assert_eq!(parse("{} trailing"), Err(ParseError::Malformed));
    }
}
