//! JSON read the way Vector's serde reads Control content, so the bridge,
//! Armada and Vector accept the same editions (Armada's `strictJson.ts`).
//!
//! `serde_json::Value` keeps the last of a repeated key silently, where a serde
//! struct — what Vector reads Roster content into — refuses the whole object.
//! Reading through `Value` would let one edition mean different things to
//! different clients, so this parser marks every object that repeated a key
//! and the readers refuse it where Vector's structs would. Lone surrogates and
//! nesting past 128 already fail in `serde_json` itself, as in serde.
//! Integer fields are judged by `Value`'s own number kinds: `1.0` and `1e2`
//! are floats there, exactly as `as_u64` sees them in Vector.

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// The key a parsed object carries when its source repeated a key. A NUL can't
/// begin a key anyone writes on purpose, and readers never look it up by name.
const REPEATED: &str = "\u{0}repeated";

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(Value::Number(v.into())))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(Value::Number(v.into())))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
        Ok(Strict(Number::from_f64(v).map_or(Value::Null, Value::Number)))
    }
    fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.to_owned())))
    }
    fn visit_string<E>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Strict(Value::Array(out)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut out = Map::new();
        let mut repeated = false;
        while let Some(k) = map.next_key::<String>()? {
            let Strict(v) = map.next_value()?;
            repeated |= out.insert(k, v).is_some();
        }
        if repeated {
            out.insert(REPEATED.into(), Value::Bool(true));
        }
        Ok(Strict(Value::Object(out)))
    }
}

/// Any JSON value as serde's `Value` reads it; objects that repeated a key are
/// marked (see [`repeated_keys`]). `None` where serde_json fails outright.
pub fn parse_value(content: &str) -> Option<Value> {
    serde_json::from_str::<Strict>(content).ok().map(|s| s.0)
}

/// Whether `v` is an object whose source repeated a key: what a serde struct refuses.
pub fn repeated_keys(v: &Value) -> bool {
    v.as_object().is_some_and(|m| m.contains_key(REPEATED))
}

/// An object, or `None` when serde wouldn't read it into a struct: not an
/// object, or a key repeated at its top level.
pub fn parse_object(content: &str) -> Option<Map<String, Value>> {
    match parse_value(content)? {
        Value::Object(m) if !m.contains_key(REPEATED) => Some(m),
        _ => None,
    }
}

/// An array of strings, as serde's `Vec<String>` reads one.
pub fn parse_string_array(content: &str) -> Option<Vec<String>> {
    let v: Vec<String> = serde_json::from_str(content).ok()?;
    Some(v)
}

/// The object's fields other than the repeat marker, for round-tripping unknown ones.
pub fn fields(m: &Map<String, Value>) -> impl Iterator<Item = (&String, &Value)> {
    m.iter().filter(|(k, _)| k.as_str() != REPEATED)
}

/// Absent or `null`, as serde reads an `Option`.
pub fn none(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Null))
}

/// An integer literal within `0..=max`; floats and exponent forms are not integers.
pub fn uint(v: &Value, max: u64) -> Option<u64> {
    v.as_u64().filter(|n| *n <= max)
}

/// CORD-04 §3 permission bits: a decimal string (digits only, leading zeros
/// allowed, at most 2^64 − 1) or a JSON integer in range.
pub fn permission_bits(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            let trimmed = s.trim_start_matches('0');
            if trimmed.is_empty() { Some(0) } else { trimmed.parse().ok() }
        }
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_key_refuses_the_object_but_not_the_value() {
        assert!(parse_object(r#"{"a":1,"a":2}"#).is_none());
        let v = parse_value(r#"{"a":1,"a":2}"#).unwrap();
        assert!(repeated_keys(&v));
        assert!(parse_object(r#"{"a":{"b":1,"b":2}}"#).is_some(), "only the top level is a struct");
    }

    #[test]
    fn integers_are_literals() {
        let m = parse_object(r#"{"a":1,"b":1.0,"c":1e2}"#).unwrap();
        assert_eq!(uint(&m["a"], 9), Some(1));
        assert_eq!(uint(&m["b"], 9), None);
        assert_eq!(uint(&m["c"], 1000), None);
    }

    #[test]
    fn permission_bits_read_both_forms() {
        assert_eq!(permission_bits(&Value::String("0042".into())), Some(42));
        assert_eq!(permission_bits(&Value::String("18446744073709551615".into())), Some(u64::MAX));
        assert_eq!(permission_bits(&Value::String("18446744073709551616".into())), None);
        assert_eq!(permission_bits(&serde_json::json!(7)), Some(7));
        assert_eq!(permission_bits(&serde_json::json!(-1)), None);
        assert_eq!(permission_bits(&Value::String("".into())), None);
    }

    #[test]
    fn lone_surrogates_fail() {
        assert!(parse_value(r#""\ud800""#).is_none());
    }
}
