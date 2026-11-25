//! A small, format-neutral document tree.
//!
//! YAML plain scalars keep their exact source text, so a `short-id: 1e5` or a
//! `password: 0123` is never silently turned into a number. Typed accessors
//! interpret the text only when a field asks for a number or a boolean, the
//! same way mihomo's decoder does for typed struct fields.

use serde_json::Value as Json;

/// A document node.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`, `~` or an empty plain scalar.
    Null,
    /// A scalar. `quoted` is true for quoted YAML scalars and JSON strings.
    Scalar { text: String, quoted: bool },
    /// A sequence.
    Seq(Vec<Value>),
    /// A mapping, in source order.
    Map(Map),
}

/// An ordered mapping with string keys.
pub type Map = Vec<(String, Value)>;

impl Value {
    /// A quoted string scalar.
    pub fn str(s: impl Into<String>) -> Self {
        Value::Scalar {
            text: s.into(),
            quoted: true,
        }
    }
    /// A plain (unquoted) scalar, e.g. a number or a boolean.
    pub fn plain(s: impl Into<String>) -> Self {
        Value::Scalar {
            text: s.into(),
            quoted: false,
        }
    }
    pub fn int(n: i64) -> Self {
        Value::plain(n.to_string())
    }
    pub fn bool(b: bool) -> Self {
        Value::plain(if b { "true" } else { "false" })
    }
    pub fn seq_str<I: IntoIterator<Item = S>, S: Into<String>>(it: I) -> Self {
        Value::Seq(it.into_iter().map(Value::str).collect())
    }

    pub fn as_map(&self) -> Option<&Map> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_seq(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Seq(s) => Some(s),
            _ => None,
        }
    }
    /// Text of a scalar, whatever its type.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Scalar { text, .. } => Some(text),
            _ => None,
        }
    }
    /// A string field: any scalar, read as text.
    pub fn as_string(&self) -> Option<String> {
        self.as_text().map(str::to_string)
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    /// A boolean field. Accepts YAML 1.1 spellings and quoted forms, as mihomo does.
    pub fn as_bool(&self) -> Option<bool> {
        let t = self.as_text()?.trim();
        match t.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "y" | "1" => Some(true),
            "false" | "no" | "off" | "n" | "0" => Some(false),
            _ => None,
        }
    }
    /// An integer field. Accepts quoted numbers, `0x`/`0o` prefixes and `_` separators.
    pub fn as_i64(&self) -> Option<i64> {
        parse_int(self.as_text()?)
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.as_i64().and_then(|n| u64::try_from(n).ok())
    }
    pub fn as_f64(&self) -> Option<f64> {
        let t = self.as_text()?.trim();
        parse_int(t).map(|n| n as f64).or_else(|| t.parse().ok())
    }
    /// A list of strings: a sequence of scalars, or one scalar (optionally comma separated).
    pub fn as_str_list(&self) -> Vec<String> {
        match self {
            Value::Seq(s) => s.iter().filter_map(Value::as_string).collect(),
            Value::Scalar { text, .. } => text
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map().and_then(|m| get(m, key))
    }

    /// Converts to JSON, resolving plain scalars with YAML 1.2 core rules.
    pub fn to_json(&self) -> Json {
        match self {
            Value::Null => Json::Null,
            Value::Scalar { text, quoted: true } => Json::String(text.clone()),
            Value::Scalar { text, quoted: false } => resolve_plain(text),
            Value::Seq(s) => Json::Array(s.iter().map(Value::to_json).collect()),
            Value::Map(m) => Json::Object(m.iter().map(|(k, v)| (k.clone(), v.to_json())).collect()),
        }
    }

    /// Converts from JSON. Strings become quoted scalars; numbers and booleans plain ones.
    pub fn from_json(j: &Json) -> Value {
        match j {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::bool(*b),
            Json::Number(n) => Value::plain(n.to_string()),
            Json::String(s) => Value::str(s.clone()),
            Json::Array(a) => Value::Seq(a.iter().map(Value::from_json).collect()),
            Json::Object(o) => Value::Map(o.iter().map(|(k, v)| (k.clone(), Value::from_json(v))).collect()),
        }
    }
}

/// Case-sensitive key lookup.
pub fn get<'a>(m: &'a Map, key: &str) -> Option<&'a Value> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Removes and returns a key.
pub fn take(m: &mut Map, key: &str) -> Option<Value> {
    let i = m.iter().position(|(k, _)| k == key)?;
    Some(m.remove(i).1)
}

/// Sets a key, replacing an existing one in place.
pub fn set(m: &mut Map, key: &str, v: Value) {
    if let Some(slot) = m.iter_mut().find(|(k, _)| k == key) {
        slot.1 = v;
    } else {
        m.push((key.to_string(), v));
    }
}

pub(crate) fn parse_int(t: &str) -> Option<i64> {
    let t = t.trim().replace('_', "");
    let (neg, body) = match t.strip_prefix('-') {
        Some(b) => (true, b.to_string()),
        None => (false, t.strip_prefix('+').unwrap_or(&t).to_string()),
    };
    let n = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else if let Some(o) = body.strip_prefix("0o") {
        i64::from_str_radix(o, 8).ok()?
    } else if !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) {
        body.parse().ok()?
    } else {
        return None;
    };
    Some(if neg { -n } else { n })
}

fn resolve_plain(t: &str) -> Json {
    match t {
        "" | "~" | "null" | "Null" | "NULL" => return Json::Null,
        "true" | "True" | "TRUE" => return Json::Bool(true),
        "false" | "False" | "FALSE" => return Json::Bool(false),
        _ => {}
    }
    if let Some(n) = parse_int(t) {
        return Json::from(n);
    }
    if looks_float(t)
        && let Ok(f) = t.parse::<f64>()
        && let Some(n) = serde_json::Number::from_f64(f)
    {
        return Json::Number(n);
    }
    Json::String(t.to_string())
}

/// YAML 1.2 core float syntax (without .inf/.nan).
pub(crate) fn looks_float(t: &str) -> bool {
    let b = t.strip_prefix(['-', '+']).unwrap_or(t);
    if b.is_empty() {
        return false;
    }
    let (mant, exp) = match b.find(['e', 'E']) {
        Some(i) => (&b[..i], Some(&b[i + 1..])),
        None => (b, None),
    };
    let digits_dot = !mant.is_empty()
        && mant.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && mant.bytes().filter(|&c| c == b'.').count() <= 1
        && mant.bytes().any(|c| c.is_ascii_digit());
    let exp_ok = match exp {
        None => true,
        Some(e) => {
            let e = e.strip_prefix(['-', '+']).unwrap_or(e);
            !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit())
        }
    };
    digits_dot && exp_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_accessors() {
        assert_eq!(Value::str("443").as_u64(), Some(443));
        assert_eq!(Value::plain("0x1bb").as_i64(), Some(443));
        assert_eq!(Value::str("yes").as_bool(), Some(true));
        assert_eq!(Value::plain("1e5").as_string().as_deref(), Some("1e5"));
        assert_eq!(Value::plain("1e5").to_json(), serde_json::json!(100000.0));
        assert_eq!(Value::plain("0123abcd").to_json(), serde_json::json!("0123abcd"));
        assert_eq!(Value::str("a, b").as_str_list(), vec!["a", "b"]);
    }
}
