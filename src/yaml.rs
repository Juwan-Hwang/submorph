//! YAML loading and emitting on top of `saphyr-parser` events.
//!
//! The loader keeps plain scalars as source text (see [`crate::value`]),
//! resolves anchors, aliases and `<<` merge keys, and enforces limits on
//! nesting depth and alias expansion so hostile input cannot exhaust memory.

use crate::value::{Map, Value, looks_float, parse_int};
use saphyr_parser::{Event, Parser, ScalarStyle};
use std::collections::HashMap;

/// Resource limits for parsing.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum nesting depth of sequences and mappings.
    pub max_depth: usize,
    /// Maximum number of nodes after alias expansion.
    pub max_nodes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 256,
            max_nodes: 4_000_000,
        }
    }
}

/// A YAML parse error with a line number when known.
#[derive(Debug, Clone, PartialEq)]
pub struct YamlError {
    pub line: Option<usize>,
    pub message: String,
}

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(l) => write!(f, "line {l}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// Parses the first document of a YAML stream. Returns the value and
/// non-fatal warnings (duplicate keys, unsupported keys).
pub fn parse(src: &str, limits: Limits) -> Result<(Value, Vec<String>), YamlError> {
    let mut b = Builder {
        anchors: HashMap::new(),
        nodes: 0,
        limits,
        warnings: Vec::new(),
    };
    let parser = Parser::new_from_str(src);
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Value> = None;
    for ev in parser {
        let (ev, span) = ev.map_err(|e| YamlError {
            line: Some(e.marker().line()),
            message: e.info().to_string(),
        })?;
        let line = span.start.line();
        let done: Option<(Value, usize)> = match ev {
            Event::StreamStart | Event::Nothing | Event::DocumentStart(_) => None,
            Event::DocumentEnd | Event::StreamEnd => {
                if root.is_some() || matches!(ev, Event::StreamEnd) {
                    break;
                }
                None
            }
            Event::Alias(id) => {
                let v = b.anchors.get(&id).cloned().ok_or(YamlError {
                    line: Some(line),
                    message: "unknown alias".into(),
                })?;
                b.count(count_nodes(&v), line)?;
                Some((v, 0))
            }
            Event::Scalar(text, style, anchor, tag) => {
                b.count(1, line)?;
                let tag_suffix = tag.as_ref().map(|t| t.suffix.clone()).unwrap_or_default();
                let v = if style == ScalarStyle::Plain && tag.is_none() {
                    if matches!(&*text, "" | "~" | "null" | "Null" | "NULL") {
                        Value::Null
                    } else {
                        Value::plain(text.into_owned())
                    }
                } else if tag_suffix == "str" || style != ScalarStyle::Plain {
                    Value::str(text.into_owned())
                } else if tag_suffix == "null" {
                    Value::Null
                } else {
                    Value::plain(text.into_owned())
                };
                Some((v, anchor))
            }
            Event::SequenceStart(anchor, _) => {
                if stack.len() >= b.limits.max_depth {
                    return Err(YamlError {
                        line: Some(line),
                        message: format!("nesting deeper than {} levels", b.limits.max_depth),
                    });
                }
                b.count(1, line)?;
                stack.push(Frame::Seq(anchor, Vec::new()));
                None
            }
            Event::MappingStart(anchor, _) => {
                if stack.len() >= b.limits.max_depth {
                    return Err(YamlError {
                        line: Some(line),
                        message: format!("nesting deeper than {} levels", b.limits.max_depth),
                    });
                }
                b.count(1, line)?;
                stack.push(Frame::Map {
                    anchor,
                    entries: Vec::new(),
                    merges: Vec::new(),
                    key: None,
                });
                None
            }
            Event::SequenceEnd => match stack.pop() {
                Some(Frame::Seq(a, items)) => Some((Value::Seq(items), a)),
                _ => {
                    return Err(YamlError {
                        line: Some(line),
                        message: "unbalanced sequence".into(),
                    });
                }
            },
            Event::MappingEnd => match stack.pop() {
                Some(Frame::Map {
                    anchor,
                    mut entries,
                    merges,
                    ..
                }) => {
                    // Explicit keys win over merged ones, regardless of order.
                    for m in merges {
                        for (k, v) in m {
                            if !entries.iter().any(|(ek, _)| *ek == k) {
                                entries.push((k, v));
                            }
                        }
                    }
                    Some((Value::Map(entries), anchor))
                }
                _ => {
                    return Err(YamlError {
                        line: Some(line),
                        message: "unbalanced mapping".into(),
                    });
                }
            },
        };
        if let Some((v, anchor)) = done {
            if anchor > 0 {
                b.anchors.insert(anchor, v.clone());
            }
            match stack.last_mut() {
                None => {
                    if root.is_none() {
                        root = Some(v);
                    }
                }
                Some(Frame::Seq(_, items)) => items.push(v),
                Some(Frame::Map {
                    entries,
                    merges,
                    key,
                    ..
                }) => match key.take() {
                    None => {
                        let k = match &v {
                            Value::Scalar { text, .. } => KeyState::Key(text.clone()),
                            Value::Null => KeyState::Key(String::new()),
                            _ => KeyState::Complex,
                        };
                        *key = Some(k);
                    }
                    Some(KeyState::Complex) => {
                        b.warnings.push(format!(
                            "line {line}: ignored a mapping entry with a non-scalar key"
                        ));
                    }
                    Some(KeyState::Key(k)) => {
                        if k == "<<" {
                            match v {
                                Value::Map(m) => merges.push(m),
                                Value::Seq(s) => {
                                    for item in s {
                                        if let Value::Map(m) = item {
                                            merges.push(m);
                                        }
                                    }
                                }
                                _ => b.warnings.push(format!(
                                    "line {line}: ignored a `<<` merge of a non-mapping"
                                )),
                            }
                        } else if let Some(slot) = entries.iter_mut().find(|(ek, _)| *ek == k) {
                            b.warnings.push(format!(
                                "line {line}: duplicate key `{k}`, the last value is used"
                            ));
                            slot.1 = v;
                        } else {
                            entries.push((k, v));
                        }
                    }
                },
            }
        }
    }
    Ok((root.unwrap_or(Value::Null), b.warnings))
}

enum KeyState {
    Key(String),
    Complex,
}

enum Frame {
    Seq(usize, Vec<Value>),
    Map {
        anchor: usize,
        entries: Map,
        merges: Vec<Map>,
        key: Option<KeyState>,
    },
}

struct Builder {
    anchors: HashMap<usize, Value>,
    nodes: usize,
    limits: Limits,
    warnings: Vec<String>,
}

impl Builder {
    fn count(&mut self, n: usize, line: usize) -> Result<(), YamlError> {
        self.nodes = self.nodes.saturating_add(n);
        if self.nodes > self.limits.max_nodes {
            return Err(YamlError {
                line: Some(line),
                message: format!(
                    "document expands to more than {} nodes (alias bomb?)",
                    self.limits.max_nodes
                ),
            });
        }
        Ok(())
    }
}

fn count_nodes(v: &Value) -> usize {
    match v {
        Value::Seq(s) => 1 + s.iter().map(count_nodes).sum::<usize>(),
        Value::Map(m) => 1 + m.iter().map(|(_, v)| count_nodes(v)).sum::<usize>(),
        _ => 1,
    }
}

// ---------------------------------------------------------------- emitter

/// Serialises a value as block-style YAML.
pub fn to_string(v: &Value) -> String {
    let mut out = String::new();
    match v {
        Value::Map(m) if !m.is_empty() => emit_map(&mut out, m, 0),
        Value::Seq(s) if !s.is_empty() => emit_seq(&mut out, s, 0),
        other => {
            emit_inline(&mut out, other);
            out.push('\n');
        }
    }
    out
}

fn indent(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push(' ');
    }
}

fn emit_map(out: &mut String, m: &Map, ind: usize) {
    for (k, v) in m {
        indent(out, ind);
        emit_str(out, k);
        out.push(':');
        emit_child(out, v, ind);
    }
}

fn emit_seq(out: &mut String, s: &[Value], ind: usize) {
    for v in s {
        indent(out, ind);
        out.push('-');
        match v {
            Value::Map(m) if !m.is_empty() && is_flat(v) && m.len() <= 24 => {
                out.push(' ');
                emit_inline(out, v);
                out.push('\n');
            }
            Value::Map(m) if !m.is_empty() => {
                out.push(' ');
                // first entry on the dash line, the rest aligned under it
                let mut tmp = String::new();
                emit_map(&mut tmp, m, ind + 2);
                out.push_str(tmp.trim_start());
            }
            Value::Seq(inner) if !inner.is_empty() => {
                out.push('\n');
                emit_seq(out, inner, ind + 2);
            }
            other => {
                out.push(' ');
                emit_inline(out, other);
                out.push('\n');
            }
        }
    }
}

fn emit_child(out: &mut String, v: &Value, ind: usize) {
    match v {
        Value::Map(m) if !m.is_empty() => {
            out.push('\n');
            emit_map(out, m, ind + 2);
        }
        Value::Seq(s)
            if !s.is_empty()
                && !s
                    .iter()
                    .all(|x| matches!(x, Value::Scalar { .. } | Value::Null)) =>
        {
            out.push('\n');
            emit_seq(out, s, ind + 2);
        }
        other => {
            out.push(' ');
            emit_inline(out, other);
            out.push('\n');
        }
    }
}

fn is_flat(v: &Value) -> bool {
    match v {
        Value::Map(m) => m.iter().all(|(_, v)| match v {
            Value::Scalar { .. } | Value::Null => true,
            Value::Seq(s) => s.iter().all(|x| matches!(x, Value::Scalar { .. })),
            Value::Map(_) => false,
        }),
        _ => true,
    }
}

/// Flow-style emission (used for scalars, short lists and flat proxy maps).
fn emit_inline(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Scalar {
            text,
            quoted: false,
        } => {
            if plain_syntax_ok(text, true) {
                out.push_str(text)
            } else {
                quote(out, text)
            }
        }
        Value::Scalar { text, quoted: true } => emit_str_flow(out, text),
        Value::Seq(s) => {
            out.push('[');
            for (i, x) in s.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                emit_inline(out, x);
            }
            out.push(']');
        }
        Value::Map(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                emit_str_flow(out, k);
                out.push_str(": ");
                emit_inline(out, x);
            }
            out.push('}');
        }
    }
}

fn emit_str(out: &mut String, s: &str) {
    if plain_syntax_ok(s, false) && resolves_as_string(s) {
        out.push_str(s)
    } else {
        quote(out, s)
    }
}

fn emit_str_flow(out: &mut String, s: &str) {
    if plain_syntax_ok(s, true) && resolves_as_string(s) {
        out.push_str(s)
    } else {
        quote(out, s)
    }
}

/// Whether `s` can be written as a plain scalar without changing its text.
fn plain_syntax_ok(s: &str, flow: bool) -> bool {
    let Some(first) = s.chars().next() else {
        return false;
    };
    if s.starts_with(' ') || s.ends_with(' ') || s.ends_with(':') {
        return false;
    }
    if "-?:,[]{}#&*!|>'\"%@`".contains(first) {
        return false;
    }
    if s.contains(": ") || s.contains(" #") || s.contains('\t') {
        return false;
    }
    if s.chars().any(|c| {
        c.is_control() || c == '\u{feff}' || c == '\u{a0}' || c == '\u{2028}' || c == '\u{2029}'
    }) {
        return false;
    }
    if flow && s.contains([',', '[', ']', '{', '}', '?']) {
        return false;
    }
    true
}

/// Whether a plain scalar `s` is read back as a string by YAML 1.1 and 1.2 loaders.
fn resolves_as_string(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    if matches!(
        l.as_str(),
        "null"
            | "~"
            | "true"
            | "false"
            | "yes"
            | "no"
            | "on"
            | "off"
            | "y"
            | "n"
            | ".inf"
            | "-.inf"
            | "+.inf"
            | ".nan"
    ) {
        return false;
    }
    if parse_int(s).is_some() || looks_float(s) {
        return false;
    }
    // YAML 1.1 octal / sexagesimal / leading-zero numbers and timestamps
    let b = s.strip_prefix(['-', '+']).unwrap_or(s);
    if !b.is_empty()
        && b.bytes()
            .all(|c| c.is_ascii_digit() || c == b':' || c == b'.' || c == b'_' || c == b'-')
    {
        return false;
    }
    true
}

fn quote(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{feff}' => out.push_str("\\uFEFF"),
            '\u{a0}' => out.push_str("\\_"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Value {
        parse(s, Limits::default()).unwrap().0
    }

    #[test]
    fn keeps_plain_text() {
        let v = p("short-id: 1e5\npw: 0123\nq: '7'\n");
        assert_eq!(v.get("short-id"), Some(&Value::plain("1e5")));
        assert_eq!(v.get("pw").unwrap().as_string().unwrap(), "0123");
        assert_eq!(v.get("q"), Some(&Value::str("7")));
    }

    #[test]
    fn anchors_and_merge() {
        let v = p("base: &b {a: 1, b: 2}\nx:\n  <<: *b\n  b: 3\n");
        let x = v.get("x").unwrap();
        assert_eq!(x.get("a").unwrap().as_i64(), Some(1));
        assert_eq!(x.get("b").unwrap().as_i64(), Some(3));
    }

    #[test]
    fn alias_bomb_is_rejected() {
        let mut s = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            s.push_str(&format!("a{i}: &a{i} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n", p = i - 1));
        }
        assert!(parse(&s, Limits::default()).is_err());
    }

    #[test]
    fn depth_limit() {
        let s = "[".repeat(10_000);
        assert!(parse(&s, Limits::default()).is_err());
    }

    #[test]
    fn emitter_round_trips() {
        let src = "a: \"1e5\"\nb: 1e5\nc: yes\nd: 'yes'\ne: \"x: y\"\nf: [1, 'a,b']\ng:\n  - {name: \"n #1\", port: 443}\n  - k: v\n    l: [x]\n";
        let v = p(src);
        let out = to_string(&v);
        assert_eq!(p(&out), v, "{out}");
    }
}
