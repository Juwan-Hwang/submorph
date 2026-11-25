//! Structured diagnostics: every dropped, approximated or repaired item is reported.

use std::fmt;

/// How serious a diagnostic is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Input was repaired or normalised; output meaning is unchanged.
    Info,
    /// Output differs from the input (approximated or partly dropped).
    Warning,
    /// An item was dropped entirely.
    Error,
}

/// What happened to the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Input was malformed and repaired.
    Repaired,
    /// Item could not be parsed and was skipped.
    Invalid,
    /// Target cannot express the item; it was dropped.
    Unsupported,
    /// Target expresses the item approximately.
    Approximated,
    /// A field was dropped but the item kept.
    FieldDropped,
    /// Item renamed (e.g. duplicate name).
    Renamed,
}

/// One diagnostic.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub kind: Kind,
    /// Where: `proxy "HK 01"`, `group "Auto"`, `rule #12`, `dns`, `input line 3`.
    pub location: String,
    /// Optional field name.
    pub field: Option<String>,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        let kind = match self.kind {
            Kind::Repaired => "repaired",
            Kind::Invalid => "invalid",
            Kind::Unsupported => "unsupported",
            Kind::Approximated => "approximated",
            Kind::FieldDropped => "field dropped",
            Kind::Renamed => "renamed",
        };
        write!(f, "{sev}[{kind}] {}", self.location)?;
        if let Some(field) = &self.field {
            write!(f, " `{field}`")?;
        }
        write!(f, ": {}", self.message)
    }
}

impl Diagnostic {
    /// JSON form for machine consumers.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "severity": format!("{:?}", self.severity).to_lowercase(),
            "kind": format!("{:?}", self.kind),
            "location": self.location,
            "field": self.field,
            "message": self.message,
        })
    }
}

/// A collector passed through parsing and emitting.
#[derive(Debug, Default, Clone)]
pub struct Diagnostics {
    pub items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn push(
        &mut self,
        severity: Severity,
        kind: Kind,
        location: impl Into<String>,
        field: Option<&str>,
        message: impl Into<String>,
    ) {
        self.items.push(Diagnostic {
            severity,
            kind,
            location: location.into(),
            field: field.map(str::to_string),
            message: message.into(),
        });
    }
    pub fn info(
        &mut self,
        kind: Kind,
        loc: impl Into<String>,
        field: Option<&str>,
        msg: impl Into<String>,
    ) {
        self.push(Severity::Info, kind, loc, field, msg)
    }
    pub fn warn(
        &mut self,
        kind: Kind,
        loc: impl Into<String>,
        field: Option<&str>,
        msg: impl Into<String>,
    ) {
        self.push(Severity::Warning, kind, loc, field, msg)
    }
    pub fn error(
        &mut self,
        kind: Kind,
        loc: impl Into<String>,
        field: Option<&str>,
        msg: impl Into<String>,
    ) {
        self.push(Severity::Error, kind, loc, field, msg)
    }
    pub fn extend(&mut self, other: Diagnostics) {
        self.items.extend(other.items)
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
}

/// `proxy "name"` location helper.
pub fn proxy_loc(name: &str) -> String {
    format!("proxy {name:?}")
}
/// `group "name"` location helper.
pub fn group_loc(name: &str) -> String {
    format!("group {name:?}")
}
/// `rule #n` location helper (1-based).
pub fn rule_loc(i: usize, raw: &str) -> String {
    format!("rule #{} ({raw})", i + 1)
}
