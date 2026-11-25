//! Input detection and parsing.
//!
//! [`parse`] accepts any supported subscription body and returns the IR plus
//! diagnostics. Detection order: HTML error pages, JSON (sing-box or Clash),
//! share-link lists, Clash/Mihomo YAML, then Base64-wrapped content (nested
//! up to three levels).

pub mod clash;
pub mod links;
pub mod singbox;

use crate::diag::{Diagnostics, Kind};
use crate::model::{Config, SourceFormat};
use crate::value::Value;
use crate::yaml;

/// Parser options.
#[derive(Debug, Clone)]
pub struct ParseOptions {
    /// Maximum input size in bytes (default 64 MiB).
    pub max_bytes: usize,
    pub yaml_limits: yaml::Limits,
}

impl Default for ParseOptions {
    fn default() -> Self {
        ParseOptions {
            max_bytes: 64 << 20,
            yaml_limits: yaml::Limits::default(),
        }
    }
}

/// A fatal parse error: nothing usable was found.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    /// Per-item problems found on the way (e.g. every link that failed).
    pub details: Vec<String>,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        for d in self.details.iter().take(20) {
            write!(f, "\n  - {d}")?;
        }
        if self.details.len() > 20 {
            write!(f, "\n  - ... and {} more", self.details.len() - 20)?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseError {}

fn err(message: impl Into<String>) -> ParseError {
    ParseError {
        message: message.into(),
        details: Vec::new(),
    }
}

/// Parses raw bytes. Invalid UTF-8 is replaced (and reported) rather than rejected.
pub fn parse_bytes(input: &[u8], opts: &ParseOptions) -> Result<(Config, Diagnostics), ParseError> {
    if input.len() > opts.max_bytes {
        return Err(err(format!("input is {} bytes, over the {} byte limit", input.len(), opts.max_bytes)));
    }
    // UTF-16 with BOM (some Windows tools save this way)
    if input.len() >= 2 && (input[..2] == [0xFF, 0xFE] || input[..2] == [0xFE, 0xFF]) {
        let le = input[0] == 0xFF;
        let units: Vec<u16> = input[2..]
            .chunks_exact(2)
            .map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
            .collect();
        let s = String::from_utf16_lossy(&units);
        let (c, mut d) = parse(&s, opts)?;
        d.info(Kind::Repaired, "input", None, "decoded UTF-16 input");
        return Ok((c, d));
    }
    match std::str::from_utf8(input) {
        Ok(s) => parse(s, opts),
        Err(e) => {
            let s = String::from_utf8_lossy(input);
            let (c, mut d) = parse(&s, opts)?;
            d.warn(
                Kind::Repaired,
                "input",
                None,
                format!("invalid UTF-8 at byte {}; bad bytes were replaced with U+FFFD", e.valid_up_to()),
            );
            Ok((c, d))
        }
    }
}

/// Parses a subscription body of any supported format.
pub fn parse(input: &str, opts: &ParseOptions) -> Result<(Config, Diagnostics), ParseError> {
    if input.len() > opts.max_bytes {
        return Err(err(format!("input is {} bytes, over the {} byte limit", input.len(), opts.max_bytes)));
    }
    let mut d = Diagnostics::default();
    let cfg = parse_inner(input, opts, &mut d, 0)?;
    if cfg.proxies.is_empty() && cfg.groups.is_empty() && cfg.proxy_providers.is_empty() {
        let mut e = err("no proxies were found in the input");
        e.details = d.items.iter().map(ToString::to_string).collect();
        return Err(e);
    }
    Ok((cfg, d))
}

fn parse_inner(input: &str, opts: &ParseOptions, d: &mut Diagnostics, depth: usize) -> Result<Config, ParseError> {
    let text = input.trim_start_matches('\u{feff}');
    if text.len() != input.len() {
        d.info(Kind::Repaired, "input", None, "removed a byte-order mark");
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(err("the input is empty"));
    }
    let head: String = trimmed.chars().take(64).collect::<String>().to_ascii_lowercase();
    if head.starts_with("<!doctype") || head.starts_with("<html") || head.starts_with("<?xml") || head.starts_with("<head") {
        return Err(err(
            "the input is an HTML/XML page, not a subscription (the server may have returned a login, error or block page)",
        ));
    }

    // JSON
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(j) => {
                if let Some(c) = from_json(j, d) {
                    return Ok(c);
                }
            }
            Err(e) if looks_like_json(trimmed) => {
                // Might still be YAML flow syntax; fall through, but remember the error.
                d.info(Kind::Repaired, "input", None, format!("not strict JSON ({e}); trying YAML"));
            }
            Err(_) => {}
        }
    }

    // Share links (one per line, possibly mixed with junk lines)
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let link_lines = lines.iter().filter(|l| links::link_scheme(l).is_some()).count();
    let yaml_proxies = text.lines().any(|l| l.starts_with("proxies:") || l.starts_with("proxy-groups:") || l.starts_with("proxy-providers:"));
    if link_lines > 0 && !yaml_proxies {
        return Ok(parse_link_lines(&lines, d));
    }

    // YAML
    let yaml_err = match yaml::parse(text, opts.yaml_limits) {
        Ok((v, warnings)) => {
            if is_clash_doc(&v) {
                for w in warnings {
                    d.info(Kind::Repaired, "input", None, w);
                }
                return Ok(clash::from_value(v, SourceFormat::ClashYaml, d));
            }
            None
        }
        Err(e) => Some(e),
    };

    // Base64-wrapped body
    if depth < 3
        && looks_base64(trimmed)
        && let Some(bytes) = links::b64_decode(trimmed)
    {
        let inner = String::from_utf8_lossy(&bytes).into_owned();
        if inner.chars().filter(|c| c.is_control() && !c.is_whitespace()).count() * 10 < inner.len().max(1) {
            return parse_inner(&inner, opts, d, depth + 1);
        }
    }

    if let Some(e) = yaml_err
        && (text.contains("proxies") || text.contains(": "))
    {
        return Err(err(format!("the input looks like YAML but cannot be parsed: {e}")));
    }
    let first: String = trimmed.lines().next().unwrap_or("").chars().take(60).collect();
    Err(err(format!(
        "unrecognised format: not a Clash/Mihomo config, sing-box config, share-link list or Base64 subscription (first line: {first:?})"
    )))
}

fn looks_like_json(s: &str) -> bool {
    s.contains("\":")
}

fn looks_base64(s: &str) -> bool {
    s.len() >= 8
        && s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_' | b'\r' | b'\n' | b' ' | b'\t'))
}

fn is_clash_doc(v: &Value) -> bool {
    match v {
        Value::Map(m) => m.iter().any(|(k, _)| matches!(k.as_str(), "proxies" | "proxy-groups" | "proxy-providers")),
        Value::Seq(s) => !s.is_empty() && s.iter().all(|x| x.get("type").is_some() && x.get("server").is_some()),
        _ => false,
    }
}

fn from_json(j: serde_json::Value, d: &mut Diagnostics) -> Option<Config> {
    let is_singbox = |o: &serde_json::Map<String, serde_json::Value>| o.contains_key("outbounds") || o.contains_key("endpoints");
    match &j {
        serde_json::Value::Object(o) if is_singbox(o) => Some(singbox::from_json(&j, d)),
        serde_json::Value::Array(a) if a.iter().any(|x| x.get("server_port").is_some()) => {
            let wrapped = serde_json::json!({ "outbounds": j });
            Some(singbox::from_json(&wrapped, d))
        }
        _ => {
            let v = Value::from_json(&j);
            if is_clash_doc(&v) {
                Some(clash::from_value(v, SourceFormat::ClashJson, d))
            } else {
                None
            }
        }
    }
}

fn parse_link_lines(lines: &[&str], d: &mut Diagnostics) -> Config {
    let mut cfg = Config {
        source: SourceFormat::Links,
        ..Default::default()
    };
    for (i, line) in lines.iter().enumerate() {
        let loc = format!("input line {}", i + 1);
        if links::link_scheme(line).is_none() {
            if !line.starts_with('#') && !line.starts_with("//") {
                let preview: String = line.chars().take(40).collect();
                d.info(Kind::Invalid, loc, None, format!("skipped a line that is not a share link: {preview:?}"));
            }
            continue;
        }
        match links::parse_link(line, d) {
            Ok(p) => clash::push_unique(&mut cfg.proxies, p, d),
            Err(e) => {
                let scheme = line.split("://").next().unwrap_or("");
                d.error(Kind::Invalid, loc, None, format!("{scheme}:// link: {e}"));
            }
        }
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn detects_formats() {
        let o = ParseOptions::default();
        let links = "trojan://pw@a.example:443#T\nnot a link\n";
        let (c, d) = parse(links, &o).unwrap();
        assert_eq!(c.proxies.len(), 1);
        assert_eq!(d.len(), 1);
        let b64 = base64::engine::general_purpose::STANDARD.encode(links);
        assert_eq!(parse(&b64, &o).unwrap().0.proxies.len(), 1);
        let y = "proxies:\n  - {name: a, type: trojan, server: s, port: 1, password: p}\n";
        assert_eq!(parse(y, &o).unwrap().0.source, SourceFormat::ClashYaml);
        let j = r#"{"proxies":[{"name":"a","type":"trojan","server":"s","port":1,"password":"p"}]}"#;
        assert_eq!(parse(j, &o).unwrap().0.source, SourceFormat::ClashJson);
        let sb = r#"{"outbounds":[{"type":"trojan","tag":"a","server":"s","server_port":1,"password":"p"}]}"#;
        assert_eq!(parse(sb, &o).unwrap().0.source, SourceFormat::SingBox);
        assert!(parse("<html><body>login</body></html>", &o).unwrap_err().message.contains("HTML"));
        assert!(parse("   ", &o).unwrap_err().message.contains("empty"));
    }

    #[test]
    fn invalid_utf8_is_repaired() {
        let mut bytes = b"trojan://pw@a.example:443#T".to_vec();
        bytes.push(0xff);
        let (c, d) = parse_bytes(&bytes, &ParseOptions::default()).unwrap();
        assert_eq!(c.proxies.len(), 1);
        assert!(d.items.iter().any(|x| x.message.contains("UTF-8")));
    }
}
