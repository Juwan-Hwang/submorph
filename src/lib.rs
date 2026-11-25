//! submorph: a local subscription converter.
//!
//! Inputs: Clash/Mihomo YAML or JSON, sing-box JSON, share links
//! (ss, ssr, vmess, vless, trojan, hysteria, hysteria2/hy2, tuic, anytls,
//! wireguard, socks, http) and Base64 subscriptions.
//! Outputs: mihomo YAML and sing-box 1.12+ JSON.
//!
//! Everything that cannot be carried over is reported as a [`diag::Diagnostic`]
//! instead of being dropped silently.
//!
//! ```
//! let input = "trojan://secret@example.com:443?sni=example.com#HK";
//! let out = submorph::convert(input, "sing-box", &submorph::ConvertOptions::default()).unwrap();
//! assert!(out.output.contains("\"type\": \"trojan\""));
//! ```

pub mod diag;
pub mod input;
pub mod model;
pub mod output;
pub mod value;
pub mod yaml;

pub use diag::{Diagnostic, Diagnostics, Kind, Severity};
pub use input::{ParseError, ParseOptions, parse, parse_bytes};
pub use model::Config;
pub use output::{Target, target_by_id, targets};

/// Options for rendering.
#[derive(Debug, Clone)]
pub struct ConvertOptions {
    /// Add a selector group, a final rule and a listening port when the input
    /// has none (a bare node list), so the output loads and works on its own.
    pub add_defaults: bool,
    /// Rule-provider contents supplied by the caller, by provider name. The
    /// lines are inlined (sing-box cannot read Clash rule lists remotely).
    pub provider_contents: Vec<(String, String)>,
    pub parse: ParseOptions,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        ConvertOptions {
            add_defaults: true,
            provider_contents: Vec::new(),
            parse: ParseOptions::default(),
        }
    }
}

/// The result of a conversion.
#[derive(Debug, Clone)]
pub struct Converted {
    pub output: String,
    pub diagnostics: Diagnostics,
    /// Number of nodes read from the input.
    pub nodes_in: usize,
}

/// A conversion that produced nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum ConvertError {
    UnknownTarget(String),
    Parse(ParseError),
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvertError::UnknownTarget(t) => write!(f, "unknown target `{t}` (expected mihomo or sing-box)"),
            ConvertError::Parse(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ConvertError {}

/// Parses `input` (any supported format) and renders it for `target`.
pub fn convert(input: &str, target: &str, opts: &ConvertOptions) -> Result<Converted, ConvertError> {
    convert_bytes(input.as_bytes(), target, opts)
}

/// Like [`convert`], for raw bytes (UTF-16 and invalid UTF-8 are handled).
pub fn convert_bytes(input: &[u8], target: &str, opts: &ConvertOptions) -> Result<Converted, ConvertError> {
    let t = target_by_id(target).ok_or_else(|| ConvertError::UnknownTarget(target.to_string()))?;
    let (mut cfg, mut d) = parse_bytes(input, &opts.parse).map_err(ConvertError::Parse)?;
    apply_provider_contents(&mut cfg, opts, &mut d);
    let output = t.render(&cfg, opts, &mut d);
    Ok(Converted {
        output,
        diagnostics: d,
        nodes_in: cfg.proxies.len(),
    })
}

/// Fills rule-provider payloads from caller-supplied contents.
pub fn apply_provider_contents(cfg: &mut Config, opts: &ConvertOptions, d: &mut Diagnostics) {
    for (name, text) in &opts.provider_contents {
        let Some(p) = cfg.rule_providers.iter_mut().find(|p| &p.name == name) else {
            d.warn(Kind::Invalid, format!("rule-provider {name:?}"), None, "content was supplied but the config has no provider by that name");
            continue;
        };
        p.payload = provider_lines(text);
    }
}

/// Reads a Clash rule list in yaml (`payload:`) or text form into lines.
pub fn provider_lines(text: &str) -> Vec<String> {
    let text = text.trim_start_matches('\u{feff}');
    if text.lines().any(|l| l.trim_start().starts_with("payload:"))
        && let Ok((v, _)) = yaml::parse(text, yaml::Limits::default())
        && let Some(list) = v.get("payload")
    {
        return list.as_str_list();
    }
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(|l| l.trim_start_matches("- ").trim_matches('\'').trim_matches('"').to_string())
        .collect()
}
