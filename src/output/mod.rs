//! Output targets.
//!
//! Each target implements [`Target`]. Adding a client (Surge, Stash, Loon,
//! Quantumult X, Shadowrocket, Surfboard, Egern, V2Ray...) means adding one
//! module that renders a [`Config`] and reports what it cannot express.

pub mod mihomo;
pub mod rulesets;
pub mod singbox;

use crate::ConvertOptions;
use crate::diag::{Diagnostics, Kind};
use crate::model::*;

/// A configuration format that can be produced from the IR.
pub trait Target {
    /// Short identifier used on the command line (`mihomo`, `sing-box`).
    fn id(&self) -> &'static str;
    /// File extension of the rendered output.
    fn extension(&self) -> &'static str;
    /// Renders the config, pushing a diagnostic for anything not carried over.
    fn render(&self, cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> String;
}

/// mihomo / Clash.Meta YAML.
pub struct Mihomo;
/// sing-box 1.12+ JSON.
pub struct SingBox;

impl Target for Mihomo {
    fn id(&self) -> &'static str {
        "mihomo"
    }
    fn extension(&self) -> &'static str {
        "yaml"
    }
    fn render(&self, cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> String {
        mihomo::render(cfg, opts, d)
    }
}

impl Target for SingBox {
    fn id(&self) -> &'static str {
        "sing-box"
    }
    fn extension(&self) -> &'static str {
        "json"
    }
    fn render(&self, cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> String {
        singbox::render(cfg, opts, d)
    }
}

/// All built-in targets.
pub fn targets() -> Vec<Box<dyn Target>> {
    vec![Box::new(Mihomo), Box::new(SingBox)]
}

/// Looks a target up by id (accepts common aliases).
pub fn target_by_id(id: &str) -> Option<Box<dyn Target>> {
    match id.to_ascii_lowercase().as_str() {
        "mihomo" | "clash" | "clash-meta" | "clashmeta" | "meta" => Some(Box::new(Mihomo)),
        "sing-box" | "singbox" | "sb" => Some(Box::new(SingBox)),
        _ => None,
    }
}

/// Name of the group added when the input has no groups.
pub const DEFAULT_GROUP: &str = "PROXY";

/// The groups and rules to render. A bare node list gets one selector with
/// every node and a final rule, so the output is usable on its own.
pub fn default_groups(cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> (Vec<Group>, Vec<Rule>) {
    if !cfg.groups.is_empty() || !cfg.rules.is_empty() || !opts.add_defaults {
        return (cfg.groups.clone(), cfg.rules.clone());
    }
    let mut name = DEFAULT_GROUP.to_string();
    while cfg.proxies.iter().any(|p| p.name == name) {
        name.push('_');
    }
    d.info(
        Kind::Repaired,
        "proxy-groups",
        None,
        format!("the input has no groups or rules; added a {name:?} selector with every node and `MATCH,{name}`"),
    );
    let mut members: Vec<String> = cfg.proxies.iter().map(|p| p.name.clone()).collect();
    members.push("DIRECT".into());
    let g = Group {
        name: name.clone(),
        kind: GroupKind::Select,
        members,
        use_providers: cfg.proxy_providers.iter().map(|(k, _)| k.clone()).collect(),
        url: None,
        interval: None,
        tolerance: None,
        timeout: None,
        lazy: None,
        filter: None,
        exclude_filter: None,
        exclude_type: None,
        include_all: false,
        include_all_proxies: false,
        include_all_providers: false,
        hidden: None,
        icon: None,
        extra: Vec::new(),
    };
    let r = Rule {
        matcher: Matcher::Match,
        target: name.clone(),
        no_resolve: false,
        src: false,
        raw: format!("MATCH,{name}"),
    };
    (vec![g], vec![r])
}
