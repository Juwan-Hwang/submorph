//! sing-box JSON output for 1.12 and later: typed DNS servers, rule actions,
//! rule-set references instead of the removed geoip/geosite fields, and
//! WireGuard as an endpoint.

use crate::ConvertOptions;
use crate::diag::{Diagnostics, Kind, group_loc, proxy_loc, rule_loc};
use crate::model::*;
use crate::output::rulesets;
use serde_json::{Map, Value as J, json};
use std::collections::{HashMap, HashSet};

const DIRECT: &str = "DIRECT";

/// Renders a config as sing-box JSON.
pub fn render(cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> String {
    let v = to_json(cfg, opts, d);
    let mut s = serde_json::to_string_pretty(&v).unwrap_or_default();
    s.push('\n');
    s
}

struct Ctx<'a> {
    d: &'a mut Diagnostics,
    rule_sets: Vec<J>,
    rule_set_tags: HashSet<String>,
    /// Valid outbound tags (proxies, endpoints, groups, DIRECT).
    tags: HashSet<String>,
    /// Clash rule-provider names that converted to a sing-box rule set.
    providers_ok: HashSet<String>,
    providers: HashMap<String, RuleProvider>,
}

impl Ctx<'_> {
    fn add_remote_set(&mut self, tag: &str, url: String) {
        if self.rule_set_tags.insert(tag.to_string()) {
            self.rule_sets
                .push(json!({"type": "remote", "tag": tag, "format": "binary", "url": url}));
        }
    }
}

fn obj(pairs: Vec<(&str, J)>) -> J {
    let mut m = Map::new();
    for (k, v) in pairs {
        if !v.is_null() {
            m.insert(k.to_string(), v);
        }
    }
    J::Object(m)
}
fn opt_s(v: &Option<String>) -> J {
    v.as_ref().map(|s| J::String(s.clone())).unwrap_or(J::Null)
}
fn opt_b(v: Option<bool>) -> J {
    v.map(J::Bool).unwrap_or(J::Null)
}
fn opt_n<N: Into<serde_json::Number>>(v: Option<N>) -> J {
    v.map(|n| J::Number(n.into())).unwrap_or(J::Null)
}
fn strs(v: &[String]) -> J {
    if v.is_empty() { J::Null } else { json!(v) }
}
/// "100 Mbps" / "100" / "1 Gbps" to Mbps.
fn mbps(s: &Option<String>) -> J {
    let Some(s) = s else { return J::Null };
    let l = s.trim().to_ascii_lowercase();
    let i = l
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(l.len());
    let Ok(n) = l[..i].parse::<f64>() else {
        return J::Null;
    };
    let unit = l[i..].trim();
    let v = if unit.starts_with('g') {
        n * 1000.0
    } else if unit.starts_with('k') {
        n / 1000.0
    } else {
        n
    };
    json!(v.max(1.0).round() as u64)
}

fn to_json(cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> J {
    let (groups, rules) = crate::output::default_groups(cfg, opts, d);
    let mut ctx = Ctx {
        d,
        rule_sets: Vec::new(),
        rule_set_tags: HashSet::new(),
        tags: HashSet::new(),
        providers_ok: HashSet::new(),
        providers: cfg
            .rule_providers
            .iter()
            .map(|p| (p.name.clone(), p.clone()))
            .collect(),
    };
    let fakeip = cfg
        .dns
        .as_ref()
        .is_some_and(|x| x.enable && x.enhanced_mode.as_deref() == Some("fake-ip"));

    // ---- DNS (first, so outbounds can name a resolver)
    let (dns, resolver_tag) = dns_json(cfg, fakeip, &mut ctx);

    // ---- proxies
    let mut outbounds: Vec<J> = Vec::new();
    let mut endpoints: Vec<J> = Vec::new();
    for p in &cfg.proxies {
        match proxy_json(p, &resolver_tag, ctx.d) {
            Some(Out::Outbound(list)) => {
                ctx.tags.insert(p.name.clone());
                outbounds.extend(list);
            }
            Some(Out::Endpoint(e)) => {
                ctx.tags.insert(p.name.clone());
                endpoints.push(e);
            }
            None => {}
        }
    }
    // dialer-proxy chains must point at an existing tag
    for o in outbounds.iter_mut().chain(endpoints.iter_mut()) {
        if let Some(det) = o.get("detour").and_then(J::as_str).map(str::to_string)
            && !ctx.tags.contains(&det)
            && !groups.iter().any(|g| g.name == det)
        {
            let tag = o
                .get("tag")
                .and_then(J::as_str)
                .unwrap_or_default()
                .to_string();
            if !tag.contains("/shadowtls") {
                ctx.d.warn(
                    Kind::FieldDropped,
                    proxy_loc(&tag),
                    Some("dialer-proxy"),
                    format!("chain target {det:?} does not exist; removed"),
                );
                o.as_object_mut().unwrap().remove("detour");
            }
        }
    }

    // ---- groups
    let group_names: HashSet<String> = groups.iter().map(|g| g.name.clone()).collect();
    let mut group_out: Vec<J> = Vec::new();
    // groups can reference groups defined later; register all names first
    for g in &groups {
        ctx.tags.insert(g.name.clone());
    }
    ctx.tags.insert(DIRECT.into());
    for g in &groups {
        group_out.extend(group_json(g, cfg, &group_names, &mut ctx, &mut outbounds));
    }
    // remove dangling group tags (groups that failed)
    let produced: HashSet<String> = group_out
        .iter()
        .filter_map(|g| g.get("tag").and_then(J::as_str).map(str::to_string))
        .collect();
    ctx.tags
        .retain(|t| !group_names.contains(t) || produced.contains(t));
    for g in &mut group_out {
        if let Some(arr) = g.get_mut("outbounds").and_then(J::as_array_mut) {
            arr.retain(|m| m.as_str().is_some_and(|s| ctx.tags.contains(s)));
            if arr.is_empty() {
                arr.push(json!(DIRECT));
            }
        }
        if let Some(def) = g.get("default").and_then(J::as_str)
            && !ctx.tags.contains(def)
        {
            g.as_object_mut().unwrap().remove("default");
        }
    }

    let clash_api = cfg.general.external_controller.is_some();
    let mode = cfg
        .general
        .mode
        .clone()
        .unwrap_or_else(|| "rule".into())
        .to_ascii_lowercase();
    let need_global = clash_api || mode == "global";
    if need_global && !ctx.tags.contains("GLOBAL") {
        let mut members: Vec<String> = groups
            .iter()
            .map(|g| g.name.clone())
            .filter(|n| ctx.tags.contains(n))
            .collect();
        members.extend(
            cfg.proxies
                .iter()
                .map(|p| p.name.clone())
                .filter(|n| ctx.tags.contains(n)),
        );
        members.push(DIRECT.into());
        group_out.push(json!({"type": "selector", "tag": "GLOBAL", "outbounds": members}));
        ctx.tags.insert("GLOBAL".into());
    }

    let mut all_out: Vec<J> = group_out;
    all_out.extend(outbounds);
    all_out.push(json!({"type": "direct", "tag": DIRECT}));

    // ---- rule providers
    for p in &cfg.rule_providers {
        provider_json(p, cfg, &mut ctx);
    }

    // ---- route rules
    let mut route_rules: Vec<J> = vec![json!({"action": "sniff"})];
    let has_tun = cfg.tun.as_ref().is_some_and(|t| t.enable);
    route_rules.push(json!({"protocol": "dns", "action": "hijack-dns"}));
    if need_global {
        route_rules.push(json!({"clash_mode": "direct", "outbound": DIRECT}));
        route_rules.push(json!({"clash_mode": "global", "outbound": "GLOBAL"}));
    }
    let mut final_out: Option<String> = None;
    let mut resolved = fakeip;
    let sub_rules: HashMap<&str, &Vec<Rule>> =
        cfg.sub_rules.iter().map(|(k, v)| (k.as_str(), v)).collect();
    for (i, r) in rules.iter().enumerate() {
        if let Matcher::Match = r.matcher {
            match action_for(&r.target, &ctx) {
                Some(Action::Route(t)) => final_out = Some(t),
                Some(Action::Reject(drop)) => route_rules.push(reject(drop, None)),
                None => ctx.d.error(
                    Kind::Unsupported,
                    rule_loc(i, &r.raw),
                    None,
                    format!("target {:?} does not exist", r.target),
                ),
            }
            break;
        }
        let expanded: Vec<(Matcher, String)> = match &r.matcher {
            Matcher::SubRule(cond, name) => match sub_rules.get(name.as_str()) {
                Some(list) => list
                    .iter()
                    .map(|sr| {
                        let m = if sr.matcher == Matcher::Match {
                            (**cond).clone()
                        } else {
                            Matcher::And(vec![(**cond).clone(), sr.matcher.clone()])
                        };
                        (m, sr.target.clone())
                    })
                    .collect(),
                None => {
                    ctx.d.error(
                        Kind::Invalid,
                        rule_loc(i, &r.raw),
                        None,
                        format!("sub-rule {name:?} does not exist"),
                    );
                    continue;
                }
            },
            m => vec![(m.clone(), r.target.clone())],
        };
        for (m, target) in expanded {
            let action = match action_for(&target, &ctx) {
                Some(a) => a,
                None => {
                    ctx.d.error(
                        Kind::Unsupported,
                        rule_loc(i, &r.raw),
                        None,
                        format!("target {target:?} does not exist or was dropped"),
                    );
                    continue;
                }
            };
            let loc = rule_loc(i, &r.raw);
            let Some(mut body) = matcher_json(&m, &mut ctx, &loc) else {
                continue;
            };
            if !resolved && !r.no_resolve && needs_ip(&m) {
                route_rules.push(json!({"action": "resolve"}));
                resolved = true;
            }
            let o = body.as_object_mut().unwrap();
            match action {
                Action::Route(t) => {
                    o.insert("outbound".into(), json!(t));
                }
                Action::Reject(drop) => {
                    o.insert("action".into(), json!("reject"));
                    if drop {
                        o.insert("method".into(), json!("drop"));
                    }
                }
            }
            route_rules.push(body);
        }
    }
    if fakeip && rules.iter().any(|r| !r.no_resolve && needs_ip(&r.matcher)) {
        ctx.d.info(
            Kind::Approximated,
            "route",
            None,
            "fake-ip DNS is on, so IP rules match only connections that already carry an IP (same as mihomo in fake-ip mode)",
        );
    }

    // ---- route
    let mut route = Map::new();
    route.insert("rules".into(), J::Array(route_rules));
    if !ctx.rule_sets.is_empty() {
        route.insert(
            "rule_set".into(),
            J::Array(std::mem::take(&mut ctx.rule_sets)),
        );
    }
    let final_out = if mode == "global" {
        Some("GLOBAL".to_string())
    } else if mode == "direct" {
        Some(DIRECT.to_string())
    } else {
        final_out
    };
    if let Some(f) = final_out {
        route.insert("final".into(), json!(f));
    }
    let auto_detect = cfg
        .tun
        .as_ref()
        .and_then(|t| t.auto_detect_interface)
        .unwrap_or(has_tun);
    if auto_detect {
        route.insert("auto_detect_interface".into(), json!(true));
    }
    if let Some(i) = &cfg.general.interface_name {
        route.insert("default_interface".into(), json!(i));
    }
    if let Some(m) = cfg.general.routing_mark {
        route.insert("default_mark".into(), json!(m));
    }
    route.insert("default_domain_resolver".into(), json!(resolver_tag));

    // ---- inbounds
    let inbounds = inbounds_json(cfg, opts, ctx.d);

    // ---- assemble
    let mut root = Map::new();
    let level = cfg.general.log_level.as_deref().unwrap_or("info");
    root.insert(
        "log".into(),
        match level {
            "silent" => json!({"disabled": true}),
            "warning" => json!({"level": "warn"}),
            l => json!({"level": l}),
        },
    );
    root.insert("dns".into(), dns);
    if !inbounds.is_empty() {
        root.insert("inbounds".into(), J::Array(inbounds));
    }
    root.insert("outbounds".into(), J::Array(all_out));
    if !endpoints.is_empty() {
        root.insert("endpoints".into(), J::Array(endpoints));
    }
    root.insert("route".into(), J::Object(route));
    let mut exp = Map::new();
    if clash_api {
        exp.insert(
            "clash_api".into(),
            obj(vec![
                (
                    "external_controller",
                    opt_s(&cfg.general.external_controller),
                ),
                ("secret", opt_s(&cfg.general.secret)),
                ("default_mode", json!(capitalize(&mode))),
            ]),
        );
    }
    if clash_api || fakeip {
        exp.insert(
            "cache_file".into(),
            obj(vec![
                ("enabled", json!(true)),
                ("store_fakeip", if fakeip { json!(true) } else { J::Null }),
            ]),
        );
    }
    if !exp.is_empty() {
        root.insert("experimental".into(), J::Object(exp));
    }
    let mut root = J::Object(root);
    fix_dns_rule_set_refs(&mut root, ctx.d);
    root
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

enum Action {
    Route(String),
    Reject(bool),
}

fn action_for(target: &str, ctx: &Ctx) -> Option<Action> {
    match target.to_ascii_uppercase().as_str() {
        "DIRECT" => Some(Action::Route(DIRECT.into())),
        "REJECT" | "REJECT-TINYGIF" => Some(Action::Reject(false)),
        "REJECT-DROP" => Some(Action::Reject(true)),
        _ if ctx.tags.contains(target) => Some(Action::Route(target.to_string())),
        _ => None,
    }
}

fn reject(drop: bool, base: Option<J>) -> J {
    let mut o = base.unwrap_or_else(|| json!({}));
    let m = o.as_object_mut().unwrap();
    m.insert("action".into(), json!("reject"));
    if drop {
        m.insert("method".into(), json!("drop"));
    }
    o
}

fn needs_ip(m: &Matcher) -> bool {
    match m {
        Matcher::Geoip(c) => !c.eq_ignore_ascii_case("LAN") || true,
        Matcher::IpCidr(_) | Matcher::IpAsn(_) | Matcher::IpSuffix(_) => true,
        Matcher::And(v) | Matcher::Or(v) => v.iter().any(needs_ip),
        Matcher::Not(x) => needs_ip(x),
        _ => false,
    }
}

// ------------------------------------------------------------- matchers

/// Converts a matcher into a route-rule body (no action). Returns `None` and
/// reports when the matcher cannot be expressed.
fn matcher_json(m: &Matcher, ctx: &mut Ctx, loc: &str) -> Option<J> {
    let one = |k: &str, v: J| -> Option<J> {
        let mut o = Map::new();
        o.insert(k.to_string(), v);
        Some(J::Object(o))
    };
    match m {
        Matcher::Domain(p) => one("domain", json!([p])),
        Matcher::DomainSuffix(p) => one("domain_suffix", json!([p])),
        Matcher::DomainKeyword(p) => one("domain_keyword", json!([p])),
        Matcher::DomainRegex(p) => one("domain_regex", json!([p])),
        Matcher::DomainWildcard(p) => one("domain_regex", json!([wildcard_regex(p)])),
        Matcher::Geosite(p) => {
            let tag = format!("geosite-{}", p.to_ascii_lowercase());
            ctx.add_remote_set(&tag, rulesets::geosite_srs(p));
            one("rule_set", json!([tag]))
        }
        Matcher::Geoip(p) if p.eq_ignore_ascii_case("LAN") || p.eq_ignore_ascii_case("private") => {
            one("ip_is_private", json!(true))
        }
        Matcher::Geoip(p) => {
            let tag = format!("geoip-{}", p.to_ascii_lowercase());
            ctx.add_remote_set(&tag, rulesets::geoip_srs(p));
            one("rule_set", json!([tag]))
        }
        Matcher::SrcGeoip(p) => {
            let tag = format!("geoip-{}", p.to_ascii_lowercase());
            ctx.add_remote_set(&tag, rulesets::geoip_srs(p));
            Some(json!({"rule_set": [tag], "rule_set_ip_cidr_match_source": true}))
        }
        Matcher::IpCidr(p) => one("ip_cidr", json!([p])),
        Matcher::SrcIpCidr(p) => one("source_ip_cidr", json!([p])),
        Matcher::DstPort(p) => Some(ports("port", "port_range", p)),
        Matcher::SrcPort(p) => Some(ports("source_port", "source_port_range", p)),
        Matcher::InName(p) => one("inbound", json!([p])),
        Matcher::InUser(p) => one("auth_user", json!([p])),
        Matcher::InType(p) => {
            let tag = match p.to_ascii_uppercase().as_str() {
                "HTTP" => "http-in",
                "SOCKS" | "SOCKS5" => "socks-in",
                "MIXED" => "mixed-in",
                "TUN" => "tun-in",
                "REDIR" => "redir-in",
                "TPROXY" => "tproxy-in",
                _ => {
                    ctx.d.error(
                        Kind::Unsupported,
                        loc,
                        None,
                        format!("IN-TYPE {p} has no sing-box inbound"),
                    );
                    return None;
                }
            };
            one("inbound", json!([tag]))
        }
        Matcher::ProcessName(p) => {
            if p.contains('.')
                && !p.to_ascii_lowercase().ends_with(".exe")
                && p.split('.').count() >= 3
            {
                // Android package names are matched by PROCESS-NAME in mihomo
                Some(json!({"package_name": [p]}))
            } else {
                one("process_name", json!([p]))
            }
        }
        Matcher::ProcessPath(p) => one("process_path", json!([p])),
        Matcher::ProcessPathRegex(p) => one("process_path_regex", json!([p])),
        Matcher::ProcessNameRegex(p) => {
            let body = p.trim_start_matches('^').trim_end_matches('$');
            ctx.d.info(
                Kind::Approximated,
                loc,
                None,
                "PROCESS-NAME-REGEX is matched against the end of the process path",
            );
            one(
                "process_path_regex",
                json!([format!("(^|[/\\\\])(?:{body})$")]),
            )
        }
        Matcher::Uid(p) => {
            let ids: Vec<u64> = p
                .split(['/', ','])
                .filter_map(|x| x.trim().parse().ok())
                .collect();
            if ids.is_empty() {
                ctx.d.error(
                    Kind::Unsupported,
                    loc,
                    None,
                    "UID ranges are not supported by sing-box",
                );
                return None;
            }
            one("user_id", json!(ids))
        }
        Matcher::Network(p) => one("network", json!([p.to_ascii_lowercase()])),
        Matcher::RuleSet(p) => {
            if ctx.providers_ok.contains(p) {
                one("rule_set", json!([p]))
            } else {
                let why = if ctx.providers.contains_key(p) {
                    "could not be converted"
                } else {
                    "does not exist"
                };
                ctx.d.error(
                    Kind::Unsupported,
                    loc,
                    None,
                    format!("rule provider {p:?} {why}; rule dropped"),
                );
                None
            }
        }
        Matcher::And(v) | Matcher::Or(v) => {
            let mode = if matches!(m, Matcher::And(_)) {
                "and"
            } else {
                "or"
            };
            let mut subs = Vec::new();
            for x in v {
                subs.push(matcher_json(x, ctx, loc)?);
            }
            Some(json!({"type": "logical", "mode": mode, "rules": subs}))
        }
        Matcher::Not(x) => {
            let mut inner = matcher_json(x, ctx, loc)?;
            let o = inner.as_object_mut().unwrap();
            if o.contains_key("type") {
                o.insert("invert".into(), json!(true));
                Some(inner)
            } else {
                Some(json!({"type": "logical", "mode": "and", "rules": [inner], "invert": true}))
            }
        }
        Matcher::IpAsn(_)
        | Matcher::SrcIpAsn(_)
        | Matcher::IpSuffix(_)
        | Matcher::InPort(_)
        | Matcher::Dscp(_)
        | Matcher::Other(..) => {
            ctx.d.error(
                Kind::Unsupported,
                loc,
                None,
                "sing-box has no equivalent matcher; rule dropped",
            );
            None
        }
        Matcher::SubRule(..) => {
            ctx.d.error(
                Kind::Unsupported,
                loc,
                None,
                "nested SUB-RULE inside a logical rule; rule dropped",
            );
            None
        }
        Matcher::Match => Some(json!({})),
    }
}

fn ports(single: &str, range: &str, p: &str) -> J {
    let mut ps = Vec::new();
    let mut rs = Vec::new();
    for part in p.split(['/', ',']) {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            rs.push(format!("{}:{}", a.trim(), b.trim()));
        } else if let Ok(n) = part.parse::<u16>() {
            ps.push(n);
        }
    }
    let mut o = Map::new();
    if !ps.is_empty() {
        o.insert(single.into(), json!(ps));
    }
    if !rs.is_empty() {
        o.insert(range.into(), json!(rs));
    }
    J::Object(o)
}

/// mihomo DOMAIN-WILDCARD (`*` any run of characters, `?` one) as a regex.
fn wildcard_regex(p: &str) -> String {
    let mut s = String::from("^");
    for c in p.chars() {
        match c {
            '*' => s.push_str(".*"),
            '?' => s.push('.'),
            c if ".+()[]{}|^$\\".contains(c) => {
                s.push('\\');
                s.push(c);
            }
            c => s.push(c),
        }
    }
    s.push('$');
    s
}

/// Converts a mihomo `domain` behaviour entry into a headless-rule field.
fn domain_entry(e: &str, dom: &mut Vec<String>, suf: &mut Vec<String>, re: &mut Vec<String>) {
    if let Some(x) = e.strip_prefix("+.") {
        suf.push(x.to_string());
    } else if e.starts_with('.') {
        suf.push(e.to_string());
    } else if e.contains('*') {
        // mihomo: `*` matches exactly one label
        let mut r = String::from("^");
        for (i, label) in e.split('.').enumerate() {
            if i > 0 {
                r.push_str("\\.");
            }
            if label == "*" {
                r.push_str("[^.]+");
            } else {
                r.push_str(&regex_escape(label));
            }
        }
        r.push('$');
        re.push(r);
    } else {
        dom.push(e.to_string());
    }
}

fn regex_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        if ".+*?()[]{}|^$\\".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

fn provider_json(p: &RuleProvider, cfg: &Config, ctx: &mut Ctx) {
    let loc = format!("rule-provider {:?}", p.name);
    let detour = p
        .proxy
        .clone()
        .filter(|x| ctx.tags.contains(x) && x != DIRECT);
    // 1) known public lists: use the sing-box build
    if let Some(url) = &p.url {
        let srs = if p.format.as_deref() == Some("srs") {
            Some(url.clone())
        } else {
            rulesets::mihomo_to_srs(url)
        };
        if let Some(srs) = srs
            && p.payload.is_empty()
        {
            let mut o = obj(vec![
                ("type", json!("remote")),
                ("tag", json!(p.name)),
                ("format", json!("binary")),
                ("url", json!(srs)),
                ("download_detour", opt_s(&detour)),
                (
                    "update_interval",
                    p.interval
                        .map(|i| json!(format!("{i}s")))
                        .unwrap_or(J::Null),
                ),
            ]);
            if !ctx.rule_set_tags.insert(p.name.clone()) {
                return;
            }
            if p.format.as_deref() != Some("srs") {
                ctx.d.info(
                    Kind::Approximated,
                    &loc,
                    Some("url"),
                    "uses the sing-box (.srs) build of the same meta-rules-dat list",
                );
            }
            ctx.rule_sets.push(std::mem::take(&mut o));
            ctx.providers_ok.insert(p.name.clone());
            return;
        }
        if p.format.as_deref() == Some("sing-box-json") {
            ctx.rule_sets.push(obj(vec![
                ("type", json!("remote")),
                ("tag", json!(p.name)),
                ("format", json!("source")),
                ("url", json!(url)),
                ("download_detour", opt_s(&detour)),
            ]));
            ctx.rule_set_tags.insert(p.name.clone());
            ctx.providers_ok.insert(p.name.clone());
            return;
        }
    }
    // 2) inline payload (inline providers, or content supplied by the caller)
    if p.payload.is_empty() {
        let why = match p.format.as_deref() {
            Some("mrs") => {
                "it is a mihomo binary (.mrs) list with no known sing-box build".to_string()
            }
            _ => format!(
                "sing-box cannot read Clash {} lists; pass the list content with --provider {}=FILE to inline it",
                p.format.as_deref().unwrap_or("yaml"),
                p.name
            ),
        };
        ctx.d.error(
            Kind::Unsupported,
            &loc,
            None,
            format!("not converted: {why}"),
        );
        return;
    }
    let mut rules: Vec<J> = Vec::new();
    match p.behavior.as_str() {
        "domain" => {
            let (mut dom, mut suf, mut re) = (Vec::new(), Vec::new(), Vec::new());
            for e in &p.payload {
                domain_entry(
                    e.trim().trim_matches('\'').trim_matches('"'),
                    &mut dom,
                    &mut suf,
                    &mut re,
                );
            }
            rules.push(obj(vec![
                ("domain", strs(&dom)),
                ("domain_suffix", strs(&suf)),
                ("domain_regex", strs(&re)),
            ]));
        }
        "ipcidr" => rules.push(json!({"ip_cidr": p.payload})),
        _ => {
            let mut dropped = 0usize;
            for line in &p.payload {
                // classical lines have no target; add a dummy one for the parser
                let parsed = crate::input::clash::parse_rule(&format!("{line},X"));
                let Ok(r) = parsed else {
                    dropped += 1;
                    continue;
                };
                let mut sink = Diagnostics::default();
                let mut sub = Ctx {
                    d: &mut sink,
                    rule_sets: Vec::new(),
                    rule_set_tags: ctx.rule_set_tags.clone(),
                    tags: HashSet::new(),
                    providers_ok: HashSet::new(),
                    providers: HashMap::new(),
                };
                match matcher_json(&r.matcher, &mut sub, &loc) {
                    Some(j) => {
                        let new_sets = std::mem::take(&mut sub.rule_sets);
                        if new_sets.is_empty() {
                            rules.push(j);
                        } else {
                            // headless rules cannot reference other rule sets
                            dropped += 1;
                        }
                    }
                    None => dropped += 1,
                }
            }
            if dropped > 0 {
                ctx.d.warn(
                    Kind::FieldDropped,
                    &loc,
                    None,
                    format!("{dropped} of {} entries have no headless-rule equivalent (GEOIP/GEOSITE/ASN...) and were dropped", p.payload.len()),
                );
            }
        }
    }
    let _ = cfg;
    if rules.is_empty() {
        ctx.d.error(
            Kind::Unsupported,
            &loc,
            None,
            "no entries could be converted",
        );
        return;
    }
    if ctx.rule_set_tags.insert(p.name.clone()) {
        ctx.rule_sets
            .push(json!({"type": "inline", "tag": p.name, "rules": rules}));
        ctx.providers_ok.insert(p.name.clone());
    }
}

// --------------------------------------------------------------- groups

fn group_json(
    g: &Group,
    cfg: &Config,
    group_names: &HashSet<String>,
    ctx: &mut Ctx,
    outbounds: &mut Vec<J>,
) -> Vec<J> {
    let loc = group_loc(&g.name);
    if !g.use_providers.is_empty() || g.include_all_providers {
        ctx.d.warn(
            Kind::FieldDropped,
            &loc,
            Some("use"),
            "sing-box has no proxy providers; nodes from providers are not included",
        );
    }
    // expand include-all / filter offline, as mihomo does at runtime
    let mut members: Vec<String> = Vec::new();
    for m in &g.members {
        members.push(m.clone());
    }
    if g.include_all || g.include_all_proxies {
        for p in &cfg.proxies {
            if !members.contains(&p.name) {
                members.push(p.name.clone());
            }
        }
    }
    let compile = |pat: &Option<String>, field: &str, d: &mut Diagnostics| -> Vec<regex::Regex> {
        let Some(pat) = pat else { return Vec::new() };
        // mihomo splits filters on the backtick character
        pat.split('`')
            .filter(|s| !s.is_empty())
            .filter_map(|s| match regex::Regex::new(s) {
                Ok(r) => Some(r),
                Err(e) => {
                    d.warn(
                        Kind::FieldDropped,
                        group_loc(&g.name),
                        Some(field),
                        format!("regex not understood ({e}); ignored"),
                    );
                    None
                }
            })
            .collect()
    };
    let filt = compile(&g.filter, "filter", ctx.d);
    let excl = compile(&g.exclude_filter, "exclude-filter", ctx.d);
    let excl_types: Vec<String> = g
        .exclude_type
        .as_deref()
        .map(|t| {
            t.split('|')
                .map(|x| x.trim().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let is_proxy = |n: &str| cfg.proxies.iter().find(|p| p.name == n);
    members.retain(|m| {
        let Some(p) = is_proxy(m) else { return true };
        // filters apply to nodes pulled in by include-all; mihomo applies them to all nodes
        (filt.is_empty() || filt.iter().any(|r| r.is_match(&p.name)))
            && !excl.iter().any(|r| r.is_match(&p.name))
            && !excl_types.iter().any(|t| t == p.protocol.clash_type())
    });
    let mut out_members: Vec<String> = Vec::new();
    for m in members {
        match m.to_ascii_uppercase().as_str() {
            "DIRECT" => out_members.push(DIRECT.into()),
            "REJECT" | "REJECT-DROP" | "REJECT-TINYGIF" | "PASS" | "COMPATIBLE" => {
                ctx.d.warn(
                    Kind::FieldDropped,
                    &loc,
                    Some("proxies"),
                    format!("member {m} removed: sing-box groups cannot hold a reject/pass policy (use a rule with action reject)"),
                );
            }
            _ if ctx.tags.contains(&m) || group_names.contains(&m) => out_members.push(m),
            _ => ctx.d.warn(
                Kind::FieldDropped,
                &loc,
                Some("proxies"),
                format!("member {m:?} does not exist or was dropped"),
            ),
        }
    }
    if out_members.is_empty() {
        ctx.d.warn(
            Kind::Approximated,
            &loc,
            None,
            "group has no usable members; DIRECT added so sing-box can load it",
        );
        out_members.push(DIRECT.into());
    }
    let interval = g
        .interval
        .map(|i| json!(format!("{i}s")))
        .unwrap_or(J::Null);
    match &g.kind {
        GroupKind::Select => vec![obj(vec![
            ("type", json!("selector")),
            ("tag", json!(g.name)),
            ("outbounds", json!(out_members)),
            ("default", json!(out_members[0])),
        ])],
        GroupKind::UrlTest | GroupKind::Fallback | GroupKind::LoadBalance { .. } => {
            if !matches!(g.kind, GroupKind::UrlTest) {
                ctx.d.warn(
                    Kind::Approximated,
                    &loc,
                    Some("type"),
                    format!("sing-box has no {} group; converted to urltest (picks the lowest-latency member)", g.kind.clash_type()),
                );
            }
            vec![obj(vec![
                ("type", json!("urltest")),
                ("tag", json!(g.name)),
                ("outbounds", json!(out_members)),
                ("url", opt_s(&g.url)),
                ("interval", interval),
                ("tolerance", opt_n(g.tolerance)),
            ])]
        }
        GroupKind::Relay => {
            // A -> B -> C: clone each node with `detour` set to the previous hop
            let mut prev: Option<String> = None;
            let mut last = String::new();
            for (i, m) in out_members.iter().enumerate() {
                let Some(src) = outbounds
                    .iter()
                    .find(|o| o.get("tag").and_then(J::as_str) == Some(m.as_str()))
                    .cloned()
                else {
                    ctx.d.error(
                        Kind::Unsupported,
                        &loc,
                        Some("proxies"),
                        format!("relay member {m:?} is not a plain node (groups/endpoints cannot be chained); group dropped"),
                    );
                    return Vec::new();
                };
                let mut c = src;
                let tag = format!("{}/{}#{}", g.name, i + 1, m);
                c["tag"] = json!(tag);
                if let Some(p) = &prev {
                    c["detour"] = json!(p);
                }
                outbounds.push(c);
                prev = Some(tag.clone());
                last = tag;
            }
            ctx.tags.insert(last.clone());
            vec![json!({"type": "selector", "tag": g.name, "outbounds": [last]})]
        }
        GroupKind::Other(t) => {
            ctx.d.warn(
                Kind::Approximated,
                &loc,
                Some("type"),
                format!("unknown group type `{t}`; converted to selector"),
            );
            vec![json!({"type": "selector", "tag": g.name, "outbounds": out_members})]
        }
    }
}

// -------------------------------------------------------------- proxies

enum Out {
    Outbound(Vec<J>),
    Endpoint(J),
}

fn tls_json(t: &Tls, p: &Proxy, d: &mut Diagnostics) -> J {
    let loc = proxy_loc(&p.name);
    let mut utls = t.utls.clone().filter(|u| !u.is_empty() && u != "none");
    if t.reality.is_some() && utls.is_none() {
        d.info(
            Kind::Approximated,
            &loc,
            Some("client-fingerprint"),
            "sing-box needs uTLS for REALITY; using chrome",
        );
        utls = Some("chrome".into());
    }
    if let Some(u) = &utls
        && !matches!(
            u.as_str(),
            "chrome"
                | "firefox"
                | "edge"
                | "safari"
                | "360"
                | "qq"
                | "ios"
                | "android"
                | "random"
                | "randomized"
        )
    {
        d.info(
            Kind::Approximated,
            &loc,
            Some("client-fingerprint"),
            format!("uTLS fingerprint `{u}` is unknown to sing-box; using chrome"),
        );
        utls = Some("chrome".into());
    }
    if t.cert_fingerprint.is_some() {
        d.warn(
            Kind::FieldDropped,
            &loc,
            Some("fingerprint"),
            "certificate pinning has no sing-box 1.12 equivalent; dropped",
        );
    }
    if t.client_cert.is_some() {
        d.warn(
            Kind::FieldDropped,
            &loc,
            Some("certificate"),
            "client certificates are passed as file paths in mihomo; dropped",
        );
    }
    obj(vec![
        ("enabled", json!(true)),
        ("server_name", opt_s(&t.sni)),
        ("insecure", opt_b(t.insecure)),
        ("alpn", strs(&t.alpn)),
        (
            "utls",
            utls.map(|f| json!({"enabled": true, "fingerprint": f}))
                .unwrap_or(J::Null),
        ),
        (
            "reality",
            t.reality
                .as_ref()
                .map(|r| {
                    obj(vec![
                        ("enabled", json!(true)),
                        ("public_key", json!(r.public_key)),
                        (
                            "short_id",
                            if r.short_id.is_empty() {
                                J::Null
                            } else {
                                json!(r.short_id)
                            },
                        ),
                    ])
                })
                .unwrap_or(J::Null),
        ),
        (
            "ech",
            t.ech
                .as_ref()
                .filter(|e| e.enable)
                .map(|e| {
                    obj(vec![
                        ("enabled", json!(true)),
                        (
                            "config",
                            e.config
                                .as_ref()
                                .map(|c| {
                                    json!([
                                        "-----BEGIN ECH CONFIGS-----",
                                        c,
                                        "-----END ECH CONFIGS-----"
                                    ])
                                })
                                .unwrap_or(J::Null),
                        ),
                    ])
                })
                .unwrap_or(J::Null),
        ),
    ])
}

fn transport_json(t: &Transport, p: &Proxy, d: &mut Diagnostics) -> Result<J, String> {
    let hdrs = |h: &[(String, String)], host: &Option<String>| -> J {
        let mut m = Map::new();
        if let Some(host) = host {
            m.insert("Host".into(), json!(host));
        }
        for (k, v) in h {
            m.insert(k.clone(), json!(v));
        }
        if m.is_empty() { J::Null } else { J::Object(m) }
    };
    Ok(match t {
        Transport::Ws {
            path,
            host,
            headers,
            max_early_data,
            early_data_header,
        } => {
            // `/path?ed=2048` early-data syntax (Xray) to sing-box fields
            let (mut path, mut ed, mut edh) =
                (path.clone(), *max_early_data, early_data_header.clone());
            if let Some((base, q)) = path.clone().split_once('?')
                && let Some(v) = q.split('&').find_map(|kv| kv.strip_prefix("ed="))
                && let Ok(n) = v.parse::<u32>()
            {
                path = base.to_string();
                ed = Some(n);
                edh.get_or_insert_with(|| "Sec-WebSocket-Protocol".into());
            }
            obj(vec![
                ("type", json!("ws")),
                ("path", json!(path)),
                ("headers", hdrs(headers, host)),
                ("max_early_data", opt_n(ed)),
                ("early_data_header_name", opt_s(&edh)),
            ])
        }
        Transport::HttpUpgrade {
            path,
            host,
            headers,
        } => obj(vec![
            ("type", json!("httpupgrade")),
            ("host", opt_s(host)),
            ("path", json!(path)),
            ("headers", hdrs(headers, &None)),
        ]),
        Transport::Grpc { service_name } => obj(vec![
            ("type", json!("grpc")),
            ("service_name", json!(service_name)),
        ]),
        Transport::H2 { hosts, path } => obj(vec![
            ("type", json!("http")),
            ("host", strs(hosts)),
            ("path", json!(path)),
        ]),
        Transport::Http {
            method,
            paths,
            hosts,
            headers,
        } => {
            if paths.len() > 1 {
                d.info(
                    Kind::Approximated,
                    proxy_loc(&p.name),
                    Some("http-opts.path"),
                    "sing-box takes one path; using the first",
                );
            }
            let mut h = Map::new();
            for (k, v) in headers {
                h.insert(k.clone(), json!(v));
            }
            obj(vec![
                ("type", json!("http")),
                ("host", strs(hosts)),
                ("path", paths.first().map(|x| json!(x)).unwrap_or(J::Null)),
                ("method", opt_s(method)),
                ("headers", if h.is_empty() { J::Null } else { J::Object(h) }),
            ])
        }
        Transport::Quic => json!({"type": "quic"}),
        Transport::Xhttp { .. } => {
            return Err("XHTTP transport is not supported by sing-box".into());
        }
    })
}

fn proxy_json(p: &Proxy, resolver: &str, d: &mut Diagnostics) -> Option<Out> {
    let loc = proxy_loc(&p.name);
    let unsupported = |d: &mut Diagnostics, why: &str| {
        d.error(
            Kind::Unsupported,
            &loc,
            None,
            format!("node dropped: {why}"),
        );
    };
    let mut o = Map::new();
    let mut extra_out: Vec<J> = Vec::new();
    let ty = match &p.protocol {
        Protocol::Shadowsocks { .. } => "shadowsocks",
        Protocol::Vmess { .. } => "vmess",
        Protocol::Vless { .. } => "vless",
        Protocol::Trojan { .. } => "trojan",
        Protocol::Hysteria { .. } => "hysteria",
        Protocol::Hysteria2 { .. } => "hysteria2",
        Protocol::Tuic { .. } => "tuic",
        Protocol::AnyTls { .. } => "anytls",
        Protocol::WireGuard(_) => "wireguard",
        Protocol::Ssh { .. } => "ssh",
        Protocol::Socks5 { .. } => "socks",
        Protocol::Http { .. } => "http",
        Protocol::ShadowsocksR { .. } => {
            unsupported(d, "ShadowsocksR was removed from sing-box");
            return None;
        }
        Protocol::Snell { .. } => {
            unsupported(d, "sing-box does not support Snell");
            return None;
        }
        Protocol::Mieru { .. } => {
            unsupported(d, "sing-box does not support mieru");
            return None;
        }
        Protocol::Other { kind } => {
            unsupported(d, &format!("type `{kind}` is not supported by sing-box"));
            return None;
        }
    };
    o.insert("type".into(), json!(ty));
    o.insert("tag".into(), json!(p.name));
    if !matches!(p.protocol, Protocol::WireGuard(_)) {
        o.insert("server".into(), json!(p.server));
        o.insert("server_port".into(), json!(p.port));
    }
    macro_rules! put {
        ($k:expr, $v:expr $(,)?) => {{
            let v: J = $v;
            if !v.is_null() {
                o.insert($k.to_string(), v);
            }
        }};
    }
    match &p.protocol {
        Protocol::Shadowsocks {
            cipher,
            password,
            plugin,
            udp_over_tcp,
            udp_over_tcp_version,
        } => {
            put!("method", json!(cipher));
            put!("password", json!(password));
            if *udp_over_tcp == Some(true) {
                put!(
                    "udp_over_tcp",
                    obj(vec![
                        ("enabled", json!(true)),
                        ("version", opt_n(*udp_over_tcp_version))
                    ])
                );
            }
            match plugin {
                None => {}
                Some(SsPlugin::Obfs { mode, host }) => {
                    put!("plugin", json!("obfs-local"));
                    let mut s = format!("obfs={mode}");
                    if let Some(h) = host {
                        s.push_str(&format!(";obfs-host={h}"));
                    }
                    put!("plugin_opts", json!(s));
                }
                Some(SsPlugin::V2ray {
                    mode,
                    tls,
                    host,
                    path,
                    mux,
                    ..
                }) => {
                    if mode != "websocket" {
                        unsupported(
                            d,
                            &format!("v2ray-plugin mode `{mode}` is not supported by sing-box"),
                        );
                        return None;
                    }
                    put!("plugin", json!("v2ray-plugin"));
                    let mut s = String::from("mode=websocket");
                    if *tls {
                        s.push_str(";tls");
                    }
                    if let Some(h) = host {
                        s.push_str(&format!(";host={h}"));
                    }
                    if let Some(pa) = path {
                        s.push_str(&format!(";path={pa}"));
                    }
                    if *mux == Some(true) {
                        s.push_str(";mux=4");
                    }
                    put!("plugin_opts", json!(s));
                }
                Some(SsPlugin::ShadowTls {
                    host,
                    password,
                    version,
                }) => {
                    let stag = format!("{}/shadowtls", p.name);
                    let utls = p.tls.as_ref().and_then(|t| t.utls.clone()).or_else(|| {
                        p.extra
                            .iter()
                            .find(|(k, _)| k == "client-fingerprint")
                            .and_then(|(_, v)| v.as_string())
                    });
                    extra_out.push(obj(vec![
                        ("type", json!("shadowtls")),
                        ("tag", json!(stag)),
                        ("server", json!(p.server)),
                        ("server_port", json!(p.port)),
                        ("version", json!(version)),
                        ("password", opt_s(password)),
                        (
                            "tls",
                            obj(vec![
                                ("enabled", json!(true)),
                                ("server_name", json!(host)),
                                ("utls", json!({"enabled": true, "fingerprint": utls.unwrap_or_else(|| "chrome".into())})),
                            ]),
                        ),
                    ]));
                    put!("detour", json!(stag));
                    o.remove("server");
                    o.remove("server_port");
                }
                Some(SsPlugin::Other { name, .. }) => {
                    unsupported(
                        d,
                        &format!("shadowsocks plugin `{name}` is not supported by sing-box"),
                    );
                    return None;
                }
            }
        }
        Protocol::Vmess {
            uuid,
            alter_id,
            security,
            global_padding,
            authenticated_length,
            packet_encoding,
        } => {
            put!("uuid", json!(uuid));
            put!("security", json!(security));
            if *alter_id > 0 {
                put!("alter_id", json!(alter_id));
            }
            put!("global_padding", opt_b(*global_padding));
            put!("authenticated_length", opt_b(*authenticated_length));
            put!("packet_encoding", opt_s(packet_encoding));
        }
        Protocol::Vless {
            uuid,
            flow,
            packet_encoding,
            encryption,
        } => {
            if encryption.is_some() {
                unsupported(
                    d,
                    "VLESS encryption (mlkem768x25519plus) is not supported by sing-box",
                );
                return None;
            }
            put!("uuid", json!(uuid));
            put!("flow", opt_s(&flow.clone().filter(|f| !f.is_empty())));
            put!("packet_encoding", opt_s(packet_encoding));
        }
        Protocol::Trojan { password } => put!("password", json!(password)),
        Protocol::Hysteria {
            auth,
            up,
            down,
            obfs,
            protocol,
            ports,
            recv_window_conn,
            recv_window,
            disable_mtu_discovery,
        } => {
            if protocol.as_deref().is_some_and(|x| x != "udp") {
                unsupported(
                    d,
                    &format!(
                        "Hysteria transport `{}` is not supported by sing-box",
                        protocol.as_deref().unwrap_or_default()
                    ),
                );
                return None;
            }
            if ports.is_some() {
                d.warn(
                    Kind::FieldDropped,
                    &loc,
                    Some("ports"),
                    "port hopping for Hysteria v1 is not supported by sing-box; uses `port` only",
                );
            }
            put!("auth_str", opt_s(auth));
            put!("up_mbps", if up.is_some() { mbps(up) } else { json!(10) });
            put!(
                "down_mbps",
                if down.is_some() {
                    mbps(down)
                } else {
                    json!(50)
                }
            );
            put!("obfs", opt_s(obfs));
            put!("recv_window_conn", opt_n(*recv_window_conn));
            put!("recv_window", opt_n(*recv_window));
            put!("disable_mtu_discovery", opt_b(*disable_mtu_discovery));
        }
        Protocol::Hysteria2 {
            password,
            ports,
            hop_interval,
            obfs,
            obfs_password,
            up,
            down,
        } => {
            put!("password", json!(password));
            if let Some(ps) = ports {
                let list: Vec<String> = ps
                    .split([',', '/'])
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(|x| {
                        if x.contains('-') {
                            x.replace('-', ":")
                        } else {
                            format!("{x}:{x}")
                        }
                    })
                    .collect();
                put!("server_ports", json!(list));
                put!(
                    "hop_interval",
                    hop_interval
                        .map(|h| json!(format!("{h}s")))
                        .unwrap_or(J::Null)
                );
            }
            if let Some(ob) = obfs {
                put!(
                    "obfs",
                    obj(vec![
                        ("type", json!(ob)),
                        ("password", opt_s(obfs_password))
                    ])
                );
            }
            put!("up_mbps", mbps(up));
            put!("down_mbps", mbps(down));
        }
        Protocol::Tuic {
            uuid,
            password,
            token,
            congestion_control,
            udp_relay_mode,
            zero_rtt,
            heartbeat,
        } => {
            if token.is_some() && uuid.is_none() {
                unsupported(d, "TUIC v4 (token) is not supported by sing-box, only v5");
                return None;
            }
            put!("uuid", opt_s(uuid));
            put!("password", opt_s(password));
            put!("congestion_control", opt_s(congestion_control));
            put!("udp_relay_mode", opt_s(udp_relay_mode));
            put!("zero_rtt_handshake", opt_b(*zero_rtt));
            put!("heartbeat", opt_s(heartbeat));
        }
        Protocol::AnyTls {
            password,
            idle_session_check_interval,
            idle_session_timeout,
            min_idle_session,
        } => {
            put!("password", json!(password));
            put!(
                "idle_session_check_interval",
                idle_session_check_interval
                    .map(|v| json!(format!("{v}s")))
                    .unwrap_or(J::Null)
            );
            put!(
                "idle_session_timeout",
                idle_session_timeout
                    .map(|v| json!(format!("{v}s")))
                    .unwrap_or(J::Null)
            );
            put!("min_idle_session", opt_n(*min_idle_session));
        }
        Protocol::WireGuard(wg) => {
            let mut addr = Vec::new();
            if let Some(ip) = &wg.ip {
                addr.push(if ip.contains('/') {
                    ip.clone()
                } else {
                    format!("{ip}/32")
                });
            }
            if let Some(ip) = &wg.ipv6 {
                addr.push(if ip.contains('/') {
                    ip.clone()
                } else {
                    format!("{ip}/128")
                });
            }
            if !wg.extra_peers.is_empty() {
                d.warn(
                    Kind::FieldDropped,
                    &loc,
                    Some("peers"),
                    format!(
                        "{} extra peer(s) dropped; only the first peer is converted",
                        wg.extra_peers.len()
                    ),
                );
            }
            let allowed = if wg.allowed_ips.is_empty() {
                vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
            } else {
                wg.allowed_ips.clone()
            };
            let peer = obj(vec![
                ("address", json!(p.server)),
                ("port", json!(p.port)),
                ("public_key", json!(wg.public_key)),
                ("pre_shared_key", opt_s(&wg.pre_shared_key)),
                ("allowed_ips", json!(allowed)),
                ("persistent_keepalive_interval", opt_n(wg.keepalive)),
                (
                    "reserved",
                    wg.reserved.as_ref().map(|r| json!(r)).unwrap_or(J::Null),
                ),
            ]);
            let ep = obj(vec![
                ("type", json!("wireguard")),
                ("tag", json!(p.name)),
                ("address", json!(addr)),
                ("private_key", json!(wg.private_key)),
                ("peers", json!([peer])),
                ("mtu", opt_n(wg.mtu)),
                ("detour", opt_s(&p.dial.detour)),
            ]);
            return Some(Out::Endpoint(ep));
        }
        Protocol::Ssh {
            user,
            password,
            private_key,
            private_key_passphrase,
            host_key,
            host_key_algorithms,
        } => {
            put!("user", json!(user));
            put!("password", opt_s(password));
            if let Some(k) = private_key {
                if k.contains("BEGIN") {
                    put!("private_key", json!(k));
                } else {
                    put!("private_key_path", json!(k));
                }
            }
            put!("private_key_passphrase", opt_s(private_key_passphrase));
            put!("host_key", strs(host_key));
            put!("host_key_algorithms", strs(host_key_algorithms));
        }
        Protocol::Socks5 { user, password } => {
            put!("version", json!("5"));
            put!("username", opt_s(user));
            put!("password", opt_s(password));
            if p.tls.as_ref().is_some_and(|t| t.enabled) {
                unsupported(d, "SOCKS5 over TLS is not supported by sing-box");
                return None;
            }
        }
        Protocol::Http {
            user,
            password,
            headers,
        } => {
            put!("username", opt_s(user));
            put!("password", opt_s(password));
            if !headers.is_empty() {
                let mut h = Map::new();
                for (k, v) in headers {
                    h.insert(k.clone(), json!(v));
                }
                put!("headers", J::Object(h));
            }
        }
        _ => unreachable!(),
    }
    if let Some(t) = &p.tls
        && t.enabled
        && !matches!(
            p.protocol,
            Protocol::Shadowsocks { .. } | Protocol::Ssh { .. }
        )
    {
        put!("tls", tls_json(t, p, d));
    }
    if let Some(tr) = &p.transport
        && matches!(
            p.protocol,
            Protocol::Vmess { .. } | Protocol::Vless { .. } | Protocol::Trojan { .. }
        )
    {
        match transport_json(tr, p, d) {
            Ok(j) => put!("transport", j),
            Err(e) => {
                unsupported(d, &e);
                return None;
            }
        }
    }
    if p.udp == Some(false)
        && !matches!(
            p.protocol,
            Protocol::Hysteria { .. } | Protocol::Hysteria2 { .. } | Protocol::Tuic { .. }
        )
    {
        put!("network", json!("tcp"));
    }
    // smux (mihomo) -> multiplex
    if let Some(Value::Map(sm)) = p
        .extra
        .iter()
        .find(|(k, _)| k == "smux")
        .map(|(_, v)| v.clone())
        && crate::value::get(&sm, "enabled").and_then(Value::as_bool) == Some(true)
    {
        let g = |k: &str| crate::value::get(&sm, k);
        put!(
            "multiplex",
            obj(vec![
                ("enabled", json!(true)),
                (
                    "protocol",
                    g("protocol")
                        .and_then(Value::as_string)
                        .map(|s| json!(s))
                        .unwrap_or(J::Null)
                ),
                (
                    "max_connections",
                    g("max-connections")
                        .and_then(Value::as_u64)
                        .map(|n| json!(n))
                        .unwrap_or(J::Null)
                ),
                (
                    "min_streams",
                    g("min-streams")
                        .and_then(Value::as_u64)
                        .map(|n| json!(n))
                        .unwrap_or(J::Null)
                ),
                (
                    "max_streams",
                    g("max-streams")
                        .and_then(Value::as_u64)
                        .map(|n| json!(n))
                        .unwrap_or(J::Null)
                ),
                (
                    "padding",
                    g("padding")
                        .and_then(Value::as_bool)
                        .map(J::Bool)
                        .unwrap_or(J::Null)
                ),
            ]),
        );
    }
    let dl = &p.dial;
    if !o.contains_key("detour") {
        put!("detour", opt_s(&dl.detour));
    }
    put!("bind_interface", opt_s(&dl.interface));
    put!("routing_mark", opt_n(dl.routing_mark));
    put!("tcp_fast_open", opt_b(dl.tfo));
    put!("tcp_multi_path", opt_b(dl.mptcp));
    if let Some(v) = &dl.ip_version {
        let strategy = match v.as_str() {
            "ipv4" => Some("ipv4_only"),
            "ipv6" => Some("ipv6_only"),
            "ipv4-prefer" | "prefer_ipv4" => Some("prefer_ipv4"),
            "ipv6-prefer" | "prefer_ipv6" => Some("prefer_ipv6"),
            _ => None,
        };
        if let Some(s) = strategy
            && p.server.parse::<std::net::IpAddr>().is_err()
        {
            put!(
                "domain_resolver",
                json!({"server": resolver, "strategy": s})
            );
        }
    }
    let mut list = vec![J::Object(o)];
    list.extend(extra_out);
    Some(Out::Outbound(list))
}

use crate::value::Value;

// ------------------------------------------------------------------ DNS

struct DnsBuild {
    servers: Vec<J>,
    by_url: HashMap<String, String>,
    n: usize,
}

impl DnsBuild {
    /// Adds a server from a mihomo DNS URL; returns its tag.
    fn add(
        &mut self,
        url: &str,
        bootstrap: &Option<String>,
        d: &mut Diagnostics,
        tags: &HashSet<String>,
    ) -> Option<String> {
        if let Some(t) = self.by_url.get(url) {
            return Some(t.clone());
        }
        let (addr, frag) = match url.split_once('#') {
            Some((a, f)) => (a.trim(), Some(f.trim())),
            None => (url.trim(), None),
        };
        let (scheme, rest) = match addr.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => ("udp".to_string(), addr),
        };
        let tag = format!("dns-{}", self.n);
        let mut detour = None;
        if let Some(f) = frag {
            for part in f.split('&') {
                if part.contains('=') {
                    continue; // h3=true / ecs=... options
                }
                if part != DIRECT && !part.is_empty() {
                    if tags.contains(part) {
                        detour = Some(part.to_string());
                    } else {
                        d.warn(
                            Kind::FieldDropped,
                            "dns",
                            Some("nameserver"),
                            format!("{url}: proxy {part:?} does not exist; queried directly"),
                        );
                    }
                }
            }
        }
        let split_host_port = |hp: &str, default: u16| -> (String, Option<u16>) {
            if let Some(h) = hp.strip_prefix('[') {
                let end = h.find(']').unwrap_or(h.len());
                let port = h.get(end + 2..).and_then(|p| p.parse().ok());
                return (h[..end].to_string(), port.filter(|&p| p != default));
            }
            match hp.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => {
                    (h.to_string(), p.parse().ok().filter(|&p| p != default))
                }
                _ => (hp.to_string(), None),
            }
        };
        let mut server = match scheme.as_str() {
            "system" | "local" => json!({"type": "local", "tag": tag}),
            "dhcp" => {
                let iface = rest.trim_matches('/');
                obj(vec![
                    ("type", json!("dhcp")),
                    ("tag", json!(tag)),
                    (
                        "interface",
                        if iface == "auto" || iface == "system" || iface.is_empty() {
                            J::Null
                        } else {
                            json!(iface)
                        },
                    ),
                ])
            }
            "udp" | "tcp" | "tls" | "quic" => {
                let default = match scheme.as_str() {
                    "tls" | "quic" => 853,
                    _ => 53,
                };
                let (h, port) = split_host_port(rest.trim_end_matches('/'), default);
                obj(vec![
                    ("type", json!(scheme)),
                    ("tag", json!(tag)),
                    ("server", json!(h)),
                    ("server_port", opt_n(port)),
                ])
            }
            "https" | "h3" => {
                let (hp, path) = match rest.find('/') {
                    Some(i) => (&rest[..i], &rest[i..]),
                    None => (rest, "/dns-query"),
                };
                let (h, port) = split_host_port(hp, 443);
                obj(vec![
                    ("type", json!(scheme)),
                    ("tag", json!(tag)),
                    ("server", json!(h)),
                    ("server_port", opt_n(port)),
                    (
                        "path",
                        if path == "/dns-query" {
                            J::Null
                        } else {
                            json!(path)
                        },
                    ),
                ])
            }
            "rcode" => return None,
            other => {
                d.warn(
                    Kind::FieldDropped,
                    "dns",
                    Some("nameserver"),
                    format!("{url}: DNS scheme `{other}` is not supported; skipped"),
                );
                return None;
            }
        };
        let host = server
            .get("server")
            .and_then(J::as_str)
            .unwrap_or("")
            .to_string();
        let o = server.as_object_mut().unwrap();
        if !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
            match bootstrap {
                Some(b) => {
                    o.insert("domain_resolver".into(), json!(b));
                }
                None => {
                    o.insert("domain_resolver".into(), json!("dns-local"));
                }
            }
        }
        if let Some(det) = detour {
            o.insert("detour".into(), json!(det));
        }
        self.n += 1;
        self.servers.push(server);
        self.by_url.insert(url.to_string(), tag.clone());
        Some(tag)
    }
}

fn dns_json(cfg: &Config, fakeip: bool, ctx: &mut Ctx) -> (J, String) {
    let proxy_tags: HashSet<String> = cfg
        .proxies
        .iter()
        .map(|p| p.name.clone())
        .chain(cfg.groups.iter().map(|g| g.name.clone()))
        .collect();
    let mut b = DnsBuild {
        servers: Vec::new(),
        by_url: HashMap::new(),
        n: 0,
    };
    let local = json!({"type": "local", "tag": "dns-local"});
    let Some(dns) = cfg.dns.as_ref().filter(|x| x.enable) else {
        return (
            json!({"servers": [local], "final": "dns-local"}),
            "dns-local".into(),
        );
    };
    let d = &mut *ctx.d;
    // bootstrap: first plain-IP server from default-nameserver
    let mut bootstrap = None;
    for u in &dns.default_nameserver {
        if let Some(t) = b.add(u, &None, d, &proxy_tags) {
            bootstrap = Some(t);
            break;
        }
    }
    let mut need_local = bootstrap.is_none();
    let main: Vec<String> = dns
        .nameserver
        .iter()
        .filter_map(|u| b.add(u, &bootstrap, d, &proxy_tags))
        .collect();
    if dns.nameserver.len() > 1 {
        d.info(Kind::Approximated, "dns", Some("nameserver"), "sing-box queries one server per rule; the first nameserver is the default, others are kept for policy use");
    }
    if !dns.fallback.is_empty() {
        d.warn(
            Kind::Approximated,
            "dns",
            Some("fallback"),
            "sing-box has no fallback/fallback-filter; fallback servers are not used",
        );
    }
    let final_tag = main
        .first()
        .cloned()
        .or_else(|| bootstrap.clone())
        .unwrap_or_else(|| {
            need_local = true;
            "dns-local".into()
        });
    let resolver = if dns.proxy_server_nameserver.is_empty() {
        bootstrap.clone().unwrap_or_else(|| {
            need_local = true;
            "dns-local".into()
        })
    } else {
        dns.proxy_server_nameserver
            .iter()
            .find_map(|u| b.add(u, &bootstrap, d, &proxy_tags))
            .unwrap_or_else(|| {
                need_local = true;
                "dns-local".into()
            })
    };
    if !dns.direct_nameserver.is_empty() {
        d.info(
            Kind::Approximated,
            "dns",
            Some("direct-nameserver"),
            "no sing-box equivalent; DIRECT connections use the normal DNS rules",
        );
    }
    if dns.respect_rules == Some(true) {
        d.info(
            Kind::Approximated,
            "dns",
            Some("respect-rules"),
            "no sing-box equivalent; use `detour` on DNS servers instead",
        );
    }

    let mut rules: Vec<J> = Vec::new();
    // hosts
    let mut predefined = Map::new();
    for (h, ips) in &cfg.hosts {
        if h.contains('*') || h.starts_with("+.") {
            d.warn(
                Kind::FieldDropped,
                "hosts",
                None,
                format!("wildcard host {h:?} is not supported by the sing-box hosts server"),
            );
            continue;
        }
        predefined.insert(h.clone(), json!(ips));
    }
    if !predefined.is_empty() && dns.use_hosts != Some(false) {
        let names: Vec<String> = predefined.keys().cloned().collect();
        b.servers
            .push(json!({"type": "hosts", "tag": "dns-hosts", "predefined": predefined}));
        rules.push(json!({"domain": names, "server": "dns-hosts"}));
    }
    // nameserver-policy
    for (pat, servers) in &dns.nameserver_policy {
        let Some(tag) = servers
            .iter()
            .find_map(|u| b.add(u, &bootstrap, d, &proxy_tags))
        else {
            continue;
        };
        for one in pat.split(',') {
            let one = one.trim();
            let body = if let Some(g) = one.strip_prefix("geosite:") {
                let mut tags = Vec::new();
                for name in g.split(',') {
                    let t = format!("geosite-{}", name.trim().to_ascii_lowercase());
                    ctx_add_set(
                        &mut ctx.rule_sets,
                        &mut ctx.rule_set_tags,
                        &t,
                        rulesets::geosite_srs(name.trim()),
                    );
                    tags.push(t);
                }
                json!({"rule_set": tags})
            } else if let Some(rs) = one.strip_prefix("rule-set:") {
                // resolved later: only valid if the provider converts
                json!({"rule_set": [rs], "_provider": rs})
            } else {
                let (mut dom, mut suf, mut re) = (Vec::new(), Vec::new(), Vec::new());
                domain_entry(one, &mut dom, &mut suf, &mut re);
                obj(vec![
                    ("domain", strs(&dom)),
                    ("domain_suffix", strs(&suf)),
                    ("domain_regex", strs(&re)),
                ])
            };
            let mut body = body;
            body.as_object_mut()
                .unwrap()
                .insert("server".into(), json!(tag));
            rules.push(body);
        }
    }
    let mut servers_tail = Vec::new();
    if fakeip {
        if !dns.fake_ip_filter.is_empty() {
            let (mut dom, mut suf, mut re, mut sets) =
                (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for f in &dns.fake_ip_filter {
                if let Some(g) = f.strip_prefix("geosite:") {
                    let t = format!("geosite-{}", g.to_ascii_lowercase());
                    ctx_add_set(
                        &mut ctx.rule_sets,
                        &mut ctx.rule_set_tags,
                        &t,
                        rulesets::geosite_srs(g),
                    );
                    sets.push(t);
                } else if let Some(rs) = f.strip_prefix("rule-set:") {
                    sets.push(rs.to_string());
                } else {
                    domain_entry(f, &mut dom, &mut suf, &mut re);
                }
            }
            let whitelist = dns.fake_ip_filter_mode.as_deref() == Some("whitelist");
            let mut r = obj(vec![
                ("domain", strs(&dom)),
                ("domain_suffix", strs(&suf)),
                ("domain_regex", strs(&re)),
                ("rule_set", strs(&sets)),
            ]);
            r.as_object_mut().unwrap().insert(
                "server".into(),
                json!(if whitelist {
                    "dns-fakeip"
                } else {
                    final_tag.as_str()
                }),
            );
            if whitelist {
                r.as_object_mut()
                    .unwrap()
                    .insert("query_type".into(), json!(["A", "AAAA"]));
            }
            rules.push(r);
            if whitelist {
                d.info(
                    Kind::Approximated,
                    "dns",
                    Some("fake-ip-filter-mode"),
                    "whitelist mode: only listed domains get fake IPs",
                );
            }
        }
        if dns.fake_ip_filter_mode.as_deref() != Some("whitelist") {
            rules.push(json!({"query_type": ["A", "AAAA"], "server": "dns-fakeip"}));
        }
        servers_tail.push(obj(vec![
            ("type", json!("fakeip")),
            ("tag", json!("dns-fakeip")),
            (
                "inet4_range",
                json!(
                    dns.fake_ip_range
                        .clone()
                        .unwrap_or_else(|| "198.18.0.1/16".into())
                ),
            ),
            ("inet6_range", opt_s(&dns.fake_ip_range6)),
        ]));
    }
    if need_local
        || b.servers
            .iter()
            .any(|s| s.get("domain_resolver").and_then(J::as_str) == Some("dns-local"))
    {
        b.servers.push(local);
    }
    b.servers.extend(servers_tail);
    let strategy = match (dns.ipv6, cfg.general.ipv6) {
        (Some(false), _) => Some("ipv4_only"),
        _ => None,
    };
    // rule-set references in DNS rules must exist; providers convert later, so keep a marker
    (
        obj(vec![
            ("servers", J::Array(b.servers)),
            (
                "rules",
                if rules.is_empty() {
                    J::Null
                } else {
                    J::Array(rules)
                },
            ),
            ("final", json!(final_tag)),
            ("strategy", strategy.map(|s| json!(s)).unwrap_or(J::Null)),
        ]),
        resolver,
    )
}

fn ctx_add_set(sets: &mut Vec<J>, tags: &mut HashSet<String>, tag: &str, url: String) {
    if tags.insert(tag.to_string()) {
        sets.push(json!({"type": "remote", "tag": tag, "format": "binary", "url": url}));
    }
}

/// Drops DNS rule-set references to rule sets that do not exist (Clash
/// providers that could not be converted).
fn fix_dns_rule_set_refs(root: &mut J, d: &mut Diagnostics) {
    let known: HashSet<String> = root
        .pointer("/route/rule_set")
        .and_then(J::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|r| r.get("tag").and_then(J::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let Some(rules) = root
        .get_mut("dns")
        .and_then(|x| x.get_mut("rules"))
        .and_then(J::as_array_mut)
    else {
        return;
    };
    rules.retain_mut(|r| {
        let o = r.as_object_mut().unwrap();
        o.remove("_provider");
        let Some(sets) = o.get_mut("rule_set").and_then(J::as_array_mut) else {
            return true;
        };
        sets.retain(|t| {
            let t = t.as_str().unwrap_or_default();
            let ok = known.contains(t);
            if !ok {
                d.warn(
                    Kind::FieldDropped,
                    "dns",
                    None,
                    format!("rule-set:{t} could not be converted; removed from the DNS rule"),
                );
            }
            ok
        });
        if sets.is_empty() {
            o.remove("rule_set");
            // nothing left to match on: drop the rule rather than match everything
            return o
                .keys()
                .any(|k| !matches!(k.as_str(), "server" | "query_type" | "action"));
        }
        true
    });
}

// -------------------------------------------------------------- inbounds

fn inbounds_json(cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> Vec<J> {
    let g = &cfg.general;
    let listen = if g.allow_lan == Some(true) {
        g.bind_address
            .clone()
            .filter(|b| b != "*")
            .unwrap_or_else(|| "::".into())
    } else {
        "127.0.0.1".into()
    };
    let mut v = Vec::new();
    let mut add = |ty: &str, tag: &str, port: Option<u16>| {
        if let Some(p) = port {
            v.push(json!({"type": ty, "tag": tag, "listen": listen, "listen_port": p}));
        }
    };
    add("mixed", "mixed-in", g.mixed_port);
    add("http", "http-in", g.http_port);
    add("socks", "socks-in", g.socks_port);
    add("redirect", "redir-in", g.redir_port);
    add("tproxy", "tproxy-in", g.tproxy_port);
    if let Some(t) = cfg.tun.as_ref().filter(|t| t.enable) {
        let mut addr: Vec<String> = t
            .inet4_address
            .iter()
            .chain(t.inet6_address.iter())
            .cloned()
            .collect();
        if addr.is_empty() {
            addr = vec!["172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into()];
        }
        let stack = t.stack.as_deref().map(|s| s.to_ascii_lowercase());
        v.push(obj(vec![
            ("type", json!("tun")),
            ("tag", json!("tun-in")),
            ("interface_name", opt_s(&t.device)),
            ("address", json!(addr)),
            ("mtu", opt_n(t.mtu)),
            ("auto_route", json!(t.auto_route.unwrap_or(true))),
            ("strict_route", opt_b(t.strict_route)),
            ("stack", opt_s(&stack)),
            ("route_address", strs(&t.route_address)),
            ("route_exclude_address", strs(&t.route_exclude_address)),
        ]));
    }
    if v.is_empty() && opts.add_defaults {
        d.info(
            Kind::Repaired,
            "inbounds",
            None,
            "the input has no listening ports; added a mixed inbound on 127.0.0.1:7890",
        );
        v.push(
            json!({"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}),
        );
    }
    v
}
