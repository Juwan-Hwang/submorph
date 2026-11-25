//! sing-box configuration input (outbounds, endpoints, route rules, rule sets,
//! DNS and inbounds), written from the public sing-box configuration docs.

use crate::diag::{Diagnostics, Kind, proxy_loc};
use crate::model::*;
use serde_json::Value as J;

fn st(o: &J, k: &str) -> Option<String> {
    match o.get(k)? {
        J::String(s) if !s.is_empty() => Some(s.clone()),
        J::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
fn bo(o: &J, k: &str) -> Option<bool> {
    o.get(k).and_then(J::as_bool)
}
fn nu(o: &J, k: &str) -> Option<u64> {
    o.get(k).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}
fn strs(o: &J, k: &str) -> Vec<String> {
    match o.get(k) {
        Some(J::Array(a)) => a
            .iter()
            .filter_map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .or_else(|| x.as_u64().map(|n| n.to_string()))
            })
            .collect(),
        Some(J::String(s)) => vec![s.clone()],
        Some(J::Number(n)) => vec![n.to_string()],
        _ => Vec::new(),
    }
}
/// Durations like `30s`, `5m`, `1h` to seconds.
fn secs(o: &J, k: &str) -> Option<u64> {
    let s = st(o, k)?;
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().ok()?;
    Some(match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "ms" => n.div_ceil(1000),
        _ => return None,
    })
}

/// Builds a [`Config`] from a sing-box JSON document.
pub fn from_json(j: &J, d: &mut Diagnostics) -> Config {
    let mut cfg = Config {
        source: SourceFormat::SingBox,
        ..Default::default()
    };
    let outs: Vec<J> = j
        .get("outbounds")
        .and_then(J::as_array)
        .cloned()
        .unwrap_or_default();
    let eps: Vec<J> = j
        .get("endpoints")
        .and_then(J::as_array)
        .cloned()
        .unwrap_or_default();
    // shadowtls outbounds wrap shadowsocks via `detour`
    let shadowtls: Vec<&J> = outs
        .iter()
        .filter(|o| st(o, "type").as_deref() == Some("shadowtls"))
        .collect();
    let mut block_tags = Vec::new();
    let mut direct_tags = Vec::new();
    for o in outs.iter().chain(eps.iter()) {
        let ty = st(o, "type").unwrap_or_default();
        let tag = st(o, "tag").unwrap_or_else(|| ty.clone());
        match ty.as_str() {
            "selector" | "urltest" => {
                let mut members = strs(o, "outbounds");
                if let Some(def) = st(o, "default")
                    && let Some(i) = members.iter().position(|m| *m == def)
                {
                    let m = members.remove(i);
                    members.insert(0, m);
                }
                cfg.groups.push(Group {
                    name: tag,
                    kind: if ty == "selector" {
                        GroupKind::Select
                    } else {
                        GroupKind::UrlTest
                    },
                    members,
                    use_providers: Vec::new(),
                    url: st(o, "url"),
                    interval: secs(o, "interval"),
                    tolerance: nu(o, "tolerance"),
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
                });
            }
            "direct" => direct_tags.push(tag),
            "block" => block_tags.push(tag),
            "dns" | "shadowtls" => {}
            _ => match outbound(o, &ty, &tag, &shadowtls) {
                Ok(p) => crate::input::clash::push_unique(&mut cfg.proxies, p, d),
                Err(e) => d.error(Kind::Invalid, proxy_loc(&tag), None, e),
            },
        }
    }
    // Map special tags to Clash built-ins in group members.
    for g in &mut cfg.groups {
        for m in &mut g.members {
            if direct_tags.contains(m) {
                *m = "DIRECT".into();
            } else if block_tags.contains(m) {
                *m = "REJECT".into();
            }
        }
    }
    let fix_target = |t: String| -> String {
        if direct_tags.contains(&t) {
            "DIRECT".into()
        } else if block_tags.contains(&t) {
            "REJECT".into()
        } else {
            t
        }
    };
    if let Some(route) = j.get("route") {
        for rs in route
            .get("rule_set")
            .and_then(J::as_array)
            .cloned()
            .unwrap_or_default()
        {
            cfg.rule_providers.push(rule_set(&rs));
        }
        for (i, r) in route
            .get("rules")
            .and_then(J::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let action = st(r, "action").unwrap_or_else(|| "route".into());
            let target = match action.as_str() {
                "route" => match st(r, "outbound") {
                    Some(t) => fix_target(t),
                    None => continue,
                },
                "reject" => {
                    if st(r, "method").as_deref() == Some("drop") {
                        "REJECT-DROP".into()
                    } else {
                        "REJECT".into()
                    }
                }
                // sniff / resolve / hijack-dns / route-options have no Clash rule equivalent
                _ => continue,
            };
            if r.get("protocol").and_then(J::as_str) == Some("dns") || r.get("clash_mode").is_some()
            {
                continue;
            }
            match rule_to_matchers(r) {
                Some(ms) => {
                    for m in ms {
                        cfg.rules.push(Rule {
                            matcher: m,
                            target: target.clone(),
                            no_resolve: false,
                            src: false,
                            raw: format!("route.rules[{i}]"),
                        });
                    }
                }
                None => d.warn(
                    Kind::Unsupported,
                    format!("route.rules[{i}]"),
                    None,
                    "rule has no field that converts",
                ),
            }
        }
        if let Some(f) = st(route, "final") {
            cfg.rules.push(Rule {
                matcher: Matcher::Match,
                target: fix_target(f),
                no_resolve: false,
                src: false,
                raw: "route.final".into(),
            });
        }
    }
    if let Some(dns) = j.get("dns") {
        cfg.dns = Some(parse_dns(dns));
    }
    for ib in j
        .get("inbounds")
        .and_then(J::as_array)
        .cloned()
        .unwrap_or_default()
    {
        match st(&ib, "type").as_deref() {
            Some("mixed") => cfg.general.mixed_port = nu(&ib, "listen_port").map(|p| p as u16),
            Some("http") => cfg.general.http_port = nu(&ib, "listen_port").map(|p| p as u16),
            Some("socks") => cfg.general.socks_port = nu(&ib, "listen_port").map(|p| p as u16),
            Some("tun") => {
                let addrs = strs(&ib, "address");
                cfg.tun = Some(Tun {
                    enable: true,
                    stack: st(&ib, "stack"),
                    auto_route: bo(&ib, "auto_route"),
                    strict_route: bo(&ib, "strict_route"),
                    mtu: nu(&ib, "mtu").map(|v| v as u32),
                    device: st(&ib, "interface_name"),
                    inet4_address: addrs.iter().filter(|a| !a.contains(':')).cloned().collect(),
                    inet6_address: addrs.iter().filter(|a| a.contains(':')).cloned().collect(),
                    route_address: strs(&ib, "route_address"),
                    route_exclude_address: strs(&ib, "route_exclude_address"),
                    ..Default::default()
                });
            }
            _ => {}
        }
        if bo(&ib, "listen").is_none()
            && st(&ib, "listen").is_some_and(|l| l == "0.0.0.0" || l == "::")
        {
            cfg.general.allow_lan = Some(true);
        }
    }
    if let Some(api) = j.get("experimental").and_then(|e| e.get("clash_api")) {
        cfg.general.external_controller = st(api, "external_controller");
        cfg.general.secret = st(api, "secret");
        cfg.general.mode = st(api, "default_mode").map(|m| m.to_ascii_lowercase());
    }
    if let Some(l) = j.get("log") {
        cfg.general.log_level = st(l, "level");
    }
    cfg
}

fn tls_of(o: &J) -> Option<Tls> {
    let t = o.get("tls")?;
    if bo(t, "enabled") != Some(true) {
        return None;
    }
    let reality = t
        .get("reality")
        .filter(|r| bo(r, "enabled") == Some(true))
        .map(|r| Reality {
            public_key: st(r, "public_key").unwrap_or_default(),
            short_id: st(r, "short_id").unwrap_or_default(),
        });
    let ech = t
        .get("ech")
        .filter(|e| bo(e, "enabled") == Some(true))
        .map(|e| EchOpts {
            enable: true,
            config: {
                let lines = strs(e, "config");
                let body: String = lines
                    .iter()
                    .filter(|l| !l.starts_with("-----"))
                    .cloned()
                    .collect();
                if body.is_empty() { None } else { Some(body) }
            },
        });
    Some(Tls {
        enabled: true,
        sni: st(t, "server_name"),
        insecure: bo(t, "insecure"),
        alpn: strs(t, "alpn"),
        utls: t
            .get("utls")
            .filter(|u| bo(u, "enabled") == Some(true))
            .map(|u| st(u, "fingerprint").unwrap_or_else(|| "chrome".into())),
        cert_fingerprint: None,
        reality,
        ech,
        client_cert: None,
        client_key: None,
    })
}

fn transport_of(o: &J) -> Option<Transport> {
    let t = o.get("transport")?;
    let hdrs = |t: &J| -> (Option<String>, Vec<(String, String)>) {
        let mut host = st(t, "host");
        let mut out = Vec::new();
        if let Some(J::Object(h)) = t.get("headers") {
            for (k, v) in h {
                let v = v.as_str().map(str::to_string).or_else(|| {
                    v.as_array()
                        .and_then(|a| a.first())
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                });
                if let Some(v) = v {
                    if k.eq_ignore_ascii_case("host") {
                        host = Some(v);
                    } else {
                        out.push((k.clone(), v));
                    }
                }
            }
        }
        (host, out)
    };
    match st(t, "type")?.as_str() {
        "ws" => {
            let (host, headers) = hdrs(t);
            Some(Transport::Ws {
                path: st(t, "path").unwrap_or_else(|| "/".into()),
                host,
                headers,
                max_early_data: nu(t, "max_early_data").map(|v| v as u32),
                early_data_header: st(t, "early_data_header_name"),
            })
        }
        "httpupgrade" => {
            let (host, headers) = hdrs(t);
            Some(Transport::HttpUpgrade {
                path: st(t, "path").unwrap_or_else(|| "/".into()),
                host,
                headers,
            })
        }
        "grpc" => Some(Transport::Grpc {
            service_name: st(t, "service_name").unwrap_or_default(),
        }),
        "http" => {
            let hosts = strs(t, "host");
            if st(t, "method").is_some()
                || o.get("tls")
                    .and_then(|x| x.get("enabled"))
                    .and_then(J::as_bool)
                    != Some(true)
            {
                Some(Transport::Http {
                    method: st(t, "method"),
                    paths: strs(t, "path"),
                    hosts,
                    headers: Vec::new(),
                })
            } else {
                Some(Transport::H2 {
                    hosts,
                    path: st(t, "path").unwrap_or_else(|| "/".into()),
                })
            }
        }
        "quic" => Some(Transport::Quic),
        _ => None,
    }
}

fn outbound(o: &J, ty: &str, tag: &str, shadowtls: &[&J]) -> Result<Proxy, String> {
    let mut server = st(o, "server").unwrap_or_default();
    let mut port = nu(o, "server_port").unwrap_or(0) as u16;
    let mut tls = tls_of(o);
    let protocol = match ty {
        "shadowsocks" => {
            let mut plugin = match st(o, "plugin").as_deref() {
                Some("obfs-local") => {
                    let opts = st(o, "plugin_opts").unwrap_or_default();
                    let kv: Vec<(&str, &str)> =
                        opts.split(';').filter_map(|p| p.split_once('=')).collect();
                    let g = |k: &str| kv.iter().find(|(a, _)| *a == k).map(|(_, b)| b.to_string());
                    Some(SsPlugin::Obfs {
                        mode: g("obfs").unwrap_or_else(|| "http".into()),
                        host: g("obfs-host"),
                    })
                }
                Some("v2ray-plugin") => {
                    let opts = st(o, "plugin_opts").unwrap_or_default();
                    let parts: Vec<&str> = opts.split(';').collect();
                    let g = |k: &str| {
                        parts
                            .iter()
                            .find_map(|p| p.strip_prefix(&format!("{k}=")).map(str::to_string))
                    };
                    Some(SsPlugin::V2ray {
                        mode: g("mode").unwrap_or_else(|| "websocket".into()),
                        tls: parts.contains(&"tls"),
                        host: g("host"),
                        path: g("path"),
                        mux: None,
                        skip_cert_verify: None,
                    })
                }
                _ => None,
            };
            if let Some(det) = st(o, "detour")
                && let Some(stls) = shadowtls
                    .iter()
                    .find(|s| st(s, "tag").as_deref() == Some(det.as_str()))
            {
                server = st(stls, "server").unwrap_or(server);
                port = nu(stls, "server_port").map(|p| p as u16).unwrap_or(port);
                plugin = Some(SsPlugin::ShadowTls {
                    host: stls
                        .get("tls")
                        .and_then(|t| st(t, "server_name"))
                        .unwrap_or_default(),
                    password: st(stls, "password"),
                    version: nu(stls, "version").unwrap_or(1) as u8,
                });
                tls = None;
            }
            Protocol::Shadowsocks {
                cipher: st(o, "method").ok_or("missing `method`")?,
                password: st(o, "password").unwrap_or_default(),
                plugin,
                udp_over_tcp: o.get("udp_over_tcp").map(|u| {
                    u.as_bool()
                        .unwrap_or_else(|| bo(u, "enabled").unwrap_or(false))
                }),
                udp_over_tcp_version: o
                    .get("udp_over_tcp")
                    .and_then(|u| nu(u, "version"))
                    .map(|v| v as u8),
            }
        }
        "vmess" => Protocol::Vmess {
            uuid: st(o, "uuid").ok_or("missing `uuid`")?,
            alter_id: nu(o, "alter_id").unwrap_or(0) as u32,
            security: st(o, "security").unwrap_or_else(|| "auto".into()),
            global_padding: bo(o, "global_padding"),
            authenticated_length: bo(o, "authenticated_length"),
            packet_encoding: st(o, "packet_encoding"),
        },
        "vless" => Protocol::Vless {
            uuid: st(o, "uuid").ok_or("missing `uuid`")?,
            flow: st(o, "flow"),
            packet_encoding: st(o, "packet_encoding"),
            encryption: None,
        },
        "trojan" => Protocol::Trojan {
            password: st(o, "password").ok_or("missing `password`")?,
        },
        "hysteria" => Protocol::Hysteria {
            auth: st(o, "auth_str"),
            up: nu(o, "up_mbps").map(|v| format!("{v} Mbps")),
            down: nu(o, "down_mbps").map(|v| format!("{v} Mbps")),
            obfs: st(o, "obfs"),
            protocol: None,
            ports: None,
            recv_window_conn: nu(o, "recv_window_conn"),
            recv_window: nu(o, "recv_window"),
            disable_mtu_discovery: bo(o, "disable_mtu_discovery"),
        },
        "hysteria2" => {
            let ports = strs(o, "server_ports")
                .iter()
                .map(|p| p.replace(':', "-"))
                .collect::<Vec<_>>();
            Protocol::Hysteria2 {
                password: st(o, "password").unwrap_or_default(),
                ports: if ports.is_empty() {
                    None
                } else {
                    Some(ports.join(","))
                },
                hop_interval: secs(o, "hop_interval"),
                obfs: o.get("obfs").and_then(|x| st(x, "type")),
                obfs_password: o.get("obfs").and_then(|x| st(x, "password")),
                up: nu(o, "up_mbps").map(|v| format!("{v} Mbps")),
                down: nu(o, "down_mbps").map(|v| format!("{v} Mbps")),
            }
        }
        "tuic" => Protocol::Tuic {
            uuid: st(o, "uuid"),
            password: st(o, "password"),
            token: None,
            congestion_control: st(o, "congestion_control"),
            udp_relay_mode: st(o, "udp_relay_mode"),
            zero_rtt: bo(o, "zero_rtt_handshake"),
            heartbeat: st(o, "heartbeat"),
        },
        "anytls" => Protocol::AnyTls {
            password: st(o, "password").ok_or("missing `password`")?,
            idle_session_check_interval: secs(o, "idle_session_check_interval"),
            idle_session_timeout: secs(o, "idle_session_timeout"),
            min_idle_session: nu(o, "min_idle_session"),
        },
        "wireguard" => {
            let peer = o
                .get("peers")
                .and_then(J::as_array)
                .and_then(|a| a.first())
                .cloned()
                .unwrap_or_else(|| o.clone());
            if server.is_empty() {
                server = st(&peer, "address")
                    .or_else(|| st(&peer, "server"))
                    .unwrap_or_default();
                port = nu(&peer, "port")
                    .or_else(|| nu(&peer, "server_port"))
                    .unwrap_or(0) as u16;
            }
            let addrs = {
                let a = strs(o, "address");
                if a.is_empty() {
                    strs(o, "local_address")
                } else {
                    a
                }
            };
            let strip = |a: &String| a.split('/').next().unwrap_or(a).to_string();
            Protocol::WireGuard(WireGuard {
                private_key: st(o, "private_key").ok_or("missing `private_key`")?,
                public_key: st(&peer, "public_key")
                    .or_else(|| st(o, "peer_public_key"))
                    .ok_or("missing peer `public_key`")?,
                pre_shared_key: st(&peer, "pre_shared_key"),
                ip: addrs.iter().find(|a| !a.contains(':')).map(strip),
                ipv6: addrs.iter().find(|a| a.contains(':')).map(strip),
                allowed_ips: strs(&peer, "allowed_ips"),
                reserved: peer.get("reserved").and_then(J::as_array).map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_u64().map(|n| n as u8))
                        .collect()
                }),
                mtu: nu(o, "mtu").map(|v| v as u32),
                keepalive: nu(&peer, "persistent_keepalive_interval").map(|v| v as u32),
                extra_peers: Vec::new(),
            })
        }
        "ssh" => Protocol::Ssh {
            user: st(o, "user").unwrap_or_else(|| "root".into()),
            password: st(o, "password"),
            private_key: {
                let k = strs(o, "private_key");
                if k.is_empty() {
                    None
                } else {
                    Some(k.join("\n"))
                }
            },
            private_key_passphrase: st(o, "private_key_passphrase"),
            host_key: strs(o, "host_key"),
            host_key_algorithms: strs(o, "host_key_algorithms"),
        },
        "socks" => Protocol::Socks5 {
            user: st(o, "username"),
            password: st(o, "password"),
        },
        "http" => Protocol::Http {
            user: st(o, "username"),
            password: st(o, "password"),
            headers: Vec::new(),
        },
        other => return Err(format!("outbound type `{other}` is not supported")),
    };
    if server.is_empty() || port == 0 {
        return Err("missing `server` or `server_port`".into());
    }
    let udp = match strs(o, "network").as_slice() {
        [n] if n == "tcp" => Some(false),
        _ => None,
    };
    Ok(Proxy {
        name: tag.to_string(),
        server,
        port,
        protocol,
        transport: transport_of(o),
        tls,
        udp,
        dial: Dial {
            interface: st(o, "bind_interface"),
            routing_mark: nu(o, "routing_mark").map(|v| v as u32),
            tfo: bo(o, "tcp_fast_open"),
            mptcp: bo(o, "tcp_multi_path"),
            ip_version: st(o, "domain_strategy").map(|s| match s.as_str() {
                "prefer_ipv4" => "ipv4-prefer".into(),
                "prefer_ipv6" => "ipv6-prefer".into(),
                "ipv4_only" => "ipv4".into(),
                "ipv6_only" => "ipv6".into(),
                other => other.to_string(),
            }),
            detour: st(o, "detour").filter(|_| ty != "shadowsocks" || shadowtls.is_empty()),
        },
        extra: Vec::new(),
    })
}

fn rule_set(rs: &J) -> RuleProvider {
    let tag = st(rs, "tag").unwrap_or_default();
    let kind = st(rs, "type").unwrap_or_else(|| "remote".into());
    let mut payload = Vec::new();
    let mut behavior = "classical".to_string();
    if kind == "inline" {
        for r in rs
            .get("rules")
            .and_then(J::as_array)
            .cloned()
            .unwrap_or_default()
        {
            for m in rule_to_matchers(&r).unwrap_or_default() {
                if let Some(line) = crate::output::mihomo::matcher_text(&m) {
                    payload.push(line);
                }
            }
        }
    }
    let url = st(rs, "url");
    if let Some(u) = &url {
        if u.contains("/geoip") {
            behavior = "ipcidr".into();
        } else if u.contains("/geosite") {
            behavior = "domain".into();
        }
    }
    RuleProvider {
        name: tag,
        kind: match kind.as_str() {
            "remote" => "http".into(),
            "local" => "file".into(),
            _ => "inline".into(),
        },
        behavior,
        format: st(rs, "format").map(|f| {
            if f == "binary" {
                "srs".into()
            } else {
                "sing-box-json".into()
            }
        }),
        url,
        path: st(rs, "path"),
        interval: secs(rs, "update_interval"),
        proxy: st(rs, "download_detour"),
        payload,
        extra: Vec::new(),
    }
}

/// Converts one sing-box headless/route rule into Clash matchers. Fields of one
/// category are OR-ed; different categories are AND-ed (sing-box semantics).
pub fn rule_to_matchers(r: &J) -> Option<Vec<Matcher>> {
    if st(r, "type").as_deref() == Some("logical") {
        let subs: Vec<Matcher> = r
            .get("rules")?
            .as_array()?
            .iter()
            .filter_map(rule_to_matchers)
            .map(|v| {
                if v.len() == 1 {
                    v.into_iter().next().unwrap()
                } else {
                    Matcher::Or(v)
                }
            })
            .collect();
        let m = if st(r, "mode").as_deref() == Some("or") {
            Matcher::Or(subs)
        } else {
            Matcher::And(subs)
        };
        return Some(vec![wrap_invert(r, m)]);
    }
    let mut cats: Vec<Vec<Matcher>> = Vec::new();
    let mut domain_cat: Vec<Matcher> = Vec::new();
    domain_cat.extend(strs(r, "domain").into_iter().map(Matcher::Domain));
    domain_cat.extend(
        strs(r, "domain_suffix")
            .into_iter()
            .map(|s| Matcher::DomainSuffix(s.trim_start_matches('.').to_string())),
    );
    domain_cat.extend(
        strs(r, "domain_keyword")
            .into_iter()
            .map(Matcher::DomainKeyword),
    );
    domain_cat.extend(
        strs(r, "domain_regex")
            .into_iter()
            .map(Matcher::DomainRegex),
    );
    domain_cat.extend(strs(r, "geosite").into_iter().map(Matcher::Geosite));
    let mut ip_cat: Vec<Matcher> = strs(r, "ip_cidr")
        .into_iter()
        .map(Matcher::IpCidr)
        .collect();
    ip_cat.extend(strs(r, "geoip").into_iter().map(Matcher::Geoip));
    if bo(r, "ip_is_private") == Some(true) {
        ip_cat.push(Matcher::Geoip("LAN".into()));
    }
    // sing-box merges domain and ip categories into one OR group
    domain_cat.extend(ip_cat);
    let simple = |k: &str, f: fn(String) -> Matcher| -> Vec<Matcher> {
        strs(r, k).into_iter().map(f).collect()
    };
    for c in [
        domain_cat,
        simple("source_ip_cidr", Matcher::SrcIpCidr),
        simple("port", Matcher::DstPort),
        strs(r, "port_range")
            .into_iter()
            .map(|p| Matcher::DstPort(p.replace(':', "-")))
            .collect(),
        simple("source_port", Matcher::SrcPort),
        simple("process_name", Matcher::ProcessName),
        simple("process_path", Matcher::ProcessPath),
        simple("process_path_regex", Matcher::ProcessPathRegex),
        simple("package_name", Matcher::ProcessName),
        simple("user_id", Matcher::Uid),
        simple("network", |n| Matcher::Network(n.to_ascii_uppercase())),
        simple("rule_set", Matcher::RuleSet),
        simple("inbound", Matcher::InName),
    ] {
        if !c.is_empty() {
            cats.push(c);
        }
    }
    if cats.is_empty() {
        return None;
    }
    let out = if cats.len() == 1 && bo(r, "invert") != Some(true) {
        cats.pop().unwrap()
    } else {
        let parts: Vec<Matcher> = cats
            .into_iter()
            .map(|c| {
                if c.len() == 1 {
                    c.into_iter().next().unwrap()
                } else {
                    Matcher::Or(c)
                }
            })
            .collect();
        let m = if parts.len() == 1 {
            parts.into_iter().next().unwrap()
        } else {
            Matcher::And(parts)
        };
        vec![wrap_invert(r, m)]
    };
    Some(out)
}

fn wrap_invert(r: &J, m: Matcher) -> Matcher {
    if bo(r, "invert") == Some(true) {
        Matcher::Not(Box::new(m))
    } else {
        m
    }
}

fn parse_dns(j: &J) -> Dns {
    let mut dns = Dns {
        enable: true,
        ..Default::default()
    };
    let servers = j
        .get("servers")
        .and_then(J::as_array)
        .cloned()
        .unwrap_or_default();
    let final_tag = st(j, "final");
    let mut ordered: Vec<(String, String)> = Vec::new();
    for s in &servers {
        let tag = st(s, "tag").unwrap_or_default();
        let ty = st(s, "type");
        let url = match ty.as_deref() {
            Some("fakeip") => {
                dns.enhanced_mode = Some("fake-ip".into());
                dns.fake_ip_range = st(s, "inet4_range");
                dns.fake_ip_range6 = st(s, "inet6_range");
                continue;
            }
            Some("local") => "system".to_string(),
            Some("udp") => format!(
                "{}{}",
                st(s, "server").unwrap_or_default(),
                nu(s, "server_port")
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default()
            ),
            Some(t @ ("tcp" | "tls" | "quic")) => format!(
                "{t}://{}{}",
                st(s, "server").unwrap_or_default(),
                nu(s, "server_port")
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default()
            ),
            Some(t @ ("https" | "h3")) => format!(
                "{t}://{}{}{}",
                st(s, "server").unwrap_or_default(),
                nu(s, "server_port")
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default(),
                st(s, "path").unwrap_or_else(|| "/dns-query".into())
            ),
            Some("dhcp") => format!(
                "dhcp://{}",
                st(s, "interface").unwrap_or_else(|| "auto".into())
            ),
            Some(_) => continue,
            // legacy format: `address` URL
            None => match st(s, "address") {
                Some(a) if a == "fakeip" => {
                    dns.enhanced_mode = Some("fake-ip".into());
                    continue;
                }
                Some(a) if a == "local" => "system".into(),
                Some(a) if a.starts_with("rcode://") => continue,
                Some(a) => a,
                None => continue,
            },
        };
        ordered.push((tag, url));
    }
    if let Some(f) = &final_tag
        && let Some(i) = ordered.iter().position(|(t, _)| t == f)
    {
        let x = ordered.remove(i);
        ordered.insert(0, x);
    }
    dns.nameserver = ordered.iter().take(1).map(|(_, u)| u.clone()).collect();
    dns.default_nameserver = ordered
        .iter()
        .filter(|(_, u)| u.parse::<std::net::IpAddr>().is_ok())
        .map(|(_, u)| u.clone())
        .collect();
    // DNS rules that route domains/rule sets to a server become nameserver-policy
    for r in j
        .get("rules")
        .and_then(J::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let Some(server) = st(&r, "server") else {
            continue;
        };
        let Some((_, url)) = ordered.iter().find(|(t, _)| *t == server) else {
            continue;
        };
        for d in strs(&r, "domain_suffix") {
            dns.nameserver_policy.push((
                format!("+.{}", d.trim_start_matches('.')),
                vec![url.clone()],
            ));
        }
        for d in strs(&r, "domain") {
            dns.nameserver_policy.push((d, vec![url.clone()]));
        }
        for rs in strs(&r, "rule_set") {
            dns.nameserver_policy
                .push((format!("rule-set:{rs}"), vec![url.clone()]));
        }
    }
    dns
}
