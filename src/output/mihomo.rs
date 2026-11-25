//! mihomo (Clash.Meta) YAML output.

use crate::ConvertOptions;
use crate::diag::Diagnostics;
use crate::model::*;
use crate::value::{Map, Value, set};
use crate::yaml;

/// Renders a config as mihomo YAML.
pub fn render(cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> String {
    yaml::to_string(&Value::Map(to_map(cfg, opts, d)))
}

fn put_s(m: &mut Map, k: &str, v: &Option<String>) {
    if let Some(v) = v {
        m.push((k.into(), Value::str(v.clone())));
    }
}
fn put_b(m: &mut Map, k: &str, v: Option<bool>) {
    if let Some(v) = v {
        m.push((k.into(), Value::bool(v)));
    }
}
fn put_n<N: ToString>(m: &mut Map, k: &str, v: Option<N>) {
    if let Some(v) = v {
        m.push((k.into(), Value::plain(v.to_string())));
    }
}
fn put_list(m: &mut Map, k: &str, v: &[String]) {
    if !v.is_empty() {
        m.push((k.into(), Value::seq_str(v.iter().cloned())));
    }
}
fn hdr_map(h: &[(String, String)], host: &Option<String>) -> Option<Value> {
    let mut m: Map = Vec::new();
    if let Some(host) = host {
        m.push(("Host".into(), Value::str(host.clone())));
    }
    for (k, v) in h {
        m.push((k.clone(), Value::str(v.clone())));
    }
    if m.is_empty() { None } else { Some(Value::Map(m)) }
}

fn to_map(cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> Map {
    let mut m: Map = Vec::new();
    let g = &cfg.general;
    put_n(&mut m, "mixed-port", g.mixed_port);
    put_n(&mut m, "port", g.http_port);
    put_n(&mut m, "socks-port", g.socks_port);
    put_n(&mut m, "redir-port", g.redir_port);
    put_n(&mut m, "tproxy-port", g.tproxy_port);
    put_b(&mut m, "allow-lan", g.allow_lan);
    put_s(&mut m, "bind-address", &g.bind_address);
    put_s(&mut m, "mode", &g.mode);
    put_s(&mut m, "log-level", &g.log_level);
    put_b(&mut m, "ipv6", g.ipv6);
    put_s(&mut m, "external-controller", &g.external_controller);
    put_s(&mut m, "secret", &g.secret);
    put_s(&mut m, "find-process-mode", &g.find_process_mode);
    put_s(&mut m, "interface-name", &g.interface_name);
    put_n(&mut m, "routing-mark", g.routing_mark);
    if cfg.source != SourceFormat::Links && cfg.source != SourceFormat::SingBox && m.is_empty() && opts.add_defaults && cfg.extra.is_empty() {
        // a bare proxy list: nothing to add
    }
    for (k, v) in &cfg.extra {
        m.push((k.clone(), v.clone()));
    }
    if !cfg.hosts.is_empty() {
        m.push((
            "hosts".into(),
            Value::Map(
                cfg.hosts
                    .iter()
                    .map(|(k, v)| (k.clone(), if v.len() == 1 { Value::str(v[0].clone()) } else { Value::seq_str(v.iter().cloned()) }))
                    .collect(),
            ),
        ));
    }
    if let Some(t) = &cfg.tun {
        m.push(("tun".into(), Value::Map(tun_map(t))));
    }
    if let Some(dns) = &cfg.dns {
        m.push(("dns".into(), Value::Map(dns_map(dns))));
    }
    m.push(("proxies".into(), Value::Seq(cfg.proxies.iter().map(|p| Value::Map(proxy_map(p))).collect())));
    if !cfg.proxy_providers.is_empty() {
        m.push(("proxy-providers".into(), Value::Map(cfg.proxy_providers.clone())));
    }
    let (groups, rules) = crate::output::default_groups(cfg, opts, d);
    m.push(("proxy-groups".into(), Value::Seq(groups.iter().map(|g| Value::Map(group_map(g))).collect())));
    if !cfg.rule_providers.is_empty() {
        m.push((
            "rule-providers".into(),
            Value::Map(cfg.rule_providers.iter().map(|r| (r.name.clone(), Value::Map(provider_map(r, d)))).collect()),
        ));
    }
    m.push(("rules".into(), Value::seq_str(rules.iter().map(rule_text))));
    if !cfg.sub_rules.is_empty() {
        m.push((
            "sub-rules".into(),
            Value::Map(cfg.sub_rules.iter().map(|(k, rs)| (k.clone(), Value::seq_str(rs.iter().map(rule_text)))).collect()),
        ));
    }
    m
}

fn tun_map(t: &Tun) -> Map {
    let mut m: Map = vec![("enable".into(), Value::bool(t.enable))];
    put_s(&mut m, "stack", &t.stack);
    put_b(&mut m, "auto-route", t.auto_route);
    put_b(&mut m, "auto-detect-interface", t.auto_detect_interface);
    put_b(&mut m, "strict-route", t.strict_route);
    put_n(&mut m, "mtu", t.mtu);
    put_list(&mut m, "dns-hijack", &t.dns_hijack);
    put_s(&mut m, "device", &t.device);
    put_list(&mut m, "inet4-address", &t.inet4_address);
    put_list(&mut m, "inet6-address", &t.inet6_address);
    put_list(&mut m, "route-address", &t.route_address);
    put_list(&mut m, "route-exclude-address", &t.route_exclude_address);
    m.extend(t.extra.iter().cloned());
    m
}

fn dns_map(dns: &Dns) -> Map {
    let mut m: Map = vec![("enable".into(), Value::bool(dns.enable))];
    put_b(&mut m, "ipv6", dns.ipv6);
    put_s(&mut m, "listen", &dns.listen);
    put_s(&mut m, "enhanced-mode", &dns.enhanced_mode);
    put_s(&mut m, "fake-ip-range", &dns.fake_ip_range);
    put_s(&mut m, "fake-ip-range6", &dns.fake_ip_range6);
    put_s(&mut m, "fake-ip-filter-mode", &dns.fake_ip_filter_mode);
    put_list(&mut m, "fake-ip-filter", &dns.fake_ip_filter);
    put_b(&mut m, "respect-rules", dns.respect_rules);
    put_b(&mut m, "use-hosts", dns.use_hosts);
    put_b(&mut m, "use-system-hosts", dns.use_system_hosts);
    put_b(&mut m, "prefer-h3", dns.prefer_h3);
    put_list(&mut m, "default-nameserver", &dns.default_nameserver);
    put_list(&mut m, "nameserver", &dns.nameserver);
    put_list(&mut m, "fallback", &dns.fallback);
    put_list(&mut m, "proxy-server-nameserver", &dns.proxy_server_nameserver);
    put_list(&mut m, "direct-nameserver", &dns.direct_nameserver);
    if !dns.nameserver_policy.is_empty() {
        m.push((
            "nameserver-policy".into(),
            Value::Map(
                dns.nameserver_policy
                    .iter()
                    .map(|(k, v)| (k.clone(), if v.len() == 1 { Value::str(v[0].clone()) } else { Value::seq_str(v.iter().cloned()) }))
                    .collect(),
            ),
        ));
    }
    m.extend(dns.extra.iter().cloned());
    m
}

/// One proxy as a mihomo mapping.
pub fn proxy_map(p: &Proxy) -> Map {
    let mut m: Map = vec![
        ("name".into(), Value::str(p.name.clone())),
        ("type".into(), Value::str(p.protocol.clash_type())),
        ("server".into(), Value::str(p.server.clone())),
        ("port".into(), Value::int(p.port as i64)),
    ];
    match &p.protocol {
        Protocol::Shadowsocks {
            cipher,
            password,
            plugin,
            udp_over_tcp,
            udp_over_tcp_version,
        } => {
            m.push(("cipher".into(), Value::str(cipher.clone())));
            m.push(("password".into(), Value::str(password.clone())));
            put_b(&mut m, "udp-over-tcp", *udp_over_tcp);
            put_n(&mut m, "udp-over-tcp-version", *udp_over_tcp_version);
            if let Some(pl) = plugin {
                let (name, opts) = match pl {
                    SsPlugin::Obfs { mode, host } => {
                        let mut o: Map = vec![("mode".into(), Value::str(mode.clone()))];
                        put_s(&mut o, "host", host);
                        ("obfs".to_string(), Value::Map(o))
                    }
                    SsPlugin::V2ray {
                        mode,
                        tls,
                        host,
                        path,
                        mux,
                        skip_cert_verify,
                    } => {
                        let mut o: Map = vec![("mode".into(), Value::str(mode.clone()))];
                        if *tls {
                            o.push(("tls".into(), Value::bool(true)));
                        }
                        put_s(&mut o, "host", host);
                        put_s(&mut o, "path", path);
                        put_b(&mut o, "mux", *mux);
                        put_b(&mut o, "skip-cert-verify", *skip_cert_verify);
                        ("v2ray-plugin".to_string(), Value::Map(o))
                    }
                    SsPlugin::ShadowTls { host, password, version } => {
                        let mut o: Map = vec![("host".into(), Value::str(host.clone()))];
                        put_s(&mut o, "password", password);
                        o.push(("version".into(), Value::int(*version as i64)));
                        ("shadow-tls".to_string(), Value::Map(o))
                    }
                    SsPlugin::Other { name, opts } => (name.clone(), opts.clone()),
                };
                m.push(("plugin".into(), Value::str(name)));
                m.push(("plugin-opts".into(), opts));
            }
        }
        Protocol::ShadowsocksR {
            cipher,
            password,
            obfs,
            obfs_param,
            protocol,
            protocol_param,
        } => {
            m.push(("cipher".into(), Value::str(cipher.clone())));
            m.push(("password".into(), Value::str(password.clone())));
            m.push(("obfs".into(), Value::str(obfs.clone())));
            put_s(&mut m, "obfs-param", obfs_param);
            m.push(("protocol".into(), Value::str(protocol.clone())));
            put_s(&mut m, "protocol-param", protocol_param);
        }
        Protocol::Vmess {
            uuid,
            alter_id,
            security,
            global_padding,
            authenticated_length,
            packet_encoding,
        } => {
            m.push(("uuid".into(), Value::str(uuid.clone())));
            m.push(("alterId".into(), Value::int(*alter_id as i64)));
            m.push(("cipher".into(), Value::str(security.clone())));
            put_b(&mut m, "global-padding", *global_padding);
            put_b(&mut m, "authenticated-length", *authenticated_length);
            put_s(&mut m, "packet-encoding", packet_encoding);
        }
        Protocol::Vless {
            uuid,
            flow,
            packet_encoding,
            encryption,
        } => {
            m.push(("uuid".into(), Value::str(uuid.clone())));
            put_s(&mut m, "flow", flow);
            put_s(&mut m, "packet-encoding", packet_encoding);
            put_s(&mut m, "encryption", encryption);
        }
        Protocol::Trojan { password } => m.push(("password".into(), Value::str(password.clone()))),
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
            put_s(&mut m, "auth-str", auth);
            put_s(&mut m, "up", up);
            put_s(&mut m, "down", down);
            put_s(&mut m, "obfs", obfs);
            put_s(&mut m, "protocol", protocol);
            put_s(&mut m, "ports", ports);
            put_n(&mut m, "recv-window-conn", *recv_window_conn);
            put_n(&mut m, "recv-window", *recv_window);
            put_b(&mut m, "disable-mtu-discovery", *disable_mtu_discovery);
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
            m.push(("password".into(), Value::str(password.clone())));
            put_s(&mut m, "ports", ports);
            put_n(&mut m, "hop-interval", *hop_interval);
            put_s(&mut m, "obfs", obfs);
            put_s(&mut m, "obfs-password", obfs_password);
            put_s(&mut m, "up", up);
            put_s(&mut m, "down", down);
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
            put_s(&mut m, "uuid", uuid);
            put_s(&mut m, "password", password);
            put_s(&mut m, "token", token);
            put_s(&mut m, "congestion-controller", congestion_control);
            put_s(&mut m, "udp-relay-mode", udp_relay_mode);
            put_b(&mut m, "reduce-rtt", *zero_rtt);
            if let Some(h) = heartbeat
                && let Some(ms) = duration_ms(h)
            {
                m.push(("heartbeat-interval".into(), Value::int(ms as i64)));
            }
        }
        Protocol::AnyTls {
            password,
            idle_session_check_interval,
            idle_session_timeout,
            min_idle_session,
        } => {
            m.push(("password".into(), Value::str(password.clone())));
            put_n(&mut m, "idle-session-check-interval", *idle_session_check_interval);
            put_n(&mut m, "idle-session-timeout", *idle_session_timeout);
            put_n(&mut m, "min-idle-session", *min_idle_session);
        }
        Protocol::WireGuard(wg) => {
            m.push(("private-key".into(), Value::str(wg.private_key.clone())));
            m.push(("public-key".into(), Value::str(wg.public_key.clone())));
            put_s(&mut m, "pre-shared-key", &wg.pre_shared_key);
            put_s(&mut m, "ip", &wg.ip);
            put_s(&mut m, "ipv6", &wg.ipv6);
            put_list(&mut m, "allowed-ips", &wg.allowed_ips);
            if let Some(r) = &wg.reserved {
                m.push(("reserved".into(), Value::Seq(r.iter().map(|b| Value::int(*b as i64)).collect())));
            }
            put_n(&mut m, "mtu", wg.mtu);
            put_n(&mut m, "persistent-keepalive", wg.keepalive);
            if !wg.extra_peers.is_empty() {
                m.push(("peers".into(), Value::Seq(wg.extra_peers.clone())));
            }
        }
        Protocol::Ssh {
            user,
            password,
            private_key,
            private_key_passphrase,
            host_key,
            host_key_algorithms,
        } => {
            m.push(("username".into(), Value::str(user.clone())));
            put_s(&mut m, "password", password);
            put_s(&mut m, "private-key", private_key);
            put_s(&mut m, "private-key-passphrase", private_key_passphrase);
            put_list(&mut m, "host-key", host_key);
            put_list(&mut m, "host-key-algorithms", host_key_algorithms);
        }
        Protocol::Socks5 { user, password } => {
            put_s(&mut m, "username", user);
            put_s(&mut m, "password", password);
        }
        Protocol::Http { user, password, headers } => {
            put_s(&mut m, "username", user);
            put_s(&mut m, "password", password);
            if let Some(h) = hdr_map(headers, &None) {
                m.push(("headers".into(), h));
            }
        }
        Protocol::Snell {
            psk,
            version,
            obfs_mode,
            obfs_host,
        } => {
            m.push(("psk".into(), Value::str(psk.clone())));
            put_n(&mut m, "version", *version);
            if obfs_mode.is_some() {
                let mut o = Vec::new();
                put_s(&mut o, "mode", obfs_mode);
                put_s(&mut o, "host", obfs_host);
                m.push(("obfs-opts".into(), Value::Map(o)));
            }
        }
        Protocol::Mieru {
            user,
            password,
            transport,
            port_range,
            multiplexing,
        } => {
            m.push(("username".into(), Value::str(user.clone())));
            m.push(("password".into(), Value::str(password.clone())));
            put_s(&mut m, "transport", transport);
            put_s(&mut m, "port-range", port_range);
            put_s(&mut m, "multiplexing", multiplexing);
        }
        Protocol::Other { .. } => {}
    }
    put_b(&mut m, "udp", p.udp);
    if let Some(t) = &p.tls {
        let implicit = matches!(
            p.protocol,
            Protocol::Trojan { .. } | Protocol::Hysteria { .. } | Protocol::Hysteria2 { .. } | Protocol::Tuic { .. } | Protocol::AnyTls { .. }
        );
        if t.enabled && !implicit {
            m.push(("tls".into(), Value::bool(true)));
        }
        let sni_key = if matches!(p.protocol, Protocol::Vmess { .. } | Protocol::Vless { .. }) { "servername" } else { "sni" };
        put_s(&mut m, sni_key, &t.sni);
        put_b(&mut m, "skip-cert-verify", t.insecure);
        put_list(&mut m, "alpn", &t.alpn);
        put_s(&mut m, "client-fingerprint", &t.utls);
        put_s(&mut m, "fingerprint", &t.cert_fingerprint);
        put_s(&mut m, "certificate", &t.client_cert);
        put_s(&mut m, "private-key", &t.client_key);
        if let Some(r) = &t.reality {
            m.push((
                "reality-opts".into(),
                Value::Map(vec![
                    ("public-key".into(), Value::str(r.public_key.clone())),
                    ("short-id".into(), Value::str(r.short_id.clone())),
                ]),
            ));
        }
        if let Some(e) = &t.ech {
            let mut o: Map = vec![("enable".into(), Value::bool(e.enable))];
            put_s(&mut o, "config", &e.config);
            m.push(("ech-opts".into(), Value::Map(o)));
        }
    }
    if let Some(tr) = &p.transport {
        let net = match tr {
            Transport::HttpUpgrade { .. } => "ws",
            other => other.name(),
        };
        m.push(("network".into(), Value::str(net)));
        match tr {
            Transport::Ws {
                path,
                host,
                headers,
                max_early_data,
                early_data_header,
            } => {
                let mut o: Map = vec![("path".into(), Value::str(path.clone()))];
                if let Some(h) = hdr_map(headers, host) {
                    o.push(("headers".into(), h));
                }
                put_n(&mut o, "max-early-data", *max_early_data);
                put_s(&mut o, "early-data-header-name", early_data_header);
                m.push(("ws-opts".into(), Value::Map(o)));
            }
            Transport::HttpUpgrade { path, host, headers } => {
                let mut o: Map = vec![("path".into(), Value::str(path.clone()))];
                if let Some(h) = hdr_map(headers, host) {
                    o.push(("headers".into(), h));
                }
                o.push(("v2ray-http-upgrade".into(), Value::bool(true)));
                m.push(("ws-opts".into(), Value::Map(o)));
            }
            Transport::Grpc { service_name } => {
                m.push(("grpc-opts".into(), Value::Map(vec![("grpc-service-name".into(), Value::str(service_name.clone()))])));
            }
            Transport::H2 { hosts, path } => {
                let mut o: Map = Vec::new();
                put_list(&mut o, "host", hosts);
                o.push(("path".into(), Value::str(path.clone())));
                m.push(("h2-opts".into(), Value::Map(o)));
            }
            Transport::Http {
                method,
                paths,
                hosts,
                headers,
            } => {
                let mut o: Map = Vec::new();
                put_s(&mut o, "method", method);
                put_list(&mut o, "path", paths);
                let mut h: Map = Vec::new();
                if !hosts.is_empty() {
                    h.push(("Host".into(), Value::seq_str(hosts.iter().cloned())));
                }
                for (k, v) in headers {
                    h.push((k.clone(), Value::seq_str(v.iter().cloned())));
                }
                if !h.is_empty() {
                    o.push(("headers".into(), Value::Map(h)));
                }
                m.push(("http-opts".into(), Value::Map(o)));
            }
            Transport::Xhttp { path, host, mode, raw } => {
                let mut o = raw.as_map().cloned().unwrap_or_default();
                set(&mut o, "path", Value::str(path.clone()));
                if let Some(h) = host {
                    set(&mut o, "host", Value::str(h.clone()));
                }
                if let Some(md) = mode {
                    set(&mut o, "mode", Value::str(md.clone()));
                }
                m.push(("xhttp-opts".into(), Value::Map(o)));
            }
            Transport::Quic => {}
        }
    }
    let dl = &p.dial;
    put_s(&mut m, "interface-name", &dl.interface);
    put_n(&mut m, "routing-mark", dl.routing_mark);
    put_b(&mut m, "tfo", dl.tfo);
    put_b(&mut m, "mptcp", dl.mptcp);
    put_s(&mut m, "ip-version", &dl.ip_version);
    put_s(&mut m, "dialer-proxy", &dl.detour);
    for (k, v) in &p.extra {
        set(&mut m, k, v.clone());
    }
    m
}

fn duration_ms(s: &str) -> Option<u64> {
    let i = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let n: u64 = s[..i].parse().ok()?;
    Some(match &s[i..] {
        "ms" => n,
        "" | "s" => n * 1000,
        "m" => n * 60_000,
        _ => return None,
    })
}

fn group_map(g: &Group) -> Map {
    let mut m: Map = vec![
        ("name".into(), Value::str(g.name.clone())),
        ("type".into(), Value::str(g.kind.clash_type())),
    ];
    if let GroupKind::LoadBalance { strategy } = &g.kind {
        put_s(&mut m, "strategy", strategy);
    }
    if !g.members.is_empty() {
        m.push(("proxies".into(), Value::seq_str(g.members.iter().cloned())));
    }
    put_list(&mut m, "use", &g.use_providers);
    put_s(&mut m, "url", &g.url);
    put_n(&mut m, "interval", g.interval);
    put_n(&mut m, "tolerance", g.tolerance);
    put_n(&mut m, "timeout", g.timeout);
    put_b(&mut m, "lazy", g.lazy);
    put_s(&mut m, "filter", &g.filter);
    put_s(&mut m, "exclude-filter", &g.exclude_filter);
    put_s(&mut m, "exclude-type", &g.exclude_type);
    if g.include_all {
        m.push(("include-all".into(), Value::bool(true)));
    }
    if g.include_all_proxies {
        m.push(("include-all-proxies".into(), Value::bool(true)));
    }
    if g.include_all_providers {
        m.push(("include-all-providers".into(), Value::bool(true)));
    }
    put_b(&mut m, "hidden", g.hidden);
    put_s(&mut m, "icon", &g.icon);
    m.extend(g.extra.iter().cloned());
    if g.members.is_empty() && g.use_providers.is_empty() && !g.include_all && !g.include_all_proxies && !g.include_all_providers {
        m.push(("proxies".into(), Value::seq_str(["DIRECT"])));
    }
    m
}

fn provider_map(r: &RuleProvider, d: &mut Diagnostics) -> Map {
    let mut m: Map = Vec::new();
    // sing-box binary rule sets: point at the mihomo build of the same list when known
    let (kind, format, url) = match (r.format.as_deref(), &r.url) {
        (Some("srs"), Some(u)) => match crate::output::rulesets::srs_to_mrs(u) {
            Some(mu) => ("http".to_string(), Some("mrs".to_string()), Some(mu)),
            None => {
                d.warn(
                    crate::diag::Kind::Approximated,
                    format!("rule-provider {:?}", r.name),
                    Some("url"),
                    "sing-box binary rule set has no known mihomo equivalent; kept the URL, mihomo cannot read .srs",
                );
                (r.kind.clone(), r.format.clone(), r.url.clone())
            }
        },
        _ if !r.payload.is_empty() && r.kind == "inline" => ("inline".into(), None, None),
        _ => (r.kind.clone(), r.format.clone(), r.url.clone()),
    };
    m.push(("type".into(), Value::str(kind.clone())));
    m.push(("behavior".into(), Value::str(r.behavior.clone())));
    put_s(&mut m, "format", &format.filter(|f| f != "sing-box-json"));
    put_s(&mut m, "url", &url);
    put_s(&mut m, "path", &r.path);
    put_n(&mut m, "interval", r.interval);
    put_s(&mut m, "proxy", &r.proxy);
    if kind == "inline" {
        m.push(("payload".into(), Value::seq_str(r.payload.iter().cloned())));
    }
    m.extend(r.extra.iter().cloned());
    m
}

/// `TYPE,payload` for a matcher (no target).
pub fn matcher_text(m: &Matcher) -> Option<String> {
    let (t, p): (&str, String) = match m {
        Matcher::Domain(p) => ("DOMAIN", p.clone()),
        Matcher::DomainSuffix(p) => ("DOMAIN-SUFFIX", p.clone()),
        Matcher::DomainKeyword(p) => ("DOMAIN-KEYWORD", p.clone()),
        Matcher::DomainRegex(p) => ("DOMAIN-REGEX", p.clone()),
        Matcher::DomainWildcard(p) => ("DOMAIN-WILDCARD", p.clone()),
        Matcher::Geosite(p) => ("GEOSITE", p.clone()),
        Matcher::Geoip(p) => ("GEOIP", p.clone()),
        Matcher::SrcGeoip(p) => ("SRC-GEOIP", p.clone()),
        Matcher::IpCidr(p) => (if p.contains(':') { "IP-CIDR6" } else { "IP-CIDR" }, p.clone()),
        Matcher::SrcIpCidr(p) => ("SRC-IP-CIDR", p.clone()),
        Matcher::IpAsn(p) => ("IP-ASN", p.clone()),
        Matcher::SrcIpAsn(p) => ("SRC-IP-ASN", p.clone()),
        Matcher::IpSuffix(p) => ("IP-SUFFIX", p.clone()),
        Matcher::DstPort(p) => ("DST-PORT", p.clone()),
        Matcher::SrcPort(p) => ("SRC-PORT", p.clone()),
        Matcher::InPort(p) => ("IN-PORT", p.clone()),
        Matcher::InType(p) => ("IN-TYPE", p.clone()),
        Matcher::InUser(p) => ("IN-USER", p.clone()),
        Matcher::InName(p) => ("IN-NAME", p.clone()),
        Matcher::ProcessName(p) => ("PROCESS-NAME", p.clone()),
        Matcher::ProcessPath(p) => ("PROCESS-PATH", p.clone()),
        Matcher::ProcessNameRegex(p) => ("PROCESS-NAME-REGEX", p.clone()),
        Matcher::ProcessPathRegex(p) => ("PROCESS-PATH-REGEX", p.clone()),
        Matcher::Uid(p) => ("UID", p.clone()),
        Matcher::Network(p) => ("NETWORK", p.clone()),
        Matcher::Dscp(p) => ("DSCP", p.clone()),
        Matcher::RuleSet(p) => ("RULE-SET", p.clone()),
        Matcher::And(v) => ("AND", logical(v)?),
        Matcher::Or(v) => ("OR", logical(v)?),
        Matcher::Not(x) => ("NOT", format!("(({}))", matcher_text(x)?)),
        Matcher::SubRule(x, _) => ("SUB-RULE", format!("({})", matcher_text(x)?)),
        Matcher::Match => return Some("MATCH".into()),
        Matcher::Other(t, p) => (t.as_str(), p.clone()),
    };
    Some(format!("{t},{p}"))
}

fn logical(v: &[Matcher]) -> Option<String> {
    let parts: Option<Vec<String>> = v.iter().map(|m| matcher_text(m).map(|t| format!("({t})"))).collect();
    Some(format!("({})", parts?.join(",")))
}

/// A full rule line.
pub fn rule_text(r: &Rule) -> String {
    let mut s = match &r.matcher {
        Matcher::Match => format!("MATCH,{}", r.target),
        Matcher::SubRule(_, name) => format!("{},{}", matcher_text(&r.matcher).unwrap_or_default(), name),
        m => format!("{},{}", matcher_text(m).unwrap_or_default(), r.target),
    };
    if r.src {
        s.push_str(",src");
    }
    if r.no_resolve {
        s.push_str(",no-resolve");
    }
    s
}
