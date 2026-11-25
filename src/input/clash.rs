//! Clash / Mihomo configuration input (YAML or JSON), written from mihomo's
//! public configuration reference.

use crate::diag::{Diagnostics, Kind, group_loc, proxy_loc, rule_loc};
use crate::model::*;
use crate::value::{Map, Value, get, take};

/// Builds a [`Config`] from a parsed Clash/Mihomo document.
pub fn from_value(root: Value, source: SourceFormat, d: &mut Diagnostics) -> Config {
    let mut cfg = Config {
        source,
        ..Default::default()
    };
    let mut m = match root {
        Value::Map(m) => m,
        Value::Seq(items) => {
            // A bare list of proxies.
            vec![("proxies".to_string(), Value::Seq(items))]
        }
        _ => Map::new(),
    };
    if let Some(v) = take(&mut m, "proxies") {
        cfg.proxies = parse_proxies(&v, d);
    }
    if let Some(Value::Map(pp)) = take(&mut m, "proxy-providers") {
        cfg.proxy_providers = pp;
    }
    if let Some(v) = take(&mut m, "proxy-groups") {
        for (i, g) in v
            .as_seq()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            match parse_group(g) {
                Ok(g) => cfg.groups.push(g),
                Err(e) => d.error(Kind::Invalid, format!("proxy-groups[{i}]"), None, e),
            }
        }
    }
    if let Some(Value::Map(rp)) = take(&mut m, "rule-providers") {
        for (name, v) in rp {
            cfg.rule_providers.push(parse_rule_provider(name, v));
        }
    }
    if let Some(v) = take(&mut m, "rules") {
        cfg.rules = parse_rules(&v, d, "rules");
    }
    if let Some(Value::Map(sr)) = take(&mut m, "sub-rules") {
        for (name, v) in sr {
            let rules = parse_rules(&v, d, &format!("sub-rules.{name}"));
            cfg.sub_rules.push((name, rules));
        }
    }
    if let Some(v) = take(&mut m, "dns") {
        cfg.dns = Some(parse_dns(v));
    }
    if let Some(v) = take(&mut m, "tun") {
        cfg.tun = Some(parse_tun(v));
    }
    if let Some(Value::Map(h)) = take(&mut m, "hosts") {
        cfg.hosts = h.into_iter().map(|(k, v)| (k, v.as_str_list())).collect();
    }
    let g = &mut cfg.general;
    g.mixed_port = port_of(take(&mut m, "mixed-port"));
    g.http_port = port_of(take(&mut m, "port"));
    g.socks_port = port_of(take(&mut m, "socks-port"));
    g.redir_port = port_of(take(&mut m, "redir-port"));
    g.tproxy_port = port_of(take(&mut m, "tproxy-port"));
    g.allow_lan = take(&mut m, "allow-lan").and_then(|v| v.as_bool());
    g.bind_address = take(&mut m, "bind-address").and_then(|v| v.as_string());
    g.mode = take(&mut m, "mode").and_then(|v| v.as_string());
    g.log_level = take(&mut m, "log-level").and_then(|v| v.as_string());
    g.ipv6 = take(&mut m, "ipv6").and_then(|v| v.as_bool());
    g.external_controller = take(&mut m, "external-controller").and_then(|v| v.as_string());
    g.secret = take(&mut m, "secret").and_then(|v| v.as_string());
    g.find_process_mode = take(&mut m, "find-process-mode").and_then(|v| v.as_string());
    g.interface_name = take(&mut m, "interface-name").and_then(|v| v.as_string());
    g.routing_mark = take(&mut m, "routing-mark")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    cfg.extra = m;
    cfg
}

fn port_of(v: Option<Value>) -> Option<u16> {
    v.and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .filter(|&p| p > 0)
}

/// Parses the `proxies` list, skipping (and reporting) invalid entries and
/// renaming duplicates.
pub fn parse_proxies(v: &Value, d: &mut Diagnostics) -> Vec<Proxy> {
    let mut out: Vec<Proxy> = Vec::new();
    let Some(items) = v.as_seq() else {
        if !v.is_null() {
            d.error(Kind::Invalid, "proxies", None, "`proxies` is not a list");
        }
        return out;
    };
    for (i, item) in items.iter().enumerate() {
        let Some(m) = item.as_map() else {
            d.error(
                Kind::Invalid,
                format!("proxies[{i}]"),
                None,
                "entry is not a mapping",
            );
            continue;
        };
        match parse_proxy(m.clone(), d) {
            Ok(p) => push_unique(&mut out, p, d),
            Err(e) => {
                let name = get(m, "name")
                    .and_then(Value::as_string)
                    .unwrap_or_else(|| format!("proxies[{i}]"));
                d.error(Kind::Invalid, proxy_loc(&name), None, e);
            }
        }
    }
    out
}

/// Adds a proxy, renaming it when the name is already taken.
pub fn push_unique(out: &mut Vec<Proxy>, mut p: Proxy, d: &mut Diagnostics) {
    if out.iter().any(|q| q.name == p.name) {
        let base = p.name.clone();
        let mut n = 2;
        while out.iter().any(|q| q.name == format!("{base} {n}")) {
            n += 1;
        }
        p.name = format!("{base} {n}");
        d.warn(
            Kind::Renamed,
            proxy_loc(&base),
            Some("name"),
            format!("duplicate name, renamed to {:?}", p.name),
        );
    }
    out.push(p);
}

fn s(m: &mut Map, k: &str) -> Option<String> {
    take(m, k)
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty())
}
fn b(m: &mut Map, k: &str) -> Option<bool> {
    take(m, k).and_then(|v| v.as_bool())
}
fn n(m: &mut Map, k: &str) -> Option<u64> {
    take(m, k).and_then(|v| v.as_u64())
}
fn list(m: &mut Map, k: &str) -> Vec<String> {
    take(m, k).map(|v| v.as_str_list()).unwrap_or_default()
}
fn headers(v: Option<Value>) -> Vec<(String, String)> {
    match v {
        Some(Value::Map(h)) => h
            .into_iter()
            .filter_map(|(k, v)| {
                let val = match &v {
                    Value::Seq(s) => s.first().and_then(Value::as_string),
                    other => other.as_string(),
                }?;
                Some((k, val))
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Parses one proxy mapping.
pub fn parse_proxy(mut m: Map, d: &mut Diagnostics) -> Result<Proxy, String> {
    let name = s(&mut m, "name").ok_or("missing `name`")?;
    let kind = s(&mut m, "type")
        .ok_or("missing `type`")?
        .to_ascii_lowercase();
    let server = s(&mut m, "server").ok_or("missing `server`")?;
    let port_v = take(&mut m, "port");
    let port = match port_v.as_ref().and_then(Value::as_u64) {
        Some(p) if (1..=65535).contains(&p) => p as u16,
        Some(p) => return Err(format!("port {p} is out of range")),
        None if kind == "hysteria2" || kind == "hysteria" || kind == "mieru" => 443,
        None => return Err("missing or invalid `port`".into()),
    };
    let loc = proxy_loc(&name);
    let udp = b(&mut m, "udp");
    let dial = Dial {
        interface: s(&mut m, "interface-name"),
        routing_mark: n(&mut m, "routing-mark").map(|v| v as u32),
        tfo: b(&mut m, "tfo"),
        mptcp: b(&mut m, "mptcp"),
        ip_version: s(&mut m, "ip-version"),
        detour: s(&mut m, "dialer-proxy"),
    };

    // TLS: implicit for these protocols.
    let implicit_tls = matches!(
        kind.as_str(),
        "trojan" | "hysteria" | "hysteria2" | "tuic" | "anytls"
    );
    let tls_flag = b(&mut m, "tls").unwrap_or(false);
    let sni = s(&mut m, "servername")
        .or_else(|| s(&mut m, "sni"))
        .or_else(|| s(&mut m, "peer"));
    let insecure = b(&mut m, "skip-cert-verify");
    let alpn = list(&mut m, "alpn");
    let utls = s(&mut m, "client-fingerprint");
    let cert_fp = s(&mut m, "fingerprint");
    let reality = match take(&mut m, "reality-opts") {
        Some(Value::Map(mut r)) => Some(Reality {
            public_key: s(&mut r, "public-key").unwrap_or_default(),
            short_id: take(&mut r, "short-id")
                .and_then(|v| v.as_string())
                .unwrap_or_default(),
        }),
        _ => None,
    };
    let ech = match take(&mut m, "ech-opts") {
        Some(Value::Map(mut e)) => Some(EchOpts {
            enable: b(&mut e, "enable").unwrap_or(false),
            config: s(&mut e, "config"),
        }),
        _ => None,
    };
    let client_cert = s(&mut m, "certificate");
    let client_key = if kind != "wireguard" && kind != "ssh" {
        s(&mut m, "private-key")
    } else {
        None
    };
    let tls_enabled = implicit_tls || tls_flag || reality.is_some();
    let tls = if tls_enabled || sni.is_some() || insecure.is_some() || !alpn.is_empty() {
        Some(Tls {
            enabled: tls_enabled,
            sni,
            insecure,
            alpn,
            utls,
            cert_fingerprint: cert_fp,
            reality,
            ech,
            client_cert,
            client_key: client_key.clone(),
        })
    } else {
        None
    };

    let transport = parse_transport(&mut m, &kind, &loc, d);

    let protocol = match kind.as_str() {
        "ss" | "shadowsocks" => {
            let plugin = match s(&mut m, "plugin") {
                None => {
                    take(&mut m, "plugin-opts");
                    None
                }
                Some(p) => {
                    let opts = take(&mut m, "plugin-opts").unwrap_or(Value::Map(Vec::new()));
                    let mut o = opts.as_map().cloned().unwrap_or_default();
                    Some(match p.as_str() {
                        "obfs" | "simple-obfs" | "obfs-local" => SsPlugin::Obfs {
                            mode: s(&mut o, "mode").unwrap_or_else(|| "http".into()),
                            host: s(&mut o, "host"),
                        },
                        "v2ray-plugin" => SsPlugin::V2ray {
                            mode: s(&mut o, "mode").unwrap_or_else(|| "websocket".into()),
                            tls: b(&mut o, "tls").unwrap_or(false),
                            host: s(&mut o, "host"),
                            path: s(&mut o, "path"),
                            mux: b(&mut o, "mux"),
                            skip_cert_verify: b(&mut o, "skip-cert-verify"),
                        },
                        "shadow-tls" => SsPlugin::ShadowTls {
                            host: s(&mut o, "host").unwrap_or_default(),
                            password: s(&mut o, "password"),
                            version: n(&mut o, "version").unwrap_or(2) as u8,
                        },
                        _ => SsPlugin::Other { name: p, opts },
                    })
                }
            };
            Protocol::Shadowsocks {
                cipher: s(&mut m, "cipher").ok_or("missing `cipher`")?,
                password: s(&mut m, "password").unwrap_or_default(),
                plugin,
                udp_over_tcp: b(&mut m, "udp-over-tcp"),
                udp_over_tcp_version: n(&mut m, "udp-over-tcp-version").map(|v| v as u8),
            }
        }
        "ssr" => Protocol::ShadowsocksR {
            cipher: s(&mut m, "cipher").ok_or("missing `cipher`")?,
            password: s(&mut m, "password").unwrap_or_default(),
            obfs: s(&mut m, "obfs").unwrap_or_else(|| "plain".into()),
            obfs_param: s(&mut m, "obfs-param"),
            protocol: s(&mut m, "protocol").unwrap_or_else(|| "origin".into()),
            protocol_param: s(&mut m, "protocol-param"),
        },
        "vmess" => Protocol::Vmess {
            uuid: s(&mut m, "uuid").ok_or("missing `uuid`")?,
            alter_id: n(&mut m, "alterId")
                .or_else(|| n(&mut m, "alter-id"))
                .unwrap_or(0) as u32,
            security: s(&mut m, "cipher").unwrap_or_else(|| "auto".into()),
            global_padding: b(&mut m, "global-padding"),
            authenticated_length: b(&mut m, "authenticated-length"),
            packet_encoding: s(&mut m, "packet-encoding").or_else(|| {
                if b(&mut m, "xudp") == Some(true) {
                    Some("xudp".into())
                } else {
                    None
                }
            }),
        },
        "vless" => Protocol::Vless {
            uuid: s(&mut m, "uuid").ok_or("missing `uuid`")?,
            flow: s(&mut m, "flow"),
            packet_encoding: s(&mut m, "packet-encoding").or_else(|| {
                if b(&mut m, "xudp") == Some(true) {
                    Some("xudp".into())
                } else {
                    None
                }
            }),
            encryption: s(&mut m, "encryption").filter(|e| e != "none"),
        },
        "trojan" => Protocol::Trojan {
            password: s(&mut m, "password").ok_or("missing `password`")?,
        },
        "hysteria" => Protocol::Hysteria {
            auth: s(&mut m, "auth-str")
                .or_else(|| s(&mut m, "auth_str"))
                .or_else(|| s(&mut m, "auth")),
            up: s(&mut m, "up"),
            down: s(&mut m, "down"),
            obfs: s(&mut m, "obfs"),
            protocol: s(&mut m, "protocol"),
            ports: s(&mut m, "ports"),
            recv_window_conn: n(&mut m, "recv-window-conn"),
            recv_window: n(&mut m, "recv-window"),
            disable_mtu_discovery: b(&mut m, "disable-mtu-discovery"),
        },
        "hysteria2" | "hy2" => Protocol::Hysteria2 {
            password: s(&mut m, "password")
                .or_else(|| s(&mut m, "auth"))
                .unwrap_or_default(),
            ports: s(&mut m, "ports"),
            hop_interval: n(&mut m, "hop-interval"),
            obfs: s(&mut m, "obfs"),
            obfs_password: s(&mut m, "obfs-password"),
            up: s(&mut m, "up"),
            down: s(&mut m, "down"),
        },
        "tuic" => Protocol::Tuic {
            uuid: s(&mut m, "uuid"),
            password: s(&mut m, "password"),
            token: s(&mut m, "token"),
            congestion_control: s(&mut m, "congestion-controller"),
            udp_relay_mode: s(&mut m, "udp-relay-mode"),
            zero_rtt: b(&mut m, "reduce-rtt"),
            heartbeat: take(&mut m, "heartbeat-interval")
                .and_then(|v| v.as_u64())
                .map(|ms| format!("{ms}ms")),
        },
        "anytls" => Protocol::AnyTls {
            password: s(&mut m, "password").ok_or("missing `password`")?,
            idle_session_check_interval: n(&mut m, "idle-session-check-interval"),
            idle_session_timeout: n(&mut m, "idle-session-timeout"),
            min_idle_session: n(&mut m, "min-idle-session"),
        },
        "wireguard" => {
            let mut wg = WireGuard {
                private_key: s(&mut m, "private-key").ok_or("missing `private-key`")?,
                public_key: s(&mut m, "public-key").unwrap_or_default(),
                pre_shared_key: s(&mut m, "pre-shared-key"),
                ip: s(&mut m, "ip"),
                ipv6: s(&mut m, "ipv6"),
                allowed_ips: list(&mut m, "allowed-ips"),
                reserved: parse_reserved(take(&mut m, "reserved")),
                mtu: n(&mut m, "mtu").map(|v| v as u32),
                keepalive: n(&mut m, "persistent-keepalive").map(|v| v as u32),
                extra_peers: Vec::new(),
            };
            if let Some(Value::Seq(peers)) = take(&mut m, "peers") {
                let mut it = peers.into_iter();
                if wg.public_key.is_empty()
                    && let Some(Value::Map(mut p)) = it.next()
                {
                    wg.public_key = s(&mut p, "public-key").unwrap_or_default();
                    wg.pre_shared_key = s(&mut p, "pre-shared-key").or(wg.pre_shared_key);
                    let ips = list(&mut p, "allowed-ips");
                    if !ips.is_empty() {
                        wg.allowed_ips = ips;
                    }
                    if let Some(r) = parse_reserved(take(&mut p, "reserved")) {
                        wg.reserved = Some(r);
                    }
                }
                wg.extra_peers = it.collect();
            }
            if wg.public_key.is_empty() {
                return Err("missing `public-key`".into());
            }
            Protocol::WireGuard(wg)
        }
        "ssh" => Protocol::Ssh {
            user: s(&mut m, "username").unwrap_or_else(|| "root".into()),
            password: s(&mut m, "password"),
            private_key: client_key.or_else(|| s(&mut m, "private-key")),
            private_key_passphrase: s(&mut m, "private-key-passphrase"),
            host_key: list(&mut m, "host-key"),
            host_key_algorithms: list(&mut m, "host-key-algorithms"),
        },
        "socks5" | "socks" => Protocol::Socks5 {
            user: s(&mut m, "username"),
            password: s(&mut m, "password"),
        },
        "http" | "https" => Protocol::Http {
            user: s(&mut m, "username"),
            password: s(&mut m, "password"),
            headers: headers(take(&mut m, "headers")),
        },
        "snell" => {
            let (obfs_mode, obfs_host) = match take(&mut m, "obfs-opts") {
                Some(Value::Map(mut o)) => (s(&mut o, "mode"), s(&mut o, "host")),
                _ => (None, None),
            };
            Protocol::Snell {
                psk: s(&mut m, "psk").ok_or("missing `psk`")?,
                version: n(&mut m, "version").map(|v| v as u8),
                obfs_mode,
                obfs_host,
            }
        }
        "mieru" => Protocol::Mieru {
            user: s(&mut m, "username").unwrap_or_default(),
            password: s(&mut m, "password").unwrap_or_default(),
            transport: s(&mut m, "transport"),
            port_range: s(&mut m, "port-range"),
            multiplexing: s(&mut m, "multiplexing"),
        },
        other => {
            d.info(
                Kind::Repaired,
                &loc,
                Some("type"),
                format!("type `{other}` is kept as-is but not modelled"),
            );
            Protocol::Other {
                kind: other.to_string(),
            }
        }
    };
    Ok(Proxy {
        name,
        server,
        port,
        protocol,
        transport,
        tls,
        udp,
        dial,
        extra: m,
    })
}

fn parse_reserved(v: Option<Value>) -> Option<Vec<u8>> {
    match v? {
        Value::Seq(s) => s
            .iter()
            .map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect(),
        Value::Scalar { text, .. } => {
            if text.contains(',') {
                text.split(',').map(|x| x.trim().parse().ok()).collect()
            } else {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(text.trim())
                    .ok()
            }
        }
        _ => None,
    }
}

fn parse_transport(m: &mut Map, kind: &str, loc: &str, d: &mut Diagnostics) -> Option<Transport> {
    let network = s(m, "network").map(|n| n.to_ascii_lowercase());
    let ws = take(m, "ws-opts");
    let grpc = take(m, "grpc-opts");
    let h2 = take(m, "h2-opts");
    let http = take(m, "http-opts");
    let xhttp = take(m, "xhttp-opts");
    // legacy vmess ws keys
    let ws_path = s(m, "ws-path");
    let ws_headers = take(m, "ws-headers");
    if matches!(
        kind,
        "ss" | "ssr"
            | "hysteria"
            | "hysteria2"
            | "tuic"
            | "wireguard"
            | "ssh"
            | "socks5"
            | "http"
            | "snell"
            | "mieru"
            | "anytls"
    ) {
        return None;
    }
    let net = network.unwrap_or_else(|| {
        if ws_path.is_some() {
            "ws".into()
        } else {
            "tcp".into()
        }
    });
    let opt = |v: Option<Value>| v.and_then(|v| v.as_map().cloned()).unwrap_or_default();
    match net.as_str() {
        "tcp" | "" => None,
        "ws" | "websocket" => {
            let mut o = opt(ws);
            let mut hdrs = headers(take(&mut o, "headers"));
            if hdrs.is_empty() {
                hdrs = headers(ws_headers);
            }
            let host_pos = hdrs
                .iter()
                .position(|(k, _)| k.eq_ignore_ascii_case("host"));
            let host = host_pos.map(|i| hdrs.remove(i).1);
            let path = s(&mut o, "path").or(ws_path).unwrap_or_else(|| "/".into());
            if b(&mut o, "v2ray-http-upgrade") == Some(true) {
                return Some(Transport::HttpUpgrade {
                    path,
                    host,
                    headers: hdrs,
                });
            }
            Some(Transport::Ws {
                path,
                host,
                headers: hdrs,
                max_early_data: n(&mut o, "max-early-data").map(|v| v as u32),
                early_data_header: s(&mut o, "early-data-header-name"),
            })
        }
        "httpupgrade" => {
            let mut o = opt(ws);
            let mut hdrs = headers(take(&mut o, "headers"));
            let host_pos = hdrs
                .iter()
                .position(|(k, _)| k.eq_ignore_ascii_case("host"));
            let host = host_pos.map(|i| hdrs.remove(i).1);
            Some(Transport::HttpUpgrade {
                path: s(&mut o, "path").unwrap_or_else(|| "/".into()),
                host,
                headers: hdrs,
            })
        }
        "grpc" => {
            let mut o = opt(grpc);
            Some(Transport::Grpc {
                service_name: s(&mut o, "grpc-service-name").unwrap_or_default(),
            })
        }
        "h2" => {
            let mut o = opt(h2);
            Some(Transport::H2 {
                hosts: list(&mut o, "host"),
                path: s(&mut o, "path").unwrap_or_else(|| "/".into()),
            })
        }
        "http" => {
            let mut o = opt(http);
            let mut hosts = Vec::new();
            let mut hdrs = Vec::new();
            if let Some(Value::Map(h)) = take(&mut o, "headers") {
                for (k, v) in h {
                    if k.eq_ignore_ascii_case("host") {
                        hosts = v.as_str_list();
                    } else {
                        hdrs.push((k, v.as_str_list()));
                    }
                }
            }
            Some(Transport::Http {
                method: s(&mut o, "method"),
                paths: list(&mut o, "path"),
                hosts,
                headers: hdrs,
            })
        }
        "xhttp" | "splithttp" => {
            let raw = xhttp.unwrap_or(Value::Map(Vec::new()));
            let mut o = raw.as_map().cloned().unwrap_or_default();
            Some(Transport::Xhttp {
                path: s(&mut o, "path").unwrap_or_else(|| "/".into()),
                host: s(&mut o, "host"),
                mode: s(&mut o, "mode"),
                raw,
            })
        }
        "quic" => Some(Transport::Quic),
        other => {
            d.warn(
                Kind::FieldDropped,
                loc,
                Some("network"),
                format!("unknown network `{other}`, treated as tcp"),
            );
            None
        }
    }
}

fn parse_group(v: Value) -> Result<Group, String> {
    let mut m = match v {
        Value::Map(m) => m,
        _ => return Err("entry is not a mapping".into()),
    };
    let name = s(&mut m, "name").ok_or("missing `name`")?;
    let t = s(&mut m, "type").ok_or_else(|| format!("{}: missing `type`", group_loc(&name)))?;
    let kind = match t.to_ascii_lowercase().as_str() {
        "select" => GroupKind::Select,
        "url-test" | "urltest" => GroupKind::UrlTest,
        "fallback" => GroupKind::Fallback,
        "load-balance" | "loadbalance" => GroupKind::LoadBalance {
            strategy: s(&mut m, "strategy"),
        },
        "relay" => GroupKind::Relay,
        other => GroupKind::Other(other.to_string()),
    };
    Ok(Group {
        name,
        kind,
        members: list(&mut m, "proxies"),
        use_providers: list(&mut m, "use"),
        url: s(&mut m, "url"),
        interval: n(&mut m, "interval"),
        tolerance: n(&mut m, "tolerance"),
        timeout: n(&mut m, "timeout"),
        lazy: b(&mut m, "lazy"),
        filter: s(&mut m, "filter"),
        exclude_filter: s(&mut m, "exclude-filter"),
        exclude_type: s(&mut m, "exclude-type"),
        include_all: b(&mut m, "include-all").unwrap_or(false),
        include_all_proxies: b(&mut m, "include-all-proxies").unwrap_or(false),
        include_all_providers: b(&mut m, "include-all-providers").unwrap_or(false),
        hidden: b(&mut m, "hidden"),
        icon: s(&mut m, "icon"),
        extra: m,
    })
}

fn parse_rule_provider(name: String, v: Value) -> RuleProvider {
    let mut m = v.as_map().cloned().unwrap_or_default();
    RuleProvider {
        name,
        kind: s(&mut m, "type").unwrap_or_else(|| "http".into()),
        behavior: s(&mut m, "behavior").unwrap_or_else(|| "classical".into()),
        format: s(&mut m, "format"),
        url: s(&mut m, "url"),
        path: s(&mut m, "path"),
        interval: n(&mut m, "interval"),
        proxy: s(&mut m, "proxy"),
        payload: list(&mut m, "payload"),
        extra: m,
    }
}

fn parse_dns(v: Value) -> Dns {
    let mut m = v.as_map().cloned().unwrap_or_default();
    let policy = match take(&mut m, "nameserver-policy") {
        Some(Value::Map(p)) => p.into_iter().map(|(k, v)| (k, v.as_str_list())).collect(),
        _ => Vec::new(),
    };
    let mut fallback_filter = take(&mut m, "fallback-filter");
    let mut dns = Dns {
        enable: b(&mut m, "enable").unwrap_or(true),
        ipv6: b(&mut m, "ipv6"),
        listen: s(&mut m, "listen"),
        enhanced_mode: s(&mut m, "enhanced-mode"),
        fake_ip_range: s(&mut m, "fake-ip-range"),
        fake_ip_range6: s(&mut m, "fake-ip-range6"),
        fake_ip_filter: list(&mut m, "fake-ip-filter"),
        fake_ip_filter_mode: s(&mut m, "fake-ip-filter-mode"),
        default_nameserver: list(&mut m, "default-nameserver"),
        nameserver: list(&mut m, "nameserver"),
        fallback: list(&mut m, "fallback"),
        proxy_server_nameserver: list(&mut m, "proxy-server-nameserver"),
        direct_nameserver: list(&mut m, "direct-nameserver"),
        nameserver_policy: policy,
        respect_rules: b(&mut m, "respect-rules"),
        use_hosts: b(&mut m, "use-hosts"),
        use_system_hosts: b(&mut m, "use-system-hosts"),
        prefer_h3: b(&mut m, "prefer-h3"),
        extra: Vec::new(),
    };
    if let Some(ff) = fallback_filter.take() {
        m.push(("fallback-filter".into(), ff));
    }
    dns.extra = m;
    dns
}

fn parse_tun(v: Value) -> Tun {
    let mut m = v.as_map().cloned().unwrap_or_default();
    Tun {
        enable: b(&mut m, "enable").unwrap_or(false),
        stack: s(&mut m, "stack"),
        auto_route: b(&mut m, "auto-route"),
        auto_detect_interface: b(&mut m, "auto-detect-interface"),
        strict_route: b(&mut m, "strict-route"),
        mtu: n(&mut m, "mtu").map(|v| v as u32),
        dns_hijack: list(&mut m, "dns-hijack"),
        device: s(&mut m, "device"),
        inet4_address: list(&mut m, "inet4-address"),
        inet6_address: list(&mut m, "inet6-address"),
        route_address: list(&mut m, "route-address"),
        route_exclude_address: list(&mut m, "route-exclude-address"),
        extra: m,
    }
}

// ------------------------------------------------------------------ rules

fn parse_rules(v: &Value, d: &mut Diagnostics, section: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for (i, r) in v.as_seq().cloned().unwrap_or_default().iter().enumerate() {
        let Some(text) = r.as_text() else {
            d.error(
                Kind::Invalid,
                format!("{section}[{i}]"),
                None,
                "rule is not a string",
            );
            continue;
        };
        match parse_rule(text) {
            Ok(rule) => out.push(rule),
            Err(e) => d.error(Kind::Invalid, rule_loc(i, text), None, e),
        }
    }
    out
}

/// Parses one Clash rule line such as `DOMAIN-SUFFIX,google.com,Proxy`.
pub fn parse_rule(text: &str) -> Result<Rule, String> {
    let raw = text.trim().to_string();
    let (ty, rest) = match raw.split_once(',') {
        Some((t, r)) => (t.trim().to_ascii_uppercase(), r.trim()),
        None => (raw.to_ascii_uppercase(), ""),
    };
    if ty == "MATCH" || ty == "FINAL" {
        let target = rest.split(',').next().unwrap_or("").trim().to_string();
        if target.is_empty() {
            return Err("MATCH without a target".into());
        }
        return Ok(Rule {
            matcher: Matcher::Match,
            target,
            no_resolve: false,
            src: false,
            raw,
        });
    }
    if matches!(ty.as_str(), "AND" | "OR" | "NOT" | "SUB-RULE") {
        let rest = rest.trim_start();
        if !rest.starts_with('(') {
            return Err(format!("{ty} expects a parenthesised list"));
        }
        let end = matching_paren(rest).ok_or("unbalanced parentheses")?;
        let inner = &rest[1..end];
        let after = rest[end + 1..].trim_start_matches(',').trim();
        let mut parts = after.split(',').map(str::trim);
        let target = parts.next().unwrap_or("").to_string();
        let no_resolve = parts.clone().any(|p| p.eq_ignore_ascii_case("no-resolve"));
        if target.is_empty() {
            return Err(format!("{ty} without a target"));
        }
        let matcher = if ty == "SUB-RULE" {
            let m = parse_matcher(inner.trim())?;
            Matcher::SubRule(Box::new(m), target.clone())
        } else {
            let items = split_groups(inner)?;
            let subs = items
                .iter()
                .map(|s| parse_matcher(s))
                .collect::<Result<Vec<_>, _>>()?;
            match ty.as_str() {
                "AND" => Matcher::And(subs),
                "OR" => Matcher::Or(subs),
                _ => Matcher::Not(Box::new(
                    subs.into_iter().next().ok_or("NOT needs one condition")?,
                )),
            }
        };
        return Ok(Rule {
            matcher,
            target,
            no_resolve,
            src: false,
            raw,
        });
    }
    let parts: Vec<&str> = rest.split(',').map(str::trim).collect();
    let mut end = parts.len();
    let mut no_resolve = false;
    let mut src = false;
    while end > 0 {
        match parts[end - 1].to_ascii_lowercase().as_str() {
            "no-resolve" => no_resolve = true,
            "src" => src = true,
            _ => break,
        }
        end -= 1;
    }
    if end < 2 {
        return Err("rule needs a value and a target".into());
    }
    let target = parts[end - 1].to_string();
    let payload = parts[..end - 1].join(",");
    let matcher = make_matcher(&ty, payload)?;
    Ok(Rule {
        matcher,
        target,
        no_resolve,
        src,
        raw,
    })
}

fn parse_matcher(s: &str) -> Result<Matcher, String> {
    let s = s.trim();
    let s = s
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(s);
    let (ty, rest) = s
        .split_once(',')
        .ok_or_else(|| format!("bad condition `{s}`"))?;
    let ty = ty.trim().to_ascii_uppercase();
    if matches!(ty.as_str(), "AND" | "OR" | "NOT") {
        let rest = rest.trim();
        let end = matching_paren(rest).ok_or("unbalanced parentheses")?;
        let items = split_groups(&rest[1..end])?;
        let subs = items
            .iter()
            .map(|x| parse_matcher(x))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(match ty.as_str() {
            "AND" => Matcher::And(subs),
            "OR" => Matcher::Or(subs),
            _ => Matcher::Not(Box::new(
                subs.into_iter().next().ok_or("NOT needs one condition")?,
            )),
        });
    }
    // conditions can carry `no-resolve`; drop it
    let rest = rest.trim();
    let rest = rest.strip_suffix(",no-resolve").unwrap_or(rest);
    make_matcher(&ty, rest.trim().to_string())
}

fn make_matcher(ty: &str, p: String) -> Result<Matcher, String> {
    if p.is_empty() {
        return Err(format!("{ty} has an empty value"));
    }
    Ok(match ty {
        "DOMAIN" => Matcher::Domain(p),
        "DOMAIN-SUFFIX" => Matcher::DomainSuffix(p),
        "DOMAIN-KEYWORD" => Matcher::DomainKeyword(p),
        "DOMAIN-REGEX" => Matcher::DomainRegex(p),
        "DOMAIN-WILDCARD" => Matcher::DomainWildcard(p),
        "GEOSITE" => Matcher::Geosite(p),
        "GEOIP" => Matcher::Geoip(p),
        "SRC-GEOIP" => Matcher::SrcGeoip(p),
        "IP-CIDR" | "IP-CIDR6" | "IP6-CIDR" => Matcher::IpCidr(p),
        "SRC-IP-CIDR" | "SOURCE-IP-CIDR" => Matcher::SrcIpCidr(p),
        "IP-ASN" => Matcher::IpAsn(p),
        "SRC-IP-ASN" => Matcher::SrcIpAsn(p),
        "IP-SUFFIX" => Matcher::IpSuffix(p),
        "DST-PORT" | "DEST-PORT" => Matcher::DstPort(p),
        "SRC-PORT" => Matcher::SrcPort(p),
        "IN-PORT" => Matcher::InPort(p),
        "IN-TYPE" => Matcher::InType(p),
        "IN-USER" => Matcher::InUser(p),
        "IN-NAME" => Matcher::InName(p),
        "PROCESS-NAME" => Matcher::ProcessName(p),
        "PROCESS-PATH" => Matcher::ProcessPath(p),
        "PROCESS-NAME-REGEX" => Matcher::ProcessNameRegex(p),
        "PROCESS-PATH-REGEX" => Matcher::ProcessPathRegex(p),
        "UID" => Matcher::Uid(p),
        "NETWORK" => Matcher::Network(p),
        "DSCP" => Matcher::Dscp(p),
        "RULE-SET" => Matcher::RuleSet(p),
        other => Matcher::Other(other.to_string(), p),
    })
}

fn matching_paren(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Splits `(A,x),(B,y)` into `["A,x", "B,y"]`.
fn split_groups(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = None;
    for (i, c) in s.char_indices() {
        match c {
            '(' => {
                if depth == 0 {
                    start = Some(i + 1);
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    out.push(s[start.take().ok_or("unbalanced parentheses")?..i].to_string());
                }
                if depth < 0 {
                    return Err("unbalanced parentheses".into());
                }
            }
            _ => {}
        }
    }
    if depth != 0 || out.is_empty() {
        return Err("bad logical rule".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        let r = parse_rule("DOMAIN-REGEX,^a{1,3}\\.com$,DIRECT").unwrap();
        assert_eq!(r.matcher, Matcher::DomainRegex("^a{1,3}\\.com$".into()));
        let r = parse_rule("IP-CIDR,1.0.0.0/8,Proxy,no-resolve").unwrap();
        assert!(r.no_resolve);
        assert_eq!(r.target, "Proxy");
        let r = parse_rule("AND,((DOMAIN-SUFFIX,example.org),(NETWORK,UDP)),REJECT").unwrap();
        assert_eq!(
            r.matcher,
            Matcher::And(vec![
                Matcher::DomainSuffix("example.org".into()),
                Matcher::Network("UDP".into())
            ])
        );
        let r =
            parse_rule("OR,((AND,((DST-PORT,443),(NETWORK,UDP))),(DOMAIN,a.com)),REJECT").unwrap();
        assert!(matches!(r.matcher, Matcher::Or(ref v) if matches!(v[0], Matcher::And(_))));
        assert!(parse_rule("DOMAIN,a.com").is_err());
    }
}
