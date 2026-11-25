//! Share-link input (`ss://`, `vmess://`, `vless://`, `trojan://`, `hysteria2://`,
//! `tuic://`, `anytls://`, `wireguard://`, `socks://`, `http://`...).

use crate::diag::{Diagnostics, Kind};
use crate::model::*;
use crate::value::Value;
use base64::Engine;
use percent_encoding::percent_decode_str;

/// Schemes recognised as proxy share links.
pub const SCHEMES: &[&str] = &[
    "ss", "ssr", "vmess", "vless", "trojan", "hysteria2", "hy2", "hysteria", "hy", "tuic", "anytls", "wireguard", "wg", "socks",
    "socks5", "socks5h", "http", "https", "ssh", "snell",
];

/// Returns the scheme of a share-link line, if it is one we parse.
pub fn link_scheme(line: &str) -> Option<&'static str> {
    let (scheme, rest) = line.split_once("://")?;
    if rest.is_empty() {
        return None;
    }
    let lower = scheme.to_ascii_lowercase();
    SCHEMES.iter().copied().find(|s| *s == lower)
}

/// Decodes base64 in any of the common variants (standard/URL-safe, padded or not).
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let trimmed = cleaned.trim_end_matches('=');
    if trimmed.is_empty() {
        return None;
    }
    let url = trimmed.contains(['-', '_']);
    let eng = if url {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        base64::engine::general_purpose::STANDARD_NO_PAD
    };
    eng.decode(trimmed).ok().or_else(|| {
        // tolerate one stray trailing character
        eng.decode(&trimmed[..trimmed.len() - 1]).ok()
    })
}

fn b64_str(s: &str) -> Option<String> {
    b64_decode(s).and_then(|b| String::from_utf8(b).ok())
}

fn dec(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// A minimal URL split that tolerates the many non-standard links in the wild.
#[derive(Debug, Default)]
struct Url {
    scheme: String,
    user: Option<String>,
    host: String,
    port: Option<String>,
    path: String,
    query: Vec<(String, String)>,
    fragment: Option<String>,
}

impl Url {
    fn parse(link: &str) -> Option<Url> {
        let (scheme, rest) = link.split_once("://")?;
        let (rest, fragment) = match rest.split_once('#') {
            Some((r, f)) => (r, Some(dec(f))),
            None => (rest, None),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((r, q)) => (r, q),
            None => (rest, ""),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, String::new()),
        };
        let (user, hostport) = match authority.rfind('@') {
            Some(i) => (Some(authority[..i].to_string()), &authority[i + 1..]),
            None => (None, authority),
        };
        let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
            let end = h.find(']')?;
            let port = h[end + 1..].strip_prefix(':').map(str::to_string);
            (h[..end].to_string(), port)
        } else {
            match hostport.split_once(':') {
                Some((h, p)) => (h.to_string(), Some(p.to_string())),
                None => (hostport.to_string(), None),
            }
        };
        let query = query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => (dec(k), dec(v)),
                None => (dec(kv), String::new()),
            })
            .collect();
        Some(Url {
            scheme: scheme.to_ascii_lowercase(),
            user,
            host: dec(&host),
            port,
            path,
            query,
            fragment: fragment.filter(|f| !f.trim().is_empty()),
        })
    }
    fn q(&self, keys: &[&str]) -> Option<String> {
        keys.iter()
            .find_map(|k| self.query.iter().find(|(qk, _)| qk.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone()))
            .filter(|v| !v.is_empty())
    }
    fn qb(&self, keys: &[&str]) -> Option<bool> {
        self.q(keys).map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
    }
    fn port_u16(&self) -> Result<u16, String> {
        let p = self.port.as_deref().ok_or("missing port")?;
        let p = p.trim_end_matches('/');
        p.parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(|| format!("invalid port `{p}`"))
    }
    fn name(&self, port: u16) -> String {
        self.fragment.clone().unwrap_or_else(|| format!("{} {}:{}", self.scheme, self.host, port))
    }
}

fn proxy(name: String, server: String, port: u16, protocol: Protocol) -> Proxy {
    Proxy {
        name,
        server,
        port,
        protocol,
        transport: None,
        tls: None,
        udp: None,
        dial: Dial::default(),
        extra: Vec::new(),
    }
}

/// Parses one share link.
pub fn parse_link(line: &str, d: &mut Diagnostics) -> Result<Proxy, String> {
    let scheme = link_scheme(line).ok_or("not a recognised share link")?;
    match scheme {
        "vmess" => parse_vmess(line),
        "ssr" => parse_ssr(line),
        "ss" => parse_ss(line),
        _ => {
            let u = Url::parse(line).ok_or("malformed link")?;
            if u.host.is_empty() {
                return Err("missing server".into());
            }
            match scheme {
                "vless" => parse_v2_style(&u, true, d),
                "trojan" => parse_v2_style(&u, false, d),
                "hysteria2" | "hy2" => parse_hy2(&u),
                "hysteria" | "hy" => parse_hy1(&u),
                "tuic" => parse_tuic(&u),
                "anytls" => parse_anytls(&u),
                "wireguard" | "wg" => parse_wg(&u),
                "socks" | "socks5" | "socks5h" => parse_socks(&u),
                "http" | "https" => parse_http(&u),
                _ => Err(format!("`{scheme}://` links are not supported yet")),
            }
        }
    }
}

fn tls_from(u: &Url, enabled: bool) -> Tls {
    Tls {
        enabled,
        sni: u.q(&["sni", "peer", "servername"]),
        insecure: u.qb(&["allowInsecure", "insecure", "allow_insecure", "skip-cert-verify"]),
        alpn: u.q(&["alpn"]).map(|a| a.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
        utls: u.q(&["fp", "fingerprint", "client-fingerprint"]).filter(|f| f != "none"),
        cert_fingerprint: u.q(&["pcs", "pinSHA256"]),
        reality: None,
        ech: u.q(&["ech"]).map(|c| EchOpts {
            enable: true,
            config: Some(c),
        }),
        client_cert: None,
        client_key: None,
    }
}

fn transport_from(u: &Url, net: &str, d: &mut Diagnostics, name: &str) -> Option<Transport> {
    let host = u.q(&["host"]);
    let path = u.q(&["path"]).unwrap_or_else(|| "/".into());
    match net {
        "" | "tcp" | "raw" => {
            if u.q(&["headerType"]).as_deref() == Some("http") {
                Some(Transport::Http {
                    method: None,
                    paths: vec![path],
                    hosts: host.map(|h| vec![h]).unwrap_or_default(),
                    headers: Vec::new(),
                })
            } else {
                None
            }
        }
        "ws" | "websocket" => {
            let ed = u.q(&["ed"]).and_then(|e| e.parse().ok());
            Some(Transport::Ws {
                path,
                host,
                headers: Vec::new(),
                max_early_data: ed,
                early_data_header: u.q(&["eh"]).or_else(|| ed.map(|_| "Sec-WebSocket-Protocol".into())),
            })
        }
        "httpupgrade" => Some(Transport::HttpUpgrade {
            path,
            host,
            headers: Vec::new(),
        }),
        "grpc" | "gun" => Some(Transport::Grpc {
            service_name: u.q(&["serviceName", "service_name"]).unwrap_or_default(),
        }),
        "h2" | "http" => Some(Transport::H2 {
            hosts: host.map(|h| h.split(',').map(str::to_string).collect()).unwrap_or_default(),
            path,
        }),
        "xhttp" | "splithttp" => Some(Transport::Xhttp {
            path,
            host,
            mode: u.q(&["mode"]),
            raw: Value::Map(Vec::new()),
        }),
        "quic" => Some(Transport::Quic),
        other => {
            d.warn(Kind::FieldDropped, crate::diag::proxy_loc(name), Some("type"), format!("unknown transport `{other}`, treated as tcp"));
            None
        }
    }
}

fn parse_v2_style(u: &Url, vless: bool, d: &mut Diagnostics) -> Result<Proxy, String> {
    let port = u.port_u16()?;
    let name = u.name(port);
    let cred = dec(u.user.as_deref().ok_or("missing credentials")?);
    let security = u.q(&["security"]).unwrap_or_else(|| if vless { "none".into() } else { "tls".into() });
    let mut tls = tls_from(u, security != "none");
    if security == "reality" {
        tls.reality = Some(Reality {
            public_key: u.q(&["pbk", "public-key"]).ok_or("reality link without `pbk`")?,
            short_id: u.q(&["sid", "short-id"]).unwrap_or_default(),
        });
    }
    let net = u.q(&["type", "network"]).unwrap_or_default().to_ascii_lowercase();
    let protocol = if vless {
        Protocol::Vless {
            uuid: cred,
            flow: u.q(&["flow"]),
            packet_encoding: u.q(&["packetEncoding"]),
            encryption: u.q(&["encryption"]).filter(|e| e != "none"),
        }
    } else {
        Protocol::Trojan { password: cred }
    };
    let mut p = proxy(name.clone(), u.host.clone(), port, protocol);
    p.transport = transport_from(u, &net, d, &name);
    p.tls = if tls.enabled { Some(tls) } else { None };
    Ok(p)
}

fn parse_hy2(u: &Url) -> Result<Proxy, String> {
    // `host:443,20000-30000` or `host:20000-30000`
    let raw_port = u.port.clone().unwrap_or_else(|| "443".into());
    let raw_port = raw_port.trim_end_matches('/');
    let mut parts = raw_port.split(',');
    let first = parts.next().unwrap_or("443");
    let (port, mut hop): (u16, Vec<String>) = match first.parse::<u16>() {
        Ok(p) => (p, parts.map(str::to_string).collect()),
        Err(_) => {
            let start = first.split('-').next().and_then(|p| p.parse().ok()).ok_or("invalid port")?;
            (start, std::iter::once(first.to_string()).chain(parts.map(str::to_string)).collect())
        }
    };
    if let Some(m) = u.q(&["mport", "ports"]) {
        hop.push(m);
    }
    let name = u.name(port);
    let password = u.user.as_deref().map(dec).unwrap_or_default();
    let protocol = Protocol::Hysteria2 {
        password,
        ports: if hop.is_empty() { None } else { Some(hop.join(",")) },
        hop_interval: u.q(&["hop-interval", "hopInterval"]).and_then(|v| v.trim_end_matches('s').parse().ok()),
        obfs: u.q(&["obfs"]).filter(|o| o != "none"),
        obfs_password: u.q(&["obfs-password", "obfsPassword"]),
        up: u.q(&["up", "upmbps"]),
        down: u.q(&["down", "downmbps"]),
    };
    let mut p = proxy(name, u.host.clone(), port, protocol);
    p.tls = Some(tls_from(u, true));
    Ok(p)
}

fn parse_hy1(u: &Url) -> Result<Proxy, String> {
    let port = u.port_u16()?;
    let name = u.name(port);
    let protocol = Protocol::Hysteria {
        auth: u.q(&["auth", "auth_str"]),
        up: u.q(&["upmbps", "up"]),
        down: u.q(&["downmbps", "down"]),
        obfs: u.q(&["obfsParam", "obfs-password"]).or_else(|| u.q(&["obfs"]).filter(|o| o != "xplus" && o != "none")),
        protocol: u.q(&["protocol"]),
        ports: u.q(&["mport"]),
        recv_window_conn: None,
        recv_window: None,
        disable_mtu_discovery: None,
    };
    let mut p = proxy(name, u.host.clone(), port, protocol);
    p.tls = Some(tls_from(u, true));
    Ok(p)
}

fn parse_tuic(u: &Url) -> Result<Proxy, String> {
    let port = u.port_u16()?;
    let name = u.name(port);
    let user = u.user.as_deref().ok_or("missing credentials")?;
    let (uuid, password) = match user.split_once(':') {
        Some((a, b)) => (dec(a), Some(dec(b))),
        None => (dec(user), u.q(&["password"])),
    };
    let protocol = Protocol::Tuic {
        uuid: Some(uuid),
        password,
        token: None,
        congestion_control: u.q(&["congestion_control", "congestion-controller"]),
        udp_relay_mode: u.q(&["udp_relay_mode", "udp-relay-mode"]),
        zero_rtt: u.qb(&["reduce_rtt", "zero_rtt_handshake"]),
        heartbeat: None,
    };
    let mut p = proxy(name, u.host.clone(), port, protocol);
    p.tls = Some(tls_from(u, true));
    Ok(p)
}

fn parse_anytls(u: &Url) -> Result<Proxy, String> {
    let port = u.port_u16()?;
    let name = u.name(port);
    let protocol = Protocol::AnyTls {
        password: dec(u.user.as_deref().ok_or("missing password")?),
        idle_session_check_interval: None,
        idle_session_timeout: None,
        min_idle_session: None,
    };
    let mut p = proxy(name, u.host.clone(), port, protocol);
    p.tls = Some(tls_from(u, true));
    p.udp = Some(true);
    Ok(p)
}

fn parse_wg(u: &Url) -> Result<Proxy, String> {
    let port = u.port_u16()?;
    let name = u.name(port);
    let mut wg = WireGuard {
        private_key: u.user.as_deref().map(dec).or_else(|| u.q(&["privatekey", "private-key"])).ok_or("missing private key")?,
        public_key: u.q(&["publickey", "public-key", "peer"]).ok_or("missing public key")?,
        pre_shared_key: u.q(&["presharedkey", "pre-shared-key", "psk"]),
        mtu: u.q(&["mtu"]).and_then(|m| m.parse().ok()),
        reserved: u.q(&["reserved"]).and_then(|r| {
            if r.contains(',') {
                r.split(',').map(|x| x.trim().parse().ok()).collect()
            } else {
                b64_decode(&r)
            }
        }),
        allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
        ..Default::default()
    };
    for a in u.q(&["address", "ip"]).unwrap_or_default().split(',') {
        let a = a.trim();
        let ip = a.split('/').next().unwrap_or(a).to_string();
        if ip.is_empty() {
            continue;
        }
        if ip.contains(':') {
            wg.ipv6 = Some(ip);
        } else {
            wg.ip = Some(ip);
        }
    }
    if wg.ip.is_none() && wg.ipv6.is_none() {
        return Err("missing local address (`address=`)".into());
    }
    let mut p = proxy(name, u.host.clone(), port, Protocol::WireGuard(wg));
    p.udp = Some(true);
    Ok(p)
}

fn split_userpass(user: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(raw) = user else { return (None, None) };
    let decoded = if raw.contains(':') { dec(raw) } else { b64_str(raw).unwrap_or_else(|| dec(raw)) };
    match decoded.split_once(':') {
        Some((a, b)) => (Some(a.to_string()), Some(b.to_string())),
        None => (Some(decoded), None),
    }
}

fn parse_socks(u: &Url) -> Result<Proxy, String> {
    let port = u.port_u16()?;
    let (user, password) = split_userpass(u.user.as_deref());
    let mut p = proxy(u.name(port), u.host.clone(), port, Protocol::Socks5 { user, password });
    if u.qb(&["tls"]) == Some(true) {
        p.tls = Some(tls_from(u, true));
    }
    Ok(p)
}

fn parse_http(u: &Url) -> Result<Proxy, String> {
    if !(u.path.is_empty() || u.path == "/") {
        return Err("looks like a web address, not an HTTP proxy".into());
    }
    let port = match u.port_u16() {
        Ok(p) => p,
        Err(_) if u.port.is_none() => {
            if u.scheme == "https" {
                443
            } else {
                80
            }
        }
        Err(e) => return Err(e),
    };
    let (user, password) = split_userpass(u.user.as_deref());
    let mut p = proxy(u.name(port), u.host.clone(), port, Protocol::Http { user, password, headers: Vec::new() });
    if u.scheme == "https" {
        p.tls = Some(tls_from(u, true));
    }
    Ok(p)
}

fn parse_ss(line: &str) -> Result<Proxy, String> {
    let body = &line[line.find("://").unwrap() + 3..];
    let (body, frag) = match body.split_once('#') {
        Some((b, f)) => (b, Some(dec(f))),
        None => (body, None),
    };
    // legacy: ss://BASE64(method:pass@host:port)
    let full = if !body.contains('@') {
        let (b64, tail) = match body.find(['?', '/']) {
            Some(i) => (&body[..i], &body[i..]),
            None => (body, ""),
        };
        format!("ss://{}{}", b64_str(b64).ok_or("undecodable legacy ss link")?, tail)
    } else {
        format!("ss://{body}")
    };
    let u = Url::parse(&full).ok_or("malformed ss link")?;
    let port = u.port_u16()?;
    let user = u.user.as_deref().ok_or("missing credentials")?;
    let userinfo = if user.contains(':') || user.contains("%3A") || user.contains("%3a") {
        dec(user)
    } else {
        b64_str(&dec(user)).ok_or("undecodable ss credentials")?
    };
    let (cipher, password) = userinfo.split_once(':').ok_or("ss credentials must be `method:password`")?;
    let plugin = u.q(&["plugin"]).map(|p| parse_sip003(&p));
    let name = frag.filter(|f| !f.trim().is_empty()).unwrap_or_else(|| format!("ss {}:{port}", u.host));
    let mut p = proxy(
        name,
        u.host.clone(),
        port,
        Protocol::Shadowsocks {
            cipher: cipher.to_string(),
            password: password.to_string(),
            plugin,
            udp_over_tcp: u.qb(&["uot", "udp-over-tcp"]),
            udp_over_tcp_version: None,
        },
    );
    p.udp = Some(true);
    Ok(p)
}

/// Parses a SIP003 plugin string: `obfs-local;obfs=http;obfs-host=a.com`.
fn parse_sip003(s: &str) -> SsPlugin {
    let mut parts = s.split(';');
    let name = parts.next().unwrap_or("").trim().to_string();
    let mut kv: Vec<(String, String)> = Vec::new();
    for p in parts {
        match p.split_once('=') {
            Some((k, v)) => kv.push((k.trim().to_string(), v.trim().to_string())),
            None => kv.push((p.trim().to_string(), "true".into())),
        }
    }
    let g = |k: &str| kv.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
    match name.as_str() {
        "obfs-local" | "simple-obfs" | "obfs" => SsPlugin::Obfs {
            mode: g("obfs").or_else(|| g("mode")).unwrap_or_else(|| "http".into()),
            host: g("obfs-host").or_else(|| g("host")),
        },
        "v2ray-plugin" => SsPlugin::V2ray {
            mode: g("mode").unwrap_or_else(|| "websocket".into()),
            tls: g("tls").is_some(),
            host: g("host"),
            path: g("path"),
            mux: g("mux").map(|m| m != "0" && m != "false"),
            skip_cert_verify: None,
        },
        "shadow-tls" => SsPlugin::ShadowTls {
            host: g("host").unwrap_or_default(),
            password: g("password"),
            version: g("version").and_then(|v| v.parse().ok()).unwrap_or(2),
        },
        _ => SsPlugin::Other {
            name,
            opts: Value::Map(kv.into_iter().map(|(k, v)| (k, Value::str(v))).collect()),
        },
    }
}

fn parse_ssr(line: &str) -> Result<Proxy, String> {
    let body = &line[6..];
    let decoded = b64_str(body).ok_or("undecodable ssr link")?;
    let (main, query) = decoded.split_once("/?").unwrap_or((&decoded, ""));
    // host may be IPv6 with colons: take the last five fields
    let fields: Vec<&str> = main.rsplitn(6, ':').collect();
    if fields.len() < 6 {
        return Err("ssr link needs host:port:protocol:method:obfs:password".into());
    }
    let (pass_b64, obfs, method, proto, port, host) = (fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]);
    let port: u16 = port.parse().map_err(|_| "invalid port")?;
    let q: Vec<(&str, String)> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k, b64_str(v).unwrap_or_default()))
        .collect();
    let g = |k: &str| q.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v.clone()).filter(|v| !v.is_empty());
    let name = g("remarks").unwrap_or_else(|| format!("ssr {host}:{port}"));
    Ok(proxy(
        name,
        host.to_string(),
        port,
        Protocol::ShadowsocksR {
            cipher: method.to_string(),
            password: b64_str(pass_b64).ok_or("undecodable ssr password")?,
            obfs: obfs.to_string(),
            obfs_param: g("obfsparam"),
            protocol: proto.to_string(),
            protocol_param: g("protoparam"),
        },
    ))
}

fn parse_vmess(line: &str) -> Result<Proxy, String> {
    let body = &line[8..];
    let (b64part, frag) = match body.split_once('#') {
        Some((b, f)) => (b, Some(dec(f))),
        None => (body, None),
    };
    let (b64part, query) = b64part.split_once('?').unwrap_or((b64part, ""));
    let text = b64_str(b64part).ok_or("undecodable vmess link")?;
    let j: serde_json::Value = match serde_json::from_str(&text) {
        Ok(j) => j,
        Err(_) => {
            // Shadowrocket style: base64(security:uuid@host:port)?params
            let (cred, hp) = text.rsplit_once('@').ok_or("vmess link is neither JSON nor `security:uuid@host:port`")?;
            let (sec, uuid) = cred.split_once(':').ok_or("bad vmess credentials")?;
            let u = Url::parse(&format!("vmess://{hp}?{query}")).ok_or("bad vmess address")?;
            let port = u.port_u16()?;
            let mut d = Diagnostics::default();
            let name = frag.or_else(|| u.q(&["remarks", "remark"])).unwrap_or_else(|| format!("vmess {}:{port}", u.host));
            let net = u.q(&["obfs", "network", "type"]).unwrap_or_default();
            let net = if net == "websocket" { "ws".to_string() } else { net };
            let mut p = proxy(
                name.clone(),
                u.host.clone(),
                port,
                Protocol::Vmess {
                    uuid: uuid.to_string(),
                    alter_id: u.q(&["alterId", "aid"]).and_then(|a| a.parse().ok()).unwrap_or(0),
                    security: sec.to_string(),
                    global_padding: None,
                    authenticated_length: None,
                    packet_encoding: None,
                },
            );
            p.transport = transport_from(&u, &net, &mut d, &name);
            if u.qb(&["tls"]) == Some(true) {
                p.tls = Some(tls_from(&u, true));
            }
            return Ok(p);
        }
    };
    let g = |k: &str| -> Option<String> {
        match j.get(k)? {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    };
    let host = g("add").ok_or("vmess link without `add`")?;
    let port: u16 = g("port").and_then(|p| p.trim().parse().ok()).filter(|&p| p > 0).ok_or("vmess link with invalid `port`")?;
    let name = g("ps").or(frag).unwrap_or_else(|| format!("vmess {host}:{port}"));
    let net = g("net").unwrap_or_else(|| "tcp".into()).to_ascii_lowercase();
    let ty = g("type").unwrap_or_default();
    let hhost = g("host");
    let path = g("path");
    let transport = match net.as_str() {
        "ws" => {
            let p = path.unwrap_or_else(|| "/".into());
            Some(Transport::Ws {
                path: p,
                host: hhost,
                headers: Vec::new(),
                max_early_data: None,
                early_data_header: None,
            })
        }
        "httpupgrade" => Some(Transport::HttpUpgrade {
            path: path.unwrap_or_else(|| "/".into()),
            host: hhost,
            headers: Vec::new(),
        }),
        "grpc" => Some(Transport::Grpc {
            service_name: path.unwrap_or_default(),
        }),
        "h2" | "http" => Some(Transport::H2 {
            hosts: hhost.map(|h| h.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
            path: path.unwrap_or_else(|| "/".into()),
        }),
        "tcp" if ty == "http" => Some(Transport::Http {
            method: None,
            paths: path.map(|p| p.split(',').map(str::to_string).collect()).unwrap_or_else(|| vec!["/".into()]),
            hosts: hhost.map(|h| h.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
            headers: Vec::new(),
        }),
        "xhttp" | "splithttp" => Some(Transport::Xhttp {
            path: path.unwrap_or_else(|| "/".into()),
            host: hhost,
            mode: g("mode"),
            raw: Value::Map(Vec::new()),
        }),
        _ => None,
    };
    let tls_on = matches!(g("tls").as_deref(), Some("tls") | Some("true") | Some("1"));
    let mut p = proxy(
        name,
        host,
        port,
        Protocol::Vmess {
            uuid: g("id").ok_or("vmess link without `id`")?,
            alter_id: g("aid").and_then(|a| a.trim().parse().ok()).unwrap_or(0),
            security: g("scy").unwrap_or_else(|| "auto".into()),
            global_padding: None,
            authenticated_length: None,
            packet_encoding: None,
        },
    );
    p.transport = transport;
    if tls_on {
        p.tls = Some(Tls {
            enabled: true,
            sni: g("sni"),
            insecure: g("allowInsecure").or_else(|| g("skip-cert-verify")).map(|v| v == "1" || v == "true"),
            alpn: g("alpn").map(|a| a.split(',').map(str::to_string).collect()).unwrap_or_default(),
            utls: g("fp"),
            ..Default::default()
        });
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(l: &str) -> Proxy {
        parse_link(l, &mut Diagnostics::default()).unwrap()
    }

    #[test]
    fn ss_variants() {
        let p = one("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#HK%2001");
        assert_eq!(p.name, "HK 01");
        assert!(matches!(p.protocol, Protocol::Shadowsocks { ref cipher, ref password, .. } if cipher == "aes-256-gcm" && password == "pass"));
        let p = one("ss://2022-blake3-aes-128-gcm:AAAA%3D%3D@h.example:443?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dx.com#n");
        assert!(matches!(p.protocol, Protocol::Shadowsocks { plugin: Some(SsPlugin::Obfs { ref mode, .. }), ref password, .. } if mode == "tls" && password == "AAAA=="));
        let legacy = format!("ss://{}#x", base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:pw@[::1]:443"));
        let p = one(&legacy);
        assert_eq!(p.server, "::1");
    }

    #[test]
    fn vless_reality() {
        let p = one("vless://uuid-1@1.2.3.4:443?security=reality&pbk=KEY&sid=01ab&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision&type=tcp#R");
        let t = p.tls.unwrap();
        assert_eq!(t.reality.unwrap().short_id, "01ab");
        assert_eq!(t.utls.as_deref(), Some("chrome"));
    }

    #[test]
    fn hy2_port_hopping() {
        let p = one("hysteria2://pw@h.example:443?mport=20000-30000&obfs=salamander&obfs-password=o#hy");
        assert!(matches!(p.protocol, Protocol::Hysteria2 { ports: Some(ref s), .. } if s == "20000-30000"));
        let p = one("hy2://pw@h.example:20000-30000/?sni=a#hy");
        assert_eq!(p.port, 20000);
    }

    #[test]
    fn vmess_json() {
        let j = r#"{"v":"2","ps":"V","add":"a.com","port":"443","id":"u","aid":0,"net":"ws","host":"h","path":"/p?ed=2048","tls":"tls"}"#;
        let p = one(&format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(j)));
        assert_eq!(p.name, "V");
        assert!(matches!(p.transport, Some(Transport::Ws { .. })));
    }
}
