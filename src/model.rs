//! The intermediate representation (IR).
//!
//! Every input parses into a [`Config`]; every output renders from one.
//! Typed fields cover what the outputs understand. Anything else is kept in
//! the `extra` maps so that a same-format round trip loses nothing, and new
//! outputs can read fields the IR does not model yet.

use crate::value::{Map, Value};

/// The format a config was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceFormat {
    #[default]
    ClashYaml,
    ClashJson,
    SingBox,
    Links,
}

/// A whole client configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub source: SourceFormat,
    pub proxies: Vec<Proxy>,
    pub groups: Vec<Group>,
    pub rules: Vec<Rule>,
    pub rule_providers: Vec<RuleProvider>,
    /// Proxy providers are remote node lists; they are kept for mihomo and
    /// reported for targets that cannot fetch them.
    pub proxy_providers: Vec<(String, Value)>,
    pub dns: Option<Dns>,
    pub general: General,
    pub tun: Option<Tun>,
    /// Static hosts: name to addresses.
    pub hosts: Vec<(String, Vec<String>)>,
    /// Sub-rules (mihomo `sub-rules`), by name.
    pub sub_rules: Vec<(String, Vec<Rule>)>,
    /// Unmodelled top-level keys from a Clash/Mihomo source, in order.
    pub extra: Map,
}

/// Ports, mode and controller settings.
#[derive(Debug, Clone, Default)]
pub struct General {
    pub mixed_port: Option<u16>,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub allow_lan: Option<bool>,
    pub bind_address: Option<String>,
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub ipv6: Option<bool>,
    pub external_controller: Option<String>,
    pub secret: Option<String>,
    pub find_process_mode: Option<String>,
    pub interface_name: Option<String>,
    pub routing_mark: Option<u32>,
}

/// TUN settings.
#[derive(Debug, Clone, Default)]
pub struct Tun {
    pub enable: bool,
    pub stack: Option<String>,
    pub auto_route: Option<bool>,
    pub auto_detect_interface: Option<bool>,
    pub strict_route: Option<bool>,
    pub mtu: Option<u32>,
    pub dns_hijack: Vec<String>,
    pub device: Option<String>,
    pub inet4_address: Vec<String>,
    pub inet6_address: Vec<String>,
    pub route_address: Vec<String>,
    pub route_exclude_address: Vec<String>,
    pub extra: Map,
}

/// DNS settings, modelled on mihomo's DNS block.
#[derive(Debug, Clone, Default)]
pub struct Dns {
    pub enable: bool,
    pub ipv6: Option<bool>,
    pub listen: Option<String>,
    /// `fake-ip`, `redir-host` or `normal`.
    pub enhanced_mode: Option<String>,
    pub fake_ip_range: Option<String>,
    pub fake_ip_range6: Option<String>,
    pub fake_ip_filter: Vec<String>,
    pub fake_ip_filter_mode: Option<String>,
    pub default_nameserver: Vec<String>,
    pub nameserver: Vec<String>,
    pub fallback: Vec<String>,
    pub proxy_server_nameserver: Vec<String>,
    pub direct_nameserver: Vec<String>,
    /// Pattern (domain, `+.suffix`, `geosite:x`, `rule-set:x`) to servers.
    pub nameserver_policy: Vec<(String, Vec<String>)>,
    pub respect_rules: Option<bool>,
    pub use_hosts: Option<bool>,
    pub use_system_hosts: Option<bool>,
    pub prefer_h3: Option<bool>,
    pub extra: Map,
}

/// One outbound node.
#[derive(Debug, Clone, PartialEq)]
pub struct Proxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub protocol: Protocol,
    pub transport: Option<Transport>,
    pub tls: Option<Tls>,
    pub udp: Option<bool>,
    pub dial: Dial,
    /// Unmodelled keys, kept for same-format output.
    pub extra: Map,
}

/// Dialer options shared by all protocols.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Dial {
    pub interface: Option<String>,
    pub routing_mark: Option<u32>,
    pub tfo: Option<bool>,
    pub mptcp: Option<bool>,
    /// `dual`, `ipv4`, `ipv6`, `ipv4-prefer`, `ipv6-prefer`.
    pub ip_version: Option<String>,
    /// Chain through another proxy (mihomo `dialer-proxy`, sing-box `detour`).
    pub detour: Option<String>,
}

/// Protocol-specific fields.
#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Shadowsocks {
        cipher: String,
        password: String,
        plugin: Option<SsPlugin>,
        udp_over_tcp: Option<bool>,
        udp_over_tcp_version: Option<u8>,
    },
    ShadowsocksR {
        cipher: String,
        password: String,
        obfs: String,
        obfs_param: Option<String>,
        protocol: String,
        protocol_param: Option<String>,
    },
    Vmess {
        uuid: String,
        alter_id: u32,
        security: String,
        global_padding: Option<bool>,
        authenticated_length: Option<bool>,
        packet_encoding: Option<String>,
    },
    Vless {
        uuid: String,
        flow: Option<String>,
        packet_encoding: Option<String>,
        encryption: Option<String>,
    },
    Trojan {
        password: String,
    },
    Hysteria {
        auth: Option<String>,
        up: Option<String>,
        down: Option<String>,
        obfs: Option<String>,
        protocol: Option<String>,
        ports: Option<String>,
        recv_window_conn: Option<u64>,
        recv_window: Option<u64>,
        disable_mtu_discovery: Option<bool>,
    },
    Hysteria2 {
        password: String,
        /// Port-hopping range(s), mihomo syntax: `20000-30000,443`.
        ports: Option<String>,
        hop_interval: Option<u64>,
        obfs: Option<String>,
        obfs_password: Option<String>,
        up: Option<String>,
        down: Option<String>,
    },
    Tuic {
        uuid: Option<String>,
        password: Option<String>,
        /// TUIC v4 token (sing-box supports v5 only).
        token: Option<String>,
        congestion_control: Option<String>,
        udp_relay_mode: Option<String>,
        zero_rtt: Option<bool>,
        heartbeat: Option<String>,
    },
    AnyTls {
        password: String,
        idle_session_check_interval: Option<u64>,
        idle_session_timeout: Option<u64>,
        min_idle_session: Option<u64>,
    },
    WireGuard(WireGuard),
    Ssh {
        user: String,
        password: Option<String>,
        private_key: Option<String>,
        private_key_passphrase: Option<String>,
        host_key: Vec<String>,
        host_key_algorithms: Vec<String>,
    },
    Socks5 {
        user: Option<String>,
        password: Option<String>,
    },
    Http {
        user: Option<String>,
        password: Option<String>,
        headers: Vec<(String, String)>,
    },
    Snell {
        psk: String,
        version: Option<u8>,
        obfs_mode: Option<String>,
        obfs_host: Option<String>,
    },
    Mieru {
        user: String,
        password: String,
        transport: Option<String>,
        port_range: Option<String>,
        multiplexing: Option<String>,
    },
    /// A type the IR does not model; kept verbatim for same-format output.
    Other { kind: String },
}

impl Protocol {
    /// mihomo type name.
    pub fn clash_type(&self) -> &str {
        match self {
            Protocol::Shadowsocks { .. } => "ss",
            Protocol::ShadowsocksR { .. } => "ssr",
            Protocol::Vmess { .. } => "vmess",
            Protocol::Vless { .. } => "vless",
            Protocol::Trojan { .. } => "trojan",
            Protocol::Hysteria { .. } => "hysteria",
            Protocol::Hysteria2 { .. } => "hysteria2",
            Protocol::Tuic { .. } => "tuic",
            Protocol::AnyTls { .. } => "anytls",
            Protocol::WireGuard(_) => "wireguard",
            Protocol::Ssh { .. } => "ssh",
            Protocol::Socks5 { .. } => "socks5",
            Protocol::Http { .. } => "http",
            Protocol::Snell { .. } => "snell",
            Protocol::Mieru { .. } => "mieru",
            Protocol::Other { kind } => kind,
        }
    }
}

/// Shadowsocks SIP003 plugin.
#[derive(Debug, Clone, PartialEq)]
pub enum SsPlugin {
    /// simple-obfs: `http` or `tls`.
    Obfs { mode: String, host: Option<String> },
    /// v2ray-plugin (websocket only).
    V2ray {
        mode: String,
        tls: bool,
        host: Option<String>,
        path: Option<String>,
        mux: Option<bool>,
        skip_cert_verify: Option<bool>,
    },
    /// shadow-tls wrapper.
    ShadowTls {
        host: String,
        password: Option<String>,
        version: u8,
    },
    /// Any other plugin, by name with raw options.
    Other { name: String, opts: Value },
}

/// WireGuard settings.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WireGuard {
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    pub allowed_ips: Vec<String>,
    pub reserved: Option<Vec<u8>>,
    pub mtu: Option<u32>,
    pub keepalive: Option<u32>,
    /// Extra peers beyond the first (mihomo `peers:`), kept raw.
    pub extra_peers: Vec<Value>,
}

/// Stream transport.
#[derive(Debug, Clone, PartialEq)]
pub enum Transport {
    Ws {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
        max_early_data: Option<u32>,
        early_data_header: Option<String>,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
        headers: Vec<(String, String)>,
    },
    Grpc {
        service_name: String,
    },
    H2 {
        hosts: Vec<String>,
        path: String,
    },
    /// HTTP/1.1 header obfuscation (mihomo `network: http`).
    Http {
        method: Option<String>,
        paths: Vec<String>,
        hosts: Vec<String>,
        headers: Vec<(String, Vec<String>)>,
    },
    /// XHTTP / SplitHTTP (mihomo only).
    Xhttp {
        path: String,
        host: Option<String>,
        mode: Option<String>,
        raw: Value,
    },
    Quic,
}

impl Transport {
    pub fn name(&self) -> &'static str {
        match self {
            Transport::Ws { .. } => "ws",
            Transport::HttpUpgrade { .. } => "httpupgrade",
            Transport::Grpc { .. } => "grpc",
            Transport::H2 { .. } => "h2",
            Transport::Http { .. } => "http",
            Transport::Xhttp { .. } => "xhttp",
            Transport::Quic => "quic",
        }
    }
}

/// TLS settings.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Tls {
    pub enabled: bool,
    pub sni: Option<String>,
    pub insecure: Option<bool>,
    pub alpn: Vec<String>,
    /// uTLS client fingerprint (`chrome`, `firefox`...).
    pub utls: Option<String>,
    /// Certificate SHA-256 pin (mihomo `fingerprint`).
    pub cert_fingerprint: Option<String>,
    pub reality: Option<Reality>,
    /// ECH config (base64, as mihomo `ech-opts.config`).
    pub ech: Option<EchOpts>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Reality {
    pub public_key: String,
    pub short_id: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct EchOpts {
    pub enable: bool,
    pub config: Option<String>,
}

/// A proxy group.
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub name: String,
    pub kind: GroupKind,
    pub members: Vec<String>,
    pub use_providers: Vec<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u64>,
    pub timeout: Option<u64>,
    pub lazy: Option<bool>,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub exclude_type: Option<String>,
    pub include_all: bool,
    pub include_all_proxies: bool,
    pub include_all_providers: bool,
    pub hidden: Option<bool>,
    pub icon: Option<String>,
    pub extra: Map,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GroupKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance { strategy: Option<String> },
    Relay,
    Other(String),
}

impl GroupKind {
    pub fn clash_type(&self) -> &str {
        match self {
            GroupKind::Select => "select",
            GroupKind::UrlTest => "url-test",
            GroupKind::Fallback => "fallback",
            GroupKind::LoadBalance { .. } => "load-balance",
            GroupKind::Relay => "relay",
            GroupKind::Other(s) => s,
        }
    }
}

/// One routing rule: a matcher and a target (policy or group name).
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub matcher: Matcher,
    /// Target policy; empty for sub-matchers inside AND/OR/NOT.
    pub target: String,
    pub no_resolve: bool,
    /// `src` flag on IP rules (mihomo).
    pub src: bool,
    /// Original text, for diagnostics.
    pub raw: String,
}

/// What a rule matches.
#[derive(Debug, Clone, PartialEq)]
pub enum Matcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(String),
    DomainWildcard(String),
    Geosite(String),
    Geoip(String),
    SrcGeoip(String),
    IpCidr(String),
    SrcIpCidr(String),
    IpAsn(String),
    SrcIpAsn(String),
    IpSuffix(String),
    DstPort(String),
    SrcPort(String),
    InPort(String),
    InType(String),
    InUser(String),
    InName(String),
    ProcessName(String),
    ProcessPath(String),
    ProcessNameRegex(String),
    ProcessPathRegex(String),
    Uid(String),
    Network(String),
    Dscp(String),
    RuleSet(String),
    And(Vec<Matcher>),
    Or(Vec<Matcher>),
    Not(Box<Matcher>),
    SubRule(Box<Matcher>, String),
    Match,
    /// Unknown type, kept as `TYPE,payload`.
    Other(String, String),
}

/// A rule provider (rule set).
#[derive(Debug, Clone, PartialEq)]
pub struct RuleProvider {
    pub name: String,
    /// `http`, `file` or `inline`.
    pub kind: String,
    /// `domain`, `ipcidr` or `classical`.
    pub behavior: String,
    /// `yaml`, `text` or `mrs`.
    pub format: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Option<u64>,
    pub proxy: Option<String>,
    /// Inline payload (for `inline` providers or caller-supplied content).
    pub payload: Vec<String>,
    pub extra: Map,
}
