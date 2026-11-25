#!/usr/bin/env python3
"""Writes the benchmark samples. Every host, key and password is fake
(example.com, RFC 5737 addresses, placeholder keys).

Outputs in bench/samples/:
  full.yaml          Clash/Mihomo config with groups, rule providers, rules, DNS
  full.json          the same config as Clash JSON
  links.txt          share links, one per line, plus links.truth.json (what each
                     link means, written as Clash proxies)
  links.b64          links.txt as a Base64 subscription
  singbox.json       a sing-box 1.12 config (outbounds, endpoints, route, DNS)
  messy.yaml         a config with the faults real subscriptions have
  large.yaml         5000 nodes, for speed and memory
  large.b64          5000 share links as Base64, for speed and memory
  errors/*           inputs that cannot be converted, for error messages
"""
import base64, json, os, shutil, urllib.parse as up
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.join(HERE, 'samples')
os.makedirs(os.path.join(S, 'errors'), exist_ok=True)


def b64(s, url=False):
    raw = s.encode() if isinstance(s, str) else s
    e = base64.urlsafe_b64encode(raw) if url else base64.b64encode(raw)
    return e.decode().rstrip('=') if url else e.decode()


q = lambda s: up.quote(s, safe='')

# ---------------------------------------------------------------- share links
# (link, clash proxy it stands for)
UUID = '11111111-2222-3333-4444-5555555555%02d'
LINKS = []


def add(link, proxy):
    LINKS.append((link, proxy))


add('ss://' + b64('aes-256-gcm:fakepass', url=True) + '@203.0.113.1:8388#' + q('SS AEAD'),
    {'name': 'SS AEAD', 'type': 'ss', 'server': '203.0.113.1', 'port': 8388, 'cipher': 'aes-256-gcm', 'password': 'fakepass'})
add('ss://' + q('2022-blake3-aes-128-gcm') + ':' + q('AAAAAAAAAAAAAAAAAAAAAA==') + '@ss.example.com:8389#' + q('SS 2022'),
    {'name': 'SS 2022', 'type': 'ss', 'server': 'ss.example.com', 'port': 8389, 'cipher': '2022-blake3-aes-128-gcm', 'password': 'AAAAAAAAAAAAAAAAAAAAAA=='})
add('ss://' + b64('chacha20-ietf-poly1305:fakepass', url=True) + '@203.0.113.2:8390/?plugin=' + q('obfs-local;obfs=http;obfs-host=bing.com') + '#' + q('SS obfs'),
    {'name': 'SS obfs', 'type': 'ss', 'server': '203.0.113.2', 'port': 8390, 'cipher': 'chacha20-ietf-poly1305', 'password': 'fakepass',
     'plugin': 'obfs', 'plugin-opts': {'mode': 'http', 'host': 'bing.com'}})
add('ss://' + b64('aes-128-gcm:fakepass', url=True) + '@203.0.113.3:443/?plugin=' + q('v2ray-plugin;mode=websocket;tls;host=v2.example.com;path=/ws') + '#' + q('SS v2ray-plugin'),
    {'name': 'SS v2ray-plugin', 'type': 'ss', 'server': '203.0.113.3', 'port': 443, 'cipher': 'aes-128-gcm', 'password': 'fakepass',
     'plugin': 'v2ray-plugin', 'plugin-opts': {'mode': 'websocket', 'tls': True, 'host': 'v2.example.com', 'path': '/ws'}})
# legacy whole-base64 ss form
add('ss://' + b64('aes-256-cfb:fakepass@203.0.113.4:8391') + '#' + q('SS legacy'),
    {'name': 'SS legacy', 'type': 'ss', 'server': '203.0.113.4', 'port': 8391, 'cipher': 'aes-256-cfb', 'password': 'fakepass'})
add('ssr://' + b64('203.0.113.5:8392:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:' + b64('fakepass', url=True)
                   + '/?obfsparam=' + b64('obfs.example.com', url=True) + '&protoparam=' + b64('32:proto', url=True)
                   + '&remarks=' + b64('SSR 节点', url=True), url=True),
    {'name': 'SSR 节点', 'type': 'ssr', 'server': '203.0.113.5', 'port': 8392, 'cipher': 'aes-256-cfb', 'password': 'fakepass',
     'protocol': 'auth_aes128_md5', 'protocol-param': '32:proto', 'obfs': 'tls1.2_ticket_auth', 'obfs-param': 'obfs.example.com'})


def vmess(name, server, port, uid, net, tls, **kw):
    j = {'v': '2', 'ps': name, 'add': server, 'port': str(port), 'id': uid, 'aid': '0', 'scy': 'auto', 'net': net,
         'type': kw.get('type', 'none'), 'host': kw.get('host', ''), 'path': kw.get('path', ''), 'tls': 'tls' if tls else '',
         'sni': kw.get('sni', ''), 'alpn': kw.get('alpn', ''), 'fp': kw.get('fp', '')}
    return 'vmess://' + b64(json.dumps(j, ensure_ascii=False))


add(vmess('VMess WS', 'vm.example.com', 443, UUID % 1, 'ws', True, host='vm.example.com', path='/vmws?ed=2048', sni='vm.example.com', alpn='h2,http/1.1', fp='chrome'),
    {'name': 'VMess WS', 'type': 'vmess', 'server': 'vm.example.com', 'port': 443, 'uuid': UUID % 1, 'alterId': 0, 'cipher': 'auto',
     'tls': True, 'servername': 'vm.example.com', 'alpn': ['h2', 'http/1.1'], 'client-fingerprint': 'chrome', 'network': 'ws',
     'ws-opts': {'path': '/vmws?ed=2048', 'headers': {'Host': 'vm.example.com'}}})
add(vmess('VMess gRPC', 'vm2.example.com', 443, UUID % 2, 'grpc', True, path='gunservice', sni='vm2.example.com'),
    {'name': 'VMess gRPC', 'type': 'vmess', 'server': 'vm2.example.com', 'port': 443, 'uuid': UUID % 2, 'alterId': 0, 'cipher': 'auto',
     'tls': True, 'servername': 'vm2.example.com', 'network': 'grpc', 'grpc-opts': {'grpc-service-name': 'gunservice'}})
add(vmess('VMess H2', 'vm3.example.com', 443, UUID % 3, 'h2', True, host='vm3.example.com', path='/h2'),
    {'name': 'VMess H2', 'type': 'vmess', 'server': 'vm3.example.com', 'port': 443, 'uuid': UUID % 3, 'alterId': 0, 'cipher': 'auto',
     'tls': True, 'network': 'h2', 'h2-opts': {'host': ['vm3.example.com'], 'path': '/h2'}})
add(vmess('VMess TCP HTTP', '203.0.113.6', 80, UUID % 4, 'tcp', False, type='http', host='www.bing.com', path='/'),
    {'name': 'VMess TCP HTTP', 'type': 'vmess', 'server': '203.0.113.6', 'port': 80, 'uuid': UUID % 4, 'alterId': 0, 'cipher': 'auto',
     'network': 'http', 'http-opts': {'method': 'GET', 'path': ['/'], 'headers': {'Host': ['www.bing.com']}}})
add(vmess('VMess TCP', '203.0.113.7', 10086, UUID % 5, 'tcp', False),
    {'name': 'VMess TCP', 'type': 'vmess', 'server': '203.0.113.7', 'port': 10086, 'uuid': UUID % 5, 'alterId': 0, 'cipher': 'auto'})

PBK = 'cU8Zyhhd2KPM53Bth1s59kIkPBRb-D63eYMPCb_LDTQ'
add('vless://' + UUID % 6 + '@203.0.113.8:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=' + PBK
    + '&sid=0123abcd&flow=xtls-rprx-vision&type=tcp#' + q('VLESS Reality'),
    {'name': 'VLESS Reality', 'type': 'vless', 'server': '203.0.113.8', 'port': 443, 'uuid': UUID % 6, 'network': 'tcp', 'tls': True,
     'flow': 'xtls-rprx-vision', 'servername': 'www.microsoft.com', 'client-fingerprint': 'chrome',
     'reality-opts': {'public-key': PBK, 'short-id': '0123abcd'}})
add('vless://' + UUID % 7 + '@vl.example.com:443?encryption=none&security=tls&sni=vl.example.com&type=ws&host=vl.example.com&path=' + q('/vlws') + '#' + q('VLESS WS'),
    {'name': 'VLESS WS', 'type': 'vless', 'server': 'vl.example.com', 'port': 443, 'uuid': UUID % 7, 'network': 'ws', 'tls': True,
     'servername': 'vl.example.com', 'ws-opts': {'path': '/vlws', 'headers': {'Host': 'vl.example.com'}}})
add('vless://' + UUID % 8 + '@vl2.example.com:443?encryption=none&security=tls&sni=vl2.example.com&type=grpc&serviceName=vlgrpc&alpn=h2#' + q('VLESS gRPC'),
    {'name': 'VLESS gRPC', 'type': 'vless', 'server': 'vl2.example.com', 'port': 443, 'uuid': UUID % 8, 'network': 'grpc', 'tls': True,
     'servername': 'vl2.example.com', 'alpn': ['h2'], 'grpc-opts': {'grpc-service-name': 'vlgrpc'}})
add('vless://' + UUID % 9 + '@vl3.example.com:443?encryption=none&security=tls&sni=vl3.example.com&type=httpupgrade&host=vl3.example.com&path=' + q('/up') + '#' + q('VLESS HTTPUpgrade'),
    {'name': 'VLESS HTTPUpgrade', 'type': 'vless', 'server': 'vl3.example.com', 'port': 443, 'uuid': UUID % 9, 'network': 'httpupgrade', 'tls': True,
     'servername': 'vl3.example.com', 'http-upgrade-opts': {'path': '/up', 'host': 'vl3.example.com'}})
add('trojan://fakepass@tj.example.com:443?sni=tj.example.com&allowInsecure=1#' + q('Trojan TCP'),
    {'name': 'Trojan TCP', 'type': 'trojan', 'server': 'tj.example.com', 'port': 443, 'password': 'fakepass', 'sni': 'tj.example.com', 'skip-cert-verify': True})
add('trojan://fakepass@tj2.example.com:443?sni=tj2.example.com&type=ws&host=tj2.example.com&path=' + q('/tjws') + '#' + q('Trojan WS'),
    {'name': 'Trojan WS', 'type': 'trojan', 'server': 'tj2.example.com', 'port': 443, 'password': 'fakepass', 'sni': 'tj2.example.com', 'network': 'ws',
     'ws-opts': {'path': '/tjws', 'headers': {'Host': 'tj2.example.com'}}})
add('trojan://fakepass@tj3.example.com:443?sni=tj3.example.com&type=grpc&serviceName=tjgrpc#' + q('Trojan gRPC'),
    {'name': 'Trojan gRPC', 'type': 'trojan', 'server': 'tj3.example.com', 'port': 443, 'password': 'fakepass', 'sni': 'tj3.example.com', 'network': 'grpc',
     'grpc-opts': {'grpc-service-name': 'tjgrpc'}})
add('hysteria://hy.example.com:443?protocol=udp&auth=fakeauth&peer=hy.example.com&upmbps=50&downmbps=200&alpn=h3#' + q('Hysteria'),
    {'name': 'Hysteria', 'type': 'hysteria', 'server': 'hy.example.com', 'port': 443, 'auth-str': 'fakeauth', 'sni': 'hy.example.com',
     'up': 50, 'down': 200, 'alpn': ['h3'], 'protocol': 'udp'})
add('hysteria2://fakepass@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=obfsfake&mport=20000-30000#' + q('Hysteria2 hop'),
    {'name': 'Hysteria2 hop', 'type': 'hysteria2', 'server': 'hy2.example.com', 'port': 443, 'ports': '20000-30000', 'password': 'fakepass',
     'sni': 'hy2.example.com', 'obfs': 'salamander', 'obfs-password': 'obfsfake'})
add('hy2://fakepass@hy3.example.com:8443?sni=hy3.example.com&insecure=1#' + q('HY2 short'),
    {'name': 'HY2 short', 'type': 'hysteria2', 'server': 'hy3.example.com', 'port': 8443, 'password': 'fakepass', 'sni': 'hy3.example.com', 'skip-cert-verify': True})
add('tuic://' + UUID % 10 + ':fakepass@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.com#' + q('TUIC v5'),
    {'name': 'TUIC v5', 'type': 'tuic', 'server': 'tuic.example.com', 'port': 443, 'uuid': UUID % 10, 'password': 'fakepass', 'alpn': ['h3'],
     'congestion-controller': 'bbr', 'udp-relay-mode': 'native', 'sni': 'tuic.example.com'})
add('anytls://fakepass@any.example.com:443/?sni=any.example.com&fp=chrome#' + q('AnyTLS'),
    {'name': 'AnyTLS', 'type': 'anytls', 'server': 'any.example.com', 'port': 443, 'password': 'fakepass', 'sni': 'any.example.com', 'client-fingerprint': 'chrome'})
WG_PRIV = 'eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU='
WG_PUB = 'Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo='
add('wireguard://' + q(WG_PRIV) + '@203.0.113.9:51820?publickey=' + q(WG_PUB) + '&address=' + q('172.16.0.2/32,fd01::2/128') + '&mtu=1280#' + q('WireGuard'),
    {'name': 'WireGuard', 'type': 'wireguard', 'server': '203.0.113.9', 'port': 51820, 'private-key': WG_PRIV, 'public-key': WG_PUB,
     'ip': '172.16.0.2', 'ipv6': 'fd01::2', 'mtu': 1280})
add('socks://' + b64('u:p') + '@203.0.113.10:1080#' + q('SOCKS5'),
    {'name': 'SOCKS5', 'type': 'socks5', 'server': '203.0.113.10', 'port': 1080, 'username': 'u', 'password': 'p'})
add('https://u:p@203.0.113.11:443#' + q('HTTPS proxy'),
    {'name': 'HTTPS proxy', 'type': 'http', 'server': '203.0.113.11', 'port': 443, 'username': 'u', 'password': 'p', 'tls': True})

links_txt = '\n'.join(l for l, _ in LINKS) + '\n'
open(os.path.join(S, 'links.txt'), 'w').write(links_txt)
open(os.path.join(S, 'links.b64'), 'w').write(b64(links_txt))
json.dump([p for _, p in LINKS], open(os.path.join(S, 'links.truth.json'), 'w'), ensure_ascii=False, indent=1)

# ---------------------------------------------------------------- full config
src_full = os.path.join(HERE, 'samples', 'full.yaml')
full = yaml.safe_load(open(src_full))
json.dump(full, open(os.path.join(S, 'full.json'), 'w'), ensure_ascii=False, indent=1)

# ---------------------------------------------------------------- sing-box input
singbox = {
    'log': {'level': 'info'},
    'dns': {
        'servers': [
            {'type': 'https', 'tag': 'ali', 'server': 'dns.alidns.com'},
            {'type': 'tls', 'tag': 'cf', 'server': '1.1.1.1', 'detour': 'Proxy'},
            {'type': 'fakeip', 'tag': 'fakeip', 'inet4_range': '198.18.0.0/15'},
        ],
        'rules': [{'rule_set': 'geosite-cn', 'server': 'ali'}, {'query_type': ['A', 'AAAA'], 'server': 'fakeip'}],
        'final': 'cf', 'strategy': 'prefer_ipv4',
    },
    'inbounds': [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7890}],
    'outbounds': [
        {'type': 'selector', 'tag': 'Proxy', 'outbounds': ['Auto', 'SB SS', 'SB VLESS Reality', 'SB Trojan WS', 'direct']},
        {'type': 'urltest', 'tag': 'Auto', 'outbounds': ['SB SS', 'SB VLESS Reality', 'SB Hysteria2', 'SB TUIC'], 'url': 'https://www.gstatic.com/generate_204', 'interval': '5m', 'tolerance': 50},
        {'type': 'shadowsocks', 'tag': 'SB SS', 'server': '203.0.113.60', 'server_port': 8388, 'method': 'aes-256-gcm', 'password': 'fakepass'},
        {'type': 'shadowsocks', 'tag': 'SB SS obfs', 'server': '203.0.113.61', 'server_port': 8389, 'method': 'aes-128-gcm', 'password': 'fakepass',
         'plugin': 'obfs-local', 'plugin_opts': 'obfs=http;obfs-host=bing.com'},
        {'type': 'vmess', 'tag': 'SB VMess WS', 'server': 'vm.example.com', 'server_port': 443, 'uuid': UUID % 21, 'security': 'auto', 'alter_id': 0,
         'tls': {'enabled': True, 'server_name': 'vm.example.com', 'utls': {'enabled': True, 'fingerprint': 'chrome'}},
         'transport': {'type': 'ws', 'path': '/vmws', 'headers': {'Host': 'vm.example.com'}, 'max_early_data': 2048, 'early_data_header_name': 'Sec-WebSocket-Protocol'}},
        {'type': 'vless', 'tag': 'SB VLESS Reality', 'server': '203.0.113.62', 'server_port': 443, 'uuid': UUID % 22, 'flow': 'xtls-rprx-vision',
         'tls': {'enabled': True, 'server_name': 'www.microsoft.com', 'utls': {'enabled': True, 'fingerprint': 'chrome'},
                 'reality': {'enabled': True, 'public_key': PBK, 'short_id': '0123abcd'}}},
        {'type': 'vless', 'tag': 'SB VLESS gRPC', 'server': 'vl.example.com', 'server_port': 443, 'uuid': UUID % 23,
         'tls': {'enabled': True, 'server_name': 'vl.example.com'}, 'transport': {'type': 'grpc', 'service_name': 'vlgrpc'}},
        {'type': 'trojan', 'tag': 'SB Trojan WS', 'server': 'tj.example.com', 'server_port': 443, 'password': 'fakepass',
         'tls': {'enabled': True, 'server_name': 'tj.example.com', 'insecure': True}, 'transport': {'type': 'ws', 'path': '/tjws', 'headers': {'Host': 'tj.example.com'}}},
        {'type': 'hysteria2', 'tag': 'SB Hysteria2', 'server': 'hy2.example.com', 'server_ports': ['20000:30000'], 'password': 'fakepass', 'up_mbps': 50, 'down_mbps': 200,
         'obfs': {'type': 'salamander', 'password': 'obfsfake'}, 'tls': {'enabled': True, 'server_name': 'hy2.example.com'}},
        {'type': 'tuic', 'tag': 'SB TUIC', 'server': 'tuic.example.com', 'server_port': 443, 'uuid': UUID % 24, 'password': 'fakepass',
         'congestion_control': 'bbr', 'udp_relay_mode': 'native', 'tls': {'enabled': True, 'server_name': 'tuic.example.com', 'alpn': ['h3']}},
        {'type': 'anytls', 'tag': 'SB AnyTLS', 'server': 'any.example.com', 'server_port': 443, 'password': 'fakepass', 'tls': {'enabled': True, 'server_name': 'any.example.com'}},
        {'type': 'socks', 'tag': 'SB SOCKS', 'server': '203.0.113.63', 'server_port': 1080, 'version': '5', 'username': 'u', 'password': 'p'},
        {'type': 'direct', 'tag': 'direct'},
    ],
    'endpoints': [
        {'type': 'wireguard', 'tag': 'SB WireGuard', 'address': ['172.16.0.2/32', 'fd01::2/128'], 'private_key': WG_PRIV, 'mtu': 1280,
         'peers': [{'address': '203.0.113.64', 'port': 51820, 'public_key': WG_PUB, 'allowed_ips': ['0.0.0.0/0', '::/0']}]},
    ],
    'route': {
        'rule_set': [
            {'type': 'remote', 'tag': 'geosite-cn', 'format': 'binary', 'url': 'https://example.com/rules/geosite-cn.srs'},
            {'type': 'remote', 'tag': 'geoip-cn', 'format': 'binary', 'url': 'https://example.com/rules/geoip-cn.srs'},
        ],
        'rules': [
            {'action': 'sniff'},
            {'protocol': 'dns', 'action': 'hijack-dns'},
            {'domain_suffix': ['ads.example.net'], 'action': 'reject'},
            {'domain': ['api.example.com'], 'outbound': 'direct'},
            {'domain_suffix': ['google.com'], 'domain_keyword': ['youtube'], 'outbound': 'Proxy'},
            {'ip_is_private': True, 'outbound': 'direct'},
            {'rule_set': ['geosite-cn', 'geoip-cn'], 'outbound': 'direct'},
            {'port': [22], 'outbound': 'direct'},
        ],
        'final': 'Proxy', 'auto_detect_interface': True,
    },
}
json.dump(singbox, open(os.path.join(S, 'singbox.json'), 'w'), ensure_ascii=False, indent=1)

# ---------------------------------------------------------------- messy input
# Faults seen in real subscriptions. MESSY_VALID lists the nodes a converter
# should keep; the broken ones should be reported and skipped, not kill the run.
messy = '\ufeff' + '''# exported by some panel\r
port: 7890\r
socks-port: 7891\r
mode: Rule\r
proxies:\r
  - {name: "M1 port as string", type: ss, server: 203.0.113.70, port: "8388", cipher: aes-256-gcm, password: fakepass}\r
  - {name: "M2 upper-case type", type: VMESS, server: 203.0.113.71, port: 443, uuid: 11111111-2222-3333-4444-555555555531, alterId: 0, cipher: auto}\r
  - {name: "M3 unknown field", type: trojan, server: 203.0.113.72, port: 443, password: fakepass, sni: tj.example.com, some-new-field: 1}\r
  - {name: "M4 missing port", type: ss, server: 203.0.113.73, cipher: aes-256-gcm, password: fakepass}\r
  - {name: "M5 unknown type", type: mieru, server: 203.0.113.74, port: 2999, username: u, password: p}\r
  - {name: "M6 duplicate", type: ss, server: 203.0.113.75, port: 8388, cipher: aes-256-gcm, password: fakepass}\r
  - {name: "M6 duplicate", type: ss, server: 203.0.113.76, port: 8388, cipher: aes-256-gcm, password: fakepass}\r
  - {name: "M7 password number", type: trojan, server: 203.0.113.77, port: 443, password: 123456, sni: tj.example.com}\r
  - {name: "M8 ws-path legacy", type: vmess, server: 203.0.113.78, port: 80, uuid: 11111111-2222-3333-4444-555555555532, alterId: 0, cipher: auto, network: ws, ws-path: /legacy, ws-headers: {Host: legacy.example.com}}\r
  - {name: "M9 bad uuid", type: vless, server: 203.0.113.79, port: 443, uuid: not-a-uuid, tls: true}\r
  - {name: "M10 tab\tin name", type: ss, server: 203.0.113.80, port: 8388, cipher: aes-256-gcm, password: fakepass}\r
proxy-groups:\r
  - {name: PROXY, type: select, proxies: ["M1 port as string", "M2 upper-case type", "M4 missing port", "M5 unknown type", "M6 duplicate", DIRECT]}\r
  - {name: Empty, type: select, proxies: []}\r
rules:\r
  - DOMAIN-SUFFIX,example.com,PROXY\r
  - DOMAIN-SUFFIX,missing.example,NoSuchGroup\r
  - MATCH,PROXY\r
'''
open(os.path.join(S, 'messy.yaml'), 'w', newline='').write(messy)
json.dump({'valid': ['M1 port as string', 'M2 upper-case type', 'M3 unknown field', 'M6 duplicate', 'M6 duplicate (2)',
                     'M7 password number', 'M8 ws-path legacy', 'M10 tab\tin name'],
           'invalid': ['M4 missing port', 'M5 unknown type', 'M9 bad uuid'],
           'note': 'M6 appears twice with different servers; both should survive (one renamed). M5 (mieru) is valid for mihomo but has no sing-box counterpart.'},
          open(os.path.join(S, 'messy.truth.json'), 'w'), ensure_ascii=False, indent=1)

# ---------------------------------------------------------------- large inputs
large = {'proxies': [], 'proxy-groups': [], 'rules': []}
links = []
for i in range(5000):
    kind = i % 5
    name = f'L{i:04d}'
    host = f'n{i}.example.com'
    if kind == 0:
        p = {'name': name, 'type': 'ss', 'server': host, 'port': 10000 + i % 50000, 'cipher': 'aes-256-gcm', 'password': f'pw{i}'}
        links.append('ss://' + b64(f'aes-256-gcm:pw{i}', url=True) + f'@{host}:{p["port"]}#{name}')
    elif kind == 1:
        u = f'11111111-2222-3333-4444-{i:012d}'
        p = {'name': name, 'type': 'vmess', 'server': host, 'port': 443, 'uuid': u, 'alterId': 0, 'cipher': 'auto', 'tls': True,
             'servername': host, 'network': 'ws', 'ws-opts': {'path': '/ws', 'headers': {'Host': host}}}
        links.append(vmess(name, host, 443, u, 'ws', True, host=host, path='/ws', sni=host))
    elif kind == 2:
        u = f'22222222-3333-4444-5555-{i:012d}'
        p = {'name': name, 'type': 'vless', 'server': host, 'port': 443, 'uuid': u, 'network': 'tcp', 'tls': True, 'flow': 'xtls-rprx-vision',
             'servername': 'www.microsoft.com', 'client-fingerprint': 'chrome', 'reality-opts': {'public-key': PBK, 'short-id': '0123abcd'}}
        links.append(f'vless://{u}@{host}:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk={PBK}&sid=0123abcd&flow=xtls-rprx-vision&type=tcp#{name}')
    elif kind == 3:
        p = {'name': name, 'type': 'trojan', 'server': host, 'port': 443, 'password': f'pw{i}', 'sni': host}
        links.append(f'trojan://pw{i}@{host}:443?sni={host}#{name}')
    else:
        p = {'name': name, 'type': 'hysteria2', 'server': host, 'port': 443, 'password': f'pw{i}', 'sni': host}
        links.append(f'hysteria2://pw{i}@{host}:443?sni={host}#{name}')
    large['proxies'].append(p)
names = [p['name'] for p in large['proxies']]
large['proxy-groups'] = [{'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO'] + names},
                         {'name': 'AUTO', 'type': 'url-test', 'proxies': names, 'url': 'https://www.gstatic.com/generate_204', 'interval': 300}]
large['rules'] = [f'DOMAIN-SUFFIX,site{i}.example.com,PROXY' for i in range(2000)] + ['MATCH,PROXY']
open(os.path.join(S, 'large.yaml'), 'w').write(yaml.safe_dump(large, allow_unicode=True, sort_keys=False))
open(os.path.join(S, 'large.b64'), 'w').write(b64('\n'.join(links) + '\n'))

# ---------------------------------------------------------------- error inputs
ERR = {
    'empty.txt': '',
    'html.txt': '<!DOCTYPE html><html><head><title>Subscription expired</title></head><body>Your plan has expired.</body></html>\n',
    'broken-yaml.yaml': 'proxies:\n  - name: a\n    type: ss\n    server: 203.0.113.90\n   port: 8388\n  cipher: aes-256-gcm\n',
    'broken-json.json': '{"outbounds": [{"type": "shadowsocks", "tag": "a", "server": "203.0.113.91",, "server_port": 8388}]}\n',
    'bad-base64.txt': 'dm1lc3M6Ly9!!!notbase64***\n',
    'no-nodes.yaml': 'port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n',
    'bad-link.txt': 'vmess://' + b64('{"add": "203.0.113.92", "port": "443"') + '\n',
}
for k, v in ERR.items():
    open(os.path.join(S, 'errors', k), 'w').write(v)
json.dump({
    'empty.txt': ['empty'],
    'html.txt': ['html', 'web page', 'webpage', 'expired'],
    'broken-yaml.yaml': ['yaml', 'indent', 'mapping'],
    'broken-json.json': ['json'],
    'bad-base64.txt': ['base64', 'not a subscription', 'unrecognized', 'unknown format', 'no node'],
    'no-nodes.yaml': ['no node', 'no proxies', 'no proxy', 'empty'],
    'bad-link.txt': ['vmess', 'json'],
}, open(os.path.join(S, 'errors.keywords.json'), 'w'), indent=1)
print('samples written to', S)
