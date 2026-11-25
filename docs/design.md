# 设计

## 总体结构

```
输入文本/字节 ──► input::parse ──► model::Config（中间表示） ──► output::Target::render ──► 目标配置文本
                      │                                              │
                      └──────────── diag::Diagnostics ◄──────────────┘
```

每一步都往同一个 `Diagnostics` 里写诊断。任何没能原样带过去的东西（修复过的输入、跳过的节点、近似转换的策略组、丢掉的字段、改过的名字）都会留下一条诊断，不会悄悄丢掉。

源码布局（`src/`）：

| 文件 | 作用 |
|---|---|
| `lib.rs` | 对外 API：`convert`、`convert_bytes`、`ConvertOptions`、`Converted` |
| `main.rs` | 命令行 |
| `model.rs` | 中间表示 |
| `diag.rs` | 诊断 |
| `value.rs` | 通用的有序值树（解析 YAML/JSON 后的统一表示） |
| `yaml.rs` | 基于 `saphyr-parser` 事件的 YAML 读写，带深度、节点数、别名展开上限 |
| `input/mod.rs` | 格式识别和总入口 |
| `input/clash.rs` | Clash/Mihomo YAML 与 JSON |
| `input/singbox.rs` | sing-box JSON |
| `input/links.rs` | 分享链接 |
| `output/mod.rs` | `Target` 接口、目标注册表、裸节点列表的默认策略组 |
| `output/mihomo.rs` | mihomo YAML |
| `output/singbox.rs` | sing-box 1.12+ JSON |
| `output/rulesets.rs` | 公开规则集在 mihomo（.mrs/.yaml/.list）和 sing-box（.srs）之间的 URL 映射 |

依赖只有 `base64`、`saphyr-parser`、`serde_json`、`percent-encoding`、`regex`，全部 MIT 或 MIT/Apache-2.0。

## 中间表示（`model.rs`）

`Config` 是与客户端无关的整份配置：

- `proxies: Vec<Proxy>`：节点。`Proxy` 由名称、`Protocol`、拨号选项 `Dial`（interface、routing-mark、tfo、mptcp、ip-version、dialer-proxy）、`Transport`、`Tls` 组成。
  - `Protocol` 覆盖 Shadowsocks（含 obfs、v2ray-plugin、shadow-tls 等插件 `SsPlugin`）、ShadowsocksR、VMess、VLESS（含 flow）、Trojan、Hysteria、Hysteria2（含端口跳跃）、TUIC、AnyTLS、WireGuard、SSH、SOCKS、HTTP、Snell、Mieru，以及 `Other`（未知类型原样保留，留给支持它的目标）。
  - `Transport`：ws、httpupgrade、grpc、http/h2、xhttp、quic。
  - `Tls`：SNI、ALPN、跳过校验、uTLS 指纹、证书指纹、Reality、ECH、客户端证书。
- `groups: Vec<Group>`：策略组。`GroupKind` 有 select、url-test、fallback、load-balance（含策略）、relay、`Other`。
- `rules: Vec<Rule>`：规则。`Matcher` 覆盖 mihomo 的全部常见匹配项（DOMAIN 系、GEOSITE/GEOIP、IP-CIDR、ASN、端口、进程、UID、网络、DSCP、RULE-SET、AND/OR/NOT 等），以及 sub-rules。
- `rule_providers`、`proxy_providers`：规则集和远程节点列表。
- `dns: Option<Dns>`、`general`（端口、模式、控制器）、`tun`、`hosts`、`sub_rules`。
- `extra`：源配置里没有建模的顶层键，按原顺序保留，目标支持就原样写出。

设计原则：IR 存「意思」而不是某个客户端的写法，例如 Hysteria2 端口跳跃存成端口范围，输出时 mihomo 写 `ports`、sing-box 写 `server_ports`。

## 输入（`input/`）

识别顺序：HTML 错误页 → JSON（sing-box 或 Clash）→ 分享链接列表 → Clash/Mihomo YAML → Base64（最多嵌套三层）。识别失败时报错会给出第一行内容和支持的格式。

容错：

- 去掉 BOM，兼容 CRLF。
- 端口写成字符串、类型大写、密码是数字等常见写法照常读。
- 旧写法（`ws-path`、`ws-headers` 等）转成新结构。
- 单个节点坏了只跳过这个节点并报错，不影响其他节点。
- 重名节点自动改名并报告。
- 输入大小上限 64 MiB；YAML 有深度、节点数和别名展开上限，防止恶意输入。

## 输出（`output/`）

### `Target` 接口

```rust
pub trait Target {
    fn id(&self) -> &'static str;          // 命令行用的名字：mihomo、sing-box
    fn extension(&self) -> &'static str;   // 文件扩展名
    fn render(&self, cfg: &Config, opts: &ConvertOptions, d: &mut Diagnostics) -> String;
}
```

新加一个客户端（Surge、Stash、Loon、Quantumult X、Shadowrocket、Surfboard、Egern、V2Ray）就是新加一个实现 `Target` 的模块，并在 `output::targets()` 里注册。它只需要关心「怎么把 IR 写成自己的格式」以及「哪些东西写不出来，要报什么诊断」。输入端同理：新输入格式只需产出 `Config`。

### mihomo

保留原来的节点、策略组、规则、规则集、DNS 和其余顶层设置。来自 sing-box 的输入会转成等价的 mihomo 写法。

### sing-box（1.12+）

- 规则用 `rule_set`。`GEOSITE`/`GEOIP` 映射成 SagerNet 的 sing-geosite / sing-geoip 远程规则集；MetaCubeX meta-rules-dat 的 mihomo 规则集映射到同仓库 `sing` 分支的 .srs。映射不了的规则集报错，不瞎猜。
- 用户可以用 `--provider NAME=FILE` 提供规则集内容，内联成 sing-box 的 inline 规则集。
- DNS 用 1.12 的新服务器格式（`type` + `server`），fake-ip、规则、策略都转。
- sing-box 没有 fallback 和 load-balance 策略组，转成 urltest 并报告；没有 SSR，丢弃并报告。
- 裸节点列表（没有策略组和规则）会补一个 `PROXY` 选择组、最终规则和本地 mixed 入站，保证输出能直接用；`--no-defaults` 关掉。

## 诊断（`diag.rs`）

每条诊断有级别（info / warning / error）、类别（Repaired、Invalid、Unsupported、Approximated、FieldDropped、Renamed）、位置（如 `proxy "HK 01"`、`rule #12`、`dns`）、可选字段名和一句说明。命令行可以输出文本或 JSON；`--strict` 在有东西被丢弃时以状态码 2 退出，方便 Zephyr 这样的调用方判断。
