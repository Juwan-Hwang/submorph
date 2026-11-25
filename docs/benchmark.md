# 对比基准

> 状态：**未完成**。样例、竞品运行器和运行脚本已写好，还没有完整跑过一遍；打分脚本 `bench/score.py` 还没写。所以目前**还不能**宣称在各个维度上超过了全部竞品。下面分开写：基准怎么设计、submorph 自己目前的实测结果、调研阶段对竞品的实测结果。

## 设计

### 样例（`bench/samples/`，由 `bench/make_samples.py` 生成）

所有主机、密码、密钥都是假的：example.com、RFC 5737 的 203.0.113.0/24 地址、占位密钥。

| 文件 | 内容 | 考察的维度 |
|---|---|---|
| `full.yaml` | 17 个节点、多种策略组、规则集、规则、DNS 的完整 Clash 配置（调研时用的同一份） | 无损、策略组和规则、DNS |
| `full.json` | 同一份配置的 JSON 写法 | 输入格式 |
| `links.txt` / `links.b64` | 26 条分享链接及其 Base64，覆盖 SS（AEAD、2022、obfs、v2ray-plugin、旧式整体 Base64）、SSR、VMess（ws、grpc、h2、http、tcp）、VLESS（Reality、ws、grpc、httpupgrade）、Trojan（tcp、ws、grpc）、Hysteria、Hysteria2（端口跳跃、hy2 简写）、TUIC、AnyTLS、WireGuard、SOCKS5、HTTPS | 协议和传输覆盖、正确率 |
| `links.truth.json` | 每条链接应该得到的 Clash 节点（标准答案） | 正确率 |
| `singbox.json` | sing-box 1.12 配置：outbounds、WireGuard endpoint、route、rule_set、新格式 DNS | sing-box 输入 |
| `messy.yaml` | BOM、CRLF、端口写成字符串、类型大写、未知字段、缺端口、未知类型、重名、密码是数字、旧式 ws-path、坏 UUID、名字含制表符、空策略组、规则指向不存在的组 | 输入容错 |
| `messy.truth.json` | 哪些节点应该保留、哪些应该报错 | 输入容错 |
| `errors/*` | 空文件、HTML 过期页、坏 YAML、坏 JSON、坏 Base64、无节点配置、坏 vmess 链接 | 报错质量 |
| `errors.keywords.json` | 每种错误的好报错应该提到的关键词 | 报错质量 |
| `large.yaml` / `large.b64` | 5000 个节点（另有 2000 条规则），运行时生成，不入库 | 速度和内存 |

### 竞品（`bench/setup.sh` 准备，`bench/runners/` 调用）

竞品源码和内核二进制放在仓库外的目录（环境变量 `CONVERTERS`，默认是仓库旁边的 `../converters`）。构建产物在 git 忽略的 `bench/runners/.cache/`，不入库。

| 工具 | 怎么调用 | 输出 |
|---|---|---|
| Sub-Store 2.44.18（SubCase 用的是同一套核心） | esbuild 打包其 `proxy-utils`，直接调 `parse` / `produce` | mihomo、sing-box |
| Sublink Worker（sub.haitunt.org 的实现） | Node 直接调它的 ConfigBuilder，默认 balanced 规则 | Clash、sing-box |
| subconverter v0.9.0（tindy2013，sub-web.wcc.best 的后端） | 本地 HTTP 服务 | Clash |
| subconverter v0.9.9（asdlokj1qpi233 活跃分支） | 本地 HTTP 服务 | Clash、sing-box |
| subconverter v0.9.2（MetaCubeX 分支） | 本地 HTTP 服务 | Clash、sing-box |
| SubBoost | esbuild 打包 `@subboost/core` 的 parser 和 generator | Clash |
| ConfigFlow | Python 直接调它的订阅解析器和 Mihomo 节点转换 | mihomo |

说明：

- subconverter 类工具：粘贴的链接按 sub-web 前端的做法用 `|` 拼接传入；订阅文件传本地路径。
- ConfigFlow 转换分享链接时会去调一个 Sub-Store 服务，本地没有这个服务时链接输入会失败，这是它的实际行为。
- 在线站不单独测，按它们背后的开源实现测。

### 运行方式（`bench/run.py`）

1. 编译 submorph release，重新生成样例。
2. 在只有回环网卡的网络命名空间里（`sudo unshare -n`）跑一遍所有工具：需要联网的工具会在结果里暴露出来，这就是「完全本地运行」这一项的数据。
3. 在正常网络下再跑一遍，给需要联网的工具公平机会（只会拉规则模板之类，样例永远不发出去）。
4. 速度和内存：大样例每个工具跑 3 次取中位数，进程类工具量整个进程的时间和峰值内存，subconverter 量 HTTP 请求时间和服务进程峰值内存（每次重启）。
5. 打分（待写）：用 sing-box 1.12.12、1.14.4 和 mihomo 加载每份输出；对照 truth 文件算节点和字段的保留率；统计策略组、规则、DNS 的保留情况；容错样例按 messy.truth.json 计分；报错样例按关键词计分。

## submorph 目前的实测结果

2026 年 11 月 25 日在开发机上手动跑（还不是 run.py 的完整结果）。内核版本：sing-box 1.12.12、sing-box 1.14.4、Mihomo Meta v1.19.34。时间和内存是 `/usr/bin/time` 量的整个进程。

| 样例 | 目标 | 内核加载 | 输出节点 | 诊断条数 |
|---|---|---|---|---|
| full.yaml | mihomo | mihomo 通过 | 17/17 | 0 |
| full.yaml | sing-box | 1.12 和 1.14 都通过 | 17/17（另有策略组等共 24 个 outbound/endpoint） | 9 |
| full.json | mihomo | 通过 | 17/17 | 0 |
| full.json | sing-box | 都通过 | 17/17 | 9 |
| links.txt / links.b64 | mihomo | 通过 | 26/26 | 1 |
| links.txt / links.b64 | sing-box | 都通过 | 25/26（SSR 已从 sing-box 移除，丢弃并报告） | 4 |
| singbox.json | sing-box | 都通过 | 10/11（**bug**：只写了 `server_ports` 的 Hysteria2 被误判为缺端口而丢弃） | 3 |
| singbox.json | mihomo | **失败** | 10/11（同一个 bug，且策略组里还引用着被丢的节点） | 3 |
| messy.yaml | sing-box | 都通过 | 9（M4 缺端口报错跳过；M5 mieru 在 sing-box 不存在，报告后丢弃；**bug**：M9 坏 UUID 没被拦下） | 8 |
| messy.yaml | mihomo | **失败** | 10（**bug**：M5 mieru 缺 `transport` 字段原样写出，mihomo 拒绝加载；M9 坏 UUID 没被拦下） | 3 |
| large.yaml（5000 节点） | mihomo | 通过 | 5000 | 0.16 秒，峰值 25 MB |
| large.yaml | sing-box | 都通过 | 5000 | 0.22 秒，峰值 30 MB |
| large.b64（5000 链接） | mihomo | 通过 | 5000 | 0.15 秒，峰值 17 MB |
| large.b64 | sing-box | 都通过 | 5000 | 0.15 秒，峰值 24 MB |

小样例每次都在 0.01 秒内完成，峰值内存 3 到 5 MB。

`full.yaml` 转 sing-box 的 9 条诊断都是 sing-box 本身表达不了的东西：DNS fallback；fallback 和 load-balance 组只能近似成 urltest；`ads` 是 mihomo 二进制 .mrs 规则集、没有已知的 sing-box 版本；`telegram-ip` 是 Clash YAML 列表、sing-box 读不了（可用 `--provider` 内联）——这两条规则因此丢弃并报错。

两个 mihomo 加载失败是已知 bug，见 [progress.md](progress.md)。

## 调研阶段对竞品的实测（只用 full.yaml）

2026 年 11 月 19 日调研时用同一份 full.yaml 在本地测过的结果（详见 [research.html](research.html)）：

- Sub-Store：只转节点，17 个全保留，sing-box 1.12.12 和 1.14.4 都能加载；不转策略组、规则和 DNS。
- subconverter 活跃分支：整份 sing-box 配置在 1.12 和 1.14 上都加载失败（规则用已删除的 geoip/geosite 字段，DNS 是旧格式）；还会用自带模板把原来的策略组和规则整个换掉。
- Sublink Worker：把 Clash 的 DNS 设置原样塞进 sing-box 配置，整份加载不了；单看节点也有 5 个加载失败。
- clash2sing-box：一个节点都没转出来。

同一份样例上，submorph 的 sing-box 输出保留全部 17 个节点和原有策略组、规则、DNS，并能被 1.12 和 1.14 加载。就 `full.yaml` 转 sing-box 这一项而言，它比上面测过的竞品都完整；但 ConfigFlow、SubBoost、MetaCubeX subconverter 当时没测，其他样例和维度也还没有对比数据，不能推广成「全面超过」。

## 复现

```sh
# 竞品源码和内核放在 ../converters（或用 CONVERTERS 指定）
bench/setup.sh
python3 bench/run.py      # 目前跑到打分一步会停下，提示 score.py 还没写
```
