# 进度、下一步和接手说明

更新于 2026 年 11 月 25 日。项目负责人让开发**暂停**，先把现有工作整理推送。这份文档写给接手的人（或另一个 AI）：不看任何聊天记录，读完 `docs/` 就能接着做。

先读的顺序：[requirements.md](requirements.md)（要做成什么样、怎么算做完）→ [design.md](design.md)（代码怎么组织）→ [benchmark.md](benchmark.md)（怎么证明比竞品好、现在测到哪）→ 本文（现在卡在哪、下一步做什么）→ [research.html](research.html)（竞品调研原始资料）。

## 当前状态：第一阶段进行中，未发布

| 部分 | 状态 |
|---|---|
| 中间表示 `model.rs` | 基本完成，覆盖 design.md 列出的协议、传输、TLS、策略组、规则、DNS |
| 输入：Clash/Mihomo YAML 和 JSON | 能用；容错还有漏洞（见已知问题） |
| 输入：分享链接、Base64 | 能用；26 条样例链接全部能解析 |
| 输入：sing-box JSON | 能用；有一个 Hysteria2 端口跳跃的 bug |
| 输出：mihomo | 能用；有两个会导致 mihomo 拒绝加载的 bug |
| 输出：sing-box 1.12+ | 能用；样例里 sing-box 1.12.12 和 1.14.4 都能加载 |
| `Target` 扩展接口 | 已有，目前注册了 mihomo、sing-box 两个实现 |
| 命令行 | 能用，参数见 README |
| 对比基准 | **未完成**：样例、竞品运行器、`bench/run.py` 的运行阶段已写；没完整跑过一遍；`bench/score.py` 没写 |
| 第二、三阶段的目标格式 | 没开始 |

代码约 8000 行 Rust（`src/`）。最后一个提交里的代码是开发中途的快照，没有为了让检查通过再改过。

## 推送时的检查结果（2026 年 11 月 25 日，rustc 1.99.1）

- `cargo fmt --check`：**通过**。
- `cargo clippy --all-targets --all-features -- -D warnings`：**没通过**。有 1 个默认就是 deny 级别的错误，编译在这里停下，所以后面还有没有别的警告不知道：
  - `src/output/singbox.rs` 的 `needs_ip`：`Matcher::Geoip(c) => !c.eq_ignore_ascii_case("LAN") || true`，`|| true` 让前半句失效（`clippy::overly_complex_bool_expr`）。这是没写完的逻辑：本意大概是 `GEOIP,LAN` 不需要解析 IP，要先想清楚 sing-box 里 LAN 的规则集是否需要 IP 再改，不要简单删掉一半。
- `cargo test`：**通过**。库单元测试 14 个、命令行测试 1 个，共 15 个，全过；文档测试 0 个。测试数量明显偏少，主要验证靠的是 benchmark.md 里手动跑的内核加载。

## 已知问题（按优先级）

1. **sing-box 输入：只写了 `server_ports` 的 Hysteria2 被误判为缺端口而丢弃**（`src/input/singbox.rs`）。`singbox.json` 转两种目标都只剩 10/11 个节点；转 mihomo 时策略组里还引用着被丢的节点，导致 mihomo 拒绝加载。修法方向：有端口范围时不要求单端口；另外，节点被丢弃后，输出端应把策略组里对它的引用一并去掉并报诊断（这是一类通用问题，不只这一处）。
2. **mihomo 输出：mieru 节点缺 `transport` 字段时原样写出**，mihomo 拒绝加载（`messy.yaml`）。要么补默认值并报 Repaired，要么跳过并报 Invalid，看 mihomo 文档里 transport 是否有默认值再定。
3. **坏 UUID 没被拦下**（`messy.yaml` 的 M9）。VMess、VLESS、TUIC 等的 UUID 要校验，坏的跳过并报错。
4. 上面那个 clippy 错误。
5. 测试太少：应把 `bench/samples/*.truth.json` 变成 `cargo test` 里的回归测试，每个已知 bug 修完配一个测试。

## 下一步（按顺序）

1. 修上面 1 到 4，补测试，让 `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test` 全过。
2. 写 `bench/score.py`：读 `bench/out/<mode>/<tool>/<sample>.<target>.out`，按 benchmark.md 的维度打分：
   - 正确率和无损：和 `links.truth.json`、`messy.truth.json`、`full.yaml` 原文逐字段比对；
   - 内核加载：每份 sing-box 输出交给 sing-box 1.12.12 和 1.14.x 的 `check`，每份 mihomo 输出交给 `mihomo -t`；
   - 策略组、规则、DNS 是否保留（不是被模板替换）；
   - 报错质量：对照 `errors.keywords.json`；
   - 速度和内存：run.py 已记录在 `meta.json`。
   调研阶段写过一个只针对 `full.yaml` 的简易打分脚本，不在本仓库里（在开发机的竞品目录 `converters/bench/score.py`，可参考其 sing-box check / mihomo -t 的调用方式，没有的话照上面重写即可）。
3. 完整跑一遍 `python3 bench/run.py`，把结果表写进 benchmark.md。哪一维没超过竞品就继续改；改不动的写清楚卡在哪里。
4. 补测还没测过的竞品：ConfigFlow、SubBoost、MetaCubeX subconverter（运行器已写，没跑过）。
5. 第一阶段收尾：README 的状态、版本号、crates.io 发布前检查（名字 `submorph`）。
6. 第二阶段：Surge、Stash、Loon、Quantumult X、Shadowrocket，每个是一个实现 `Target` 的新模块，在 `output::targets()` 注册。第三阶段：Surfboard、Egern、V2Ray。
7. Zephyr 接入：Zephyr 以 Rust 依赖引用本库（`default-features = false` 去掉命令行），用 `convert` / `convert_bytes`，根据诊断决定是否提示用户。

## 怎么搭开发和基准环境

```sh
cargo build --release
cargo test
```

对比基准需要竞品源码和内核二进制，**不放进本仓库**（许可证和体积原因）。放在仓库旁边的 `../converters`，或用环境变量 `CONVERTERS` 指定，目录结构：

- 竞品源码（目录名 = `<owner>_<repo>`，调研时的提交）：
  - `sub-store-org_Sub-Store`（92ea17c）、`sub-store-org_subcase`（dd58460）
  - `7Sageer_sublink-worker`（8091c6e）
  - `thsrite_configflow`（00f5c18）
  - `SubBoost_subboost`（664a9c8）
  - `tindy2013_subconverter`（a0d4eab）、`asdlokj1qpi233_subconverter`（a48be9c）
  - 调研时还看过：CareyWang/sub-web、youshandefeiyang/sub-web-modify（sub-web 前端）、Script-Hub-Org/Script-Hub、feiyangprojects/clash2sing-box、douglarek/clash2singbox、Toperlock/sing-box-subscribe
- `bin/`：`sing-box-1.12.12`、`sing-box`（1.14.x，调研时 1.14.4）、`mihomo`（Meta v1.19.34），以及 subconverter 发行版 `sc-tindy`（v0.9.0）、`sc-asd`（v0.9.9）、`sc-mcx`（MetaCubeX v0.9.2），各自解压成 `bin/<名字>/subconverter/`。

然后：

```sh
bench/setup.sh            # 打包 Sub-Store、SubBoost，建 ConfigFlow 的 venv，准备三个 subconverter
python3 bench/make_samples.py   # 重新生成样例（large.* 不入库，每次生成）
python3 bench/run.py      # 目前跑到打分一步会停，提示 score.py 还没写
```

`run.py` 的 offline 模式在只有回环网卡的网络命名空间里跑（`sudo unshare -n`），哪个工具偷偷联网会在结果里暴露；online 模式工具同样在本机跑，只是允许它们下载规则等资源。无论哪种模式，都**不往任何在线转换站发订阅**。

## 接手时要守的规矩

- 范围只做订阅转换，不做脚本、覆写、订阅管理。
- GPL / AGPL 竞品（subconverter、Sub-Store、SubBoost 等）只看思路，不复制代码；Sublink Worker（MIT）可借用，保留版权声明。
- 样例只用假凭证（example.com、RFC 5737 地址、占位密钥），不提交真实订阅或密钥。
- 结论要有测试、内核加载或基准数据支撑；没测过的写「没测」。
- 提交信息和 PR 描述里不提 issue。
