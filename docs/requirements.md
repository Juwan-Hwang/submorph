# 需求

这份文档记下项目负责人对 submorph 提的全部要求，是以后判断「做完没有」的依据。引号里的是原话。

## 定位

- 做一个**通用**的订阅转换器：「开始做吧，做个通用的」。
- **独立项目**：「这个作为独立项目」。不放在 Zephyr 仓库里。桌面客户端 Zephyr（MIT）以后作为使用方接入。
- 形态：Rust 写的库加命令行工具，开源，MIT 许可证。
- **范围只做订阅格式转换**：「只做订阅转换就行了不需要其他什么脚本之类的」。不做脚本、覆写（override）、订阅库和订阅管理。
- **所有转换都在本地跑**，不依赖、也不调用任何在线转换服务。
- 输出**不止 sing-box**。第一阶段先做 mihomo 和 sing-box，后面要扩到更多客户端，接口从一开始就要留好。

## 目标：用数据超越全部竞品

「要求超越所有我给你的竞品」。两种输出在下面每个维度上都要用可重复的数据证明超过全部竞品；还没超过的继续改，改不动的写清楚卡在哪里：

1. 正确率和无损程度（节点、字段是否完整保留，输出能否被内核加载）
2. 协议和传输覆盖
3. 策略组和规则（保留原有的，不用模板整体替换）
4. DNS
5. 输入容错
6. 报错质量（说清楚哪一项、为什么、怎么办）
7. 速度和内存
8. 完全本地运行

### 竞品清单

用户清单里所有做订阅转换的项目和站点：

- Sub-Store（含 SubCase）
- Sublink Worker
- ConfigFlow
- subconverter（tindy2013）及其活跃分支（asdlokj1qpi233、MetaCubeX）
- SubBoost
- 在线站点背后用的开源实现：sub.dler.io、nexconvert.com、sub-web.wcc.best、sublink.dev、amyconvert.com、sub.v1.mk、sub.haitunt.org

各站点背后是什么实现，见 [research.html](research.html)。sub.dler.io 拒绝连接、nexconvert.com 返回 403，背后的实现没能确认。

### 对比基准的要求

- 能重复跑，一条命令出结果。
- 样例里不用真实凭证（只用 example.com、RFC 5737 地址和占位密钥）。
- 输出要真的交给 mihomo 和 sing-box（1.12 与 1.14）加载校验，不能只看格式。
- 所有工具都在本地跑，**不往任何在线站发订阅**。

## 第一阶段

- 统一的中间表示（IR），方便以后加新格式。
- 输入：Clash/Mihomo 的 YAML 和 JSON、分享链接和 Base64 订阅、sing-box JSON。要容错，报错写清楚。
- 输出：mihomo 和 sing-box。sing-box 用 1.12 以后的格式：规则用 rule-set，不用已删除的 geoip、geosite 字段，DNS 用新格式。保留原来的策略组和规则，不用模板整体替换。
- 对比基准，见上。
- 留好扩展接口，列出要全面超过竞品还差什么。
- 跑 cargo fmt、clippy 和测试。

## 后续阶段

- 第二阶段：Surge、Stash、Loon、Quantumult X、Shadowrocket。
- 第三阶段：Surfboard、Egern、V2Ray。

（调研时按代码量估的工作量：sing-box 先跑起来 4 到 6 周，与 mihomo 功能对齐合计 2.5 到 3.5 个月；第二阶段再 4 到 6 周；第三阶段再 3 到 4 周。这些是估计，没有实测。）

## 许可证原则

- submorph 用 MIT。
- subconverter（GPL）、Sub-Store（AGPL）、SubBoost（AGPL）只参考思路，照 mihomo、sing-box 的公开格式规范自己写，不逐段移植代码。
- Sublink Worker 是 MIT，可以借用，借用时保留它的版权声明。
- 对比基准运行竞品时只在本地调用它们的源码或发行版，竞品代码不复制进本仓库（构建产物放在 git 忽略的缓存目录里）。

## 协作要求

- 提交信息和 PR 描述里不提 issue。
- 结论要有测试、内核加载结果或基准数据支撑，不凭推测；做不到的如实写明。
