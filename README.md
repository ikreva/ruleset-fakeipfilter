# ruleset-fakeipfilter

Fake-IP 排除名单（fakeipfilter-cn / fakeipfilter-!cn）的自维护仓库：上游语义类别 + 手写段 → CI 每日校验合并 → 双格式发布（sing-box source json / mihomo clash list / sing-box srs）。

## 准入语义（唯一）

**域名进名单的理由只有两个**：

1. 客户端要在本地消费解析结果里的真实 IP（NTP 校时 / STUN 探测 / 连网检测 / 游戏主机 NAT / 号码认证 / 金融风控 / 远程访问 DDNS / 本地域 / IP 调度型 CDN）；
2. 快速通过机制需要真实 IP 作输入（国内域名真实解析是绕过大陆 / cn_ip 直连判定的输入）。

不满足语义的域必须走 Fake-IP（代理 + 落地解析）。多收 = 降级不致命但违背原理；漏收轻症有配置链路兜底；**重症只有名单本身能救**：

| 场景 | 分级 | 漏掉的后果 |
| --- | --- | --- |
| 本地/路由管理域（`localhost`、`router.asus.com`、mDNS） | 必需 | 功能直接坏（重症） |
| NTP 校时 / STUN 探测 / 连网检测 | 必需 | 校时失败、NAT 误判、误报"无互联网"（重症） |
| 游戏主机 NAT / 号码认证 / 金融风控 / 远程访问 DDNS | 必需 | 联机/登录/远程访问失败（重症） |
| IP 调度型 CDN（音乐/Apple 更新/Steam 国内）、测速、BT UDP tracker | 优化 | 就近调度失效、测速失真（轻症，有判定链路兜底） |

两用检测/资源域（如 `gstatic.com`——既是连网检测端点又是 Google 静态资源 CDN）进名单会从「Fake-IP 代理+落地解析」降级为「本地解析直连」，违背路由预期 → 由 `sources/connectivity-exclude.list` 在构建期剔除。分类目（`category-games` 这类分流分类）**禁止整类并入**；DNS 泄露检测站域名永不收。

## 目录

```text
sources/                        手写权威段（人工维护，Actions 永不覆盖）
  ├── fakeipfilter-cn.manual.list
  ├── fakeipfilter-!cn.manual.list
  └── connectivity-exclude.list # 两用域剔除清单（build 期过滤）
upstream/                       上游类别缓存（fetch_upstream.py 下载提交）
  └── meta.json                 各类别最后成功日期与行数（新鲜度审计）
scripts/                        build.py（合并生成）+ assert.py（语义断言）+ fetch_upstream.py（下载校验）
.github/workflows/update-rules.yml  每日自动化
dist/                           产物：fakeipfilter-{cn,!cn}.{json,list,srs}（提交回仓库，供 raw 引用）
```

## 产物与消费端对应

| 产物 | 格式 | 消费方 |
| --- | --- | --- |
| `dist/fakeipfilter-{cn,!cn}.json` | sing-box rule-set source | sing-box 主配置 `rule_set`（remote 下载后内核自行编译） |
| `dist/fakeipfilter-{cn,!cn}.srs` | sing-box 二进制 rule-set | sing-box 内核直用（自托管分发/离线场景） |
| `dist/fakeipfilter-{cn,!cn}.list` | mihomo classical text | mihomo `rule-providers`（behavior: classical） |

消费 URL 模板：

```text
https://raw.githubusercontent.com/<user>/ruleset-fakeipfilter/main/dist/fakeipfilter-{cn,!cn}.json
https://raw.githubusercontent.com/<user>/ruleset-fakeipfilter/main/dist/fakeipfilter-{cn,!cn}.srs
https://raw.githubusercontent.com/<user>/ruleset-fakeipfilter/main/dist/fakeipfilter-{cn,!cn}.list
（国内直连下载可套 gh-proxy / jsDelivr 前缀；`!` 在 URL 中合法，无需转义）
```

## 构建与本地验证

```bash
python3 scripts/fetch_upstream.py     # 可选：刷新上游类别（下载+校验+新鲜度告警）
python3 scripts/build.py              # sources + upstream → dist/*.json 与 .list
python3 scripts/assert.py             # 51 条语义断言（正例/反例/纪律固化）
sing-box rule-set compile dist/fakeipfilter-cn.json -o dist/fakeipfilter-cn.srs
sing-box rule-set compile dist/fakeipfilter-'!cn'.json -o dist/fakeipfilter-'!cn'.srs
```

srs 编译器版本锚定 `1.14.4`（workflow `env.SINGBOX_VERSION` 与本机验证同版本，保证产物可复现；srs 格式向后兼容，升级时同步两处即可）。脚本全部标准库实现，无第三方依赖。

## 上游失败时的行为语义

| 情形 | 行为 |
| --- | --- |
| 下载失败（重试 3 次后） | `::warning` + 沿用仓库里的旧类别文件继续构建（best-effort） |
| 下载内容校验失败（HTML 错误页 / 有效行数 <5 / 行语法非法 / 单行垃圾跳过） | 整类别拒收（保留旧文件）；单行垃圾告警跳过 |
| 行数较上次成功骤降 >50% | 保留旧文件，`exit 1` 红灯（上游疑似真删减，强制人工裁决） |
| 同一类别连续失败 ≥3 天 | 保留旧文件，`exit 1` 红灯（防静默降级无人察觉） |
| 校验记录 | `upstream/meta.json` 记录每类别最后成功日期与行数，随仓库提交可审计 |

## 断言说明

`scripts/assert.py` 51 条 CASES 分四层，任一不符则 CI 失败不发布：

1. **重症正例**：连网检测 / NTP（含 `time.android.com`）/ STUN / 游戏主机 / 号码认证 / 路由管理域（`localhost`、`router.asus.com`）/ 远程访问 DDNS / 测速 / BT tracker——与准入语义的重症场景表逐行对应；
2. **大厂覆盖反例**：baidu / github / youtube / netflix / openai / anthropic / bilibili 必须不在名单；
3. **两用域过滤证据**：`www.gstatic.com`、`connectivitycheck.gstatic.com` 必须被剔除；
4. **纪律固化反例**：DNS 泄露检测站（dnsleaktest / browserleaks / ipleak）、Steam 商店 / Epic 官网（games 分流域）、DoH 自举域（`dns.google`——污染环境本地解析反而有害）永不收。

## 维护手册

- **日常零操作**：Actions 每日跑（北京时间约 05:00）；上游坏一天自动沿用旧文件告警，次日自愈。
- **新场景加行**（某 App 联机失败/校时不对/误报无网）：
  1. 确认语义：客户端要本地消费真实 IP？（是 → 继续；否 → 它该走 Fake-IP/分流规则，不收）
  2. 判断分级：漏了直接坏（重症，进名单）；只是绕远路（轻症，先确认无兜底再收）
  3. 在 `sources/fakeipfilter-cn.manual.list` 或 `fakeipfilter-!cn.manual.list` 加一行并注释场景，push 即可——CI 自动重建、断言、发布
  4. 有代表意义的重症域同步补一条 assert CASES，并向 `v2fly/domain-list-community` 提 PR 反哺上游
- **新增上游类别**：先按准入语义审查内容（分类目禁止整类并入）→ 确认 meta-rules-dat 有对应 `.list` → `fetch_upstream.py` 的 `UPSTREAMS` 与 `build.py` 的 `TARGETS` 各加一行 → 补 assert 用例 → 本地跑通三步验证再 push。
- **禁改**：`dist/` 与 `upstream/*.list` 不手改（CI 覆盖）；`category-games` 类分流分类目永不进 `TARGETS`。
- 手写段语法：裸域 = 域及子域（apex+后缀双落）；`+.x` 同上；`*.x` = 单层子域；`DOMAIN-KEYWORD,k`；`DOMAIN-REGEX,r`；含 `*` 的其它行自动转锚定正则；行内 `#` 注释。

设计细节与原理推导见 `docs/fakeipfilter-rules-github-plan.md`（GitHub 操作手册）。
