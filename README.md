# ruleset-fakeipfilter

Fake-IP 排除名单（fakeipfilter-cn / fakeipfilter-!cn）自建仓：上游类别 + 手写段 → 每日 CI 校验合并 → **sing-box srs / mihomo classical list** 双内核分发，51 条语义断言守门。

| 产物 | 格式 | 分发（jsDelivr CDN） |
| --- | --- | --- |
| `dist/fakeipfilter-cn.srs` / `dist/fakeipfilter-!cn.srs` | sing-box domain 二进制 | `https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn.srs`（!cn 同路径） |
| `dist/fakeipfilter-cn.list` / `dist/fakeipfilter-!cn.list` | mihomo classical text | `https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn.list`（!cn 同路径） |
| `dist/*.json` | sing-box source（透明可审计） | raw 仓库路径同上 |

## 使用

### sing-box

```json
{ "type": "remote", "tag": "fakeipfilter-cn", "format": "binary",
  "url": "https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn.srs" }
```

引用于 DNS 规则（`dns.rules[].rule_set` + `action: route` 到国内上游）与路由规则（`route.rules[].rule_set` → 直连）。

### mihomo

```yaml
rule-providers:
  fakeipfilter-cn:
    type: http
    behavior: classical
    format: text
    url: "https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn.list"
    path: ./ruleset/fakeipfilter-cn.list
    interval: 86400
dns:
  fake-ip-filter:
    - rule-set:fakeipfilter-cn
nameserver-policy:
  "rule-set:fakeipfilter-cn": https://223.5.5.5/dns-query
```

> **为什么没有 mrs**：名单含 DOMAIN-KEYWORD/DOMAIN-REGEX，classical 语义进不了 mrs（mihomo `convert-ruleset classical` 实测 panic）——mihomo 侧使用 classical text；sing-box 侧 srs 为 domain 语义（KEYWORD/REGEX 已入 source）。

## 准入语义（唯一）

域名进名单的理由只有两个：**客户端要在本地消费真实 IP**（NTP / STUN / 连网检测 / 游戏主机 NAT / 号码认证 / 金融风控 / DDNS / 本地域 / IP 调度型 CDN），或**快速通过机制需要真实 IP 作输入**（国内真实解析是绕过大陆的输入）。不满足则必须走 Fake-IP（代理 + 落地解析）。两用域（如 gstatic.com）由 `sources/connectivity-exclude.list` 在构建期剔除；DNS 泄露检测站、分流分类目永不收。

## 构建与 CI

```bash
python3 scripts/fetch_upstream.py   # 上游类别（raw + jsDelivr 双链重试 + 新鲜度审计）
python3 scripts/build.py            # sources + upstream → dist/*.json 与 .list
SINGBOX_BIN=<sing-box> python3 scripts/assert.py   # 51 条 json 语义断言 + 51 条 srs 读回语义探针
```

CI：每日 UTC 21:00（北京时间 05:00）；断言失败不发布；上游失败沿用本地缓存并 `::warning`，行数骤降 >50% 或连续失败 ≥3 天红灯。srs 编译器锚定 v1.14.4（workflow `env.SINGBOX_VERSION`）。

## 维护

- 新场景加行：`sources/fakeipfilter-{cn,!cn}.manual.list` 加一行（注明场景）→ push 即可；有代表性的重症域同步补 assert CASES 并向 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) 反哺
- 语法/纪律/禁改清单与原理推导：见本仓 `assert.py` 头注释与构建手册 `fakeipfilter-rules-github-plan.md`（存于主工作区 docs/，未随本仓分发）
