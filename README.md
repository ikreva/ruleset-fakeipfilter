# ruleset-fakeipfilter

Fake-IP 排除名单（`fakeipfilter-cn` / `fakeipfilter-!cn`）自建仓：上游类别 + 手写段 → 每日 CI 校验合并（同族正则合并、强制 `^...$` 两端锚定、纯前缀 `*.x` 落 Trie `domain_suffix`、后缀包含剪枝、`cn`/`!cn` 严格互斥）→ **sing-box `.srs` / mihomo `.mrs` + 极简 `-regex.list`（+ 兼容全量 `.list`）** 双内核分发，三层产物全对称断言守门。

| 产物 | 格式 | 分发（jsDelivr CDN） |
| --- | --- | --- |
| `dist/fakeipfilter-{cn,!cn}.srs` | sing-box domain+regex 二进制（1 个文件含全部） | `https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn.srs`（`!cn` 同路径） |
| `dist/fakeipfilter-{cn,!cn}.mrs` | **mihomo 纯域名二进制 Trie（推荐主集，$O(L)$ 查找）** | `https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn.mrs`（`!cn` 同路径） |
| `dist/fakeipfilter-{cn,!cn}-regex.list` | **mihomo 极简正则伴随集（4 条 / 7 条，配合 `.mrs`）** | `https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn-regex.list`（`!cn` 同路径） |
| `dist/fakeipfilter-{cn,!cn}.list` | mihomo 兼容全量 classical text（单文件向后兼容） | `https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn.list`（`!cn` 同路径） |
| `dist/fakeipfilter-{cn,!cn}.json` | sing-box source（透明可审计） | 同路径 `.json` |

## 使用

### sing-box（单文件 `.srs` 原生内置 Trie + 正则）

```json
{
  "type": "remote",
  "tag": ["fakeipfilter-cn", "fakeipfilter-!cn"],
  "format": "binary",
  "url": "https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/{tag}.srs"
}
```

引用于 `dns.rules`（`fakeipfilter-cn` → 国内上游，`fakeipfilter-!cn` → 代理上游）。**顺序要求**：`fakeipfilter-cn` 必须置于 `fakeipfilter-!cn` 之前（`!cn` 含 `+.pool.ntp.org`、`^ntp[1-7]?\.[^.]+\.com$` 等全局父级匹配）。

### mihomo（推荐 5B 高性能模式：`.mrs` 二进制 Trie + 极简 `-regex.list`）

```yaml
rule-providers:
  fakeipfilter-cn:
    type: http
    behavior: domain
    format: mrs
    url: "https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn.mrs"
    path: ./ruleset/fakeipfilter-cn.mrs
    interval: 86400
  fakeipfilter-cn-regex:
    type: http
    behavior: classical
    format: text
    url: "https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-cn-regex.list"
    path: ./ruleset/fakeipfilter-cn-regex.list
    interval: 86400
  fakeipfilter-!cn:
    type: http
    behavior: domain
    format: mrs
    url: "https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-!cn.mrs"
    path: ./ruleset/fakeipfilter-!cn.mrs
    interval: 86400
  fakeipfilter-!cn-regex:
    type: http
    behavior: classical
    format: text
    url: "https://cdn.jsdelivr.net/gh/ikreva/ruleset-fakeipfilter@main/dist/fakeipfilter-!cn-regex.list"
    path: ./ruleset/fakeipfilter-!cn-regex.list
    interval: 86400

dns:
  fake-ip-filter:
    - rule-set:geosite-private
    - rule-set:fakeipfilter-cn
    - rule-set:fakeipfilter-cn-regex
    - rule-set:fakeipfilter-!cn
    - rule-set:fakeipfilter-!cn-regex
  nameserver-policy:
    "rule-set:fakeipfilter-cn,fakeipfilter-cn-regex": https://223.5.5.5/dns-query#disable-ipv6=true
    "rule-set:fakeipfilter-!cn,fakeipfilter-!cn-regex": https://8.8.8.8/dns-query#默认代理
```

> **为什么拆分 `.mrs` + `-regex.list`**：mihomo 的 `mrs` 格式仅支持纯域名 Trie，不支持 `DOMAIN-REGEX`。拆分后 600+ 精确/后缀域名走 $O(L)$ 二进制 `mrs`（零 `Classical` 警告），仅 4 条（`cn`）+ 7 条（`!cn`）正则走极小 classical 文件，每次 DNS 查询大幅降耗。若追求极简配置也可继续使用兼容单文件 `fakeipfilter-{cn,!cn}.list`。

## 准入语义（唯一）

域名进名单的理由只有两个：**客户端要在本地消费真实 IP**（NTP / STUN / 连网检测 / 游戏主机 NAT / 号码认证 / 金融风控 / DDNS / 本地域），或**快速通过机制需要真实 IP 作输入**。不满足则必须走 Fake-IP（代理 + 落地解析）：
- Windows NCSI（`msftncsi.com` / `msftconnecttest.com`）与 Apple/国产手机连网检测归 `fakeipfilter-cn`，防止代理未就绪时误报断网；
- 两用域（`gstatic.com`、`cp.cloudflare.com`）由 `sources/connectivity-exclude.list` 剔除；
- 流媒体 CDN（Netflix/Disney+）、DNS 泄露检测站、分流分类目永不收。

## 构建与 CI

```bash
python3 scripts/fetch_upstream.py
SINGBOX_BIN=<sing-box> MIHOMO_BIN=<mihomo> python3 scripts/build.py
SINGBOX_BIN=<sing-box> python3 scripts/assert.py
```

CI：每日 UTC 21:00（北京时间 05:00）；编译器锚定 `sing-box v1.14.4` 与 `mihomo v1.19.34`；任一断言失败不发布。
