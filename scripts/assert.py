#!/usr/bin/env python3
"""CI 语义断言：全层产物（JSON / SRS / 兼容 .list / 5B .mrs + -regex.list）与结构不变量全对称守门。

关键对齐：
- 正则匹配使用 `re.search`（对齐 Go `regexp.MatchString` 与 mihomo `regexp2.MatchString`）；
- 校验每条 `domain_regex` 必须以 `^` 开头、以 `$` 结尾；
- 校验 `fakeipfilter-cn` 与 `fakeipfilter-!cn` 的 `domain` / `domain_suffix` 严格互斥；
- 校验后缀剪枝后无自包含冗余；
- JSON、SRS 反编译读回、classical `.list` 三层对称跑单集断言 + 联合优先级断言；
- 5B 产物 `.mrs`（存在且非空）+ `-regex.list`（纯 DOMAIN-REGEX 且条数与 JSON 一致）完整核验。
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

DIST = pathlib.Path(__file__).resolve().parent.parent / "dist"


def load(name: str) -> dict:
    rules = json.loads((DIST / f"{name}.json").read_text(encoding="utf-8"))["rules"]
    return load_from_rules(rules)


def load_from_rules(rules: list) -> dict:
    acc = {"domain": set(), "domain_suffix": set(), "domain_keyword": set(), "domain_regex": []}
    for r in rules:
        for k in ("domain", "domain_suffix", "domain_keyword"):
            acc[k] |= set(r.get(k, []))
        acc["domain_regex"] += r.get("domain_regex", [])
    acc["regex"] = [re.compile(p) for p in acc["domain_regex"]]
    return acc


def hit(sets: dict, domain: str) -> bool:
    if domain in sets["domain"]:
        return True
    if any(domain.endswith(s) for s in sets["domain_suffix"]):
        return True
    if any(k in domain for k in sets["domain_keyword"]):
        return True
    return any(p.search(domain) for p in sets["regex"])


cn, notcn = load("fakeipfilter-cn"), load("fakeipfilter-!cn")

# ---- 结构不变量 1：全部 domain_regex 必须两端锚定 ^...$ 且不含逗号（防 classical .list 逗号截断）----
for name, sets in (("fakeipfilter-cn", cn), ("fakeipfilter-!cn", notcn)):
    bad_regex = [p for p in sets["domain_regex"] if not (p.startswith("^") and p.endswith("$")) or "," in p]
    if bad_regex:
        print(f"ASSERT FAILED ({name}): 非法 domain_regex（未 ^...$ 锚定或含逗号）：{bad_regex}")
        sys.exit(1)

# ---- 结构不变量 2：cn 与 !cn 的 domain / domain_suffix 严格互斥 ----
dup_domains = sorted(cn["domain"] & notcn["domain"])
dup_suffixes = sorted(cn["domain_suffix"] & notcn["domain_suffix"])
if dup_domains or dup_suffixes:
    print(f"ASSERT FAILED: cn 与 !cn 存在重叠：domains={dup_domains}, suffixes={dup_suffixes}")
    sys.exit(1)

# ---- 结构不变量 3：后缀剪枝后无自包含冗余 ----
for name, sets in (("fakeipfilter-cn", cn), ("fakeipfilter-!cn", notcn)):
    sub_dup = [d for d in sets["domain"] if any(d.endswith(s) for s in sets["domain_suffix"])]
    sfx_dup = [s for s in sets["domain_suffix"] if any(s != o and s.endswith(o) for o in sets["domain_suffix"])]
    if sub_dup or sfx_dup:
        print(f"ASSERT FAILED ({name}): 存在后缀冗余：sub={sub_dup[:5]}, sfx={sfx_dup[:5]}")
        sys.exit(1)

print(f"ok structural invariants: regex anchored (cn={len(cn['domain_regex'])}, !cn={len(notcn['domain_regex'])}), disjoint & suffix-pruned")

# (域名, 名单, 期望是否命中)
CASES = [
    # ---- 重症：本地/国内连网检测（归 cn，防断代理误报无网络；且不入 !cn）----
    ("captive.apple.com",           cn,    True),
    ("captive.apple.com",           notcn, False),
    ("dns.msftncsi.com",            cn,    True),
    ("dns.msftncsi.com",            notcn, False),
    ("www.msftconnecttest.com",     cn,    True),
    ("www.msftconnecttest.com",     notcn, False),
    ("connect.rom.miui.com",        cn,    True),
    ("connect.rom.miui.com",        notcn, False),
    # ---- 重症：海外连网检测 ----
    ("detectportal.firefox.com",    notcn, True),
    ("networkcheck.kde.org",        notcn, True),
    # ---- 重症：NTP 校时 ----
    ("time.windows.com",            notcn, True),
    ("time.apple.com",              notcn, True),
    ("time.android.com",            notcn, True),
    ("time.edu.cn",                 cn,    True),
    ("ntp.aliyun.com",              cn,    True),
    ("time1.cloud.tencent.com",     cn,    True),
    ("2.cn.pool.ntp.org",           cn,    True),
    ("europe.pool.ntp.org",         notcn, True),
    # ---- 重症：STUN / NAT 探测 ----
    ("stun.l.google.com",           notcn, True),
    ("stun.cloudflare.com",         notcn, True),
    ("stun.qq.cn",                  cn,    True),
    ("stunning.example.com",        notcn, False),
    # ---- 重症：游戏主机 NAT / 平台联机 ----
    ("battle.net",                  notcn, True),
    ("patch.steamcontent.com",      notcn, True),
    ("a.srv.nintendo.net",          notcn, True),
    ("stun.playstation.net",        notcn, True),
    ("xbox.ipv6.microsoft.com",     notcn, True),
    # ---- 重症：运营商号码认证 / 一键登录 ----
    ("id6.me",                      cn,    True),
    ("cmpassport.com",              cn,    True),
    ("enrichgw.10010.com",          cn,    True),
    # ---- 重症：本地/路由管理域（走 trie domain_suffix）----
    ("localhost",                   cn,    True),
    ("printer.lan",                 cn,    True),
    ("nas.local",                   cn,    True),
    ("router.home.arpa",            cn,    True),
    ("router.asus.com",             cn,    True),
    ("printer.internal",            cn,    True),
    ("camera.home",                 cn,    True),
    ("pdc._msdcs.corp.local",       cn,    True),
    # ---- 正则防泄露反例：绝不可被 .lan/.home/.direct/.corp/.local/.test 误杀 ----
    ("www.langchain.com",           cn,    False),
    ("www.langchain.com",           notcn, False),
    ("www.homedepot.com",           cn,    False),
    ("www.homedepot.com",           notcn, False),
    ("www.directv.com",             cn,    False),
    ("www.directv.com",             notcn, False),
    ("www.corporate.com",           cn,    False),
    ("www.testing.com",             cn,    False),
    ("www.localhost.com",           cn,    False),
    ("www.example.com",             cn,    False),
    # ---- 重症：远程访问 / DDNS ----
    ("myhost.ts.net",               notcn, True),
    ("mesh.tailscale.com",          notcn, True),
    ("abc.quickconnect.to",         notcn, True),
    ("myvps.duckdns.org",           notcn, True),
    ("myhost.ddns.net",             notcn, True),
    ("nas.hopto.org",               notcn, True),
    # ---- 轻症优化：测速 / BT UDP tracker / A-GPS / 音乐 ----
    ("speedtest.net",               notcn, True),
    ("tracker.opentrackr.org",      notcn, True),
    ("exodus.desync.com",           notcn, True),
    ("open.tracker.cl",             notcn, True),
    ("supl.google.com",             notcn, True),
    ("xtra1.gpsonextra.net",        notcn, True),
    ("music.163.com",               cn,    True),
    # ---- 流媒体 CDN 与历史误收反例：必须保留 Fake-IP ----
    ("ipv4-c001-lax001-ix.1.oca.nflxvideo.net", notcn, False),
    ("vod-ftc-na-west-1.media.dssott.com",      notcn, False),
    ("proxy.golang.org",                        notcn, False),
    ("a.xiami.com",                             cn,    False),
    ("static.126.net",                          cn,    False),
    # ---- 大厂覆盖反例：路由大厂必须走 Fake-IP ----
    ("www.baidu.com",               cn,    False),
    ("www.baidu.com",               notcn, False),
    ("github.com",                  cn,    False),
    ("github.com",                  notcn, False),
    ("youtube.com",                 notcn, False),
    ("netflix.com",                 notcn, False),
    ("openai.com",                  notcn, False),
    ("anthropic.com",               notcn, False),
    ("bilibili.com",                cn,    False),
    ("bilibili.com",                notcn, False),
    # ---- 两用域过滤证据：gstatic 系必须被 connectivity-exclude 剔除 ----
    ("www.gstatic.com",             cn,    False),
    ("www.gstatic.com",             notcn, False),
    ("connectivitycheck.gstatic.com", cn,  False),
    ("connectivitycheck.gstatic.com", notcn, False),
    # ---- 纪律固化反例：永不收 ----
    ("dnsleaktest.com",             notcn, False),
    ("browserleaks.com",            notcn, False),
    ("ipleak.net",                  notcn, False),
    ("store.steampowered.com",      notcn, False),
    ("epicgames.com",               notcn, False),
    ("dns.google",                  notcn, False),
]

COMBINED_CASES = [
    ("dns.msftncsi.com", "cn"),
    ("www.msftconnecttest.com", "cn"),
    ("captive.apple.com", "cn"),
    ("connect.rom.miui.com", "cn"),
    ("ntp.aliyun.com", "cn"),
    ("2.cn.pool.ntp.org", "cn"),
    ("printer.lan", "cn"),
    ("stun.qq.cn", "cn"),
    ("stun.l.google.com", "!cn"),
    ("europe.pool.ntp.org", "!cn"),
    ("time.windows.com", "!cn"),
    ("a.srv.nintendo.net", "!cn"),
    ("www.langchain.com", "fakeip"),
    ("www.homedepot.com", "fakeip"),
    ("www.directv.com", "fakeip"),
    ("ipv4-c001-lax001-ix.1.oca.nflxvideo.net", "fakeip"),
    ("vod-ftc-na-west-1.media.dssott.com", "fakeip"),
    ("proxy.golang.org", "fakeip"),
    ("www.gstatic.com", "fakeip"),
    ("dnsleaktest.com", "fakeip"),
]


def route_combined(cn_sets: dict, notcn_sets: dict, matcher, domain: str) -> str:
    if matcher(cn_sets, domain):
        return "cn"
    if matcher(notcn_sets, domain):
        return "!cn"
    return "fakeip"


def check_combined(label: str, cn_sets: dict, notcn_sets: dict, matcher) -> None:
    bad = [
        (d, exp, route_combined(cn_sets, notcn_sets, matcher, d))
        for d, exp in COMBINED_CASES
        if route_combined(cn_sets, notcn_sets, matcher, d) != exp
    ]
    if bad:
        print(f"ASSERT FAILED (combined {label}):", bad)
        sys.exit(1)
    print(f"ok combined ({label}): {len(COMBINED_CASES)} 条联合优先级探针全通过")


# 1. JSON 层
failed = [(d, expect) for d, target, expect in CASES if hit(target, d) != expect]
if failed:
    print("ASSERT FAILED (json):", failed)
    sys.exit(1)
print(f"ok json: {len(CASES)} 条单集断言全通过")
check_combined("json", cn, notcn, hit)

# 2. SRS 反编译读回层（单集 + 联合优先级）
singbox = os.environ.get("SINGBOX_BIN") or shutil.which("sing-box")
if not singbox:
    print("WARN: 未找到 sing-box，跳过 srs 读回断言")
else:
    srs_loaded: dict[str, dict] = {}
    for name in ("fakeipfilter-cn", "fakeipfilter-!cn"):
        srs = DIST / f"{name}.srs"
        if not srs.exists():
            print(f"ASSERT FAILED: {srs.name} 不存在")
            sys.exit(1)
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "readback.json"
            r = subprocess.run([singbox, "rule-set", "decompile", str(srs), "-o", str(out)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(f"ASSERT FAILED: {srs.name} 反编译失败：{(r.stderr or r.stdout)[:300]}")
                sys.exit(1)
            back = load_from_rules(json.loads(out.read_text(encoding="utf-8"))["rules"])
            srs_loaded[name] = back
        cases = [(d, tgt, exp) for d, tgt, exp in CASES if tgt is (cn if name == "fakeipfilter-cn" else notcn)]
        failed_back = [(d, exp) for d, target, exp in cases if hit(back, d) != exp]
        if failed_back:
            print(f"ASSERT FAILED: {name} srs 读回语义断言失败：{failed_back}")
            sys.exit(1)
        print(f"ok {name}: srs 读回单集断言通过（{len(cases)} 条探针）")
    check_combined("srs", srs_loaded["fakeipfilter-cn"], srs_loaded["fakeipfilter-!cn"], hit)


# 3. 兼容全量 classical `.list` 层（单集 + 联合优先级）
def load_classical(path: pathlib.Path) -> dict:
    dom, sfx, kw, rex = set(), set(), set(), []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(",")
        t = parts[0].strip().upper()
        if t == "DOMAIN":
            dom.add(parts[1].strip().lower())
        elif t == "DOMAIN-SUFFIX":
            sfx.add(parts[1].strip().lower())
        elif t == "DOMAIN-KEYWORD":
            kw.add(parts[1].strip().lower())
        elif t == "DOMAIN-REGEX":
            rex.append(re.compile(parts[1].strip()))
    return {"domain": dom, "suffix": sfx, "keyword": kw, "regex": rex}


def hit_classical(c: dict, d: str) -> bool:
    return (d in c["domain"]
            or any(d == s or d.endswith("." + s) for s in c["suffix"])
            or any(k in d for k in c["keyword"])
            or any(p.search(d) for p in c["regex"]))


cl_loaded: dict[str, dict] = {}
for name in ("fakeipfilter-cn", "fakeipfilter-!cn"):
    cl = load_classical(DIST / f"{name}.list")
    cl_loaded[name] = cl
    cases = [(d, tgt, exp) for d, tgt, exp in CASES if tgt is (cn if name == "fakeipfilter-cn" else notcn)]
    failed_cl = [(d, exp) for d, target, exp in cases if hit_classical(cl, d) != exp]
    if failed_cl:
        print(f"ASSERT FAILED: {name} classical .list 语义断言失败：{failed_cl}")
        sys.exit(1)
    print(f"ok {name}: classical .list 单集断言通过（{len(cases)} 条探针）")
check_combined("classical .list", cl_loaded["fakeipfilter-cn"], cl_loaded["fakeipfilter-!cn"], hit_classical)

# 4. 5B 产物核验（.mrs 非空 + -regex.list 纯 DOMAIN-REGEX 且条数与 JSON 一致）
for name, sets in (("fakeipfilter-cn", cn), ("fakeipfilter-!cn", notcn)):
    mrs = DIST / f"{name}.mrs"
    rx_list = DIST / f"{name}-regex.list"
    if not mrs.exists() or mrs.stat().st_size < 32:
        print(f"ASSERT FAILED: {mrs.name} 缺失或异常过小")
        sys.exit(1)
    if not rx_list.exists():
        print(f"ASSERT FAILED: {rx_list.name} 缺失")
        sys.exit(1)
    rx_lines = [l.strip() for l in rx_list.read_text(encoding="utf-8").splitlines() if l.strip() and not l.strip().startswith("#")]
    if not all(l.startswith("DOMAIN-REGEX,^") and l.endswith("$") for l in rx_lines):
        print(f"ASSERT FAILED: {rx_list.name} 含非锚定或非 DOMAIN-REGEX 行：{rx_lines}")
        sys.exit(1)
    if len(rx_lines) != len(sets["domain_regex"]):
        print(f"ASSERT FAILED: {rx_list.name} 条数({len(rx_lines)}) != JSON regex 条数({len(sets['domain_regex'])})")
        sys.exit(1)
    print(f"ok {name}: 5B 产物就绪（{mrs.name}={mrs.stat().st_size}B, {rx_list.name}={len(rx_lines)} 条正则）")
