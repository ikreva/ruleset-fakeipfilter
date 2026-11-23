#!/usr/bin/env python3
"""CI 语义断言：命中/不命中样例必须全部符合预期，否则失败不发布。

语义依据（L1 判定器①准入）：名单 = 客户端本地消费真实 IP（a）+ 国内快速通过输入（b）；
路由大厂必须走 Fake-IP（不在名单）。

CASES 分层：
1. 重症正例——漏了直接坏的域（连网检测/NTP/STUN/游戏主机/号码认证/远程访问/路由管理），
   与设计文档 §1 重症场景表逐行对应；
2. 大厂覆盖反例（L3 指南采纳原则 1）——路由大厂必须不在排除名单；
3. 两用域过滤证据——gstatic 系必须被 connectivity-exclude 剔除
   （www.gstatic.com = 检测+资源两用 → Fake-IP 代理+落地解析；
     connectivitycheck.gstatic.com = 被墙纯检测端点 → Fake-IP 代理探测自洽）；
4. 纪律固化反例——DNS 泄露检测站永不收（自欺欺人）、游戏"分流分类"域
   （Steam 商店/Epic 官网）与 DoH 自举域（污染环境本地解析反而有害）永不收。
"""
import json
import pathlib
import re
import sys

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
    # 前导点后缀匹配子域；apex（裸域本身）由 add_domain 的精确条目覆盖，
    # 但为防御 optimize 剔除精确条目后的边界，这里同时接受 apex 相等
    if any(domain.endswith(s) or domain == s.lstrip(".") for s in sets["domain_suffix"]):
        return True
    if any(k in domain for k in sets["domain_keyword"]):
        return True
    return any(p.fullmatch(domain) for p in sets["regex"])   # 去冗余后 regex 是最终覆盖者


cn, notcn = load("fakeipfilter-cn"), load("fakeipfilter-!cn")

# (域名, 名单, 期望是否命中)
CASES = [
    # ---- 重症：连网检测（captive portal / NCSI）----
    ("captive.apple.com",           notcn, True),
    ("dns.msftncsi.com",            notcn, True),
    ("www.msftconnecttest.com",     notcn, True),
    ("detectportal.firefox.com",    notcn, True),
    ("networkcheck.kde.org",        notcn, True),
    # ---- 重症：NTP 校时 ----
    ("time.windows.com",            notcn, True),
    ("time.apple.com",              notcn, True),
    ("time.android.com",            notcn, True),   # Android 校时（手写段补充，v2fly 未收录）
    ("time.edu.cn",                 cn,    True),   # 教育网 NTP 主域（+. 修复后含裸域）
    ("ntp.aliyun.com",              cn,    True),
    ("time1.cloud.tencent.com",     cn,    True),
    ("2.cn.pool.ntp.org",           cn,    True),
    ("europe.pool.ntp.org",         notcn, True),
    # ---- 重症：STUN / NAT 探测 ----
    ("stun.l.google.com",           notcn, True),
    ("stun.cloudflare.com",         notcn, True),   # 手写通配 +.stun.*.* 覆盖
    # ---- 重症：游戏主机 NAT / 平台联机 ----
    ("battle.net",                  notcn, True),   # 战网登录/NAT（裸域 apex）
    ("patch.steamcontent.com",      notcn, True),   # Steam 内容 CDN（真实 IP 就近下载）
    ("a.srv.nintendo.net",          notcn, True),   # Switch NAT 打洞
    ("stun.playstation.net",        notcn, True),   # PSN STUN（裸域 apex）
    # ---- 重症：运营商号码认证 / 一键登录 ----
    ("id6.me",                      cn,    True),
    ("cmpassport.com",              cn,    True),   # 移动认证基础设施（+. 修复后含裸域）
    ("enrichgw.10010.com",          cn,    True),
    # ---- 重症：本地/路由管理域 ----
    ("localhost",                   cn,    True),   # RFC 6761 特殊域（单标签豁免）
    ("router.asus.com",             cn,    True),   # 华硕管理主域（+. 修复后含裸域）
    ("printer.internal",            cn,    True),   # 企业/家庭内网伪 TLD
    ("camera.home",                 cn,    True),   # 摄像头等 IoT 内网主机名
    # ---- 重症：远程访问 / DDNS（解析结果指向用户自己的设备）----
    ("myhost.ts.net",               notcn, True),
    ("mesh.tailscale.com",          notcn, True),
    ("abc.quickconnect.to",         notcn, True),   # 群晖 QuickConnect
    ("myvps.duckdns.org",           notcn, True),   # 自建 VPN DDNS
    ("myhost.ddns.net",             notcn, True),   # 免费 DDNS 扩充
    ("nas.hopto.org",               notcn, True),   # no-ip 系免费 DDNS
    # ---- 轻症优化：IP 调度型 CDN / 测速 / BT UDP tracker ----
    ("speedtest.net",               notcn, True),   # Ookla 测速（选服务器消费真实 IP）
    ("tracker.opentrackr.org",      notcn, True),   # BT UDP announce 直连
    ("exodus.desync.com",           notcn, True),   # 公共 tracker 上游类别探针
    ("open.tracker.cl",             notcn, True),   # 公共 tracker 上游类别探针
    ("supl.google.com",             notcn, True),   # Android SUPL A-GPS（真实 IP 就近）
    ("xtra1.gpsonextra.net",        notcn, True),   # Qualcomm XTRA 星历下载
    ("music.163.com",               cn,    True),   # 网易云音乐调度
    # ---- 大厂覆盖反例：路由大厂必须走 Fake-IP（不在名单）----
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
    ("dnsleaktest.com",             notcn, False),  # DNS 泄露检测站（自欺欺人）
    ("browserleaks.com",            notcn, False),  # 指纹/泄露检测站
    ("ipleak.net",                  notcn, False),  # 泄露检测站
    ("store.steampowered.com",      notcn, False),  # Steam 商店 = 分流域（games 纪律：只收 CDN/NAT 子域）
    ("epicgames.com",               notcn, False),  # Epic 官网 = 分流域，禁止整类并入
    ("dns.google",                  notcn, False),  # DoH 自举不收：污染环境本地解析反而有害，Fake-IP 域名出站自洽
]

failed = [d for d, target, expect in CASES if hit(target, d) != expect]
if failed:
    print("ASSERT FAILED:", failed)
    sys.exit(1)
print(f"all {len(CASES)} assertions passed")

# ---- srs 语义读回：compile 可能合法优化条目（被 suffix 覆盖的精确 domain 折叠），
# 机械条数对比不成立；正确断言 = 51 条 CASES 在编译产物（decompile 读回）上重跑全通过。
# 需要 sing-box 在 PATH（CI 已安装；本地可用 SINGBOX_BIN 指定），不可用时跳过并告警
import os
import shutil
import subprocess
import tempfile

singbox = os.environ.get("SINGBOX_BIN") or shutil.which("sing-box")
if not singbox:
    print("WARN: 未找到 sing-box，跳过 srs 读回断言（CI 中始终执行）")
else:
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
        cases = [(d, tgt, exp) for d, tgt, exp in CASES if tgt is (cn if name == "fakeipfilter-cn" else notcn)]
        failed_back = [d for d, target, expect in cases if hit(back, d) != expect]
        if failed_back:
            print(f"ASSERT FAILED: {name} srs 读回语义断言失败：{failed_back}")
            sys.exit(1)
        print(f"ok {name}: srs 读回语义断言通过（{len(cases)} 条探针）")

# ---- classical .list 语义探针（mihomo 侧产物闭环）：
# DOMAIN 精确 / DOMAIN-SUFFIX 含 apex 与子域（rules/common/domain_suffix.go：
# HasSuffix(domain, "."+suffix) || domain == suffix）/ KEYWORD 子串 / REGEX fullmatch。
# build 的 apex 去冗余逻辑正确性由本组探针守门。
def load_classical(name: str) -> dict:
    dom, sfx, kw, rex = set(), set(), set(), []
    for raw in (DIST / f"{name}.list").read_text(encoding="utf-8").splitlines():
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
        # IP-CIDR 行在 fake-ip-filter 域匹配语境自然失效（parseDomainRuleSet 只取域规则），跳过
    return {"domain": dom, "suffix": sfx, "keyword": kw, "regex": rex}


def hit_classical(c: dict, d: str) -> bool:
    return (d in c["domain"]
            or any(d == s or d.endswith("." + s) for s in c["suffix"])
            or any(k in d for k in c["keyword"])
            or any(p.fullmatch(d) for p in c["regex"]))


for name in ("fakeipfilter-cn", "fakeipfilter-!cn"):
    cl = load_classical(name)
    cases = [(d, tgt, exp) for d, tgt, exp in CASES if tgt is (cn if name == "fakeipfilter-cn" else notcn)]
    failed_cl = [d for d, target, expect in cases if hit_classical(cl, d) != expect]
    if failed_cl:
        print(f"ASSERT FAILED: {name} classical .list 语义断言失败：{failed_cl}")
        sys.exit(1)
    print(f"ok {name}: classical .list 语义断言通过（{len(cases)} 条探针）")
