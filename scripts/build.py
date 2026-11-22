#!/usr/bin/env python3
"""合并手写段与上游类别，产出 sing-box source json + clash list。

用法：python3 scripts/build.py
输入：sources/*.manual.list、sources/connectivity-exclude.list、upstream/*.list（meta-rules-dat 类别 .list 直读）
输出：dist/fakeipfilter-{cn,!cn}.json 与 .list（srs 由 workflow 的 sing-box compile 生成）

产物语义（L1 判定器①）：进名单 = 客户端本地消费真实 IP（a）或快速通过需要真实 IP（b）；
两用检测/资源域（gstatic 等）按 sources/connectivity-exclude.list 剔除，走 Fake-IP。
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC, UP, DIST = ROOT / "sources", ROOT / "upstream", ROOT / "dist"
FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr")

# 产物 → 组成（manual 手写段 + upstream 标记）
TARGETS = {
    "fakeipfilter-cn": [
        ("manual", "fakeipfilter-cn"),
        ("upstream", "connectivity-check-cn"),
        ("upstream", "ntp-cn"),
    ],
    "fakeipfilter-!cn": [
        ("manual", "fakeipfilter-!cn"),
        ("upstream", "connectivity-check"),
        ("upstream", "ntp"),
        ("upstream", "stun"),
        ("upstream", "ookla-speedtest"),
        ("upstream", "speedtest"),
        ("upstream", "public-tracker"),
    ],
}

# 单标签豁免集：RFC 6761 特殊域（localhost 等）无点但合法，允许进 domain 精确条目。
# normalize 的"必须含点"过滤只防上游垃圾条目，不适用于这类特殊域。
SINGLE_LABEL_OK = {"localhost"}

# 上游类别文件有效行数下限（低于此值视为损坏/截断）
UPSTREAM_MIN_LINES = 5


def star_to_regex(line: str) -> str:
    """含 * 的普通行转锚定正则：* → [^.]+（与参考配置 json 风格一致）。"""
    segs = line.split(".")
    pat = "\\.".join("[^.]+" if s == "*" else re.escape(s) for s in segs)
    return "^" + pat


def plus_star_to_regex(rest: str) -> str:
    """+.x.*.y 转正则：前缀可选（(.+\\.)?），* → [^.]+。"""
    segs = rest.split(".")
    pat = "\\.".join("[^.]+" if s == "*" else re.escape(s) for s in segs)
    return "^(.+\\.)?" + pat


def add_domain(acc: dict, domain: str) -> None:
    """按 mihomo +.x 语义落条目：裸域（apex）+ 前导点后缀（子域），双保险。"""
    acc["domain"].append(domain)
    acc["domain_suffix"].append("." + domain)


def parse_manual(path: pathlib.Path) -> dict:
    acc = {k: [] for k in FIELDS}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        upper = line.upper()
        if upper.startswith("DOMAIN-SUFFIX,"):
            d = line.split(",", 1)[1].strip().lower()
            acc["domain_suffix"].append("." + d)
            acc["domain"].append(d)
        elif upper.startswith("DOMAIN-KEYWORD,"):
            acc["domain_keyword"].append(line.split(",", 1)[1].strip().lower())
        elif upper.startswith("DOMAIN-REGEX,"):
            acc["domain_regex"].append(line.split(",", 1)[1].strip())
        elif upper.startswith("IP-CIDR,"):
            acc["ip_cidr"].append(line.split(",")[1].strip())
        elif line.startswith("^"):
            acc["domain_regex"].append(line)
        elif "*" in line:
            # 含通配的行一律转正则（+.stun.*.cn / stun.*.cn / PDC._msDCS.*.* 等），
            # 避免 * 混入 domain_suffix 产生非法条目
            if line.startswith("+."):
                acc["domain_regex"].append(plus_star_to_regex(line[2:].lower()))
            else:
                acc["domain_regex"].append(star_to_regex(line.lower()))
        elif line.startswith("+."):
            add_domain(acc, line[2:].lower())
        elif line.startswith("*."):
            acc["domain_suffix"].append("." + line[2:].lower())
        else:
            acc["domain"].append(line.lower())
    return acc


def load_excludes() -> set[str]:
    """两用域剔除清单（+.gstatic.com 形式）：按 L1 准入语义应走 Fake-IP 的大厂域。"""
    p = SRC / "connectivity-exclude.list"
    if not p.exists():
        return set()
    acc = set()
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        acc.add(line[2:] if line.startswith("+.") else line)
    return acc


def apply_exclude(merged: dict, excludes: set[str]) -> dict:
    """剔除与 exclude 后缀匹配的条目（L1 准入语义：两用域必须走 Fake-IP）。

    覆盖全部域类条目（防御上游将来出现 keyword/regex 形式的 gstatic 覆盖）：
    - domain/domain_suffix：== 或后缀匹配即剔；
    - domain_keyword：keyword 与任一 exclude 域的点分段相等即剔（保守——
      如 exclude 含 gstatic.com 则 keyword "gstatic" 不收；宁可误杀过宽关键词）；
    - domain_regex：编译后对样本域（apex 及 www./a.b. 两层子域）fullmatch 命中即剔；
    - ip_cidr 与域名无关，保留。
    """
    if not excludes:
        return merged
    labels = {seg for e in excludes for seg in e.split(".")}
    samples = [s for e in excludes for s in (e, "www." + e, "a.b." + e)]
    out = {}
    for k, vals in merged.items():
        if k == "ip_cidr":
            out[k] = vals
        elif k == "domain_keyword":
            out[k] = [v for v in vals if v not in labels]
        elif k == "domain_regex":
            kept = []
            for pat in vals:
                try:
                    c = re.compile(pat)
                except re.error:
                    kept.append(pat)
                    continue
                if not any(c.fullmatch(s) for s in samples):
                    kept.append(pat)
            out[k] = kept
        else:
            out[k] = [v for v in vals if not any(v == e or v.endswith("." + e) for e in excludes)]
    return {k: v for k, v in out.items() if v}


def load_upstream_list(tag: str) -> dict | None:
    """读上游 meta-rules-dat .list（mihomo 领域语法：裸域/+.x 均含 apex，*.x 仅单层子域）。

    上游裸域与 +.x 按 mihomo DOMAIN-SUFFIX 语义（含 apex）落 domain+suffix 双条目，
    保证 sing-box 侧 domain_suffix ".x"（只匹配子域）不丢 apex 精确匹配。
    内置健全性校验（HTML 错误页 / 行数下限 / 行语法），异常视为该类别缺失。
    """
    p = UP / f"{tag}.list"
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8-sig", errors="replace")   # utf-8-sig 去 BOM
    text = text.replace("\r\n", "\n").replace("\r", "\n")        # CRLF 归一
    head = text[:2000].lower()
    if "<!doctype" in head or "<html" in head:
        print(f"::error:: upstream {tag} 内容疑似 HTML 错误页，已跳过")
        return None
    acc = {k: [] for k in FIELDS}
    n_lines = 0
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if not re.fullmatch(r"[a-z0-9.*+_-]+", line):
            print(f"::warning:: upstream {tag} 非法行已跳过：{line[:40]!r}")
            continue
        n_lines += 1
        if "*" in line:
            if line.startswith("+."):
                acc["domain_regex"].append(plus_star_to_regex(line[2:]))
            else:
                acc["domain_regex"].append(star_to_regex(line))
        elif line.startswith("+.") or line.startswith("*."):
            if line.startswith("+."):
                add_domain(acc, line[2:])       # +.x = 域及子域（apex+后缀双落）
            else:
                acc["domain_suffix"].append("." + line[2:])   # *.x 仅子域语义
        else:
            add_domain(acc, line)               # 裸域 = suffix 语义（apex+子域双落）
    if n_lines < UPSTREAM_MIN_LINES:
        print(f"::error:: upstream {tag} 仅 {n_lines} 有效行（下限 {UPSTREAM_MIN_LINES}），疑似损坏，已跳过")
        return None
    return acc


def merge(*parts: dict | None) -> dict:
    out = {k: [] for k in FIELDS}
    for part in parts:
        if not part:
            continue
        for k in FIELDS:
            for v in part.get(k, []):
                if v not in out[k]:
                    out[k].append(v)
    return out


def normalize(merged: dict) -> dict:
    """排序规范化 + 健全性过滤 + 字段规范化（确定性输出，git 历史即真实变更记录）。

    健全性过滤：domain/domain_suffix 条目必须含 '.'（防御上游构建产物中的
    单字母/裸 TLD 垃圾条目——sing-geosite 的 @cn srs 曾实测出现）；
    单标签豁免集（localhost）除外——RFC 6761 特殊域无点但合法，
    必须保留 domain 精确条目（domain_suffix ".localhost" 只匹配子域）。
    """
    out = {}
    for k in FIELDS:
        vals = sorted(set(merged.get(k, [])))
        if k == "domain":
            vals = [v for v in vals if "." in v or v in SINGLE_LABEL_OK]
        elif k == "domain_suffix":
            vals = [v for v in vals if "." in v]
        if vals:
            out[k] = vals
    return out


def optimize_by_regex(merged: dict) -> tuple[dict, int]:
    """确定性去冗余：已被本产物 domain_regex 覆盖的精确/后缀条目剔除（regex 保留）。

    - domain：任一 regex fullmatch 命中即剔除；
    - domain_suffix：apex 与样本子域（ci.apex）**双双命中**才剔除（保守，
      避免通配只盖子域不盖 apex 时误删）；regex/ip_cidr/keyword 不动。
    返回 (新 dict, 剔除条数)。
    """
    patterns = merged.get("domain_regex", [])
    if not patterns:
        return merged, 0
    compiled = [re.compile(p) for p in patterns]
    covered = lambda d: any(c.fullmatch(d) for c in compiled)
    out = {k: list(v) for k, v in merged.items()}
    dropped = 0
    doms = []
    for d in out.get("domain", []):
        if covered(d):
            dropped += 1
            continue
        doms.append(d)
    out["domain"] = doms
    sfx = []
    for s in out.get("domain_suffix", []):
        apex = s.lstrip(".")
        if covered(apex) and covered("ci." + apex):
            dropped += 1
            continue
        sfx.append(s)
    out["domain_suffix"] = sfx
    return {k: v for k, v in out.items() if v}, dropped


def to_clash_list(merged: dict) -> str:
    lines = ["# 自动生成于 build.py，勿手改；修改请编辑 sources/*.manual.list"]
    lines += [f"DOMAIN,{d}" for d in merged.get("domain", [])]
    lines += [f"DOMAIN-SUFFIX,{s.lstrip('.')}" for s in merged.get("domain_suffix", [])]
    lines += [f"DOMAIN-KEYWORD,{k}" for k in merged.get("domain_keyword", [])]
    lines += [f"DOMAIN-REGEX,{r}" for r in merged.get("domain_regex", [])]
    lines += [f"IP-CIDR,{i},no-resolve" for i in merged.get("ip_cidr", [])]
    return "\n".join(lines) + "\n"


def main() -> None:
    DIST.mkdir(exist_ok=True)
    excludes = load_excludes()
    for name, spec in TARGETS.items():
        parts = []
        for kind, key in spec:
            if kind == "manual":
                path = SRC / f"{key}.manual.list"
                if path.exists():
                    parts.append(parse_manual(path))
                else:
                    print(f"::warning:: manual 段缺失：{path}")
            else:
                up = load_upstream_list(key)
                if up is None:
                    print(f"::warning:: upstream {key} 缺失或校验失败，本次跳过")
                else:
                    parts.append(up)
        merged, dropped = optimize_by_regex(normalize(apply_exclude(merge(*parts), excludes)))
        if dropped:
            print(f"  -> regex 覆盖去冗余：剔除 {dropped} 条")
        (DIST / f"{name}.json").write_text(
            json.dumps({"version": 3, "rules": [merged]}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (DIST / f"{name}.list").write_text(to_clash_list(merged), encoding="utf-8")
        stats = ", ".join(f"{k}={len(v)}" for k, v in merged.items())
        print(f"{name}: {stats}")


if __name__ == "__main__":
    main()
