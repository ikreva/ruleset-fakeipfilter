#!/usr/bin/env python3
"""合并手写段与上游类别，产出 sing-box (json/srs) 与 mihomo (mrs + regex.list + 兼容全量 .list)。

用法：
  python3 scripts/build.py
  SINGBOX_BIN=... MIHOMO_BIN=... python3 scripts/build.py

产物：
  - dist/fakeipfilter-{cn,!cn}.json        sing-box source（透明可审计）
  - dist/fakeipfilter-{cn,!cn}.srs         sing-box 二进制规则集（若 sing-box 可用则直接编译）
  - dist/fakeipfilter-{cn,!cn}.mrs         mihomo 纯域名二进制 Trie（5B 高性能主集，若 mihomo 可用则直接编译）
  - dist/fakeipfilter-{cn,!cn}-regex.list  mihomo 极简正则伴随集（4 条 / 7 条，配合 .mrs 使用）
  - dist/fakeipfilter-{cn,!cn}.list        mihomo 兼容全量 classical text（单文件向后兼容）

硬不变量：
1. 纯前缀通配 `*.x`（rest 不含 `*`）直接落入 trie `domain_suffix`，绝不退化为正则；
2. 仅中间/复合通配进入 `domain_regex`，且强制两端锚定 `^...$`，防止子串误杀导致海外域名泄露；
3. `fakeipfilter-cn` 与 `fakeipfilter-!cn` 严格互斥（`!cn` 自动扣除已由 `cn` 覆盖的域与后缀）；
4. 后缀包含剪枝（`prune_by_suffix`）自动清除被更短后缀覆盖的子域与子后缀冗余。
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC, UP, DIST = ROOT / "sources", ROOT / "upstream", ROOT / "dist"
FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr")

# 按顺序构建：先构建 fakeipfilter-cn，再在 fakeipfilter-!cn 中扣除 cn 已覆盖条目
TARGETS = [
    ("fakeipfilter-cn", [
        ("manual", "fakeipfilter-cn"),
        ("upstream", "connectivity-check-cn"),
        ("upstream", "ntp-cn"),
    ]),
    ("fakeipfilter-!cn", [
        ("manual", "fakeipfilter-!cn"),
        ("upstream", "connectivity-check"),
        ("upstream", "ntp"),
        ("upstream", "stun"),
        ("upstream", "ookla-speedtest"),
        ("upstream", "public-tracker"),
    ]),
]

SINGLE_LABEL_OK = {"localhost"}
UPSTREAM_MIN_LINES = 5


def star_to_regex(line: str) -> str:
    """含中间/多层 `*` 的通配行转两端锚定正则：`^...$`，避免 MatchString 子串误杀。"""
    segs = line.split(".")
    pat = "\\.".join("[^.]+" if s == "*" else re.escape(s) for s in segs)
    return "^" + pat + "$"


def plus_star_to_regex(rest: str) -> str:
    """`+.x.*.y` 转两端锚定正则：前缀可选 `(.+\\.)?`，`*` → `[^.]+`，尾部强制 `$`。"""
    segs = rest.split(".")
    pat = "\\.".join("[^.]+" if s == "*" else re.escape(s) for s in segs)
    return "^(.+\\.)?" + pat + "$"


def add_domain(acc: dict, domain: str) -> None:
    """按 mihomo `+.x` 语义落条目：裸域（apex）+ 前导点后缀（子域），双保险。"""
    acc["domain"].append(domain)
    acc["domain_suffix"].append("." + domain)


def add_pattern_line(acc: dict, line: str, *, bare_is_suffix: bool) -> None:
    """统一分发 `+.x`、`*.x`、复合通配与裸域。"""
    if line.startswith("*.") and "*" not in line[2:]:
        acc["domain_suffix"].append("." + line[2:])
    elif line.startswith("+.") and "*" not in line[2:]:
        add_domain(acc, line[2:])
    elif "*" in line:
        if line.startswith("+."):
            acc["domain_regex"].append(plus_star_to_regex(line[2:]))
        else:
            acc["domain_regex"].append(star_to_regex(line))
    elif bare_is_suffix:
        add_domain(acc, line)
    else:
        acc["domain"].append(line)


def parse_manual(path: pathlib.Path) -> dict:
    acc = {k: [] for k in FIELDS}
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw_clean = raw.split("#", 1)[0].strip()
        if not raw_clean:
            continue
        line = raw_clean.lower()
        upper = line.upper()
        if upper.startswith("DOMAIN-SUFFIX,"):
            add_domain(acc, line.split(",", 1)[1].strip())
        elif upper.startswith("DOMAIN-KEYWORD,"):
            acc["domain_keyword"].append(line.split(",", 1)[1].strip())
        elif upper.startswith("DOMAIN-REGEX,"):
            acc["domain_regex"].append(raw_clean.split(",", 1)[1].strip())
        elif upper.startswith("IP-CIDR,"):
            acc["ip_cidr"].append(line.split(",")[1].strip())
        elif raw_clean.startswith("^"):
            acc["domain_regex"].append(raw_clean)
        else:
            add_pattern_line(acc, line, bare_is_suffix=False)
    return acc


def load_excludes() -> set[str]:
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
                if not any(c.search(s) for s in samples):
                    kept.append(pat)
            out[k] = kept
        else:
            out[k] = [v for v in vals if not any(v == e or v.endswith("." + e) for e in excludes)]
    return {k: v for k, v in out.items() if v}


def subtract_cn(notcn: dict, cn: dict) -> tuple[dict, int]:
    """从 `!cn` 中扣除已被 `cn` 覆盖的 `domain` 与 `domain_suffix`，保证两名单互斥。"""
    cn_domains = set(cn.get("domain", []))
    cn_suffixes = set(cn.get("domain_suffix", []))

    def in_cn_domain(d: str) -> bool:
        return d in cn_domains or any(d.endswith(s) for s in cn_suffixes)

    def in_cn_suffix(s: str) -> bool:
        apex = s.lstrip(".")
        return s in cn_suffixes or any(s.endswith(cs) for cs in cn_suffixes) or apex in cn_domains

    out = {k: list(v) for k, v in notcn.items()}
    dropped = 0
    if "domain" in out:
        kept = [d for d in out["domain"] if not in_cn_domain(d)]
        dropped += len(out["domain"]) - len(kept)
        out["domain"] = kept
    if "domain_suffix" in out:
        kept = [s for s in out["domain_suffix"] if not in_cn_suffix(s)]
        dropped += len(out["domain_suffix"]) - len(kept)
        out["domain_suffix"] = kept
    return {k: v for k, v in out.items() if v}, dropped


def prune_by_suffix(merged: dict) -> tuple[dict, int]:
    """后缀包含剪枝：剔除已被自身更短 `domain_suffix` 覆盖的子后缀与子域（保留 apex 自身）。"""
    sfxs = list(merged.get("domain_suffix", []))
    if not sfxs:
        return merged, 0
    sfx_set = set(sfxs)
    kept_sfxs = [s for s in sfxs if not any(s != o and s.endswith(o) for o in sfx_set)]
    dropped = len(sfxs) - len(kept_sfxs)

    doms = list(merged.get("domain", []))
    kept_doms = [d for d in doms if not any(d.endswith(s) for s in kept_sfxs)]
    dropped += len(doms) - len(kept_doms)

    out = {k: list(v) for k, v in merged.items()}
    out["domain_suffix"] = kept_sfxs
    out["domain"] = kept_doms
    return {k: v for k, v in out.items() if v}, dropped


def load_upstream_list(tag: str) -> dict | None:
    p = UP / f"{tag}.list"
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
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
        add_pattern_line(acc, line, bare_is_suffix=True)
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
    out = {}
    for k in FIELDS:
        vals = sorted(set(merged.get(k, [])))
        if k == "domain":
            vals = [v for v in vals if "." in v or v in SINGLE_LABEL_OK]
        elif k == "domain_suffix":
            vals = [v for v in vals if "." in v]
        elif k == "domain_regex":
            for pat in vals:
                if not (pat.startswith("^") and pat.endswith("$")):
                    raise ValueError(f"domain_regex 必须以 ^ 开头并以 $ 结尾，防止子串误杀：{pat!r}")
        if vals:
            out[k] = vals
    return out


def optimize_by_regex(merged: dict) -> tuple[dict, int]:
    """确定性去冗余：已被本产物两端锚定 domain_regex 覆盖的精确/后缀条目剔除。"""
    patterns = merged.get("domain_regex", [])
    if not patterns:
        return merged, 0
    compiled = [re.compile(p) for p in patterns]
    covered = lambda d: any(c.search(d) for c in compiled)
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
    """兼容全量 classical `.list`（单文件含 domain/suffix/regex）。"""
    lines = ["# 自动生成于 build.py，勿手改；修改请编辑 sources/*.manual.list"]
    suffixes = {s.lstrip(".") for s in merged.get("domain_suffix", [])}

    def suffix_covered(d: str) -> bool:
        return any(d == s or d.endswith("." + s) for s in suffixes)

    lines += [f"DOMAIN,{d}" for d in merged.get("domain", []) if not suffix_covered(d)]
    lines += [f"DOMAIN-SUFFIX,{s.lstrip('.')}" for s in merged.get("domain_suffix", [])]
    lines += [f"DOMAIN-KEYWORD,{k}" for k in merged.get("domain_keyword", [])]
    lines += [f"DOMAIN-REGEX,{r}" for r in merged.get("domain_regex", [])]
    lines += [f"IP-CIDR,{i},no-resolve" for i in merged.get("ip_cidr", [])]
    return "\n".join(lines) + "\n"


def to_mrs_domain_text(merged: dict) -> str:
    """生成 `mihomo convert-ruleset domain text` 输入（精确保持 apex 与子域语义）：
    - `domain_suffix` `.x` 且 apex `x` 也在 `domain` → `+.x`（匹配 apex + 任意子域）；
    - `domain_suffix` `.x` 但 apex `x` 不在 `domain` → `.x`（仅匹配子域，严格对齐 `*.x`）；
    - 其余 `domain` → `x`（仅精确匹配）。
    """
    dom_set = set(merged.get("domain", []))
    lines: list[str] = []
    covered_apex: set[str] = set()
    for s in merged.get("domain_suffix", []):
        apex = s.lstrip(".")
        if apex in dom_set:
            lines.append(f"+.{apex}")
            covered_apex.add(apex)
        else:
            lines.append(s)
    for d in merged.get("domain", []):
        if d not in covered_apex:
            lines.append(d)
    return "\n".join(sorted(set(lines))) + "\n"


def to_regex_clash_list(merged: dict) -> str:
    """5B 极简正则伴随集（仅含 DOMAIN-REGEX，配合二进制 `.mrs` 主集使用）。"""
    lines = ["# 自动生成于 build.py（5B 极简正则伴随集，配合同名 .mrs 使用），勿手改"]
    lines += [f"DOMAIN-REGEX,{r}" for r in merged.get("domain_regex", [])]
    return "\n".join(lines) + "\n"


def compile_binary(name: str, merged: dict) -> None:
    singbox = os.environ.get("SINGBOX_BIN") or shutil.which("sing-box")
    if singbox:
        json_path = DIST / f"{name}.json"
        srs_path = DIST / f"{name}.srs"
        subprocess.run([singbox, "rule-set", "format", str(json_path)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([singbox, "rule-set", "compile", str(json_path), "-o", str(srs_path)], check=True)
    else:
        print(f"  [提示] 未找到 sing-box，跳过 {name}.srs 编译（可用 SINGBOX_BIN 指定）")

    mihomo = os.environ.get("MIHOMO_BIN") or shutil.which("mihomo")
    if mihomo:
        mrs_path = DIST / f"{name}.mrs"
        with tempfile.TemporaryDirectory() as td:
            txt_path = pathlib.Path(td) / f"{name}.domain.txt"
            txt_path.write_text(to_mrs_domain_text(merged), encoding="utf-8")
            subprocess.run([mihomo, "convert-ruleset", "domain", "text", str(txt_path), str(mrs_path)], check=True)
    else:
        print(f"  [提示] 未找到 mihomo，跳过 {name}.mrs 编译（可用 MIHOMO_BIN 指定）")


def main() -> None:
    DIST.mkdir(exist_ok=True)
    excludes = load_excludes()
    built: dict[str, dict] = {}
    for name, spec in TARGETS:
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
        merged = normalize(apply_exclude(merge(*parts), excludes))
        if name == "fakeipfilter-!cn" and "fakeipfilter-cn" in built:
            merged, sub_dropped = subtract_cn(merged, built["fakeipfilter-cn"])
            if sub_dropped:
                print(f"  -> 与 fakeipfilter-cn 互斥去重：从 !cn 扣除 {sub_dropped} 条")
        merged, sfx_dropped = prune_by_suffix(merged)
        if sfx_dropped:
            print(f"  -> 后缀包含剪枝：剔除 {sfx_dropped} 条")
        merged, rx_dropped = optimize_by_regex(merged)
        if rx_dropped:
            print(f"  -> regex 覆盖去冗余：剔除 {rx_dropped} 条")
        built[name] = merged
        (DIST / f"{name}.json").write_text(
            json.dumps({"version": 3, "rules": [merged]}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (DIST / f"{name}.list").write_text(to_clash_list(merged), encoding="utf-8")
        (DIST / f"{name}-regex.list").write_text(to_regex_clash_list(merged), encoding="utf-8")
        compile_binary(name, merged)
        stats = ", ".join(f"{k}={len(v)}" for k, v in merged.items())
        print(f"{name}: {stats}")


if __name__ == "__main__":
    main()
