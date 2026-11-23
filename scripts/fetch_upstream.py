#!/usr/bin/env python3
"""下载并校验上游类别 .list（输入校验 + 重试 + 新鲜度告警）。

用法：python3 scripts/fetch_upstream.py
标准库 only（urllib），CI / 本地均直接运行。

行为语义（对应设计文档 §7 失败模式分级）：
- 每类别最多重试 RETRY 次，间隔 RETRY_WAIT 秒；
- 输入校验：HTML 错误页特征 / 空文件 / 有效行数下限 / 行语法白名单，
  并做 BOM/CRLF 归一；
- 新鲜度（防"上游静默坏 N 天无人察觉"）：
  * 行数较上次成功骤降 >DROP_RATIO → 视为异常：保留旧文件，exit 1
    （强制人工裁决：上游是真删减还是构建事故）；
  * 下载失败 → 保留旧文件继续构建（best-effort），::warning；
  * 同一类别连续失败 ≥STALE_DAYS 天（meta 记录最后成功日）→ exit 1 红灯；
- 成功后覆盖 upstream/{tag}.list 并更新 upstream/meta.json（提交回仓库供审计）。
"""
import json
import pathlib
import re
import sys
import time
import urllib.request
from datetime import datetime

ROOT = pathlib.Path(__file__).resolve().parent.parent
UP = ROOT / "upstream"
META = UP / "meta.json"

BASE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/{name}.list"
# 双链容灾：raw 失败依次尝试 jsDelivr 镜像（同分支同路径）
MIRRORS = [
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/{name}.list",
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/{name}.list",
]
RETRY, RETRY_WAIT, TIMEOUT = 3, 5, 60
MIN_LINES = 5          # 有效行数下限（connectivity-check-cn 仅 9 行，5 足够保守）
DROP_RATIO = 0.5       # 行数低于上一版的该比例视为骤降
STALE_DAYS = 3         # 同一类别连续失败天数上限

# (上游类别名, 本地标记)
UPSTREAMS = [
    ("connectivity-check", "connectivity-check"),
    ("connectivity-check@cn", "connectivity-check-cn"),
    ("category-ntp", "ntp"),
    ("category-ntp-cn", "ntp-cn"),
    ("category-stun", "stun"),
    # 注：v2fly 的 speedtest 类别与 ookla-speedtest 内容完全相同（2026-11-23 实测
    # 交集 20/20），按「已覆盖不重复引入」原则不接入；若日后分化再评估
    ("ookla-speedtest", "ookla-speedtest"),
    ("category-public-tracker", "public-tracker"),
]

LINE_RE = re.compile(r"[a-z0-9.*+_-]+")   # .list 行语法白名单（小写化后）


def load_meta() -> dict:
    if META.exists():
        return json.loads(META.read_text(encoding="utf-8"))
    return {}


def save_meta(meta: dict) -> None:
    META.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def fetch(name: str) -> str | None:
    urls = [u.format(name=name) for u in MIRRORS]
    for url in urls:
        for attempt in range(1, RETRY + 1):
            try:
                with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
                    return resp.read().decode("utf-8", errors="replace")
            except Exception as exc:                   # 网络/HTTP 异常统一按失败处理
                print(f"  第 {attempt}/{RETRY} 次下载失败 {url}：{exc}")
                if attempt < RETRY:
                    time.sleep(RETRY_WAIT)
    return None


def validate(text: str) -> tuple[str | None, int]:
    """归一 + 输入校验，返回 (错误原因, 有效行数)；错误原因为 None 表示通过。"""
    text = text.replace("\r\n", "\n").replace("\r", "\n")          # CRLF 归一
    head = text[:2000].lower()
    if "<!doctype" in head or "<html" in head:
        return "内容疑似 HTML 错误页", 0
    n = 0
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if not LINE_RE.fullmatch(line):
            return f"行语法非法：{line[:40]!r}", n
        n += 1
    if n < MIN_LINES:
        return f"有效行数 {n} < 下限 {MIN_LINES}", n
    return None, n


def days_since(iso: str) -> int:
    return (datetime.now().date() - datetime.strptime(iso, "%Y-%m-%d").date()).days


def main() -> None:
    UP.mkdir(exist_ok=True)
    meta = load_meta()
    hard_fail = False
    for name, tag in UPSTREAMS:
        prev = meta.get(tag, {})
        text = fetch(name)
        if text is None:
            stale = days_since(prev["date"]) if "date" in prev else 0
            if stale >= STALE_DAYS:
                # 保留旧文件，但必须让人看见：红灯终止，防静默降级无限延续
                print(f"::error:: upstream {name} 已连续失败约 {stale} 天，中止（红灯告警）")
                hard_fail = True
            else:
                print(f"::warning:: upstream {name} 下载失败，本次沿用旧文件（best-effort）")
            continue
        err, n = validate(text)
        if err is not None:
            print(f"::error:: upstream {name} 校验失败（{err}），保留旧文件")
            hard_fail = True
            continue
        if "lines" in prev and n < prev["lines"] * DROP_RATIO:
            print(f"::error:: upstream {name} 行数骤降：{prev['lines']} -> {n}（>50%），中止更新，保留旧文件")
            hard_fail = True
            continue
        (UP / f"{tag}.list").write_text(text, encoding="utf-8")
        meta[tag] = {"date": datetime.now().strftime("%Y-%m-%d"), "lines": n}
        print(f"OK  {tag}  {n} 条")
    save_meta(meta)
    if hard_fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
