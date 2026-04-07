#!/usr/bin/env python3
"""
複数フォルダの「レポート.md」を 01〜04 セクションにまとめる。
04 は test1572004-01〜03 を 04-1〜04-3 として全文収録（構造保持のため段落マージはしない）。
"""
from __future__ import annotations

import argparse
from pathlib import Path


def strip_leading_h1(md: str) -> str:
    lines = md.strip().splitlines()
    i = 0
    if lines and lines[0].startswith("# "):
        i = 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    return "\n".join(lines[i:]).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="妥当性レポート複数フォルダを1 Markdown に統合")
    ap.add_argument(
        "-o",
        "--output",
        default="data/output/T1572_妥当性レポート_統合.md",
        help="出力 Markdown パス（プロジェクトルートからの相対可）",
    )
    args = ap.parse_args()

    base = Path(__file__).resolve().parent.parent
    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = base / out_path

    sec01_03 = [
        ("01", "test1572001"),
        ("02", "test1572002"),
        ("03", "test1572003"),
    ]
    sec04_dirs = ["test1572004-01", "test1572004-02", "test1572004-03"]

    chunks: list[str] = []
    chunks.append("# T1572 検索ワード妥当性レポート（統合）\n")
    chunks.append(
        "以下は `test1572001`〜`test1572004-03` の各出力フォルダで生成したレポートを、"
        "**01〜04** に分けて1ファイルに整理したものです。"
        "\n\n"
        "- **01〜03**: 各フォルダのレポートをそのまま収録（先頭の重複タイトル行のみ除去）。\n"
        "- **04**: ngrok シナリオの3段階（取得・実行・削除）を **04-1〜04-3** に分け、それぞれ全文を収録。"
        "（段落マージによる見出し欠落を避けるため、04 内は重複削除しません。）\n"
    )

    sep = "\n\n\n---\n\n\n"

    for label, folder in sec01_03:
        p = base / "data" / "output" / folder / "レポート.md"
        if not p.exists():
            print(f"missing: {p}", flush=True)
            return 1
        body = strip_leading_h1(p.read_text(encoding="utf-8"))
        chunks.append(f"{sep}## {label} `{folder}`\n\n{body}")

    chunks.append(f"{sep}## 04 ngrok シナリオ（test1572004-01 〜 test1572004-03）\n\n")
    for i, d in enumerate(sec04_dirs, start=1):
        p = base / "data" / "output" / d / "レポート.md"
        if not p.exists():
            print(f"missing: {p}", flush=True)
            return 1
        body = strip_leading_h1(p.read_text(encoding="utf-8"))
        chunks.append(f"### 04-{i} `{d}`\n\n{body.strip()}\n\n\n")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("".join(chunks), encoding="utf-8")
    print(f"wrote: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
