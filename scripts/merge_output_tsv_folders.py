#!/usr/bin/env python3
"""
指定した data/output 配下の複数フォルダ内の *.tsv を1つのTSVにまとめる。

- フォルダ内: consolidate_output_to_excel.py と同様に、同一 LineNo in file は1行にまとめる（ファイル名ソート順で先勝ち）
- フォルダ間: 行はそのまま縦に連結（同じ LineNo でもフォルダが違えば別行）
- 先頭列に「出力フォルダ」を付与

使い方:
  python scripts/merge_output_tsv_folders.py
  python scripts/merge_output_tsv_folders.py -o data/output/custom_merged.tsv folderA folderB
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

DEFAULT_FOLDERS = [
    "test1572001",
    "test1572002",
    "test1572003",
    "test1572004-01",
    "test1572004-02",
    "test1572004-03",
]
DEFAULT_OUTPUT = "data/output/T1572_出力想定形式_統合.tsv"


def load_tsv(path: Path) -> list[dict]:
    rows: list[dict] = []
    for enc in ("utf-8-sig", "utf-8", "cp932", "shift_jis"):
        try:
            with open(path, encoding=enc, newline="") as f:
                r = csv.DictReader(f, delimiter="\t")
                for row in r:
                    rows.append(dict(row))
            return rows
        except (UnicodeDecodeError, csv.Error):
            rows = []
    return rows


def merge_tsvs_in_folder(folder: Path) -> tuple[list[dict], list[str]]:
    tsv_files = sorted(
        [p for p in folder.iterdir() if p.suffix.lower() == ".tsv"],
        key=lambda p: p.name,
    )
    if not tsv_files:
        return [], []

    seen_line_no: set[str] = set()
    merged_rows: list[dict] = []
    columns: list[str] = []

    for tsv_path in tsv_files:
        rows = load_tsv(tsv_path)
        if not rows:
            continue
        if not columns:
            columns = list(rows[0].keys())
        for row in rows:
            line_no = (row.get("LineNo in file") or "").strip()
            if line_no in seen_line_no:
                continue
            seen_line_no.add(line_no)
            merged_rows.append(row)

    return merged_rows, columns


def collect_rows(
    output_root: Path, folder_names: list[str]
) -> tuple[list[dict], list[str]]:
    all_rows: list[dict] = []
    base_columns: list[str] = []

    for name in folder_names:
        folder = output_root / name
        if not folder.is_dir():
            print(f"警告: スキップ（フォルダなし）: {folder}", file=sys.stderr)
            continue
        merged, cols = merge_tsvs_in_folder(folder)
        if not merged:
            print(f"警告: TSVが0件: {folder}", file=sys.stderr)
            continue
        if not base_columns:
            base_columns = cols
        for row in merged:
            r = dict(row)
            r["出力フォルダ"] = name
            all_rows.append(r)

    # 列順: 出力フォルダ → 既存ヘッダ順 → その他
    fieldnames = ["出力フォルダ"]
    for k in base_columns:
        if k not in fieldnames:
            fieldnames.append(k)
    for row in all_rows:
        for k in row:
            if k not in fieldnames:
                fieldnames.append(k)

    return all_rows, fieldnames


def main() -> int:
    ap = argparse.ArgumentParser(
        description="複数の output サブフォルダ内TSVを1ファイルに統合"
    )
    ap.add_argument(
        "folders",
        nargs="*",
        default=DEFAULT_FOLDERS,
        help=f"フォルダ名（data/output 直下）。省略時: {' '.join(DEFAULT_FOLDERS)}",
    )
    ap.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        metavar="TSV",
        help=f"出力TSV（デフォルト: {DEFAULT_OUTPUT}）",
    )
    args = ap.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    output_root = base_dir / "data" / "output"
    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = base_dir / out_path

    rows, fieldnames = collect_rows(output_root, args.folders)
    if not rows:
        print("エラー: 結合できる行がありません。", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"出力: {out_path}（{len(rows)} 行）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
