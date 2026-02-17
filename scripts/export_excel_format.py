#!/usr/bin/env python3
"""
出力想定形式でエクセル用TSVを出力

入力: traced CSV + 生ログ T1615_add.csv
出力: 出力想定.csv 形式のTSV（タブ区切り、Excelでそのまま開く想定）
"""

import argparse
import csv
import re
import sys
from pathlib import Path
from typing import Optional


def load_csv(path: Path) -> list[dict]:
    rows = []
    for enc in ("utf-8-sig", "utf-8", "cp932", "shift_jis"):
        try:
            with open(path, encoding=enc, newline="") as f:
                r = csv.DictReader(f)
                for i, row in enumerate(r):
                    row["_LineNo"] = i + 2
                    rows.append(row)
                return rows
        except UnicodeDecodeError:
            rows = []
    raise ValueError(f"読み込めません: {path}")


def ts_to_excel_format(ts: str) -> str:
    """2025-12-09 00:07:06.719 +00:00 -> 2025/12/9 9:07"""
    if not ts:
        return ""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})", ts)
    if m:
        y, mon, d, h, mi = m.groups()
        mon = str(int(mon))
        d = str(int(d))
        return f"{y}/{mon}/{d} {h}:{mi}"
    return ts


def build_raw_lookup(raw_rows: list[dict]) -> dict[int, dict]:
    """LineNo -> raw row"""
    return {int(r.get("_LineNo", 0)): r for r in raw_rows if r.get("_LineNo")}


def export(
    traced_rows: list[dict],
    raw_rows: list[dict],
    technique: str = "T1615",
    test_name: str = "Test01",
) -> list[dict]:
    raw_by_line = build_raw_lookup(raw_rows)
    out = []
    for row in traced_rows:
        line_no = row.get("LineNo in file") or row.get("LineNo", "")
        try:
            ln = int(line_no)
        except (ValueError, TypeError):
            ln = 0
        raw = raw_by_line.get(ln, {})

        out.append({
            "code": row.get("code", ""),
            "Technique": technique,
            "Test name": test_name,
            "Attak cmd": row.get("ProcessChain", ""),
            "LineNo in file": line_no,
            "TimeStamp": ts_to_excel_format(row.get("Timestamp", "") or raw.get("Timestamp", "")),
            "Rule Title": row.get("RuleTitle", "") or raw.get("RuleTitle", ""),
            "Level": row.get("Level", "") or raw.get("Level", ""),
            "Links": row.get("Links", "") or raw.get("Links", ""),
            "Channel": row.get("Channel", "") or raw.get("Channel", ""),
            "EventID": row.get("EventID", "") or raw.get("EventID", ""),
            "msg": raw.get("Details", row.get("Details", "")),
            "ExtraFieldInfo": raw.get("ExtraFieldInfo", row.get("ExtraFieldInfo", "")),
            "Computer": raw.get("Computer", row.get("Computer", "")),
            "RecordID": raw.get("RecordID", row.get("RecordID", "")),
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="出力想定形式でExcel用TSVを出力")
    ap.add_argument("-t", "--traced", required=True, help="traced CSV")
    ap.add_argument("-r", "--raw", required=True, help="生ログCSV（T1615_add.csv）")
    ap.add_argument("-o", "--output", default=None, help="出力TSV")
    ap.add_argument("--technique", default="T1615", help="Technique ID")
    ap.add_argument("--test-name", default="Test01", help="Test name")
    args = ap.parse_args()

    traced_path = Path(args.traced)
    raw_path = Path(args.raw)
    if not traced_path.exists():
        print(f"エラー: traced が見つかりません: {traced_path}", file=sys.stderr)
        return 1
    if not raw_path.exists():
        print(f"エラー: raw が見つかりません: {raw_path}", file=sys.stderr)
        return 1

    out_path = Path(args.output) if args.output else traced_path.parent / f"{traced_path.stem}_excel_format.tsv"

    traced = load_csv(traced_path)
    raw = load_csv(raw_path)

    rows = export(traced, raw, technique=args.technique, test_name=args.test_name)

    # 出力想定.csv と同じカラム並び
    cols = ["code", "Technique", "Test name", "Attak cmd", "LineNo in file", "TimeStamp",
            "Rule Title", "Level", "Links", "Channel", "EventID", "msg", "ExtraFieldInfo", "Computer", "RecordID"]

    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print(f"出力: {out_path} ({len(rows)} 行)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
