#!/usr/bin/env python3
"""
攻撃ログ解析 - 検索キーワードで関連ログを抽出する（乾燥環境）

入力: T1615_add.csv 等のログCSV
検索: コマンドラインで指定したキーワードでヒットした行を抽出
出力: 抽出結果を別CSVに保存（code列付き）
"""

import argparse
import csv
import sys
from pathlib import Path


# 検索対象となるテキスト列（生ログ／前処理済みの両方に対応）
SEARCH_COLUMNS = [
    "Details", "ExtraFieldInfo",  # 生ログ
    "Proc", "ParentImage", "CommandLine", "SrcProc", "TgtProc",  # 前処理済み
    "RuleTitle", "Timestamp", "Links",
]
OUTPUT_COLUMNS = [
    "code",
    "LineNo in file",
    "Timestamp",
    "RuleTitle",
    "Level",
    "Links",
    "Channel",
    "EventID",
    "Details",
    "ExtraFieldInfo",
    "Computer",
    "RecordID",
]


def load_log_csv(path: Path) -> list[dict]:
    """CSVを読み込み、行番号付きで返す。"""
    rows = []
    encodings = ["utf-8-sig", "utf-8", "cp932", "shift_jis"]
    last_error = None
    for enc in encodings:
        try:
            with open(path, encoding=enc, newline="") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    line_no = i + 2  # ヘッダが1行目、データは2行目～
                    row["_LineNo"] = line_no
                    rows.append(row)
                return rows
        except UnicodeDecodeError as e:
            last_error = e
            rows = []
            continue
    raise last_error


def row_matches_keyword(row: dict, keyword: str, case_sensitive: bool = False) -> bool:
    """行がキーワードにマッチするか。"""
    kw = keyword if case_sensitive else keyword.lower()
    for col in SEARCH_COLUMNS:
        val = row.get(col, "")
        if val is None:
            continue
        s = str(val) if case_sensitive else str(val).lower()
        if kw in s:
            return True
    return False


def extract_rows(rows: list[dict], keyword: str, case_sensitive: bool = False) -> list[dict]:
    """キーワードにマッチする行を抽出。"""
    code_label = f"{keyword}で検索"
    hits = []
    for row in rows:
        if row_matches_keyword(row, keyword, case_sensitive):
            out = {"code": code_label}
            out["LineNo in file"] = row.get("_LineNo", "")
            for k, v in row.items():
                if k.startswith("_"):
                    continue
                out[k] = v
            hits.append(out)
    return hits


def save_extracted_csv(hits: list[dict], out_path: Path) -> None:
    """抽出結果をCSVに保存。0件でもヘッダーだけ書き、後段が参照できるようにする。"""
    fieldnames = list(hits[0].keys()) if hits else OUTPUT_COLUMNS
    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(hits)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="検索キーワードでログCSVから関連行を抽出し、別ファイルに保存"
    )
    parser.add_argument(
        "keyword",
        help="検索キーワード（例: gpresult /z, cmd.exe）",
    )
    parser.add_argument(
        "-i",
        "--input",
        default="T1615_add.csv",
        help="入力ログCSV（デフォルト: T1615_add.csv）",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="出力CSV（未指定時: <input>_<keyword置換>_extracted.csv）",
    )
    parser.add_argument(
        "-c",
        "--case-sensitive",
        action="store_true",
        help="大文字小文字を区別して検索",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"エラー: 入力ファイルが見つかりません: {input_path}", file=sys.stderr)
        return 1

    # 出力パス
    if args.output:
        output_path = Path(args.output)
    else:
        safe_keyword = "".join(c if c.isalnum() or c in "._-" else "_" for c in args.keyword).strip("_")
        if not safe_keyword:
            safe_keyword = "search"
        output_path = input_path.parent / f"{input_path.stem}_{safe_keyword}_extracted.csv"

    print(f"入力: {input_path}")
    print(f"検索: {args.keyword}")
    print(f"出力: {output_path}")

    rows = load_log_csv(input_path)
    print(f"読み込み: {len(rows)} 行")

    hits = extract_rows(rows, args.keyword, args.case_sensitive)
    print(f"ヒット: {len(hits)} 行")

    save_extracted_csv(hits, output_path)
    print(f"保存完了: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
