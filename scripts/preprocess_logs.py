#!/usr/bin/env python3
"""
ログCSV前処理 - 関連プロセス追跡に必要な情報を抜き出す

入力: T1615_add.csv 等の生ログCSV
出力: PID, ParentPID, Proc, ParentImage 等を列にしたCSV
      （extract_logs.py や PID 検索に使いやすい形）
"""

import argparse
import csv
import re
import sys
from pathlib import Path


def parse_kv_fields(text: str) -> dict[str, str]:
    """'Key: value | Key2: value2' 形式をパース。"""
    result = {}
    if not text or not isinstance(text, str):
        return result
    for part in text.split(" | "):
        part = part.strip()
        if ": " in part:
            key, _, val = part.partition(": ")
            result[key.strip()] = val.strip()
    return result


def extract_process_fields(row: dict) -> dict:
    """
    Details / ExtraFieldInfo からプロセス追跡に必要なフィールドを抽出。
    Sec 4688, Sysmon 1, Sysmon 10 等の形式に対応。
    """
    details = parse_kv_fields(row.get("Details", ""))
    extra = parse_kv_fields(row.get("ExtraFieldInfo", ""))
    event_id = str(row.get("EventID", ""))
    channel = str(row.get("Channel", ""))

    out = {}

    # Sec 4688: PID, Proc は Details / ParentProcessName, ProcessId は ExtraFieldInfo
    if event_id == "4688" or channel == "Sec":
        out["PID"] = details.get("PID", "")
        out["ParentPID"] = extra.get("ProcessId", "")  # Sec では ProcessId が親PID
        out["Proc"] = details.get("Proc", "")
        out["ParentImage"] = extra.get("ParentProcessName", "")
        out["CommandLine"] = details.get("Cmdline", "")
        out["User"] = details.get("User", "")
        out["PGUID"] = details.get("PGUID", "")
        out["ParentPGUID"] = details.get("ParentPGUID", "")

    # Sysmon 1: プロセス作成
    if event_id == "1" or (channel == "Sysmon" and "ParentPID" in details):
        out["PID"] = out.get("PID") or details.get("PID", "")
        out["ParentPID"] = out.get("ParentPID") or details.get("ParentPID", "")
        out["Proc"] = out.get("Proc") or details.get("Proc", "")
        out["ParentImage"] = out.get("ParentImage") or details.get("ParentImage", "") or extra.get("ParentImage", "")
        out["CommandLine"] = out.get("CommandLine") or details.get("Cmdline", details.get("CommandLine", ""))
        out["User"] = out.get("User") or details.get("User", "")
        out["PGUID"] = out.get("PGUID") or details.get("PGUID", "")
        out["ParentPGUID"] = out.get("ParentPGUID") or details.get("ParentPGUID", "")

    # Sysmon 10: Process Access（SrcPID, TgtPID）
    if event_id == "10":
        out["SrcPID"] = details.get("SrcPID", "")
        out["TgtPID"] = details.get("TgtPID", "")
        out["SrcProc"] = details.get("SrcProc", "")
        out["TgtProc"] = details.get("TgtProc", "")

    # Sysmon 3 等: Proc, PID, PGUID があり得る
    if event_id in ("3", "7", "11", "12", "13"):
        out["PID"] = out.get("PID") or details.get("PID", "")
        out["Proc"] = out.get("Proc") or details.get("Proc", "")
        out["PGUID"] = out.get("PGUID") or details.get("PGUID", "")

    return {k: v or "" for k, v in out.items()}


# 出力カラム（プロセス追跡に必要十分）
OUTPUT_COLS = [
    "LineNo",
    "Timestamp",
    "Channel",
    "EventID",
    "Computer",
    "RecordID",
    "PID",
    "ParentPID",
    "PGUID",
    "ParentPGUID",
    "Proc",
    "ParentImage",
    "CommandLine",
    "User",
    "SrcPID",
    "TgtPID",
    "SrcProc",
    "TgtProc",
    "RuleTitle",
    "Level",
]


def load_csv(path: Path) -> list[dict]:
    """CSV読み込み（エンコーディング自動判定）。"""
    rows = []
    encodings = ["utf-8-sig", "utf-8", "cp932", "shift_jis"]
    last_err = None
    for enc in encodings:
        try:
            with open(path, encoding=enc, newline="") as f:
                r = csv.DictReader(f)
                for i, row in enumerate(r):
                    row["_LineNo"] = i + 2
                    rows.append(row)
                return rows
        except UnicodeDecodeError as e:
            last_err = e
            rows = []
    raise last_err


def preprocess(rows: list[dict]) -> list[dict]:
    """全行にプロセス関連フィールドを付与。"""
    result = []
    for row in rows:
        proc = extract_process_fields(row)
        out = {col: "" for col in OUTPUT_COLS}
        out["LineNo"] = str(row.get("_LineNo", ""))
        out["Timestamp"] = row.get("Timestamp", "")
        out["Channel"] = row.get("Channel", "")
        out["EventID"] = row.get("EventID", "")
        out["Computer"] = row.get("Computer", "")
        out["RecordID"] = row.get("RecordID", "")
        out["RuleTitle"] = row.get("RuleTitle", "")
        out["Level"] = row.get("Level", "")
        for k, v in proc.items():
            if k in out:
                out[k] = v
        result.append(out)
    return result


def save_csv(rows: list[dict], path: Path) -> None:
    """CSVに保存。"""
    if not rows:
        return
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUTPUT_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="ログCSVを前処理し、PID/Proc等を列にしたCSVを出力")
    ap.add_argument("-i", "--input", default="T1615_add.csv", help="入力ログCSV")
    ap.add_argument("-o", "--output", default=None, help="出力CSV（未指定時: <input>_preprocessed.csv）")
    args = ap.parse_args()

    inp = Path(args.input)
    if not inp.exists():
        print(f"エラー: 入力が見つかりません: {inp}", file=sys.stderr)
        return 1

    out_path = Path(args.output) if args.output else inp.parent / f"{inp.stem}_preprocessed.csv"

    print(f"入力: {inp}")
    rows = load_csv(inp)
    print(f"読み込み: {len(rows)} 行")

    preprocessed = preprocess(rows)
    save_csv(preprocessed, out_path)
    print(f"出力: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
