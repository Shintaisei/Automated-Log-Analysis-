#!/usr/bin/env python3
"""
一気通貫パイプライン: 生ログCSV + 検索ワード（複数可） → 出力想定形式TSV

入力: data/input/T1615_add.csv（または -i で指定）, 検索ワードを1つ以上指定
出力: data/output/ にワードごとのTSV（単一ワード時は <stem>_出力想定形式.tsv、複数時は <stem>_<ワード>_出力想定形式.tsv）
中間: debug/ に preprocessed / extracted / traced を保存
"""

import argparse
import subprocess
import sys
from pathlib import Path


def safe_keyword(s: str) -> str:
    """ファイル名に使うための安全な文字列"""
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s).strip("_") or "search"


def run_cmd(base_dir: Path, name: str, cmd: list) -> int:
    """1ステップ実行。戻り値は exit code。"""
    print(f"--- {name}: {' '.join(cmd[1:])}")
    r = subprocess.run(cmd, cwd=str(base_dir))
    return r.returncode


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(
        description="生ログCSVと検索ワード（複数可）から出力想定形式TSVまで一括実行（中間はdebug/に保存）"
    )
    ap.add_argument(
        "keywords",
        nargs="+",
        help="検索ワードを1つ以上（例: gpresult cmd explorer）",
    )
    ap.add_argument(
        "-i",
        "--input",
        default="data/input/T1615_add.csv",
        help="入力ログCSV（デフォルト: data/input/T1615_add.csv）",
    )
    ap.add_argument(
        "-o",
        "--output",
        default=None,
        help="最終出力TSV（単一ワード時のみ有効。複数ワード時は無視され data/output/<stem>_<ワード>_出力想定形式.tsv になる）",
    )
    ap.add_argument(
        "-O",
        "--output-stem",
        default=None,
        help="出力TSVのファイル名に使うベース名（未指定時は入力CSVのstem）。例: -O T1615_Atomic2 → data/output/T1615_Atomic2_<ワード>_出力想定形式.tsv",
    )
    ap.add_argument(
        "-d",
        "--debug-dir",
        default="debug",
        help="中間出力フォルダ（デフォルト: debug）",
    )
    ap.add_argument(
        "-c",
        "--case-sensitive",
        action="store_true",
        help="検索で大文字小文字を区別",
    )
    args = ap.parse_args()

    inp = Path(args.input)
    if not inp.is_absolute():
        inp = base_dir / inp
    if not inp.exists():
        print(f"エラー: 入力ファイルが見つかりません: {inp}", file=sys.stderr)
        return 1

    debug_dir = base_dir / args.debug_dir
    debug_dir.mkdir(parents=True, exist_ok=True)
    stem = inp.stem
    out_stem = (args.output_stem or stem).strip()
    if not out_stem:
        out_stem = stem
    # 実行ごとに data/output/<出力名>/ フォルダを作り、その中にTSVを出す
    out_dir = base_dir / "data" / "output" / out_stem
    out_dir.mkdir(parents=True, exist_ok=True)
    scripts_dir = base_dir / "scripts"

    # 前処理は1回だけ
    preprocessed = debug_dir / f"{stem}_preprocessed.csv"
    if run_cmd(base_dir, "前処理", [
        sys.executable, str(scripts_dir / "preprocess_logs.py"),
        "-i", str(inp), "-o", str(preprocessed),
    ]) != 0:
        print("エラー: 前処理で失敗", file=sys.stderr)
        return 1

    # ワードごとに 抽出 → 追跡 → Excel形式出力
    case_flag = ["-c"] if args.case_sensitive else []
    single = len(args.keywords) == 1

    for keyword in args.keywords:
        safe_kw = safe_keyword(keyword)
        extracted = debug_dir / f"{stem}_{safe_kw}_extracted.csv"
        traced = debug_dir / f"{stem}_{safe_kw}_extracted_traced.csv"
        if single and args.output:
            out_tsv = Path(args.output)
            if not out_tsv.is_absolute():
                out_tsv = base_dir / out_tsv
            out_tsv.parent.mkdir(parents=True, exist_ok=True)
        else:
            out_tsv = out_dir / f"{out_stem}_{safe_kw}_出力想定形式.tsv"

        print(f"\n[検索ワード: {keyword}]")
        if run_cmd(base_dir, "抽出", [
            sys.executable, str(scripts_dir / "extract_logs.py"), keyword,
            "-i", str(preprocessed), "-o", str(extracted),
        ] + case_flag) != 0:
            print(f"エラー: 抽出で失敗 (keyword={keyword})", file=sys.stderr)
            return 1
        if run_cmd(base_dir, "追跡", [
            sys.executable, str(scripts_dir / "trace_processes.py"),
            "-e", str(extracted), "-f", str(preprocessed), "-o", str(traced),
        ]) != 0:
            print(f"エラー: 追跡で失敗 (keyword={keyword})", file=sys.stderr)
            return 1
        if run_cmd(base_dir, "Excel形式出力", [
            sys.executable, str(scripts_dir / "export_excel_format.py"),
            "-t", str(traced), "-r", str(inp), "-o", str(out_tsv),
        ]) != 0:
            print(f"エラー: Excel形式出力で失敗 (keyword={keyword})", file=sys.stderr)
            return 1
        print(f"  → {out_tsv}")

    print(f"\n完了: 出力 → data/output/（{len(args.keywords)} 件）")
    print(f"中間: {debug_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
