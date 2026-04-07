#!/usr/bin/env python3
"""
攻撃レポートから検索ワードを生成し、パイプラインを実行する。
候補数は config.json の num_keywords で指定（デフォルト5）。

使い方: python suggest_keywords.py -o 出力名
  例: python suggest_keywords.py -o T1615_Atomic2
  レポート: data/input/攻撃レポート.txt / 入力CSV: data/input/T1615_add.csv を自動使用。
APIキー: 環境変数 OPENAI_API_KEY または api_key.txt
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

CONFIG_PATH = "config.json"
DEFAULT_NUM_KEYWORDS = 5

# 概算コスト用（USD per 1M tokens）。モデル追加時はここを更新
MODEL_PRICE_PER_1M = {
    "gpt-5.2": (2.50, 10.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4-turbo": (10.00, 30.00),
}


def estimate_cost(prompt_tokens: int, completion_tokens: int, model: str) -> float:
    """入力・出力トークンから概算コスト（USD）を算出。"""
    price = MODEL_PRICE_PER_1M.get(model) or MODEL_PRICE_PER_1M.get("gpt-5.2", (2.50, 10.00))
    input_1m, output_1m = price
    return (prompt_tokens / 1_000_000 * input_1m) + (completion_tokens / 1_000_000 * output_1m)


def load_config(base_dir: Path) -> dict:
    """config.json を読む。無ければデフォルトのみ返す。"""
    path = base_dir / CONFIG_PATH
    out = {"num_keywords": DEFAULT_NUM_KEYWORDS, "input_csv": "data/input/T1615_add.csv"}
    if not path.exists():
        return out
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        n = data.get("num_keywords", DEFAULT_NUM_KEYWORDS)
        out["num_keywords"] = max(1, min(20, int(n)))
        if "input_csv" in data and data["input_csv"]:
            out["input_csv"] = data["input_csv"].strip()
    except Exception:
        pass
    return out


# APIキー取得: 環境変数 → api_key.txt
def get_api_key(base_dir: Path) -> str:
    import os
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if key:
        return key
    key_file = base_dir / "api_key.txt"
    if key_file.exists():
        key = key_file.read_text(encoding="utf-8").strip().split("\n")[0].strip()
        if key and "YOUR_" not in key and "ここに" not in key:
            return key
    return ""


def safe_keyword(s: str) -> str:
    """ファイル名に使うための安全な文字列（run_pipeline と同一）"""
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s).strip("_") or "search"


def build_prompt(text: str, num_keywords: int) -> str:
    n = num_keywords
    return f"""以下の攻撃実行結果レポートに記載されている**実行コマンド**を起点に、
イベントログ（Sysmon/Security）検索用の「検索ワード」を{n}つ提案してください。

【方針】
- **コマンド起点**: レポート内のコマンドライン・PowerShell・スクリプト実行をまず洗い出す
- **短い語を最優先（重要）**: ログに「含まれそうな」内容は、**長い一致文字列ではなく短いトークン**で検索する
  - 長いコマンド行・長いパス・長いBase64断片をそのまま1語にしない
  - 代わりに、その中に含まれる**最小の特徴的な語**に落とす（例: 実行体名のみ、コマレット1語、メソッド名、スイッチ1つ、スクリプトのファイル名のみ）
- **長さの目安**: 原則として各ワードは **3〜40文字程度**、単語・短いフレーズに留める（スペース区切りでも2〜3語まで）
- **具体例（良い）**: gpresult.exe, Invoke-WebRequest, DownloadString, -EncodedCommand, schtasks, mshta
- **具体例（避ける）**: コマンド全体のコピー、数十文字を超える1連の文字列、フルパス全体
- **複数パターン**: 同じ攻撃から「実行体名」「コマレット」「メソッド名」など、**別々の短い切り口**で{n}つ出す
- 英語のまま・短く具体的に。1行1つ。先頭に番号や記号は付けない
- 必ず{n}つ、1行に1つで出力する

攻撃レポート:
---
{text}
---

上記の方針に従い、**短くログに含まれやすい検索ワード**を{n}つ、1行1つで出力してください。"""


REPORT_SYSTEM = """あなたはWindowsイベントログ解析と攻撃検知の専門家です。
与えられた「攻撃レポート」と「検索ワードごとのヒット数」をもとに、
各検索ワードが「この攻撃の印（IOC/ログ上の痕跡）として妥当か」を分析し、
第三者に提出できるレポート品質のMarkdownを書いてください。
簡潔さより、根拠と解釈が分かる丁寧な記述を心がけてください。"""


def build_report_prompt(attack_text: str, keyword_results: list[tuple[str, int]]) -> str:
    lines = [
        "## 攻撃レポート（抜粋）",
        "```",
        attack_text[:3000].strip(),
        "```",
        "",
        "## 検索結果（ワードごとのヒット数）",
        "| 検索ワード | ヒット数 |",
        "|------------|----------|",
    ]
    for kw, count in keyword_results:
        lines.append(f"| {kw} | {count} |")
    lines.extend([
        "",
        "---",
        "",
        "上記を踏まえ、以下の構成で**分析レポート**を出力してください。簡潔にまとめるのではなく、",
        "「なぜその判定になるか」「ログ調査の文脈でどう解釈すべきか」が伝わるよう、しっかり書いてください。",
        "",
        "## 出力するレポートの構成",
        "",
        "### 1. 目的・対象（見出し: ## 1. 目的・対象）",
        "- このレポートの目的（何を検証したか）を1〜2文で述べる。",
        "- 対象とした攻撃の概要を、攻撃レポートの内容に基づき2〜4文で要約する。",
        "",
        "### 2. 検索結果一覧（見出し: ## 2. 検索結果一覧）",
        "- 検索ワードとヒット数を表で示す。",
        "- 必要に応じて、ヒット数が0のワードと1以上のワードを分けて言及する。",
        "",
        "### 3. 各検索ワードの分析（見出し: ## 3. 各検索ワードの分析）",
        "- **検索ワードごとに**小見出し（### 検索ワード名）を付け、以下を書く：",
        "  - **判定**: 妥当 / 限定的 / 妥当でない のいずれか。",
        "  - **根拠**: その判定に至った理由を2〜4文で説明する（ヒット数だけではなく、そのワードが攻撃特有かどうか、一般的な処理でも出るかどうかなど）。",
        "  - **ログ調査上の解釈**: このワードでヒットした場合、インシデント調査でどう扱うべきか（優先して確認すべきか、補助的な情報か、ノイズの可能性か）を1〜2文で述べる。",
        "",
        "### 4. 総括と推奨（見出し: ## 4. 総括と推奨）",
        "- 本攻撃の印として、どの検索ワードが特に有用か（または有用でないか）をまとめる（3〜5文）。",
        "- 今後の調査やアラート化を検討する際のポイントがあれば2〜3文で記載する。",
        "",
        "---",
        "出力はMarkdownのみとし、大見出しは「# 検索ワード妥当性レポート」から始めてください。",
    ])
    return "\n".join(lines)


def generate_report(
    base_dir: Path,
    output_stem: str,
    keywords: list[str],
    attack_text: str,
    client,  # OpenAI
    model: str,
) -> tuple[Optional[str], dict]:
    """各ワードのヒット数を集計し、AIで妥当性判定レポートを生成して保存。戻り値は (保存パスまたはNone, トークン使用量)。"""
    out_dir = base_dir / "data" / "output" / output_stem
    keyword_results = []
    for kw in keywords:
        safe = safe_keyword(kw)
        tsv_path = out_dir / f"{output_stem}_{safe}_出力想定形式.tsv"
        if tsv_path.exists():
            try:
                n_lines = len(tsv_path.read_text(encoding="utf-8-sig").strip().splitlines())
                count = max(0, n_lines - 1)  # ヘッダー除く
            except Exception:
                count = 0
        else:
            count = 0
        keyword_results.append((kw, count))

    prompt = build_report_prompt(attack_text, keyword_results)
    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": REPORT_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        content = (resp.choices[0].message.content or "").strip()
        if getattr(resp, "usage", None):
            usage["prompt_tokens"] = getattr(resp.usage, "prompt_tokens", 0) or 0
            usage["completion_tokens"] = getattr(resp.usage, "completion_tokens", 0) or 0
    except Exception as e:
        print(f"レポート生成でAPIエラー: {e}", file=sys.stderr)
        return None, usage

    report_path = out_dir / "レポート.md"
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(content, encoding="utf-8")
    except Exception as e:
        print(f"レポート保存エラー: {e}", file=sys.stderr)
        return None, usage
    return str(report_path), usage


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    config = load_config(base_dir)
    ap = argparse.ArgumentParser(
        description="攻撃レポートから検索ワードを生成しパイプラインを実行。候補数・入力CSVは config.json で指定可能。"
    )
    ap.add_argument(
        "-i", "--input-csv",
        default=config["input_csv"],
        metavar="CSV",
        help="入力ログCSV（デフォルト: config.json の input_csv または data/input/T1615_add.csv）",
    )
    ap.add_argument(
        "-o", "--output-name",
        default=None,
        metavar="NAME",
        help="出力フォルダ名（省略時は入力CSVのファイル名。例: -i T1572_add.csv → data/output/T1572_add/）",
    )
    ap.add_argument(
        "report",
        nargs="?",
        default="data/input/攻撃レポート.txt",
        help=argparse.SUPPRESS,
    )
    ap.add_argument(
        "--model",
        default="gpt-5.2",
        help=argparse.SUPPRESS,
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = ap.parse_args()
    args.run = True  # 実行モード
    if args.output_name is None:
        args.output_name = Path(args.input_csv).stem

    num_keywords = config["num_keywords"]

    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = base_dir / report_path
    if not report_path.exists():
        print(f"エラー: レポートファイルが見つかりません: {report_path}", file=sys.stderr)
        print("APIキーは api_key.txt に1行で貼るか、環境変数 OPENAI_API_KEY を設定してください。", file=sys.stderr)
        return 1

    text = report_path.read_text(encoding="utf-8").strip()
    if not text:
        print("エラー: レポートが空です。", file=sys.stderr)
        print(f"  読み込んだファイル: {report_path}", file=sys.stderr)
        print("  攻撃レポートのテキストをこのファイルに保存するか、別ファイルを第1引数で指定してください。", file=sys.stderr)
        return 1

    if args.dry_run:
        print("# 以下のコマンドで検索ワード候補を生成し、run_pipeline 用コマンドを出します")
        print(f"python suggest_keywords.py \"{report_path.name}\"")
        return 0

    api_key = get_api_key(base_dir)
    if not api_key:
        print("エラー: APIキーが設定されていません。", file=sys.stderr)
        print("  - 環境変数: export OPENAI_API_KEY='sk-...'", file=sys.stderr)
        print("  - または api_key.txt を用意し、1行目にAPIキーを貼って保存してください。", file=sys.stderr)
        return 1

    try:
        from openai import OpenAI
    except ImportError:
        print("エラー: openai パッケージがありません。pip install openai を実行してください。", file=sys.stderr)
        return 1

    client = OpenAI(api_key=api_key)
    prompt = build_prompt(text[:8000], num_keywords)  # 長いレポートは先頭のみ

    total_prompt = 0
    total_completion = 0

    print(f"検索ワード候補を生成中（候補数: {num_keywords}）...", file=sys.stderr)
    try:
        resp = client.chat.completions.create(
            model=args.model,
            messages=[
                {"role": "system", "content": f"あなたはWindowsイベントログ解析の専門家です。攻撃レポート内の実行コマンドを起点に検索ワードを考えます。長いコマンド断片やフルパスは避け、ログに含まれるであろう内容は**短いトークン**（実行体名・コマレット1語・メソッド名など）に分解して優先する。各ワードは短く（目安3〜40文字、2〜3語まで）、{num_keywords}つを1行1つで出力する。"},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        content = (resp.choices[0].message.content or "").strip()
        if getattr(resp, "usage", None):
            total_prompt += getattr(resp.usage, "prompt_tokens", 0) or 0
            total_completion += getattr(resp.usage, "completion_tokens", 0) or 0
    except Exception as e:
        print(f"APIエラー: {e}", file=sys.stderr)
        return 1

    # N行としてパース（番号・箇条書きを除去。長いプレフィックスを先に試す）
    number_prefixes = [p for i in range(1, num_keywords + 1) for p in (f"{i}.", f"{i})")]
    number_prefixes = sorted(number_prefixes, key=len, reverse=True)
    other_prefixes = ("- ", "・", "* ")
    keywords = []
    for line in content.splitlines():
        line = line.strip()
        for prefix in (*number_prefixes, *other_prefixes):
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
                break
        if line and len(keywords) < num_keywords:
            keywords.append(line)
    keywords = keywords[:num_keywords]

    if not keywords:
        print("エラー: 候補が取得できませんでした。", file=sys.stderr)
        print(content, file=sys.stderr)
        return 1

    # コマンド用にエスケープ（シェルで安全にするためダブルクォート内は " を \" に）
    escaped = []
    for k in keywords:
        k = k.replace("\\", "\\\\").replace('"', '\\"')
        escaped.append(f'"{k}"')

    # オプションを先に、キーワードは -- の後に渡す（-UseBasicParsing 等がオプションと解釈されないように）
    run_args = ["python", "run_pipeline.py", "-i", args.input_csv]
    if args.output_name:
        run_args += ["-O", args.output_name]
    run_args += ["--"] + keywords
    cmd = f"python run_pipeline.py -i {args.input_csv}"
    if args.output_name:
        cmd += f" -O {args.output_name}"
    cmd += " -- " + " ".join(escaped)
    print(cmd)

    if args.run:
        import subprocess
        r = subprocess.run(run_args, cwd=str(base_dir))
        if r.returncode != 0:
            return r.returncode
        # パイプライン成功後、検索ワードごとの妥当性を判定してレポート化
        print("妥当性レポートを生成中...", file=sys.stderr)
        report_file, report_usage = generate_report(
            base_dir, args.output_name, keywords, text, client, args.model
        )
        if report_file:
            print(f"レポート保存: {report_file}", file=sys.stderr)
        total_prompt += report_usage.get("prompt_tokens", 0)
        total_completion += report_usage.get("completion_tokens", 0)

        cost_usd = estimate_cost(total_prompt, total_completion, args.model)
        print("", file=sys.stderr)
        print("--- 今回の解析（API利用）---", file=sys.stderr)
        print(f"  入力トークン: {total_prompt:,} / 出力トークン: {total_completion:,} / 合計: {total_prompt + total_completion:,}", file=sys.stderr)
        print(f"  概算コスト: ${cost_usd:.4f} USD（モデル: {args.model}）", file=sys.stderr)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
