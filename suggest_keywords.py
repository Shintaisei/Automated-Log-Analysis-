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


def load_config(base_dir: Path) -> dict:
    """config.json を読む。無ければデフォルトのみ返す。"""
    path = base_dir / CONFIG_PATH
    if not path.exists():
        return {"num_keywords": DEFAULT_NUM_KEYWORDS}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        n = data.get("num_keywords", DEFAULT_NUM_KEYWORDS)
        n = max(1, min(20, int(n)))  # 1〜20にクランプ
        return {"num_keywords": n}
    except Exception:
        return {"num_keywords": DEFAULT_NUM_KEYWORDS}


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
- **コマンドの一部を最優先**: ログの CommandLine/Details に含まれやすい「コマンドの一部」を検索ワードにする
  - 例: 実行ファイル名（gpresult.exe, curl, powershell）、コマレット名（Get-DomainGPO, DownloadString）、
    スクリプト名（powerview.ps1）、引数やメソッド名（Net.WebClient, IEX）、パスの一部
- **複数パターン**: 同じコマンドから複数の候補を出す（例: フルコマンドの特徴部分、実行体名のみ、メソッド名のみ）
- 英語のまま・短く具体的に。1行1つ。先頭に番号や記号は付けない
- 必ず{n}つ、1行に1つで出力する

攻撃レポート:
---
{text}
---

上記の方針に従い、**コマンドの一部を優先した**検索ワードを{n}つ、1行1つで出力してください。"""


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
) -> Optional[str]:
    """各ワードのヒット数を集計し、AIで妥当性判定レポートを生成して保存。戻り値は保存パスまたはNone。"""
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
    except Exception as e:
        print(f"レポート生成でAPIエラー: {e}", file=sys.stderr)
        return None

    report_path = out_dir / "レポート.md"
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(content, encoding="utf-8")
    except Exception as e:
        print(f"レポート保存エラー: {e}", file=sys.stderr)
        return None
    return str(report_path)


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(
        description="攻撃レポートから検索ワードを生成しパイプラインを実行。候補数は config.json の num_keywords で指定。"
    )
    ap.add_argument(
        "-o", "--output-name",
        required=True,
        metavar="NAME",
        help="出力TSVのベース名（必須）。例: T1615_Atomic2 → data/output/T1615_Atomic2_<ワード>_出力想定形式.tsv ができる",
    )
    ap.add_argument(
        "report",
        nargs="?",
        default="data/input/攻撃レポート.txt",
        help=argparse.SUPPRESS,
    )
    ap.add_argument(
        "-i", "--input-csv",
        default="data/input/T1615_add.csv",
        help=argparse.SUPPRESS,
    )
    ap.add_argument(
        "--model",
        default="gpt-4o",
        help=argparse.SUPPRESS,
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = ap.parse_args()
    args.run = True  # -o 指定時は常に実行

    config = load_config(base_dir)
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

    print(f"検索ワード候補を生成中（候補数: {num_keywords}）...", file=sys.stderr)
    try:
        resp = client.chat.completions.create(
            model=args.model,
            messages=[
                {"role": "system", "content": f"あなたはWindowsイベントログ解析の専門家です。攻撃レポート内の実行コマンドを起点に、複数パターンの検索ワードを考えます。特にコマンドの一部（実行体名・コマレット・メソッド名・スクリプト名など）をログ検索ワードとして優先し、{num_keywords}つを1行1つで出力します。"},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        content = (resp.choices[0].message.content or "").strip()
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

    run_args = ["python", "run_pipeline.py"] + keywords + ["-i", args.input_csv]
    if args.output_name:
        run_args += ["-O", args.output_name]
    cmd = f"python run_pipeline.py {' '.join(escaped)} -i {args.input_csv}"
    if args.output_name:
        cmd += f" -O {args.output_name}"
    print(cmd)

    if args.run:
        import subprocess
        r = subprocess.run(run_args, cwd=str(base_dir))
        if r.returncode != 0:
            return r.returncode
        # パイプライン成功後、検索ワードごとの妥当性を判定してレポート化
        print("妥当性レポートを生成中...", file=sys.stderr)
        report_file = generate_report(
            base_dir, args.output_name, keywords, text, client, args.model
        )
        if report_file:
            print(f"レポート保存: {report_file}", file=sys.stderr)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
