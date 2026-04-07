攻撃コマンドをdata/input/攻撃レポート.txtに直張り
python suggest_keywords.py -o T1615_Atomic4
python consolidate_output_to_excel.py



# ログ解析ツール（乾燥環境）

## フォルダ構成

```
├── run_pipeline.py     # 一気通貫（ルートのみ実行）
├── suggest_keywords.py # 攻撃レポート→検索ワード候補生成→パイプライン実行（OpenAI API）
├── config.json         # 候補数 num_keywords（デフォルト5、1〜20）
├── api_key.txt         # OpenAI APIキーを1行で（貼って使う。gitignore推奨）
├── api_key.txt.example
├── scripts/            # サブスクリプト
│   ├── preprocess_logs.py
│   ├── extract_logs.py
│   ├── trace_processes.py
│   └── export_excel_format.py
├── data/
│   ├── input/          # 生ログCSV（入力）
│   ├── output/         # 出力（実行ごとに output/<名前>/ フォルダができ、TSVとレポートが入る）
│   │                   # consolidate_output_to_excel.py で全TSVを1Excelに集約 → consolidated.xlsx
│   ├── reference/      # 参照用（出力想定.csv等）
│   └── T1615/          # 元データ
└── debug/              # 中間出力（前処理・抽出・追跡）
```

## 概要

- **run_pipeline.py**: 一気通貫（生ログ + 検索ワード → 出力想定形式TSV、中間は debug/ に保存）
- **suggest_keywords.py**: 攻撃レポートからLLMが検索ワード候補を生成し、パイプラインを実行。候補数は `config.json` の `num_keywords` で指定（デフォルト5）
- **scripts/**: サブスクリプト（preprocess, extract, trace, export）

## セットアップ（初回のみ）

```bash
# 仮想環境の作成
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux

# 検索ワード候補生成（suggest_keywords.py）を使う場合
pip install -r requirements.txt
```

**APIキー（suggest_keywords.py 用）**

- **方法1**: プロジェクト直下に `api_key.txt` を作成し、1行目にOpenAI APIキーを貼って保存  
  （`api_key.txt.example` をコピーしてリネームし、中身をキーに差し替え）
- **方法2**: 環境変数 `OPENAI_API_KEY` を設定  
  `export OPENAI_API_KEY='sk-...'`  
※ `api_key.txt` は .gitignore 済みです（コミットしない）。

## 使い方

### 一気通貫（推奨）

**入力**: `data/input/T1615_add.csv`（デフォルト）と検索ワード（1つ以上）  
**出力**: `data/output/` にワードごとのTSV  
**中間**: すべて `debug/` に保存

```bash
source .venv/bin/activate
# 単一ワード
python run_pipeline.py "gpresult"
# 複数ワード（前処理は1回だけ、各ワードで抽出→追跡→出力）
python run_pipeline.py "gpresult" "cmd" "explorer"
```

- **単一ワード**: 出力は `data/output/<stem>_出力想定形式.tsv`
- **複数ワード**: 出力は `data/output/<stem>_<ワード>_出力想定形式.tsv` がワードごとにできる
- `-i` で入力CSVを指定（デフォルト: `data/input/T1615_add.csv`）
- `-o` で出力TSVを指定（単一ワード時のみ有効）
- `-d` で中間出力フォルダを変更（デフォルト: `debug`）
- `-c` で大文字小文字を区別

### 検索ワード候補をLLMで生成してから実行

**出力名だけ指定すれば実行される。**

```bash
source .venv/bin/activate
pip install -r requirements.txt   # 初回のみ（openai）

# APIキーを api_key.txt に貼ったうえで、出力名を指定して実行
python suggest_keywords.py -o T1615_Atomic2
```

- レポートは `data/input/攻撃レポート.txt`、入力CSVは `data/input/T1615_add.csv` を自動で使用
- 出力は **実行ごとにフォルダ** `data/output/T1615_Atomic2/` が作られ、その中にワードごとのTSVとレポートが入る
  - 例: `data/output/T1615_Atomic2/T1615_Atomic2_gpresult_出力想定形式.tsv`、`data/output/T1615_Atomic2/レポート.md`
- 候補数は `config.json` の `num_keywords` で指定（1〜20、デフォルト5）
- 実行後、各検索ワードが「攻撃の印として妥当か」をAIが判定した **妥当性レポート** を同フォルダ内の `レポート.md` に保存する

### ステップ別（従来）

```bash
source .venv/bin/activate

# 1. 前処理
python scripts/preprocess_logs.py -i data/input/T1615_add.csv -o debug/T1615_add_preprocessed.csv

# 2. キーワードで抽出
python scripts/extract_logs.py "gpresult" -i debug/T1615_add_preprocessed.csv -o debug/T1615_gpresult_extracted.csv

# 3. 親子プロセスを追跡
python scripts/trace_processes.py -e debug/T1615_gpresult_extracted.csv -f debug/T1615_add_preprocessed.csv -o debug/T1615_gpresult_extracted_traced.csv

# 4. 出力想定形式でExcel用TSV出力
python scripts/export_excel_format.py -t debug/T1615_gpresult_extracted_traced.csv -r data/input/T1615_add.csv -o data/output/T1615_add_出力想定形式.tsv
```

### preprocess_logs.py の出力列

| 列 | 用途 |
|----|------|
| LineNo | 元ファイルの行番号 |
| PID, ParentPID | プロセスID（PID=, ParentPID= 検索用） |
| PGUID, ParentPGUID | Sysmon ProcessGuid |
| Proc, ParentImage | 実行イメージパス |
| CommandLine | コマンドライン |
| SrcPID, TgtPID | Sysmon 10 用 |

### trace_processes.py（親子プロセス追跡）

抽出ログから親子プロセスを追跡し、`explorer.exe(6700)→cmd.exe(3944)→gpresult.exe(7048)` 形式でCSV出力。

```bash
python scripts/trace_processes.py -e debug/T1615_gpresult_extracted.csv -f debug/T1615_add_preprocessed.csv
```

**出力:**
- `<extracted>_traced.csv` … 抽出ログに ProcessChain 列を付与
- `<extracted>_traced_summary.csv` … チェーン文字列・関連PID数・行数サマリ

### export_excel_format.py（出力想定形式でExcel用TSV）

traced CSV と生ログから、出力想定.csv 形式のTSVを生成（Excelでそのまま開く想定）。

```bash
python scripts/export_excel_format.py -t debug/T1615_gpresult_extracted_traced.csv -r data/input/T1615_add.csv -o data/output/T1615_add_出力想定形式.tsv
```

**出力列:** code, Technique, Test name, Attak cmd（ProcessChain）, LineNo in file, TimeStamp, Rule Title, Level, Links, Channel, EventID, msg, ExtraFieldInfo

## オプション

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `keyword` | 検索キーワード（必須） | - |
| `-i, --input` | 入力ログCSV | data/input/T1615_add.csv |
| `-o, --output` | 出力CSV | `<input>_<keyword>_extracted.csv` |
| `-c, --case-sensitive` | 大文字小文字を区別 | しない |

## 検索対象カラム

- Details（Cmdline, Proc, PID 等を含む）
- ExtraFieldInfo（ParentProcessName, ProcessId 等を含む）
- RuleTitle
- Timestamp
- Links

## 最終整形: TSVを1つのExcelに集約

目視で不要なTSVを削除したあと、各フォルダのTSVを1つのExcelにまとめる。

```bash
pip install openpyxl   # 初回のみ
python consolidate_output_to_excel.py
```

- **入力**: `data/output/` 内の各サブフォルダ（T1615_Atomic1, T1615_Atomic2 など）内の `*.tsv`
- **出力**: `data/output/consolidated.xlsx`
- **仕様**: フォルダごとにシート（タブ）を作成。同一行（`LineNo in file` が同じ）は1行にまとめ、検索ワード（code）は**ファイル名の若い順で最初に出現したTSVの値**を採用。

## 出力

- `code` 列: 検索ラベル（例: `gpresult /zで検索`）
- `LineNo in file`: 元ファイルの行番号
- その他元CSVの全カラム
