#!/usr/bin/env python3
"""
プロセス追跡 - 抽出ログから親子プロセスを追跡し、explorer.exe(6700)→cmd.exe(3944) 形式で出力

入力: 抽出済みCSV（gpresult抽出等） + 前処理済みログ全体
出力: 追跡結果CSV（ProcessChain列付き）
"""

import argparse
import csv
import sys
from pathlib import Path
from typing import Optional


H_PARENT = 3   # 親方向の最大ホップ
H_CHILD = 2    # 子方向の最大ホップ
PROC_CREATE_EVENTS = ("4688", "1")  # Sec 4688, Sysmon 1


def proc_name(path: str) -> str:
    """フルパスから実行ファイル名を抽出。"""
    if not path or not isinstance(path, str):
        return ""
    return path.replace("\\", "/").split("/")[-1].strip() or path


def load_csv(path: Path) -> list[dict]:
    """CSV読み込み。"""
    rows = []
    encodings = ["utf-8-sig", "utf-8", "cp932", "shift_jis"]
    for enc in encodings:
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


def build_process_graph(rows: list[dict]) -> tuple[dict, dict]:
    """
    プロセス作成イベント（4688, 1）から PID→複数情報 と 親PID→子リスト を構築。
    同一PID再利用に対応（複数エントリを保持し、子のParentImageで照合時に選択）。
    """
    pid_to_infos: dict[int, list[dict]] = {}  # pid -> [{proc, parent_pid, parent_image, ts, row}, ...]
    children: dict[int, list[tuple[int, str]]] = {}  # parent_pid -> [(pid, proc), ...]

    for row in rows:
        eid = str(row.get("EventID", ""))
        if eid not in PROC_CREATE_EVENTS:
            continue
        pid_s = row.get("PID", "")
        ppid_s = row.get("ParentPID", "")
        proc = row.get("Proc", "")
        pimg = row.get("ParentImage", "")
        ts = row.get("Timestamp", "")
        if not pid_s:
            continue
        try:
            pid = int(pid_s)
        except (ValueError, TypeError):
            continue
        ppid = None
        if ppid_s:
            try:
                ppid = int(ppid_s)
            except (ValueError, TypeError):
                pass

        pname = proc_name(proc) or proc
        pinfo = {"proc": pname, "parent_pid": ppid, "parent_image": proc_name(pimg) or pimg, "ts": ts, "row": row}
        pid_to_infos.setdefault(pid, []).append(pinfo)
        if ppid is not None:
            children.setdefault(ppid, [])
            if (pid, pname) not in children[ppid]:
                children[ppid].append((pid, pname))

    return pid_to_infos, children


def pick_best_info(pid: int, pid_to_infos: dict, expected_parent_image: Optional[str]) -> Optional[dict]:
    """子のParentImageと一致する情報を優先。同一PID再利用に対応。"""
    infos = pid_to_infos.get(pid, [])
    if not infos:
        return None
    if len(infos) == 1:
        return infos[0]
    # 子が期待する ParentImage と Proc が一致するものを優先（exe名で比較）
    exp = proc_name(expected_parent_image or "").lower()
    if exp:
        for i in infos:
            p = (i.get("proc") or "").lower()
            if p and (exp in p or p in exp):
                return i
    # 複数ある場合は最も新しいタイムスタンプを採用
    infos_sorted = sorted(infos, key=lambda x: x.get("ts", ""), reverse=True)
    return infos_sorted[0]


def walk_parent_chain(
    pid: int, pid_to_infos: dict, max_hops: int = H_PARENT, child_parent_image: Optional[str] = None
) -> list[tuple[int, str]]:
    """親方向にたどり、(pid, proc_name) のリストを返す（root→leaf の順）。"""
    chain: list[tuple[int, str]] = []
    seen: set[int] = set()
    cur = pid
    expected_pimg: Optional[str] = child_parent_image
    for _ in range(max_hops):
        if cur in seen or cur is None:
            break
        seen.add(cur)
        info = pick_best_info(cur, pid_to_infos, expected_pimg)
        proc = info["proc"] if info else f"unknown({cur})"
        chain.append((cur, proc))
        expected_pimg = info.get("parent_image") if info else None  # 次に探す親のProcと一致させる
        cur = info.get("parent_pid") if info else None
    chain.reverse()  # root→leaf に並び替え
    return chain


def walk_child_chain(pid: int, children: dict, max_hops: int = H_CHILD) -> set[tuple[int, str]]:
    """子方向にたどり、(pid, proc_name) の集合を返す。"""
    result: set[tuple[int, str]] = set()
    frontier = [(pid, 0)]
    seen: set[int] = set()
    while frontier:
        cur, depth = frontier.pop(0)
        if depth >= max_hops or cur in seen:
            continue
        seen.add(cur)
        for child_pid, child_proc in children.get(cur, []):
            if child_pid in seen:
                continue
            result.add((child_pid, child_proc))
            frontier.append((child_pid, depth + 1))
    return result


def chain_to_string(chain: list[tuple[int, str]]) -> str:
    """(pid, proc) リストを explorer.exe(6700)→cmd.exe(3944) 形式に。"""
    return "→".join(f"{p}({pid})" for pid, p in chain if p)


def collect_seed_pids(rows: list[dict]) -> set[int]:
    """抽出CSVからシードPIDを収集。"""
    pids: set[int] = set()
    for row in rows:
        for col in ("PID", "ParentPID", "SrcPID", "TgtPID"):
            v = row.get(col, "")
            if v:
                try:
                    pids.add(int(v))
                except (ValueError, TypeError):
                    pass
    return pids


def trace(
    extracted_rows: list[dict],
    full_rows: list[dict],
    h_parent: int = H_PARENT,
    h_child: int = H_CHILD,
) -> tuple[str, set[int], list[dict]]:
    """
    抽出ログから親子を追跡し、(メインチェーン文字列, 関連PID集合, 関連ログ行) を返す。
    """
    pid_to_infos, children = build_process_graph(full_rows)
    seed_pids = collect_seed_pids(extracted_rows)

    all_related: set[tuple[int, str]] = set()
    main_chain: list[tuple[int, str]] = []

    # シードのうち最も深い（子に近い＝数値が大きい）ものを優先してメインチェーンを構築
    for pid in sorted(seed_pids, reverse=True):
        chain = walk_parent_chain(pid, pid_to_infos, h_parent, child_parent_image=None)
        for p, proc in chain:
            all_related.add((p, proc))
        for p, proc in walk_child_chain(pid, children, h_child):
            all_related.add((p, proc))
        # より長いチェーンを優先（ルート→リーフにシードを含む）
        if len(chain) > len(main_chain):
            main_chain = chain

    # メインチェーンが空ならシードをそのまま使う
    if not main_chain and seed_pids:
        for pid in sorted(seed_pids):
            info = pick_best_info(pid, pid_to_infos, None)
            proc = info.get("proc", f"pid_{pid}") if info else f"pid_{pid}"
            main_chain.append((pid, proc))
            all_related.add((pid, proc))

    # チェーン末尾にシードが含まれていない場合は、代表シードを追加
    chain_pids = {p for p, _ in main_chain}
    for pid in sorted(seed_pids, reverse=True):
        if pid not in chain_pids:
            info = pick_best_info(pid, pid_to_infos, None)
            proc = info.get("proc", f"pid_{pid}") if info else f"pid_{pid}"
            main_chain.append((pid, proc))
            all_related.add((pid, proc))
            chain_pids.add(pid)
        break  # 代表シード1つ追加

    chain_str = chain_to_string(main_chain) if main_chain else ""
    related_pids = {p for p, _ in all_related}

    # 出力は抽出ログが主役。ProcessChain（起動元）は参考情報として付与するだけ
    related_rows = []
    for row in extracted_rows:
        r = dict(row)
        r["ProcessChain"] = chain_str
        related_rows.append(r)

    return chain_str, related_pids, related_rows


def main() -> int:
    ap = argparse.ArgumentParser(description="抽出ログから親子プロセスを追跡し、ProcessChain付きCSVを出力")
    ap.add_argument("-e", "--extracted", required=True, help="抽出済みCSV（例: T1615_preprocessed_gpresult_extracted.csv）")
    ap.add_argument("-f", "--full", required=True, help="前処理済みログ全体（例: T1615_add_preprocessed.csv）")
    ap.add_argument("-o", "--output", default=None, help="出力CSV（未指定時: <extracted>_traced.csv）")
    ap.add_argument("--parent-hops", type=int, default=H_PARENT, help="親方向の最大ホップ")
    ap.add_argument("--child-hops", type=int, default=H_CHILD, help="子方向の最大ホップ")
    args = ap.parse_args()

    ext_path = Path(args.extracted)
    full_path = Path(args.full)
    if not ext_path.exists():
        print(f"エラー: 抽出ファイルが見つかりません: {ext_path}", file=sys.stderr)
        return 1
    if not full_path.exists():
        print(f"エラー: 前処理ログが見つかりません: {full_path}", file=sys.stderr)
        return 1

    out_path = Path(args.output) if args.output else ext_path.parent / f"{ext_path.stem}_traced.csv"

    print(f"抽出: {ext_path}")
    print(f"全体: {full_path}")

    extracted = load_csv(ext_path)
    full = load_csv(full_path)
    print(f"抽出行数: {len(extracted)}, 全体行数: {len(full)}")

    chain_str, related_pids, related_rows = trace(
        extracted, full,
        h_parent=args.parent_hops,
        h_child=args.child_hops,
    )

    print(f"ProcessChain: {chain_str}")
    print(f"出力行数: {len(related_rows)}（抽出ログ + ProcessChain）")

    if not related_rows:
        print("ヒット0件のため、追跡結果は0行です。", file=sys.stderr)
        # 0件でもファイルを書き、後段の export が参照できるようにする
        fieldnames = ["ProcessChain", "code", "LineNo in file", "Timestamp", "RuleTitle", "Level", "Links", "Channel", "EventID", "Details", "ExtraFieldInfo", "Computer", "RecordID"]
    else:
        fieldnames = list(related_rows[0].keys())
        if "ProcessChain" not in fieldnames:
            fieldnames.insert(0, "ProcessChain")
    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(related_rows)

    print(f"出力: {out_path}")

    # サマリCSV（チェーンのみ）も出力
    summary_path = out_path.parent / f"{out_path.stem}_summary.csv"
    with open(summary_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ProcessChain", "RelatedPIDs", "RelatedRowCount"])
        w.writerow([chain_str or "（ヒット0件）", ",".join(map(str, sorted(related_pids))), len(related_rows)])
    print(f"サマリ: {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
