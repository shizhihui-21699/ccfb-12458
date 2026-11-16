#!/usr/bin/env python3
"""命令行入口：扫描、导出、启动 Web。

用法：
  python -m crypto_inventory.cli scan   [ROOT] [--db PATH]
  python -m crypto_inventory.cli export [ROOT] --format cyclonedx|csv|summary -o FILE
  python -m crypto_inventory.cli web    [--host 127.0.0.1] [--port 5000] [ROOT]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .exporter import to_csv, to_cyclonedx, to_summary_csv, dump_json
from .inventory import scan_system, scan_workspace
from .store import Store


def _resolve_root(arg: str | None) -> Path:
    default = Path(__file__).resolve().parents[1] / "samples"
    return Path(arg).resolve() if arg else default


def cmd_scan(a: argparse.Namespace) -> int:
    root = _resolve_root(a.root)
    store = Store(a.db) if a.db else None
    inventories = scan_workspace(root) if root.is_dir() else [scan_system(root)]
    for inv in inventories:
        r = inv.readiness
        print(f"\n=== {inv.system} ===")
        print(f"  发现 {len(inv.findings)} 条 | 综合 {r.overall} ({r.level_cn}) | "
              f"经典 {r.classic_score} | PQ {r.pq_score}")
        print(f"  严重度 {r.by_severity}")
        print(f"  PQ 状态 {r.by_pq_status}")
        weak = sorted({f.algorithm for f in inv.findings if f.weak})
        if weak:
            print(f"  弱用法算法: {', '.join(weak)}")
        if store:
            sid = store.save_scan(inv)
            print(f"  已持久化 scan_id={sid}")
    return 0


def cmd_export(a: argparse.Namespace) -> int:
    root = _resolve_root(a.root)
    inventories = scan_workspace(root) if root.is_dir() else [scan_system(root)]
    if a.format == "cyclonedx":
        content = dump_json(to_cyclonedx(inventories))
    elif a.format == "csv":
        content = to_csv(inventories)
    else:
        content = to_summary_csv(inventories)
    if a.output:
        Path(a.output).write_text(content, encoding="utf-8")
        print(f"已写入 {a.output}（{len(content)} 字节）")
    else:
        sys.stdout.write(content)
    return 0


def cmd_web(a: argparse.Namespace) -> int:
    from .web import create_app
    app = create_app(sample_root=_resolve_root(a.root), db_path=a.db)
    print(f"扫描根目录: {app.config['SCAN_ROOT']}")
    print(f"启动 Web: http://{a.host}:{a.port}")
    app.run(host=a.host, port=a.port, debug=a.debug)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="crypto-inventory",
                                description="密码资产盘点与后量子准备度平台")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="扫描工作区并打印摘要")
    s.add_argument("root", nargs="?")
    s.add_argument("--db")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("export", help="导出 CBOM / CSV")
    e.add_argument("root", nargs="?")
    e.add_argument("--format", choices=["cyclonedx", "csv", "summary"], default="cyclonedx")
    e.add_argument("-o", "--output")
    e.set_defaults(func=cmd_export)

    w = sub.add_parser("web", help="启动 Flask Web 平台")
    w.add_argument("root", nargs="?")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=5000)
    w.add_argument("--db")
    w.add_argument("--debug", action="store_true")
    w.set_defaults(func=cmd_web)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
