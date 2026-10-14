"""命令行入口：与 Web 层调用同一 Container，结果可互证（计划书 2.3）。

用法:
  python -m webvuln.cli init-db
  python -m webvuln.cli create-user -u admin -p admin123 -r admin
  python -m webvuln.cli serve
  python -m webvuln.cli scan --target <target_id> --user admin
  python -m webvuln.cli replay --scan <scan_id>
  python -m webvuln.cli report --scan <scan_id> --format md
  python -m webvuln.cli verify-evidence
"""
from __future__ import annotations

import argparse
import json

from webvuln.config import load_settings
from webvuln.container import Container
from webvuln.models.schemas import Role


def main() -> None:
    parser = argparse.ArgumentParser(prog="webvuln")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init-db")
    cu = sub.add_parser("create-user")
    cu.add_argument("-u", "--username", required=True)
    cu.add_argument("-p", "--password", required=True)
    cu.add_argument("-r", "--role", default="admin", choices=[r.value for r in Role])
    sub.add_parser("serve")
    sc = sub.add_parser("scan")
    sc.add_argument("--target", required=True)
    sc.add_argument("--user", default="cli")
    rp = sub.add_parser("replay")
    rp.add_argument("--scan", required=True)
    rt = sub.add_parser("report")
    rt.add_argument("--scan", required=True)
    rt.add_argument("--format", default="md", choices=["json", "md", "html"])
    sub.add_parser("verify-evidence")

    args = parser.parse_args()
    c = Container(load_settings())

    if args.cmd == "init-db":
        print("数据库已初始化:", c.settings.db_path)
    elif args.cmd == "create-user":
        c.users.create(args.username, args.password, Role(args.role))
        print("用户已创建:", args.username)
    elif args.cmd == "serve":
        import uvicorn
        uvicorn.run("webvuln.web.app:app", host="0.0.0.0", port=8000, reload=True)
    elif args.cmd == "scan":
        print(json.dumps(c.pipeline.run_scan(args.target, args.user), ensure_ascii=False))
    elif args.cmd == "replay":
        print(json.dumps(c.pipeline.replay(args.scan), ensure_ascii=False, indent=2))
    elif args.cmd == "report":
        print(c.reporter.render(args.scan, args.format))
    elif args.cmd == "verify-evidence":
        print(json.dumps(c.evidence.manifest(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
