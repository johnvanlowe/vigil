"""CLI commands for verdict management and export."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from core.findings.export import export_verdicts


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vigil verdicts")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    export_p = subparsers.add_parser("export", help="Export anonymized verdicts to JSONL")
    export_p.add_argument("--since", help="ISO format timestamp filter (e.g. 2026-01-01T00:00:00Z)", default=None)
    export_p.add_argument("--out", help="Output JSONL filepath", default="verdicts_export.jsonl")
    export_p.add_argument("--min-frequency", type=int, default=1, help="Minimum shape frequency threshold")

    args = parser.parse_args(argv)

    if args.subcommand == "export":
        since_dt = None
        if args.since:
            since_dt = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
        report = export_verdicts(since=since_dt, out_path=args.out, min_shape_frequency=args.min_frequency)
        print("=== Vigil Verdicts Export Report ===")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
