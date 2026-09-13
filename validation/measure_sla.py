"""CLI for deterministic, offline detection-SLA fixture measurement."""
import argparse
import json
from pathlib import Path

from validation.sla import measure_sla


def _latency_display(result):
    if not result.latencies_seconds:
        return "-"
    latency = max(result.latencies_seconds)
    if 0 < latency < 0.001:
        return f"{latency * 1_000_000:g}us"
    return f"{latency:g}s"


def print_report(report):
    print(f"\n=== Detection SLA scorecard: {report.target} ===")
    print("  Rule  Event                       Phase           Target  Latency  Status")
    for result in report.results:
        print(
            f"  {result.rule_id:>4}  {result.event:<27} "
            f"{result.phase:<15} {result.target_seconds:>5}s  "
            f"{_latency_display(result):>7}  {result.status}"
        )
        if result.status != "HIT":
            print(f"        {result.detail}")
    for error in report.evidence_errors:
        print(f"  evidence error: {error}")
    counts = report.counts
    print(
        f"\n  {counts['HIT']} HIT, {counts['MISS']} MISS, "
        f"{counts['UNMEASURED']} UNMEASURED ({report.evidence_kind} evidence only)"
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="path to a target configs/ dir")
    parser.add_argument("--json-output", help="optional path for machine-readable results")
    parser.add_argument(
        "--require-all-hit", action="store_true",
        help="exit non-zero unless all configured rules are HIT",
    )
    args = parser.parse_args(argv)

    report = measure_sla(args.target)
    print_report(report)
    if args.json_output:
        Path(args.json_output).write_text(json.dumps(report.to_dict(), indent=2) + "\n")
    if args.require_all_hit and report.counts != {
        "HIT": len(report.results), "MISS": 0, "UNMEASURED": 0,
    }:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
