#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


def as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--truth-steps", required=True)
    parser.add_argument("--min-score", type=float, default=0.9)
    args = parser.parse_args()

    failures = []
    matrix_path = Path(args.matrix)
    truth_path = Path(args.truth_steps)

    with matrix_path.open(newline="") as f:
        for row in csv.DictReader(f):
            name = row.get("name") or "<unknown>"
            alert_score = as_float(row.get("alert_score"))
            evidence_score = as_float(row.get("evidence_score"))
            if alert_score < args.min_score:
                failures.append(f"{name}: alert_score={alert_score} < {args.min_score}")
            if evidence_score < args.min_score:
                failures.append(f"{name}: evidence_score={evidence_score} < {args.min_score}")

    with truth_path.open(newline="") as f:
        for row in csv.DictReader(f):
            if row.get("required") == "True" and row.get("matched") != "True":
                failures.append(
                    "%s/%s/%s: missing required %s label %s"
                    % (
                        row.get("workload") or "-",
                        row.get("scenario") or "-",
                        row.get("policy") or "-",
                        row.get("label_type") or "-",
                        row.get("label_id") or "-",
                    )
                )

    if failures:
        print("[assert-detection][ERROR] detection expectations failed:")
        for failure in failures:
            print(f"  - {failure}")
        raise SystemExit(1)

    print("[assert-detection] ok")


if __name__ == "__main__":
    main()
