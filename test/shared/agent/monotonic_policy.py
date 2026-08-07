#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path


UINT64_MAX = 2**64 - 1
DECIMAL_VERSION = re.compile(r"0|[1-9][0-9]*")


def parse_version(value):
    if isinstance(value, bool):
        raise ValueError("version must be a canonical uint64")
    if isinstance(value, int):
        version = value
    elif isinstance(value, str) and DECIMAL_VERSION.fullmatch(value):
        version = int(value)
    else:
        raise ValueError("version must be a canonical uint64")
    if not 0 <= version <= UINT64_MAX:
        raise ValueError("version must be within uint64 range")
    return version


def generate(current_path, template_path, output_path):
    current = json.loads(current_path.read_text())
    template = json.loads(template_path.read_text())
    if not isinstance(current, dict) or not isinstance(template, dict):
        raise ValueError("current policy and template must be JSON objects")

    version = parse_version(current.get("version"))
    if version == UINT64_MAX:
        raise ValueError("cannot increment uint64 maximum version")

    next_version = version + 1
    template["version"] = next_version
    output_path.write_text(json.dumps(template, indent=2) + "\n")
    return next_version


def main(argv):
    if len(argv) != 4:
        print("usage: monotonic_policy.py CURRENT TEMPLATE OUTPUT", file=sys.stderr)
        return 2
    try:
        next_version = generate(*(Path(value) for value in argv[1:]))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"monotonic_policy: {error}", file=sys.stderr)
        return 1
    print(next_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
