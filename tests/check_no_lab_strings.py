#!/usr/bin/env python3
"""The deliverables carry nothing of the qualification laboratory.

    check_no_lab_strings.py --points src/agent/lab.c --absent FILE... [--present FILE...]

Every FILE given with --absent (the installed programs and archives, in any
build type) must contain none of the needles: the private definition and
the names of the laboratory, and every point name read from the table of
lab.c between its `points:begin` and `points:end` marks. Every FILE given
with --present (the -lab programs, the positive control of this check) must
contain all of them that a program of its role carries. Exit 0 when both
hold, 1 otherwise, naming each file and needle that fails.
"""
import argparse
import re
import sys
from pathlib import Path

FIXED_NEEDLES = [b"MG_LAB", b"MG_QUAL_FAULT", b"maelys-git-lab", b"maelys-lab", b"markers.jsonl"]


def point_names(lab_source):
    text = Path(lab_source).read_text()
    begin, end = text.index("/* points:begin */"), text.index("/* points:end */")
    names = re.findall(r'\{"([a-z_]+\.[a-z_]+)"', text[begin:end])
    if len(names) < 10:
        raise SystemExit(f"{lab_source}: the point table was not read ({len(names)} names)")
    return [name.encode() for name in names]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--points", required=True, help="src/agent/lab.c, the table of points")
    parser.add_argument("--absent", nargs="*", default=[], help="deliverables: no needle may appear")
    parser.add_argument("--present", nargs="*", default=[], help="-lab programs: the needles must appear")
    args = parser.parse_args(argv)
    needles = FIXED_NEEDLES + point_names(args.points)
    failures = []
    for path in args.absent:
        data = Path(path).read_bytes()
        for needle in needles:
            if needle in data:
                failures.append(f"{path}: carries {needle.decode()}")
    for path in args.present:
        data = Path(path).read_bytes()
        missing = [needle.decode() for needle in needles if needle not in data]
        if missing:
            failures.append(f"{path}: lacks {', '.join(missing)}")
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"checked {len(args.absent)} deliverable(s) and {len(args.present)} laboratory program(s) "
          f"for {len(needles)} needles: {'FAILED' if failures else 'ok'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
