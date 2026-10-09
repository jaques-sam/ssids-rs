#!/usr/bin/env python3
"""Regenerate crates/ssids-domain/data/oui.tsv from the IEEE MA-L registry.

Usage: scripts/update-oui.py [path-to-oui.csv]
Without an argument the registry is downloaded from standards-oui.ieee.org.
The output is sorted "HHHHHH<TAB>Organization" lines, which the domain crate
embeds and binary-searches.
"""
import csv
import io
import pathlib
import sys
import urllib.request

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = pathlib.Path(__file__).resolve().parent.parent / "crates/ssids-domain/data/oui.tsv"


def main() -> None:
    if len(sys.argv) > 1:
        text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(URL) as response:
            text = response.read().decode("utf-8")
    entries = {}
    for row in csv.DictReader(io.StringIO(text)):
        oui = row["Assignment"].strip().upper()
        name = " ".join(row["Organization Name"].split())
        if len(oui) == 6 and name and name != "Private":
            entries[oui] = name
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(f"{oui}\t{entries[oui]}\n" for oui in sorted(entries)), encoding="utf-8")
    print(f"wrote {len(entries)} entries to {OUT}")


if __name__ == "__main__":
    main()
