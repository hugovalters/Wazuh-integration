#!/usr/bin/env python3
# Copyright 2026 Valters Capital, SIA
# Licensed under the Apache License, Version 2.0.
# ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
# Maintained by Hugo Valters

"""
ValtersIT -> Wazuh

Turns a ValtersIT scan result into Wazuh events - one per matched CVE, plus
one scan summary - so CVEs found by any ValtersIT scanner raise alerts in
Wazuh like any other security event.

Every event is a single line:
    valtersit: {"integration": "valtersit", "event_type": "cve", ...}
which the decoder in custom_valtersit.xml parses as JSON, and the rules in
valtersit_rules.xml turn into alerts (level 5 / 10 / 13 for low-medium /
high / critical CVSS).

Delivery, one of:
  --output FILE   append the lines to a log file the Wazuh agent monitors
                  (default /var/ossec/logs/valtersit.log - see README.md for
                  the <localfile> block)
  --socket        write straight into the local Wazuh queue socket
                  (/var/ossec/queue/sockets/queue) - no ossec.conf change,
                  needs to run as root or the wazuh user on an agent/manager

Where the results come from, one of:
  --run CMD ...   run any ValtersIT scanner (with --yes) and take the scan
                  response from its output
  --input FILE    a saved scanner output, or a raw scan-response JSON ("-"
                  for stdin)

--only-new remembers what was already reported (in the ValtersIT state
directory) and emits only CVEs not seen before on this machine, so a daily
scan does not re-alert the same finding every day.

This script makes no network calls of its own.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import valtersit_client as vit  # noqa: E402

DEFAULT_OUTPUT = "/var/ossec/logs/valtersit.log"
DEFAULT_SOCKET = "/var/ossec/queue/sockets/queue"
SEEN_FILE = vit.STATE_DIR / "wazuh-seen.json"


def extract_response(text: str):
    """(response_dict, scanner_label) from a raw response JSON or from a
    ValtersIT scanner's full output (the JSON after "[+] Scan submitted")."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            return json.loads(stripped), None
        except ValueError:
            pass
    m = re.search(r"^ValtersIT (.+?) - ", text, re.MULTILINE)
    label = m.group(1).strip() if m else None
    marker = text.find("[+] Scan submitted")
    brace = text.find("{", marker) if marker != -1 else -1
    if brace == -1:
        return None, label
    try:
        return json.JSONDecoder().raw_decode(text[brace:])[0], label
    except ValueError:
        return None, label


def run_scanner(cmd: list[str]) -> str:
    if not cmd:
        print("[!] --run needs a command, e.g. --run python3 /opt/linux-cve-scanner/valtersit-linux-scan.py --yes",
              file=sys.stderr)
        sys.exit(2)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("[!] Could not run {}: {}".format(cmd[0], exc), file=sys.stderr)
        sys.exit(2)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        print(proc.stdout[-2000:], file=sys.stderr)
        print("[!] Scanner exited with code {} - no events written.".format(proc.returncode), file=sys.stderr)
        sys.exit(1)
    return proc.stdout


def severity_for(cvss) -> str:
    if not isinstance(cvss, (int, float)):
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low" if cvss > 0 else "none"


def build_events(response: dict, scanner: str) -> list[dict]:
    results = [r for r in (response.get("results") or []) if isinstance(r, dict)]
    events = []
    for r in results:
        cvss = r.get("cvss")
        cve = r.get("cve_id") or r.get("cve") or r.get("id")
        ev = {
            "integration": "valtersit",
            "event_type": "cve",
            "scanner": scanner,
            "vulnerability": {
                "id": cve,
                "cvss": cvss if isinstance(cvss, (int, float)) else None,
                # Wazuh prints numeric fields as "9.100000" in rule descriptions; this one reads "9.1".
                "cvss_text": "{:.1f}".format(cvss) if isinstance(cvss, (int, float)) else "n/a",
                "severity": severity_for(cvss),
                "reference": "https://www.valtersit.com/cve/{}/".format(cve) if cve else None,
            },
            "package": {"name": r.get("slug") or r.get("product"), "version": r.get("version"),
                        "fixed_version": r.get("patched_in")},
        }
        if isinstance(r.get("epss"), (int, float)):
            ev["vulnerability"]["epss"] = r["epss"]
        events.append(ev)
    matched = response.get("matched_cves")
    events.append({
        "integration": "valtersit",
        "event_type": "scan",
        "scanner": scanner,
        "scan": {
            "matched_cves": matched if isinstance(matched, int) else len(results),
            "critical": sum(1 for e in events if e["vulnerability"]["severity"] == "critical"),
            "high": sum(1 for e in events if e["vulnerability"]["severity"] == "high"),
        },
    })
    return events


def finding_key(ev: dict) -> str:
    raw = "|".join(str(x) for x in (ev["scanner"], ev["vulnerability"]["id"], ev["package"]["name"],
                                     ev["package"]["version"]))
    return hashlib.sha1(raw.encode()).hexdigest()


def filter_new(events: list[dict]) -> list[dict]:
    try:
        seen = set(json.loads(SEEN_FILE.read_text()))
    except (OSError, ValueError):
        seen = set()
    out, current = [], set()
    for ev in events:
        if ev["event_type"] != "cve":
            out.append(ev)
            continue
        key = finding_key(ev)
        current.add(key)
        if key not in seen:
            out.append(ev)
    try:
        vit.STATE_DIR.mkdir(parents=True, exist_ok=True)
        # Only findings still present are remembered, so a CVE that is fixed and later
        # re-introduced alerts again.
        SEEN_FILE.write_text(json.dumps(sorted(current)))
    except OSError as exc:
        print("[!] Could not save {} ({}) - --only-new will repeat these findings next run.".format(SEEN_FILE, exc),
              file=sys.stderr)
    return out


def format_line(ev: dict) -> str:
    return "valtersit: " + json.dumps(ev, separators=(",", ":"), sort_keys=True)


def write_file(path: str, lines: list[str]):
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
    except OSError as exc:
        print("[!] Could not write {}: {}".format(p, exc), file=sys.stderr)
        sys.exit(1)


def write_socket(path: str, lines: list[str]):
    """Wazuh's local queue takes datagrams of the form '1:<location>:<message>'."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(path)
        for line in lines:
            sock.send("1:valtersit:{}".format(line).encode("utf-8"))
        sock.close()
    except OSError as exc:
        print("[!] Could not write to the Wazuh queue socket {}: {} (run as root on a host with a Wazuh "
              "agent or manager, or use --output).".format(path, exc), file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Send ValtersIT scan results to Wazuh.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--run", nargs=argparse.REMAINDER, help="Run a scanner command (put this option last).")
    src.add_argument("--input", help="Saved scanner output or scan-response JSON ('-' for stdin).")
    dest = parser.add_mutually_exclusive_group()
    dest.add_argument("--output", default=DEFAULT_OUTPUT, help="Log file monitored by the Wazuh agent "
                                                               "(default {}).".format(DEFAULT_OUTPUT))
    dest.add_argument("--socket", nargs="?", const=DEFAULT_SOCKET, help="Write to the local Wazuh queue socket "
                                                                       "(default path {}).".format(DEFAULT_SOCKET))
    parser.add_argument("--only-new", action="store_true", help="Only emit CVEs not reported by a previous run.")
    parser.add_argument("--scanner-name", help="Value for the `scanner` field (default: detected from output).")
    parser.add_argument("--dry-run", action="store_true", help="Print the event lines instead of delivering them.")
    args = parser.parse_args()

    if args.run is not None:
        response, label = extract_response(run_scanner(args.run))
    else:
        text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
        response, label = extract_response(text)
    if not isinstance(response, dict):
        print("[!] No ValtersIT scan response found (the scan may not have been submitted - check the API key "
              "and the scanner output).", file=sys.stderr)
        sys.exit(1)

    events = build_events(response, args.scanner_name or label or "unknown")
    if args.only_new:
        events = filter_new(events)
    lines = [format_line(ev) for ev in events]

    if args.dry_run:
        print("\n".join(lines))
        return
    if args.socket:
        write_socket(args.socket, lines)
        where = "Wazuh queue socket {}".format(args.socket)
    else:
        write_file(args.output, lines)
        where = args.output
    print("[+] {} CVE event(s) + 1 scan summary written to {}.".format(len(lines) - 1, where))


if __name__ == "__main__":
    main()
