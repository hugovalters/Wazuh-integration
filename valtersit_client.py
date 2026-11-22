# Copyright 2026 Valters Capital, SIA
# Licensed under the Apache License, Version 2.0.
# ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
# Maintained by Hugo Valters

"""
ValtersIT API client — shared by every tool in this repository.

This file is imported by the scanner scripts (WordPress, Linux packages,
Docker, Python, Node.js, Ruby, .NET, Laravel, Magento, Kubernetes, and the
integrations built on top of them). It is not a standalone script.

Design constraints:
  - Standard library only. No pip install, no requirements.txt. These tools
    are meant to run unmodified on production systems (web servers, hosts,
    build agents) that may not have network access to PyPI or permission to
    install packages.
  - Never collects or transmits IP address, hostname, MAC address, file
    contents, credentials, or database contents. Only component name +
    version, plus an opaque system identifier (see compute_fingerprint_v2()
    below): a one-way SHA-256 hash of stable local machine signals
    (machine-id, first disk UUID, CPU count, OS/architecture), or a random
    locally-stored token when those signals are unavailable. The hash cannot
    be reversed to any of those values; it only lets repeat scans of the
    same machine be recognised as the same system. Each submission signs it
    with an HMAC timestamp so a captured value cannot be replayed.

Before a scan runs, require_consent() shows AUTHORISATION_NOTICE and
requires an explicit "YES" - a plain authorised-use attestation for running
this scanner, unrelated to any separate checkout-time flow on the website.
"""

import hashlib
import hmac
import json
import os
import platform
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Option A: set your key here. Option B (recommended): export
# VALTERSIT_API_KEY in your shell / cron / CI environment instead, and leave
# this blank. If you edit this line, remember this repository is public —
# never commit a real key.
API_KEY = ""

API_BASE = os.environ.get("VALTERSIT_API_BASE", "https://api.valtersit.com/api/v1")
STATE_DIR = Path(os.environ.get("VALTERSIT_STATE_DIR", str(Path.home() / ".valtersit")))
CONSENT_FILE = STATE_DIR / "consent.json"

CLIENT_VERSION = "1.2.0"
USER_AGENT = "valtersit-scanner/{} (+https://www.valtersit.com)".format(CLIENT_VERSION)

# Bumped whenever AUTHORISATION_NOTICE's wording changes in substance, so a
# confirmation given against older wording is asked for again once.
ATTESTATION_VERSION = "v2"


class ValtersITError(RuntimeError):
    """Raised for API/config errors the calling script should handle."""


def get_api_key():
    """Resolve the API key: env var takes precedence over the in-file constant,
    so a real key exported for one-off testing never risks being committed."""
    key = os.environ.get("VALTERSIT_API_KEY", "").strip() or API_KEY.strip()
    if not key:
        raise ValtersITError(
            "No API key configured. Set the VALTERSIT_API_KEY environment "
            "variable, or edit API_KEY in valtersit_client.py."
        )
    return key


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _request(method, path, params=None, json_body=None, timeout=15, _retry=0):
    """Low-level request helper. Returns (status_code, parsed_body_or_None).
    Never raises: a missing/invalid key or a network failure both come back
    as (None, {"detail": ...}) so callers can always check status/body
    instead of wrapping every call in try/except."""
    try:
        key = get_api_key()
    except ValtersITError as exc:
        return None, {"detail": str(exc), "no_api_key": True}

    url = API_BASE.rstrip("/") + "/" + path.lstrip("/")
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url += "?" + urllib.parse.urlencode(clean)

    headers = {
        "Authorization": "Bearer " + key,
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.getcode(), (json.loads(body) if body else {})
    except urllib.error.HTTPError as exc:
        if exc.code == 429 and _retry < 3:
            wait = 2 ** (_retry + 1)
            time.sleep(wait)
            return _request(method, path, params, json_body, timeout, _retry + 1)
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, (json.loads(body) if body else {})
        except ValueError:
            return exc.code, {"detail": body}
    except urllib.error.URLError as exc:
        return None, {"detail": str(exc.reason)}


def api_get(path, params=None):
    return _request("GET", path, params=params)


def api_post(path, json_body=None):
    return _request("POST", path, json_body=json_body)


def explain_status(status, body):
    """Human-readable one-liner for a non-2xx API response."""
    detail = ""
    if isinstance(body, dict):
        detail = body.get("detail") or body.get("error") or ""
        if isinstance(detail, dict):
            detail = detail.get("error") or json.dumps(detail)
    if status is None:
        return "Could not reach the ValtersIT API ({}).".format(detail or "network error")
    if status == 401:
        return "Not authenticated — check your VALTERSIT_API_KEY. ({})".format(detail)
    if status == 403:
        return "Forbidden — your plan does not include this endpoint. ({})".format(detail)
    if status == 404:
        return "Endpoint not found ({}). {}".format(path_hint(), detail)
    if status == 422:
        return "Request rejected by the API — validation error. ({})".format(detail)
    if status == 429:
        return "Rate limited by the API, even after retrying. ({})".format(detail)
    return "Unexpected API response: HTTP {} ({})".format(status, detail)


def path_hint():
    return "it may not be live yet"


# ---------------------------------------------------------------------------
# Public CVE lookup (live today)
# ---------------------------------------------------------------------------

def lookup_cve(**filters):
    """Thin wrapper around GET /api/v1/cve. At least one filter is required
    by the API (e.g. vendor='cisco', severity='critical', cvss_min=9.0)."""
    return api_get("/cve", params=filters)


# ---------------------------------------------------------------------------
# First-run consent gate
# ---------------------------------------------------------------------------

# Shown before this tool's first scan. This is a plain authorised-use
# attestation for running the scanner - it is unrelated to any separate
# checkout-time consumer-rights flow shown on the website for purchased
# digital content, which is captured server-side there.
AUTHORISATION_NOTICE = """------------------------------------------------------------------------------
 ValtersIT Scanner — Authorised Use Confirmation
------------------------------------------------------------------------------
 Run this tool ONLY against systems you own, or for which you have explicit
 written authorisation to assess.

 This scan sends only component name + version, plus an opaque system
 identifier (a one-way hash of local machine signals such as machine-id
 and disk UUID, so repeat scans are recognised as the same system), to
 the ValtersIT API — no IP address, hostname, MAC address, or file
 contents. See the Privacy Policy: https://www.valtersit.com/privacy

 Type YES to confirm you are authorised to scan this system and continue.
 Anything else aborts without scanning.
------------------------------------------------------------------------------"""


def _load_consent_state():
    try:
        return json.loads(CONSENT_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save_consent_state(state):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        CONSENT_FILE.write_text(json.dumps(state, indent=2))
        try:
            os.chmod(CONSENT_FILE, 0o600)
        except OSError:
            pass
    except OSError as exc:
        print("[!] Could not persist consent record locally: {}".format(exc), file=sys.stderr)


def require_consent(tool_name, non_interactive=False):
    """Must be called, and must return True, before a scan does anything.
    Returns False (script must exit) if confirmation is refused or
    unavailable. Confirmation, once given, is remembered locally per tool so
    the prompt does not repeat on every run - unless the notice's wording
    has since changed (ATTESTATION_VERSION), in which case it is shown once
    more."""
    state = _load_consent_state()
    previous = state.get(tool_name, {})
    if previous.get("confirmed") and previous.get("attestation_version") == ATTESTATION_VERSION:
        return True

    if non_interactive:
        if previous.get("confirmed"):
            reason = ("the authorised-use notice has changed since you last confirmed it for '{}' - "
                      "run once interactively to review and re-confirm.".format(tool_name))
        else:
            reason = ("--yes was not combined with a prior confirmation for '{}': "
                      "refusing to scan non-interactively.".format(tool_name))
        print("[!] " + reason, file=sys.stderr)
        return False

    print()
    print(AUTHORISATION_NOTICE)
    print()
    try:
        answer = input("Type YES to continue: ").strip()
    except (EOFError, KeyboardInterrupt):
        answer = ""

    if answer != "YES":
        print("\nConfirmation not received - exiting without scanning.")
        return False

    record = {
        "confirmed": True,
        "confirmed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "attestation_version": ATTESTATION_VERSION,
        "source": "scanner-cli",
        "client_version": CLIENT_VERSION,
    }
    state[tool_name] = record
    _save_consent_state(state)
    return True


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

FINGERPRINT_V2_FILE = STATE_DIR / "fingerprint_v2"


def _collect_hw_signals():
    """Collect stable local machine signals for the opaque system identifier.

    Returns (signals, has_machine_signal). has_machine_signal is True only
    when at least one per-machine value (machine-id or a disk UUID) was
    found - CPU count and OS/architecture alone are shared by huge numbers
    of machines and must never be the whole basis of the identifier."""
    signals = []
    has_machine_signal = False
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            with open(path) as fh:
                v = fh.read().strip()
            if len(v) >= 8:
                signals.append("mid:" + v)
                has_machine_signal = True
                break
        except OSError:
            pass
    try:
        out = subprocess.check_output(
            ["blkid", "-s", "UUID", "-o", "value"],
            stderr=subprocess.DEVNULL, timeout=5, text=True,
        )
        uuids = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if uuids:
            signals.append("disk:" + uuids[0])
            has_machine_signal = True
    except Exception:
        pass
    signals.append("cpu:" + str(os.cpu_count() or 1))
    signals.append("os:" + platform.system() + ":" + platform.machine())
    return signals, has_machine_signal


def _get_or_create_random_stable():
    """Fallback stable token when no per-machine signal is available
    (typical inside containers and on some CI runners): a random value,
    created once and persisted locally under STATE_DIR."""
    try:
        existing = FINGERPRINT_V2_FILE.read_text().strip()
        if len(existing) >= 16:
            return existing
    except OSError:
        pass
    token = secrets.token_hex(16)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        FINGERPRINT_V2_FILE.write_text(token)
        try:
            os.chmod(FINGERPRINT_V2_FILE, 0o600)
        except OSError:
            pass
    except OSError as exc:
        print("[!] Could not persist fingerprint_v2 locally ({}) - a new one will be "
              "generated next run, which the API will see as a different system.".format(exc),
              file=sys.stderr)
    return token


def compute_fingerprint_v2(api_key):
    """Opaque, HMAC-signed system identifier.

    Format: <stable_32hex>.<unix_ts>.<hmac_sha256_20hex>

    The stable part is SHA-256 (truncated to 32 hex chars) over machine-id,
    first disk UUID, CPU count and OS/architecture - or, when neither
    machine-id nor a disk UUID is available, a persisted random token. It
    cannot be reversed to any of those values. The HMAC (keyed with the API
    key) over stable part + timestamp binds each request to a short time
    window so a captured identifier cannot be replayed.
    """
    signals, has_machine_signal = _collect_hw_signals()
    if has_machine_signal:
        raw = "\n".join(sorted(signals))
        stable = hashlib.sha256(raw.encode()).hexdigest()[:32]
    else:
        stable = _get_or_create_random_stable()
    ts = int(time.time())
    msg = "{stable}:{ts}".format(stable=stable, ts=ts).encode()
    sig = hmac.new(api_key.encode(), msg, hashlib.sha256).hexdigest()[:20]
    return "{stable}.{ts}.{sig}".format(stable=stable, ts=ts, sig=sig)


# ---------------------------------------------------------------------------
# Scan submission
# ---------------------------------------------------------------------------

def _ensure_server_consent():
    """POST /api/v1/scan/consent — the real, required, server-side gate:
    the API rejects every POST /api/v1/scan with 403 until this account has
    a recorded scanner-consent, checked fresh per request (not cached from
    require_consent()'s LOCAL attestation above, which is a separate,
    client-side-only concept). Confirmed live 2026-09-27 by reading the
    actual deployed route (routers/scan.py: `@router.post("/scan/consent")`
    under the router's own "/api/v1" prefix) — an earlier version of this
    client guessed "/consent" (no "/api/v1/scan" prefix) and got a 404 it
    then treated as best-effort/non-blocking, so every real scan attempt
    was 403ing on this account-level gate without ever surfacing why.
    No request body — the endpoint takes none. Idempotent server-side (a
    204 no-op if already granted for this account), so calling it before
    every scan is cheap and self-heals any account whose earlier attempt
    failed under the old, wrong path."""
    status, body = api_post("/scan/consent", json_body=None)
    return status in (200, 204), status, body


# The API hard-rejects a scan with more than this many components (422,
# "Inventory too large") -- confirmed live 2026-09-28 scanning eu1's full
# dpkg list (1482 packages, no way to succeed at all without this). Every
# scanner's own --limit flag only ever controlled what got PRINTED, not
# what got SENT, so any real system over this size could never complete a
# scan through this client, silently. Capped here, once, so every scanner
# benefits without each needing its own truncation logic.
MAX_SCAN_COMPONENTS = 1000


def submit_scan(inventory):
    """Submits the detected component list for vulnerability matching:

        POST /api/v1/scan
        {
          "fingerprint": "<from compute_fingerprint_v2()>",
          "components": [
            {"vendor": "...", "product": "...", "version": "...", "slug": "..."},
            ...
          ]
        }

    Returns a dict: {"available": bool, "status": int|None, "body": dict|None,
    "reason": str|None}. "available" is False when nothing was sent (no API
    key configured, or the required consent step failed) or the API
    rejected the request - callers should check "reason" ("no_api_key" is
    the one routine, non-error case) before treating a False result as a
    failure.
    """
    try:
        get_api_key()
    except ValtersITError as exc:
        body = {"detail": str(exc), "no_api_key": True}
        return {"available": False, "status": None, "body": body, "reason": "no_api_key"}

    if len(inventory) > MAX_SCAN_COMPONENTS:
        print(
            "[!] {} components detected, but the API accepts at most {} per scan -- "
            "submitting the first {} only. Contact us for large-fleet scanning.".format(
                len(inventory), MAX_SCAN_COMPONENTS, MAX_SCAN_COMPONENTS,
            ),
            file=sys.stderr,
        )
        inventory = inventory[:MAX_SCAN_COMPONENTS]

    consent_ok, consent_status, consent_body = _ensure_server_consent()
    if not consent_ok:
        if isinstance(consent_body, dict) and consent_body.get("no_api_key"):
            return {"available": False, "status": None, "body": consent_body, "reason": "no_api_key"}
        return {"available": False, "status": consent_status, "body": consent_body, "reason": "consent_failed"}

    fingerprint = compute_fingerprint_v2(get_api_key())
    payload = {"fingerprint": fingerprint, "components": inventory}
    status, body = api_post("/scan", json_body=payload)
    if isinstance(body, dict) and body.get("no_api_key"):
        return {"available": False, "status": None, "body": body, "reason": "no_api_key"}
    ok = status is not None and 200 <= status < 300
    return {"available": ok, "status": status, "body": body, "reason": None if ok else "error"}


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def print_inventory_table(title, rows, columns):
    """rows: list of dicts. columns: list of (key, header, width) tuples."""
    print()
    print("=" * 78)
    print(" " + title)
    print("=" * 78)
    if not rows:
        print(" (nothing detected)")
        print()
        return
    header = "  ".join(h.ljust(w) for _, h, w in columns)
    print(header)
    print("-" * len(header))
    for row in rows:
        line = "  ".join(str(row.get(k, "")).ljust(w)[:w] for k, _, w in columns)
        print(line)
    print()
    print(" {} item(s) detected. No IP address, hostname, MAC address, file".format(len(rows)))
    print(" contents, or credentials were read or transmitted by this scan.")
    print("=" * 78)
    print()


def print_no_api_key_notice():
    print(
        "[i] No VALTERSIT_API_KEY configured, so nothing was sent anywhere. "
        "Local inventory is shown above; set an API key to get it matched "
        "against known CVEs.\n"
    )
