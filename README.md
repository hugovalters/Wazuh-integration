# Wazuh Integration

Turn ValtersIT CVE scan results into Wazuh alerts — a decoder, a rule set
and a small sender script, so a critical CVE on any host raises a level-13
alert in your Wazuh dashboard like any other security event. Open source,
auditable, privacy-first — powered by the ValtersIT CVE API.

> Part of the ValtersIT platform — CVE & Threat-IP data you can query or run yourself.
> Explore both API and scanners: https://www.valtersit.com/platform/
> Scanner plans & pricing: https://www.valtersit.com/cve/pricing/#scanners

## What it does

| File | Goes on | Purpose |
|---|---|---|
| `valtersit-wazuh.py` | each scanned host (agent) | Runs a ValtersIT scanner (or reads its saved output) and emits one event per matched CVE, plus a scan summary |
| `custom_valtersit.xml` | Wazuh manager, `etc/decoders/` | Decoder: `valtersit: {json}` lines, decoded with Wazuh's JSON decoder |
| `valtersit_rules.xml` | Wazuh manager, `etc/rules/` | Rules 100700–100704 |
| `valtersit_client.py` | next to the script | Shared ValtersIT client (state directory for `--only-new`) |

Alerts:

| Rule | Level | When |
|---|---|---|
| 100701 | 3 | Scan completed — `<scanner> scan completed - N CVE(s) matched` |
| 100702 | 5 | CVE with low/medium CVSS (< 7.0) or no score |
| 100703 | 10 | CVE with CVSS 7.0–8.9 |
| 100704 | 13 | CVE with CVSS 9.0+ (includes the fixed version) |

CVE rules carry PCI DSS 6.2 / 11.2.1, GDPR IV 35.7.d, NIST 800-53 RA.5 /
SI.2 and TSC CC7.1 tags, so they show up in Wazuh's compliance views.

Decoded fields: `scanner`, `vulnerability.id`, `vulnerability.cvss`,
`vulnerability.severity`, `vulnerability.epss`, `vulnerability.reference`,
`package.name`, `package.version`, `package.fixed_version`,
`scan.matched_cves`, `scan.critical`, `scan.high`.

## Your data stays yours

- **What ValtersIT receives:** nothing from this integration itself — it
  only reads the result of a scan that already happened. The scanner you
  run sends what its own README describes: component name + version and an
  opaque system identifier.
- **What goes to Wazuh:** the matched CVEs above, through your own agent
  or local queue. Nothing leaves your Wazuh deployment.
- **What it does not do:** the script makes no network calls, needs no
  Wazuh API credentials, and changes nothing except appending to its log
  file (or writing to the local queue socket) and its `--only-new` state.
- **Audit it yourself.** ~800 lines in total, three of the four files are
  short; read them before installing.

## Install

### On the Wazuh manager

```bash
curl -fsSL https://gitlab.com/valtersit/wazuh-ntegration/-/raw/main/custom_valtersit.xml \
  -o /var/ossec/etc/decoders/custom_valtersit.xml
curl -fsSL https://gitlab.com/valtersit/wazuh-ntegration/-/raw/main/valtersit_rules.xml \
  -o /var/ossec/etc/rules/valtersit_rules.xml
chown wazuh:wazuh /var/ossec/etc/decoders/custom_valtersit.xml /var/ossec/etc/rules/valtersit_rules.xml
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
```

If rule IDs 100700–100704 clash with your own local rules, renumber them
(anything in 100000–120000 is the local range).

### On each scanned host

Install the scanner for the host (e.g.
[`linux-cve-scanner`](https://gitlab.com/valtersit/linux-cve-scanner)),
confirm authorised use once interactively as its README describes, then:

```bash
mkdir -p /opt/wazuh-ntegration && cd /opt/wazuh-ntegration
for f in valtersit-wazuh.py valtersit_client.py; do
  curl -fsSLO "https://gitlab.com/valtersit/wazuh-ntegration/-/raw/main/$f"
done
```

Tell the agent to read the log file — add to `/var/ossec/etc/ossec.conf`
(or to an agent group's `agent.conf` on the manager):

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/ossec/logs/valtersit.log</location>
</localfile>
```

and restart the agent. Alternatively use `--socket` (below), which needs no
`ossec.conf` change.

Requires only a stock Python 3 interpreter (3.7+). No `pip install`.

## Usage

```bash
# Run the Linux scanner and send its findings to Wazuh via the log file
python3 valtersit-wazuh.py --only-new --run python3 /opt/linux-cve-scanner/valtersit-linux-scan.py --yes

# Same, but straight into the local Wazuh queue (run as root on an agent or manager)
python3 valtersit-wazuh.py --socket --only-new --run python3 /opt/linux-cve-scanner/valtersit-linux-scan.py --yes

# From a saved scanner output
python3 valtersit-wazuh.py --input /var/log/valtersit-linux-scan.log

# See the events without delivering them
python3 valtersit-wazuh.py --input saved-scan.txt --dry-run
```

`--run` must be the last option — everything after it is the scanner
command.

| Option | Default | Meaning |
|---|---|---|
| `--output FILE` | `/var/ossec/logs/valtersit.log` | Append events to this file |
| `--socket [PATH]` | `/var/ossec/queue/sockets/queue` | Write to the Wazuh queue socket instead |
| `--only-new` | off | Skip CVEs already reported by an earlier run (a fixed-then-reintroduced CVE alerts again) |
| `--scanner-name` | detected | Value of the `scanner` field |
| `--dry-run` | off | Print the event lines only |

## Sample alert

```
** Alert 1795037210.4402: mail  - valtersit,vulnerability,pci_dss_6.2,pci_dss_11.2.1,gdpr_IV_35.7.d,nist_800_53_RA.5,nist_800_53_SI.2,tsc_CC7.1,
2026 Nov 18 03:30:10 (web-01) any->valtersit
Rule: 100704 (level 13) -> 'ValtersIT: CRITICAL CVE-2026-11023 (CVSS 9.1) in openssl 3.0.13-0ubuntu3.4 - fixed in 3.0.13-0ubuntu3.6'
```

Test the decoder and rules on the manager before rolling out:

```bash
echo 'valtersit: {"event_type":"cve","integration":"valtersit","package":{"name":"openssl","version":"3.0.13"},"scanner":"test","vulnerability":{"cvss":9.1,"cvss_text":"9.1","id":"CVE-2026-11023","severity":"critical"}}' \
  | /var/ossec/bin/wazuh-logtest
```

## Schedule it

```
30 3 * * * cd /opt/wazuh-ntegration && VALTERSIT_API_KEY=vit_v1_xxx /usr/bin/python3 valtersit-wazuh.py --only-new --run /usr/bin/python3 /opt/linux-cve-scanner/valtersit-linux-scan.py --yes >> /var/log/valtersit-wazuh.log 2>&1
```

Rotate `/var/ossec/logs/valtersit.log` with your usual logrotate policy —
the agent follows rotation automatically.

## Authorised use only

Run the scanners only against systems you own, or for which you have
explicit written authorisation to assess. Each scanner shows this notice
before its first scan and requires you to type `YES`:

```
------------------------------------------------------------------------------
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
------------------------------------------------------------------------------
```

Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`); provided without
warranty of any kind. "ValtersIT" and the ValtersIT logo are trademarks of
Valters Capital, SIA and are not licensed for use. Wazuh is a trademark of
Wazuh, Inc.; this project is not affiliated with or endorsed by it.

## Questions or a bug?

Please **don't** open GitHub/GitLab issues — I don't monitor them.
Reach me through the contact form instead: https://www.valtersit.com/contacts/

Maintained by Hugo Valters
