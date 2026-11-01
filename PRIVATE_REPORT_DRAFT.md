# C75 — journalpump 2.4.6: syslog non-transparent framing allows local log record forgery

## Program / asset
- **Program:** Aiven Managed Bug Bounty (Bugcrowd `aiven-mbb-og`) — public, paid ($50–$25,000)
- **Asset:** `github.com/Aiven-Open` → `Aiven-Open/journalpump`
- **Vulnerable version:** tag **2.4.6** (`3e1b59c8d95c1be8ad536088a389a3f36dec15a2`)
- **Unreleased fixes (master, no newer tag):**
  - `dbe51f2` — escape newlines in syslog messages **by default**
  - `9fb67a4` — sanitize rsyslog header fields on every record

## Title
Local process can forge arbitrary syslog records via newlines in journal MESSAGE / SYSLOG_IDENTIFIER when journalpump forwards with default non-transparent TCP framing.

## Root cause
`SyslogTcpClient.log()` on 2.4.6 embeds `program`, `hostname`, `pid`, `msgid`, and `msg` into the RFC 5424/3164 line **without** escaping CR/LF. The TCP sender uses **non-transparent framing** (records delimited by `\n`). Any embedded newline terminates the physical record; subsequent bytes that look like a syslog header are accepted by typical receivers as a **new authentic event**.

Journald allows unprivileged local processes to set `MESSAGE` and `SYSLOG_IDENTIFIER` (e.g. via `logger` / sd-journal). Those values are read by journalpump and forwarded unchanged.

Fingerprint: `journalpump | rsyslog SyslogTcpClient.log/send | journal MESSAGE/SYSLOG_IDENTIFIER with CR/LF | non-transparent syslog TCP framing | missing newline escape/sanitize (default) | CWE-117/CWE-93 | SIEM/log integrity forgery | local write to journald + rsyslog sender enabled`

## Trust-boundary failure
Local untrusted journal writers → journalpump (trusted forwarder) → remote SIEM/syslog (treats each newline-delimited line as a trusted host event).

## Affected code (2.4.6)
- `journalpump/rsyslog.py` — `SyslogTcpClient.log()` assigns header/body fields raw; `send()` writes newline-delimited frames
- `journalpump/senders/rsyslog.py` — passes `HOSTNAME` / appname / `MESSAGE` from journal entries into `log()`

## Reproduction (harmless, synthetic, no network)
```bash
cd poc/r21-journalpump-log-inject
python3 poc_log_inject.py
```
Expected: TEST 1 and TEST 2 print ≥2 physical records including forged `sshd` / `forged-as-root` lines; negative control on master emits **exactly one** physical record with sanitized/escaped content; `poc_results.txt` = `ALL PoC CHECKS PASSED`.

### Actual (2.4.6)
Two TCP records from one `log()` call; forged second record attributed to `forged-host` / `sshd` or `victim` / `root`.

### Expected
Single framed record; header controls stripped/escaped so receivers cannot parse a second event.

### Negative controls
- Master `rsyslog.py` with `escape_newlines=True` + `_sanitize_header_field` → one record (PoC TEST 3).
- Octet-counted framing (post-fix path) length-prefixes the body; combined with header sanitize, header newlines cannot open a new frame.

## Impact
- **Integrity:** Plant false security events (fake logins, fake alerts) in central logging / SIEM.
- **Detection evasion:** Mix forged noise with real events; attribute actions to other hosts/programs.
- **Prerequisites:** journalpump running with an rsyslog TCP sender (Aiven cloud rsyslog integrations expose `escape_newlines` defaulting to **false** in Terraform docs as of research date); attacker can write to the local journal (any local user/process).
- **Limitations:** Not remote RCE; integrity of logs, not confidentiality of other tenants. Impact scales with how much operators trust syslog attribution.

## CWE / CVSS (conservative)
- **CWE-117** Improper Output Neutralization for Logs; **CWE-93** CRLF Injection
- **CVSS 3.1:** `AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N` ≈ **6.5 Medium** (Scope Changed: impacts SIEM trust)

## Duplicate search
- **GHSA-738v-v386-8r6g** — different issue (integration **config** written into pipeline). Not this sink.
- No CVE/GHSA found for newline-based syslog record forgery in journalpump.
- Upstream commits themselves describe the forgery; fixes unreleased as a tag.

## Distinctness
Not C69 (Karapace OAuth inherit), not C26. New component (journalpump), new sink (syslog framing).

## Remediation
Ship a tagged release including `dbe51f2` + `9fb67a4` (default escape + unconditional header sanitize). Until then, operators should set `escape_newlines: true` or use octet-counted framing **and** ensure header fields cannot contain controls (sanitize still required per `9fb67a4`).

## Realistic payout
Bugcrowd Medium / P3 band for Aiven OSS — roughly **$250–$1,000** depending on triage (log integrity vs “hardening”).

## Evidence
- Package: `EVIDENCE_C75.tar.gz` (sha256 in `hashes.sha256`)
- PoC: `poc_log_inject.py`
- Vulnerable + fixed sources under `evidence/`
