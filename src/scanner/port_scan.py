"""
async tcp port scanner with realtime per-port service detection

refs:
- https://nmap.org/book/man.html
- https://nmap.org/book/vscan.html
- https://nmap.org/book/output-formats-xml-output.html
- https://nmap.org/book/nmap-services.html
- https://docs.python.org/3/library/asyncio-stream.html
- https://docs.python.org/3/library/socket.html
- https://docs.python.org/3/library/ssl.html
- https://docs.python.org/3/library/xml.etree.elementtree.html
- https://www.rfc-editor.org/rfc/rfc4253
- https://www.rfc-editor.org/rfc/rfc8446
- https://www.rfc-editor.org/rfc/rfc9112
"""

import argparse
import asyncio
import csv
import getpass
import html
import ipaddress
import io
import json
import os
import random
import re
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

import select
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# output goes here
console = Console(highlight=False)

# colors we use throughout
CYAN = "cyan"
GREEN = "bright_green"
RED = "bright_red"
YELLOW = "yellow"
WHITE = "white"
DIM = "grey50"
DIMMER = "grey35"
DETAIL = "grey62"
BORDER = "grey23"
SVC_COL = "cyan"

# common ports that benefit from a lightweight native probe
WEB_PORTS = {
    80,
    81,
    88,
    2052,
    2082,
    2086,
    2095,
    3000,
    5000,
    8000,
    8008,
    8080,
    8888,
    9000,
    9090,
}
TLS_WEB_PORTS = {443, 2053, 2083, 2087, 2096, 4443, 8443, 9443}
SSH_PROBE_PORTS = {22}
HTTP_PROBE_TIMEOUT = 0.75
HTTP_PROBE_LIMIT = 16384
HTTP_TITLE_MAX = 120
SSH_BANNER_LIMIT = 256
LIVE_REFRESH_INTERVAL = 0.10
SVC_PROGRESS_POLL = 0.05
LARGE_SCAN_PORT_THRESHOLD = 4096
WEB_SVC_HINTS = ("http", "https", "proxy", "www", "web")

HTTP_BLOCK_STATUSES = {403, 429, 503}

HTTP_SSL_CTX = ssl.create_default_context()
HTTP_SSL_CTX.check_hostname = False
HTTP_SSL_CTX.verify_mode = ssl.CERT_NONE

# nmap services db paths
# checked in order, first one found wins
NMAP_DB = [
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
]

# port -> service name mapping
# most common ports, saves us from calling nmap for basic stuff
PORT2SVC: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    # 8443: "https-alt",
}


def parse_ports(raw: Optional[str]) -> List[int]:
    # default to well-known ports (1-1024) if nothing given
    if not raw:
        return list(range(1, 1025))

    out: set = set()

    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue

        # range notation: 1-1024
        if "-" in chunk:
            left, right = chunk.split("-", 1)
            if not (left.strip().isdigit() and right.strip().isdigit()):
                continue

            a, b = int(left), int(right)
            # swap if reversed (1024-1 instead of 1-1024)
            if a > b:
                a, b = b, a

            out.update(p for p in range(a, b + 1) if 0 < p < 65536)
        else:
            # single port
            if chunk.isdigit():
                p = int(chunk)
                if 0 < p < 65536:
                    out.add(p)

    return sorted(out)


def top_ports(n: int) -> List[int]:
    for db_path in NMAP_DB:
        p = Path(db_path)
        if not p.exists():
            continue

        scored = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            # skip blanks and comments
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            # need at least: port/proto, service, frequency
            if len(parts) < 3 or not parts[1].endswith("/tcp"):
                continue

            # extract port number
            port_str = parts[1].split("/", 1)[0]
            if not port_str.isdigit():
                continue

            # frequency score (lower = more common)
            try:
                score = float(parts[2])
            except ValueError:
                continue

            port = int(port_str)
            if 0 < port < 65536:
                scored.append((score, port))

        if scored:
            scored.sort(key=lambda x: x[0], reverse=True)

            res, seen = [], set()
            for _score, port in scored:
                if port not in seen:
                    res.append(port)
                    seen.add(port)
                    if len(res) >= n:
                        break

            if res:
                return res

    # db not found, just sequential ports
    return list(range(1, min(n, 65535) + 1))


def guess_svc_meta(port: int):
    """
    # Service Lookup Chain
    # --------------------
    # 1. PORT2SVC (builtin)  → fastest
    # 2. /etc/services       → system fallback
    # 3. "unknown"            → nothing found
    #
    # Returns: (service_name, source)
    #   source: "builtin" | "system" | "none"
    """
    if port in PORT2SVC:
        return PORT2SVC[port], "builtin"

    try:
        return socket.getservbyport(port, "tcp"), "system"
    except OSError:
        return "unknown", "none"


def guess_svc(port: int) -> str:
    svc, _source = guess_svc_meta(port)
    return svc


def should_try_http_probe(port: int, guessed_svc: str, guess_source: str) -> bool:
    low = guessed_svc.lower()

    if port in WEB_PORTS or port in TLS_WEB_PORTS:
        return True
    if port in SSH_PROBE_PORTS or low == "ssh":
        return False
    if any(hint in low for hint in WEB_SVC_HINTS):
        return True
    if port >= 1024 and guess_source != "builtin":
        return True
    return False


def has_http_probe_signal(res) -> bool:
    if res.err is not None:
        return False

    raw = (res.raw or "").lstrip().lower()
    info = (res.info or "").lower()
    return (
        raw.startswith("http/")
        or "http/" in info
        or "title:" in info
        or "server:" in info
        or "cf-ray" in info
        or "redirect" in info
    )


def parse_nmap_row(out: str):
    """
    # Nmap Output Format
    # ------------------
    # PORT      STATE  SERVICE      VERSION
    # 22/tcp    open   ssh          OpenSSH 8.4p1 Debian 5
    #
    # Returns: dict with lowest port | None on failure
    """
    rows = parse_nmap_rows(out)
    if not rows:
        return None
    return rows[sorted(rows)[0]]


def parse_nmap_rows(out: str) -> Dict[int, Dict[str, str]]:
    """
    # Parses nmap text output:
    #
    #   22/tcp   open   ssh     OpenSSH 8.4p1 Debian 5
    #   80/tcp   open   http    Apache httpd 2.4.46
    #   443/tcp  open   https   nginx 1.18.0
    #
    # Returns: {port: {"port", "state", "svc", "info"}}
    """
    rows: Dict[int, Dict[str, str]] = {}
    for line in out.splitlines():
        m = re.match(
            r"^\s*(\d+)\/tcp\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$", line
        )
        if m:
            port = int(m.group(1))
            rows[port] = {
                "port": port,
                "state": m.group(2),
                "svc": m.group(3),
                "info": (m.group(4) or "").strip(),
            }
    return rows


def _nmap_xml_svc_name(service_el: Optional[ET.Element], port: int) -> str:
    if service_el is None:
        return guess_svc(port)

    name = (service_el.get("name") or "").strip()
    tunnel = (service_el.get("tunnel") or "").strip()
    if tunnel and name:
        return f"{tunnel}/{name}"
    if name:
        return name
    return guess_svc(port)


def _nmap_xml_info(service_el: Optional[ET.Element], port_el: ET.Element) -> str:
    info_parts: List[str] = []

    if service_el is not None:
        for attr in ("product", "version", "extrainfo"):
            value = (service_el.get(attr) or "").strip()
            if value:
                info_parts.append(value)

    for script_el in port_el.findall("script"):
        output = (script_el.get("output") or "").strip()
        if output:
            info_parts.append(output)

    return " | ".join(info_parts)


def parse_nmap_xml_rows(xml_text: str) -> Dict[int, Dict[str, str]]:
    rows: Dict[int, Dict[str, str]] = {}
    if not xml_text.strip():
        return rows

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return rows

    for port_el in root.findall(".//host/ports/port"):
        if (port_el.get("protocol") or "").strip().lower() != "tcp":
            continue

        port_id = (port_el.get("portid") or "").strip()
        if not port_id.isdigit():
            continue

        port = int(port_id)
        state_el = port_el.find("state")
        if state_el is None:
            continue

        state = (state_el.get("state") or "").strip()
        service_el = port_el.find("service")
        rows[port] = {
            "port": port,
            "state": state or "unknown",
            "svc": _nmap_xml_svc_name(service_el, port),
            "info": _nmap_xml_info(service_el, port_el),
            "raw": ET.tostring(port_el, encoding="unicode"),
        }

    return rows


def merge_nmap_rows(
    text_rows: Dict[int, Dict[str, str]],
    xml_rows: Dict[int, Dict[str, str]],
) -> Dict[int, Dict[str, str]]:
    merged: Dict[int, Dict[str, str]] = {}

    for port in sorted(set(text_rows) | set(xml_rows)):
        row = dict(xml_rows.get(port, {}))
        for key, value in text_rows.get(port, {}).items():
            if value not in (None, ""):
                row[key] = value
        merged[port] = row

    return merged


def parse_nmap_ignored_counts(out: str) -> Dict[str, int]:
    counts = {"closed": 0, "filtered": 0}

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Not shown:"):
            for count, state in re.findall(
                r"(\d+)\s+(closed|filtered)\s+tcp\s+ports?", line
            ):
                counts[state] += int(count)
        else:
            m = re.match(
                r"^All\s+(\d+)\s+scanned ports on .+ are (closed|filtered)\.?$",
                line,
            )
            if m:
                counts[m.group(2)] += int(m.group(1))

    return counts


def sock_addr(ip: str, port: int, family: int):
    if family == socket.AF_INET6:
        return (ip, port, 0, 0)
    return (ip, port)


def grab_nmap_block(out: str, port: int) -> str:
    """
    # Extracts port block from nmap output:
    #
    #   22/tcp    open   ssh   OpenSSH 8.4p1
    #   | ssh-hostkey:
    #   |   2048 SHA256:xxxxx
    #   |_  1024 SHA256:yyyyy
    #
    # Stops at: blank line | next port | scan report header
    # Returns: "" if port not found
    """
    lines = out.splitlines()
    needle = f"{port}/tcp"
    idx = None

    # find start
    for i, ln in enumerate(lines):
        if ln.strip().startswith(needle):
            idx = i
            break

    if idx is None:
        return ""

    block = [lines[idx].strip()]

    # collect until blank line, next port, or new scan report
    for ln in lines[idx + 1 :]:
        s = ln.strip()
        if not s:
            break
        if re.match(r"^\d+/(tcp|udp)\s", s):
            break
        if s.startswith("Nmap scan report"):
            break
        # nested output starts with |
        if (
            s.startswith("|")
            or s.startswith("Service Info:")
            or s.startswith("Warning:")
        ):
            block.append(s)

    return "\n".join(block)


# scan configuration
@dataclass
class Cfg:
    target: str
    ports: List[int]
    c_conc: int
    c_to: float
    s_conc: int
    n_args: List[str]
    svc_on: bool
    aggr_on: bool
    sudo_pw: Optional[str]
    stealth: bool  # enable stealth mode with timing jitter
    syn_scan: bool  # use SYN scan (half-open) instead of full TCP connect
    verbose: int = 0
    quiet: bool = False


# result from service detection on one port
@dataclass
class SvcInfo:
    port: int
    ok: bool
    state: str
    svc: str
    info: str
    elapsed: float
    n_cmd: str
    raw: str
    err: Optional[str]

    def to_dict(self):
        return self.__dict__


# complete scan result for one target
@dataclass
class ScanOut:
    target: str
    ip: str
    req_ports: List[int]
    open_ports: List[int]
    svcs: List[SvcInfo]
    started: str
    finished: str
    elapsed: float
    errors: List[str]

    def to_dict(self):
        d = dict(self.__dict__)
        d["svcs"] = [s.to_dict() for s in self.svcs]
        return d


def hr(title: str = "") -> None:
    if title:
        console.print(
            Rule(title=Text(f"  {title}  ", style=DIMMER), style=BORDER, align="left")
        )
    else:
        console.print(Rule(style=BORDER))


def _clean_text(value: str, limit: int = 0) -> str:
    text = " ".join(html.unescape(value).split())
    if limit > 0 and len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _extract_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return _clean_text(match.group(1), HTTP_TITLE_MAX)


def _flatten_cert_name(parts) -> Dict[str, str]:
    flat: Dict[str, str] = {}
    for item in parts or ():
        for key, value in item:
            flat[key] = value
    return flat


def _fmt_cert_date(raw: str) -> str:
    if not raw:
        return ""
    normalized = re.sub(r"\s+", " ", raw.strip())
    try:
        return datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z").strftime(
            "%Y-%m-%d"
        )
    except ValueError:
        return normalized


def _tls_cert_bits(cert: Optional[Dict[str, object]]) -> List[str]:
    if not cert:
        return []

    bits: List[str] = []
    subject = _flatten_cert_name(cert.get("subject"))
    common_name = subject.get("commonName", "")
    if common_name:
        bits.append(f"TLS CN: {_clean_text(common_name, 80)}")

    san = cert.get("subjectAltName") or []
    dns_names = [value for kind, value in san if kind.lower() == "dns"]
    if dns_names:
        first = _clean_text(dns_names[0], 80)
        if len(dns_names) > 1:
            bits.append(f"TLS SAN: {first} (+{len(dns_names) - 1})")
        elif first != common_name:
            bits.append(f"TLS SAN: {first}")

    expires = _fmt_cert_date(str(cert.get("notAfter", "")).strip())
    if expires:
        bits.append(f"TLS Expires: {expires}")

    return bits


def _probe_detail_panel(res: ScanOut, verbose: int) -> Optional[Panel]:
    if verbose <= 0 or not res.svcs:
        return None

    lines: List[Text] = []
    for svc in sorted(res.svcs, key=lambda item: item.port):
        head = Text.assemble(
            (f"{svc.port:>5}/tcp", f"bold {WHITE}"),
            ("  ", DIM),
            (svc.svc, SVC_COL),
            ("  ", DIM),
            (f"{svc.elapsed:.3f}s", DIM),
        )
        if svc.n_cmd:
            head.append(f"  via {svc.n_cmd}", style=DIMMER)
        if svc.err:
            head.append(f"  err={svc.err}", style=YELLOW)
        lines.append(head)

        if svc.info:
            lines.append(Text(f"      {_clean_text(svc.info, 220)}", style=DIMMER))
        if verbose > 1 and svc.raw:
            lines.append(Text(f"      raw: {_clean_text(svc.raw, 260)}", style=DETAIL))

    return Panel(
        Group(*lines),
        title=f"[bold {WHITE}]Probe Details[/bold {WHITE}]",
        border_style=BORDER,
        box=box.ROUNDED,
        expand=True,
    )


def hdr(hosts: List[str], total_ports: int, cfg: Cfg) -> None:
    """
    # Scan Header Banner
    # ------------------
    # X3R0DAY  //  Async TCP Port Scanner  [STEALTH]
    # ─────────────────────────────────────────────────
    #
    # Target    scanme.nmap.org           Timeout   2.00s
    # Ports     1,024 selected            Svc Scan  basic
    # Max Conc  256                       Started   2026-03-27  14:30:00
    """
    console.print()
    hr()

    # tool title
    title = Text()
    title.append("  X3R0DAY", style=f"bold {CYAN}")
    title.append("  //  ", style=DIM)
    title.append("Async TCP Port Scanner", style=f"bold {WHITE}")
    if cfg.stealth:
        title.append("  ", style=DIM)
        title.append("[STEALTH]", style=f"bold {YELLOW}")
    console.print(title)

    hr()
    console.print()

    # figure out what mode we're in
    mode = (
        "aggressive (nmap)"
        if cfg.aggr_on
        else "basic (light probe)"
        if cfg.svc_on
        else "disabled"
    )

    # settings grid
    grid = Table.grid(padding=(0, 0))
    grid.add_column(min_width=16)
    grid.add_column(min_width=28)
    grid.add_column(min_width=6)
    grid.add_column(min_width=16)
    grid.add_column()

    rows = [
        ("Target", ", ".join(hosts), "Timeout", f"{cfg.c_to:.2f}s"),
        ("Ports", f"{total_ports:,} selected", "Svc Scan", mode),
        (
            "Max Concurrency",
            str(cfg.c_conc),
            "Started",
            datetime.now().strftime("%Y-%m-%d  %H:%M:%S"),
        ),
    ]

    for k1, v1, k2, v2 in rows:
        grid.add_row(
            Text(k1, style=DIM),
            Text(v1, style=WHITE),
            Text(""),
            Text(k2, style=DIM),
            Text(v2, style=WHITE),
        )

    console.print(Padding(grid, (0, 2)))
    console.print()
    hr()
    console.print()


def mk_prog(transient: bool = True) -> Progress:
    """
    # Progress Bar Layout
    # -------------------
    # [spinner]  task description  ████████████████░░░░  45%  12/27  0:05:02  0:06:11
    #             ↑                ↑         ↑                  ↑       ↑        ↑
    #           spinner         bar fill   fraction           count   elapsed  remaining
    #
    # transient=True  → disappears on finish
    # transient=False → stays visible
    """
    return Progress(
        SpinnerColumn(spinner_name="dots2", style=CYAN),
        TextColumn("  [bold white]{task.description}[/bold white]"),
        BarColumn(
            bar_width=44, style=DIMMER, complete_style=CYAN, finished_style=GREEN
        ),
        TaskProgressColumn(style=DIM),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=transient,
    )


def state_label(state: str) -> Text:
    """
    # State Color Mapping
    # -------------------
    # "open"     → bright_green  "open"
    # "closed"   → bright_red    "closed"
    # "filtered" → yellow        "filtered"
    # "failed"   → bright_red    "failed"
    # <other>    → grey50        <state>
    """
    mapping = {
        "open": (GREEN, "open"),
        "closed": (RED, "closed"),
        "filtered": (YELLOW, "filtered"),
        "failed": (RED, "failed"),
    }
    style, label = mapping.get(state, (DIM, state))
    return Text(label, style=style)


def res_tbl(res: ScanOut) -> Table:
    """
    # Results Table Format
    # --------------------
    # PORT    PROTO   STATE     SERVICE           DETAILS
    # -----   -----   -----     -------           -------
    # 22      tcp     open      ssh               OpenSSH 8.4p1 Debian...
    # 80      tcp     open      http              Apache/2.4.46
    #
    # Truncates details >55 chars
    """
    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {DIM}",
        border_style=BORDER,
        show_edge=True,
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("PORT", style=WHITE, justify="right", width=7, no_wrap=True)
    tbl.add_column("PROTO", style=DIM, justify="center", width=7, no_wrap=True)
    tbl.add_column("STATE", justify="left", width=10, no_wrap=True)
    tbl.add_column("SERVICE", style=SVC_COL, justify="left", width=20, no_wrap=True)
    tbl.add_column("DETAILS", style=DETAIL, justify="left", min_width=30, max_width=55)

    # quick lookup: port -> service info
    svc_map = {s.port: s for s in res.svcs}

    for port in res.open_ports:
        sv = svc_map.get(port)
        svc = sv.svc if sv else "unknown"
        info = sv.info if sv else ""
        state = sv.state if sv else "open"

        # Clean up newlines that break formatting
        if info:
            info = " ".join(info.split())

        # chop long details to fit table
        if len(info) > 55:
            info = info[:52] + "..."
        tbl.add_row(str(port), "tcp", state_label(state), svc, info)

    return tbl


def stats_tbl(res: ScanOut) -> Table:
    """
    # Scan Stats Grid
    # ---------------
    # Scanned    65,535 ports    Elapsed   12.456s
    # Open       3  [0.0%]       Started   2026-03-27  14:30:00
    # Closed     65,532          Filtered  0         Finished   2026-03-27  14:30:12
    """
    total = len(res.req_ports)
    opened = len(res.open_ports)
    filtered = getattr(res, "_filtered_count", 0)
    closed = getattr(res, "_closed_count", max(total - opened - filtered, 0))
    pct = opened / total * 100 if total > 0 else 0.0
    # strip timezone and format timestamps
    ts = res.started[:19].replace("T", "  ")
    tf = res.finished[:19].replace("T", "  ")

    grid = Table.grid(padding=(0, 4))
    grid.add_column(min_width=13, no_wrap=True)
    grid.add_column(min_width=20, no_wrap=True)
    grid.add_column(min_width=13, no_wrap=True)
    grid.add_column(min_width=22, no_wrap=True)
    grid.add_column(min_width=13, no_wrap=True)
    grid.add_column(min_width=18, no_wrap=True)

    def k(s):
        return Text(s, style=DIM)

    def v(s):
        return Text(s, style=WHITE)

    # row 1: scanned count, elapsed time, target
    grid.add_row(
        k("Scanned"),
        v(f"{total:,} ports"),
        k("Elapsed"),
        v(f"{res.elapsed:.3f}s"),
        k("Target"),
        v(res.target),
    )
    # row 2: open count with %, start time, ip
    grid.add_row(
        k("Open"), v(f"{opened}  [{pct:.1f}%]"), k("Started"), v(ts), k("IP"), v(res.ip)
    )
    # row 3: closed count, filtered count, finish time
    grid.add_row(
        k("Closed"),
        v(str(closed)),
        k("Filtered"),
        v(str(filtered)),
        k("Finished"),
        v(tf),
    )

    return grid


def show(res: ScanOut, idx: int = 0, total: int = 1, verbose: int = 0) -> None:
    """
    # Output Flow
    # -----------
    # 1. [Target 1/3]                    ← only if total > 1
    # 2. ┌─ Scan Summary ─────────────┐
    #    │  Scanned  Open  Elapsed    │
    #    └────────────────────────────┘
    # 3. ┌─ Open Ports • target ──────┐
    #    │  PORT  STATE  SERVICE      │
    #    │  22    open   ssh          │
    #    └────────────────────────────┘
    # 4. [Probe Details]               ← only if verbose > 0
    """
    console.print()
    # show target number header when scanning multiple
    if total > 1:
        hr(f"Target {idx + 1}/{total}")

    # stats panel
    stats_panel = Panel(
        Padding(stats_tbl(res), (0, 1)),
        title=f"[bold {WHITE}]Scan Summary[/bold {WHITE}]",
        border_style=BORDER,
        box=box.ROUNDED,
        expand=True,
    )
    console.print(stats_panel)

    # open ports table or "nothing found" message
    if res.open_ports:
        results_panel = Panel(
            Padding(res_tbl(res), (0, 1)),
            title=f"[bold {WHITE}]Open Ports  •  {res.target}[/bold {WHITE}]",
            border_style=CYAN,
            box=box.ROUNDED,
            expand=True,
        )
    else:
        msg = Text("No open ports discovered in selected range.", style=DIM)
        results_panel = Panel(
            Padding(msg, (0, 1)),
            title=f"[bold {WHITE}]Open Ports  •  {res.target}[/bold {WHITE}]",
            border_style=BORDER,
            box=box.ROUNDED,
            expand=True,
        )

    console.print(results_panel)
    detail_panel = _probe_detail_panel(res, verbose)
    if detail_panel is not None:
        console.print(detail_panel)
    console.print()


def multi_sum(results: List[ScanOut]) -> None:
    """
    # Aggregate Summary Table
    # -----------------------
    # #   TARGET              IP              OPEN  SCANNED  ELAPSED
    # -   ------              --              ----  -------  -------
    # 1   example.com         93.184.216.34   3     1,024    1.234s
    # 2   scanme.nmap.org     45.33.32.156    5     100      0.892s
    #                                      ─────────────────────────────
    #     TOTAL                                   8     1,124
    """
    if len(results) < 2:
        return

    console.print()
    hr("Aggregate Summary")
    console.print()

    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {DIM}",
        border_style=BORDER,
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("#", style=DIM, justify="right", width=4)
    tbl.add_column("TARGET", style=WHITE, justify="left", min_width=26)
    tbl.add_column("IP", style=DIM, justify="left", min_width=16)
    tbl.add_column("OPEN", justify="right", width=7)
    tbl.add_column("SCANNED", style=DIM, justify="right", width=9)
    tbl.add_column("ELAPSED", style=DIM, justify="right", width=10)

    total_open = 0
    total_scanned = 0

    for i, res in enumerate(results, 1):
        n = len(res.open_ports)
        total_open += n
        total_scanned += len(res.req_ports)
        tbl.add_row(
            str(i),
            res.target,
            res.ip,
            Text(str(n), style=GREEN if n > 0 else DIM),
            f"{len(res.req_ports):,}",
            f"{res.elapsed:.3f}s",
        )

    # totals row
    tbl.add_section()
    tbl.add_row(
        "",
        Text("TOTAL", style=DIM),
        "",
        Text(str(total_open), style=f"bold {GREEN}"),
        Text(f"{total_scanned:,}", style="bold"),
        "",
    )

    console.print(Padding(tbl, (0, 2)))
    console.print()
    hr()
    console.print()


# build live discovery table showing ports as they're found
def live_disc_tbl(open_ports: List[int], target: str) -> Table:
    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style=f"bold {WHITE}",
        border_style=CYAN,
        title=f"[bold {WHITE}]Open Ports Discovered  •  {target}[/bold {WHITE}]",
        title_style=f"bold {WHITE}",
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("PORT", style=GREEN, justify="right", width=8, no_wrap=True)
    tbl.add_column("SERVICE", style=SVC_COL, justify="left", width=20, no_wrap=True)

    if not open_ports:
        tbl.add_row(
            Text("scanning...", style=DIM, justify="center"), Text("", style=DIM)
        )
    else:
        for port in sorted(open_ports):
            svc = guess_svc(port)
            tbl.add_row(str(port), svc)

    return tbl


# build combined renderable: progress bar + discovered ports table
def build_live_panel(progress: Progress, open_ports: List[int], target: str) -> Group:
    parts = [progress]
    if open_ports:
        parts.append(Text(""))  # spacer
        parts.append(live_disc_tbl(open_ports, target))
    return Group(*parts)


def _out_mode(raw: str):
    out = Path(raw)
    if not out.suffix:
        out = out.with_name(out.name + ".html")
        return out, "html"

    suf = out.suffix.lower()
    if suf == ".json":
        return out, "json"
    if suf == ".csv":
        return out, "csv"
    return out, "html"


def _csv_scan(results: List[ScanOut]) -> str:
    buf = io.StringIO()
    fields = [
        "target",
        "ip",
        "port",
        "proto",
        "state",
        "service",
        "details",
        "probe_elapsed",
        "probe_cmd",
        "probe_error",
        "scan_started",
        "scan_finished",
        "scan_elapsed",
        "scanned",
        "open_count",
        "closed_count",
        "filtered_count",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()

    for res in results:
        total = len(res.req_ports)
        opened = len(res.open_ports)
        filtered = getattr(res, "_filtered_count", 0)
        closed = getattr(res, "_closed_count", max(total - opened - filtered, 0))
        svc_map = {svc.port: svc for svc in res.svcs}
        row_ports = res.open_ports or [0]

        for port in row_ports:
            svc = svc_map.get(port)
            writer.writerow(
                {
                    "target": res.target,
                    "ip": res.ip,
                    "port": port or "",
                    "proto": "tcp" if port else "",
                    "state": svc.state if svc else "",
                    "service": svc.svc if svc else "",
                    "details": _clean_text(svc.info, 500) if svc else "",
                    "probe_elapsed": f"{svc.elapsed:.3f}" if svc else "",
                    "probe_cmd": svc.n_cmd if svc else "",
                    "probe_error": svc.err if svc and svc.err else "",
                    "scan_started": res.started,
                    "scan_finished": res.finished,
                    "scan_elapsed": f"{res.elapsed:.3f}",
                    "scanned": total,
                    "open_count": opened,
                    "closed_count": closed,
                    "filtered_count": filtered,
                }
            )

    return buf.getvalue()


# build unified html report
def build_html(results: List[ScanOut]) -> str:
    lines = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "  <title>X3R0DAY Scan Report</title>",
        "  <style>",
        "    * { box-sizing: border-box; margin: 0; padding: 0; }",
        "    body {",
        "      font-family: system-ui, -apple-system, sans-serif;",
        "      background: #121212;",
        "      color: #d4d4d4;",
        "      font-size: 14px;",
        "      line-height: 1.5;",
        "      padding: 24px;",
        "    }",
        "    .wrap { max-width: 900px; margin: 0 auto; }",
        "    h1 {",
        "      font-size: 16px;",
        "      font-weight: 600;",
        "      color: #e0e0e0;",
        "      margin-bottom: 8px;",
        "    }",
        "    .meta { font-size: 12px; color: #707070; margin-bottom: 24px; }",
        "    hr { border: none; border-top: 1px solid #2a2a2a; margin: 24px 0; }",
        "    .target { margin-bottom: 16px; }",
        "    .target-name { font-size: 15px; font-weight: 500; color: #c0c0c0; }",
        "    .target-ip { font-size: 12px; color: #606060; margin-top: 2px; }",
        "    .stats { display: flex; gap: 24px; font-size: 13px; margin-bottom: 20px; }",
        "    .stats span { color: #606060; }",
        "    .stats strong { color: #a0a0a0; margin-left: 4px; }",
        "    .stats .open strong { color: #6a9955; }",
        "    table { width: 100%; border-collapse: collapse; }",
        "    th {",
        "      text-align: left;",
        "      font-size: 11px;",
        "      font-weight: 500;",
        "      color: #606060;",
        "      padding: 8px 12px;",
        "      border-bottom: 1px solid #2a2a2a;",
        "    }",
        "    td {",
        "      padding: 10px 12px;",
        "      border-bottom: 1px solid #1e1e1e;",
        "      vertical-align: top;",
        "    }",
        "    .port { font-family: monospace; color: #9cdcfe; }",
        "    .state { color: #6a9955; }",
        "    .service { color: #ce9178; }",
        "    .info { font-size: 12px; color: #606060; }",
        "    details { margin-top: 4px; }",
        "    summary {",
        "      color: #505050;",
        "      cursor: pointer;",
        "      font-size: 11px;",
        "      list-style: none;",
        "      display: flex;",
        "      align-items: center;",
        "      gap: 4px;",
        "    }",
        "    summary::-webkit-details-marker { display: none; }",
        "    summary::before { content: '▶'; font-size: 8px; transition: transform 0.1s; }",
        "    details[open] summary::before { transform: rotate(90deg); }",
        "    .detail-box {",
        "      margin-top: 8px;",
        "      padding: 12px;",
        "      background: #1a1a1a;",
        "      border: 1px solid #2a2a2a;",
        "      border-radius: 4px;",
        "      font-family: monospace;",
        "      font-size: 12px;",
        "      color: #808080;",
        "      white-space: pre-wrap;",
        "      word-break: break-all;",
        "      max-height: 200px;",
        "      overflow-y: auto;",
        "    }",
        "    .empty { color: #606060; font-size: 13px; padding: 16px 0; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <div class='wrap'>",
        "    <h1>Port Scan Report</h1>",
        f"    <p class='meta'>X3R0DAY Specter &middot; {len(results)} target(s) &middot; {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>",
    ]

    for res in results:
        total = len(res.req_ports)
        opened = len(res.open_ports)
        filtered = getattr(res, "_filtered_count", 0)
        closed = getattr(res, "_closed_count", max(total - opened - filtered, 0))

        lines.append("    <hr>")
        lines.append("    <div class='target'>")
        lines.append(f"      <div class='target-name'>{html.escape(res.target)}</div>")
        lines.append(f"      <div class='target-ip'>{html.escape(res.ip)}</div>")
        lines.append("    </div>")

        lines.append("    <div class='stats'>")
        lines.append(f"      <span>Scanned<strong>{total:,}</strong></span>")
        lines.append(f"      <span class='open'>Open<strong>{opened}</strong></span>")
        lines.append(f"      <span>Closed<strong>{closed}</strong></span>")
        lines.append(f"      <span>Filtered<strong>{filtered}</strong></span>")
        lines.append(f"      <span>{res.elapsed:.2f}s</span>")
        lines.append("    </div>")

        if res.open_ports:
            svc_map = {s.port: s for s in res.svcs}
            lines.append("    <table>")
            lines.append(
                "      <thead><tr><th style='width:70px'>Port</th><th style='width:60px'>State</th><th style='width:120px'>Service</th><th>Info</th></tr></thead>"
            )
            lines.append("      <tbody>")

            for port in res.open_ports:
                sv = svc_map.get(port)
                svc = sv.svc if sv else "unknown"
                info_short = _clean_text(sv.info, 80) if sv and sv.info else ""
                info_full = sv.info if sv and sv.info else ""

                lines.append("      <tr>")
                lines.append(f"        <td class='port'>{port}</td>")
                lines.append("        <td class='state'>open</td>")
                lines.append(f"        <td class='service'>{html.escape(svc)}</td>")
                lines.append("        <td class='info'>")

                if len(info_full) > 80:
                    lines.append(f"          {html.escape(info_short)}")
                    lines.append(f"          <details>")
                    lines.append(f"            <summary>show more</summary>")
                    lines.append(
                        f"            <div class='detail-box'>{html.escape(info_full)}</div>"
                    )
                    lines.append(f"          </details>")
                else:
                    lines.append(f"          {html.escape(info_short)}")

                lines.append("        </td>")
                lines.append("      </tr>")

            lines.append("      </tbody>")
            lines.append("    </table>")
        else:
            lines.append("    <p class='empty'>No open ports found</p>")

    lines.append("  </div>")
    lines.append("</body>")
    lines.append("</html>")

    return "\n".join(lines)


# custom semaphore for the fallback scanner to enable sliding window concurrency
class DynamicSemaphore:
    def __init__(self, value: int):
        self.value = value
        self.max_value = value
        self.current = 0
        self.cond = asyncio.Condition()

    async def acquire(self):
        async with self.cond:
            while self.current >= self.value:
                await self.cond.wait()
            self.current += 1

    async def release(self):
        async with self.cond:
            self.current -= 1
            self.cond.notify()

    async def set_value(self, new_val: int):
        async with self.cond:
            self.value = min(self.max_value, max(1, new_val))
            self.cond.notify_all()


# SYN scan helper functions for raw socket packet construction
def checksum(data: bytes) -> int:
    """Calculate Internet checksum (RFC 1071)"""
    if len(data) % 2 != 0:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_tcp_header(
    src_port: int, dst_port: int, seq: int, ack: int, flags: int
) -> bytes:
    """Build TCP header with SYN flag"""
    # TCP header fields
    data_offset = 5  # 5 * 4 = 20 bytes (no options)
    window = socket.htons(65535)
    checksum_val = 0  # Will be calculated later
    urgent_ptr = 0

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,  # Source port
        dst_port,  # Destination port
        seq,  # Sequence number
        ack,  # Acknowledgment number
        (data_offset << 4),  # Data offset (4 bits) + reserved (4 bits)
        flags,  # Flags (SYN = 0x02, ACK = 0x10, RST = 0x04)
        window,  # Window size
        checksum_val,  # Checksum (0 for now)
        urgent_ptr,  # Urgent pointer
    )
    return tcp_header


def build_tcp_pseudo_header(src_ip: str, dst_ip: str, tcp_len: int) -> bytes:
    """Build TCP pseudo header for checksum calculation"""
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    reserved = 0
    protocol = socket.IPPROTO_TCP

    pseudo_header = struct.pack(
        "!4s4sBBH", src_addr, dst_addr, reserved, protocol, tcp_len
    )
    return pseudo_header


def build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build complete TCP SYN packet"""
    # TCP header
    seq = random.randint(0, 0xFFFFFFFF)
    ack = 0
    flags = 0x02  # SYN flag

    tcp_header = build_tcp_header(src_port, dst_port, seq, ack, flags)

    # Pseudo header for checksum
    pseudo_header = build_tcp_pseudo_header(src_ip, dst_ip, len(tcp_header))

    # Calculate checksum
    checksum_val = checksum(pseudo_header + tcp_header)

    # Rebuild TCP header with correct checksum
    tcp_header = (
        struct.pack(
            "!HHIIBBH",
            src_port,
            dst_port,
            seq,
            ack,
            (5 << 4),
            flags,
            socket.htons(65535),
        )
        + struct.pack("H", checksum_val)
        + struct.pack("!H", 0)
    )

    return tcp_header


def parse_tcp_response(data: bytes) -> Optional[tuple]:
    """Parse TCP response to extract flags and port information"""
    try:
        # Skip IP header (typically 20 bytes, but check IHL)
        ihl = (data[0] & 0x0F) * 4
        tcp_header = data[ihl : ihl + 20]

        if len(tcp_header) < 20:
            return None

        # Unpack TCP header
        tcp_data = struct.unpack("!HHIIBBHHH", tcp_header)
        src_port = tcp_data[0]
        dst_port = tcp_data[1]
        flags = tcp_data[5]

        # Check for SYN-ACK (0x12) or RST-ACK (0x14) or RST (0x04)
        return (src_port, dst_port, flags)
    except Exception:
        return None


class Scanner:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._s_sem = asyncio.Semaphore(cfg.s_conc)
        self._svc_tasks: List[asyncio.Task] = []
        self._svc_results: Dict[int, SvcInfo] = {}
        self._svc_scheduled: Set[int] = set()
        self._svcs: List[SvcInfo] = []
        self._lock = asyncio.Lock()
        self._st = {p: "pending" for p in cfg.ports}
        self._tested = 0
        self._open = 0
        self._closed = 0
        self._filtered = 0
        self._svc_started = 0
        self._svc_done = 0
        self._svc_failed = 0
        self._open_ports: List[int] = []
        self._live_next_refresh = 0.0
        self._http_probe_blocked = False
        self._target_is_ip = self._is_ip_literal(cfg.target)
        self._raw_sock = None
        self._src_ip = None
        self._resolved_ip: Optional[str] = None

        # SYN scan receiver state
        self._syn_receiver_task: Optional[asyncio.Task] = None
        self._syn_tracking: Dict[
            int, tuple
        ] = {}  # src_port -> (dst_port, event, result_holder, started_at)
        self._syn_tracking_lock = asyncio.Lock()
        self._syn_receiver_lock = asyncio.Lock()
        self._syn_receiver_running = False

        # Create raw socket for SYN scan if enabled
        if cfg.syn_scan:
            try:
                self._raw_sock = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
                )
                self._raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
                self._raw_sock.setblocking(False)
                # Get source IP by connecting to the target (or use 0.0.0.0)
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    test_sock.connect(
                        (
                            cfg.target
                            if self._target_is_ip
                            else socket.gethostbyname(cfg.target),
                            80,
                        )
                    )
                    self._src_ip = test_sock.getsockname()[0]
                    test_sock.close()
                except Exception:
                    self._src_ip = "0.0.0.0"
            except PermissionError:
                # Will be caught during validation
                pass

    # mark port as started service scan
    async def _mark_svc_start(self, port: int):
        async with self._lock:
            self._svc_started += 1
            self._st[port] = "scanning"

    # mark service scan as done
    async def _mark_svc_done(self, port: int, ok: bool):
        async with self._lock:
            self._svc_done += 1
            self._st[port] = "done" if ok else "failed"
            if not ok:
                self._svc_failed += 1

    def _is_ip_literal(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _ordered_ports(self) -> List[int]:
        common = set(top_ports(min(1000, len(self.cfg.ports))))
        priority = [p for p in self.cfg.ports if p in common]
        rest = [p for p in self.cfg.ports if p not in common]
        return priority + rest

    def _scan_profile(self) -> Dict[str, int]:
        port_count = len(self.cfg.ports)

        if self.cfg.stealth:
            return {
                "window": max(1, min(self.cfg.c_conc, 96)),
                "max_window": max(1, min(self.cfg.c_conc, 192)),
                "min_window": max(1, min(self.cfg.c_conc, 24)),
                "increase": 4,
                "max_retries": 0,
                "timeout_floor": min(self.cfg.c_to, 0.25),
            }

        if port_count >= LARGE_SCAN_PORT_THRESHOLD:
            start_window = max(1, min(self.cfg.c_conc, 1024))
            max_window = max(start_window, min(self.cfg.c_conc, 2048))
            min_window = max(64, min(start_window, 256))
            return {
                "window": start_window,
                "max_window": max_window,
                "min_window": min_window,
                "increase": 32,
                "max_retries": 1,
                "timeout_floor": min(self.cfg.c_to, 0.35),
            }

        return {
            "window": max(1, min(self.cfg.c_conc, 256)),
            "max_window": max(1, self.cfg.c_conc),
            "min_window": max(1, min(self.cfg.c_conc, 32)),
            "increase": 8,
            "max_retries": 1,
            "timeout_floor": min(self.cfg.c_to, 0.10),
        }

    async def _maybe_refresh_live(
        self,
        live: Live,
        prog: Progress,
        live_ports: List[int],
        force: bool = False,
    ):
        now = time.perf_counter()
        async with self._lock:
            if not force and now < self._live_next_refresh:
                return
            self._live_next_refresh = now + LIVE_REFRESH_INTERVAL
        live.update(build_live_panel(prog, live_ports, self.cfg.target))

    async def _finish_port(
        self,
        port: int,
        state: str,
        prog: Progress,
        tid: int,
        live_ports: List[int],
        live: Live,
    ):
        svc = guess_svc(port)
        announce_open = False
        queue_svc = False

        async with self._lock:
            current = self._st.get(port, "pending")
            if current not in {"pending", "retrying"}:
                return

            self._tested += 1
            self._st[port] = state

            if state == "open":
                self._open += 1
                self._open_ports.append(port)
                live_ports.append(port)
                announce_open = True
                queue_svc = self.cfg.svc_on
            elif state == "filtered":
                self._filtered += 1
            else:
                self._closed += 1

            prog.advance(tid)

        if announce_open:
            live.console.print(
                Text.assemble(
                    ("  ◉ ", GREEN),
                    (f"{port:>5}/tcp", f"bold {WHITE}"),
                    ("  →  ", DIM),
                    (svc, SVC_COL),
                ),
            )

        if queue_svc:
            await self._queue_service_detection(port)

    async def _run_nmap(self, base_cmd: List[str]):
        cmd = list(base_cmd)
        sudo_in = None

        if self.cfg.sudo_pw is not None:
            cmd = ["sudo", "-S", "-p", ""] + cmd
            sudo_in = (self.cfg.sudo_pw + "\n").encode()

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if sudo_in is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_b, err_b = await proc.communicate(input=sudo_in)
        return (
            proc.returncode,
            (out_b or b"").decode(errors="replace"),
            (err_b or b"").decode(errors="replace").strip(),
            " ".join(cmd),
        )

    async def _nmap_batch(self, host: str, ports: List[int]) -> List[SvcInfo]:
        if not ports:
            return []

        t0 = time.perf_counter()
        xml_path = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="x3r0day-nmap-",
                suffix=".xml",
                delete=False,
                dir="/tmp",
            ) as tmp:
                xml_path = tmp.name
        except OSError:
            xml_path = None

        base_cmd = [
            "nmap",
            "-Pn",
            "-n",
        ]
        if xml_path:
            base_cmd.extend(["-oX", xml_path])
        base_cmd.extend(
            [
                "-p",
                ",".join(str(p) for p in ports),
            ]
        )
        base_cmd.extend(self.cfg.n_args)
        base_cmd.append(host)

        try:
            rc, out, err, n_cmd = await self._run_nmap(base_cmd)
        except FileNotFoundError:
            elapsed = round(time.perf_counter() - t0, 3)
            return [
                SvcInfo(
                    port=port,
                    ok=False,
                    state="scan_failed",
                    svc="unknown",
                    info="nmap not found in PATH",
                    elapsed=elapsed,
                    n_cmd=" ".join(base_cmd),
                    raw="",
                    err="nmap not found in PATH",
                )
                for port in ports
            ]
        finally:
            xml_out = ""
            if xml_path:
                try:
                    xml_out = Path(xml_path).read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    xml_out = ""
                try:
                    Path(xml_path).unlink(missing_ok=True)
                except OSError:
                    pass

        text_rows = parse_nmap_rows(out)
        xml_rows = parse_nmap_xml_rows(xml_out)
        rows = merge_nmap_rows(text_rows, xml_rows)
        elapsed = round(time.perf_counter() - t0, 3)
        results: List[SvcInfo] = []

        for port in sorted(ports):
            parsed = rows.get(port)
            block = grab_nmap_block(out, port)
            xml_block = xml_rows.get(port, {}).get("raw", "")
            if parsed:
                results.append(
                    SvcInfo(
                        port=port,
                        ok=rc == 0,
                        state=parsed["state"],
                        svc=parsed["svc"],
                        info=parsed["info"] or block,
                        elapsed=elapsed,
                        n_cmd=n_cmd,
                        raw=block or xml_block or out or xml_out,
                        err=err or None,
                    )
                )
            else:
                results.append(
                    SvcInfo(
                        port=port,
                        ok=rc == 0,
                        state="open",
                        svc=guess_svc(port),
                        info=block or "nmap completed but no port row parsed",
                        elapsed=elapsed,
                        n_cmd=n_cmd,
                        raw=block or xml_block or out or xml_out,
                        err=err or None,
                    )
                )

        return results

    async def _store_svc_result(self, res: SvcInfo):
        async with self._lock:
            self._svc_results[res.port] = res

    async def _queue_service_detection(self, port: int):
        if not self.cfg.svc_on or self._resolved_ip is None:
            return

        async with self._lock:
            if port in self._svc_scheduled:
                return

            self._svc_scheduled.add(port)
            if self.cfg.aggr_on:
                task = asyncio.create_task(
                    self._svc_worker_aggressive(self.cfg.target, port)
                )
            else:
                task = asyncio.create_task(
                    self._svc_worker_basic(self._resolved_ip, port)
                )
            self._svc_tasks.append(task)

    async def _svc_worker_basic(self, ip: str, port: int):
        await self._mark_svc_start(port)
        try:
            async with self._s_sem:
                res = await self._basic(ip, port)
        except Exception as err:
            res = SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc=guess_svc(port),
                info=f"light probe worker failed: {str(err)[:60]}",
                elapsed=0.0,
                n_cmd="",
                raw="",
                err=str(err),
            )
        await self._store_svc_result(res)
        await self._mark_svc_done(port, res.ok)

    async def _svc_worker_aggressive(self, host: str, port: int):
        await self._mark_svc_start(port)
        try:
            async with self._s_sem:
                results = await self._nmap_batch(host, [port])
            res = results[0]
        except Exception as err:
            res = SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc=guess_svc(port),
                info=f"nmap service scan failed: {str(err)[:60]}",
                elapsed=0.0,
                n_cmd="",
                raw="",
                err=str(err),
            )
        await self._store_svc_result(res)
        await self._mark_svc_done(port, res.ok)

    async def _nmap_discover(
        self,
        host: str,
        ports: List[int],
        prog: Progress,
        tid: int,
        live: Live,
        live_ports: List[int],
    ) -> Optional[str]:
        base_cmd = [
            "nmap",
            "-Pn",
            "-n",
            "-sS",
            "-p",
            ",".join(str(p) for p in ports),
            host,
        ]

        try:
            rc, out, err, _n_cmd = await self._run_nmap(base_cmd)
        except FileNotFoundError:
            return "nmap not found in PATH"

        rows = parse_nmap_rows(out)
        ignored = parse_nmap_ignored_counts(out)
        open_ports = sorted(
            port for port, row in rows.items() if row["state"] == "open"
        )
        shown_closed = sum(1 for row in rows.values() if row["state"] == "closed")
        shown_filtered = sum(1 for row in rows.values() if row["state"] == "filtered")

        for port, row in rows.items():
            self._st[port] = row["state"]

        for port in open_ports:
            self._open_ports.append(port)
            live_ports.append(port)

        self._open = len(open_ports)
        shown_total = len(open_ports) + shown_closed + shown_filtered
        remaining = max(0, len(ports) - shown_total)
        self._filtered = shown_filtered + ignored["filtered"]
        self._closed = shown_closed + ignored["closed"]

        assigned = self._open + self._closed + self._filtered
        if assigned < len(ports):
            self._closed += len(ports) - assigned

        self._tested = len(ports)
        prog.update(tid, completed=len(ports))

        for port in open_ports:
            live.console.print(
                Text.assemble(
                    ("  ◉ ", GREEN),
                    (f"{port:>5}/tcp", f"bold {WHITE}"),
                    ("  →  ", DIM),
                    (guess_svc(port), SVC_COL),
                ),
            )

        await self._maybe_refresh_live(live, prog, live_ports, force=True)

        if self.cfg.svc_on:
            for port in open_ports:
                await self._queue_service_detection(port)

        if rc != 0 and not open_ports:
            return err or "nmap discovery returned a non-zero exit code"

        if remaining and not rows and rc != 0:
            return err or "nmap discovery returned no parseable results"

        return None

    async def _read_http_response(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> bytes:
        buf = bytearray()
        while len(buf) < HTTP_PROBE_LIMIT:
            try:
                chunk = await asyncio.wait_for(reader.read(512), timeout=timeout)
            except (
                asyncio.TimeoutError,
                ConnectionResetError,
                BrokenPipeError,
                OSError,
                ssl.SSLError,
            ):
                break
            if not chunk:
                break
            buf.extend(chunk)
            if b"\r\n\r\n" in buf and b"</title" in buf.lower():
                break
        return bytes(buf)

    def _probe_fallback(
        self,
        port: int,
        t0: float,
        n_cmd: str,
        *,
        svc: Optional[str] = None,
        info: str = "",
        err: Optional[str] = None,
        raw: str = "",
    ) -> SvcInfo:
        return SvcInfo(
            port=port,
            ok=True,
            state="open",
            svc=svc or guess_svc(port),
            info=info,
            elapsed=round(time.perf_counter() - t0, 3),
            n_cmd=n_cmd,
            raw=raw,
            err=err,
        )

    def _tls_info_from_writer(self, writer: asyncio.StreamWriter) -> List[str]:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return []
        try:
            cert = ssl_obj.getpeercert()
        except Exception:
            return []
        return _tls_cert_bits(cert)

    def _probe_timeout(self) -> float:
        # Keep light probes from being stricter than the user-visible scan timeout.
        return max(HTTP_PROBE_TIMEOUT, self.cfg.c_to)

    async def _ssh_probe(self, ip: str, port: int) -> SvcInfo:
        t0 = time.perf_counter()
        reader = None
        writer = None
        n_cmd = "light ssh probe"
        probe_timeout = self._probe_timeout()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=probe_timeout,
            )
            banner = await asyncio.wait_for(
                reader.read(SSH_BANNER_LIMIT),
                timeout=probe_timeout,
            )
            text = banner.decode(errors="ignore").strip()
            if not text:
                return self._probe_fallback(
                    port,
                    t0,
                    n_cmd,
                    svc="ssh",
                    info="no SSH banner",
                    err="probe-no-banner",
                )

            return SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc="ssh",
                info=f"Banner: {_clean_text(text, 140)}",
                elapsed=round(time.perf_counter() - t0, 3),
                n_cmd=n_cmd,
                raw=text[:500],
                err=None,
            )
        except asyncio.TimeoutError:
            return self._probe_fallback(
                port,
                t0,
                n_cmd,
                svc="ssh",
                info="no SSH banner before probe timeout",
                err="probe-timeout",
            )
        except (ConnectionResetError, BrokenPipeError, OSError) as err:
            return self._probe_fallback(
                port,
                t0,
                n_cmd,
                svc="ssh",
                info="no SSH banner",
                err=str(err),
            )
        finally:
            if writer is not None:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                    except Exception:
                        pass

    async def _http_probe(self, ip: str, port: int) -> SvcInfo:
        t0 = time.perf_counter()
        if self.cfg.stealth or self._http_probe_blocked:
            return SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc=guess_svc(port),
                info="",
                elapsed=round(time.perf_counter() - t0, 3),
                n_cmd="",
                raw="",
                err=None,
            )

        guessed_ssl = port in TLS_WEB_PORTS
        host_header = self.cfg.target if not self._target_is_ip else ip
        n_cmd = "light http probe"
        probe_timeout = self._probe_timeout()
        attempt_notes: List[str] = []
        final_err = "probe-no-banner"

        for attempt_idx, is_ssl in enumerate((guessed_ssl, not guessed_ssl)):
            reader = None
            writer = None
            scheme = "https" if is_ssl else "http"
            try:
                kwargs = {}
                if is_ssl:
                    kwargs["ssl"] = HTTP_SSL_CTX
                    if not self._target_is_ip:
                        kwargs["server_hostname"] = self.cfg.target

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, **kwargs),
                    timeout=probe_timeout,
                )
                tls_bits = self._tls_info_from_writer(writer) if is_ssl else []
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"Connection: close\r\n"
                    f"Accept: text/html,*/*;q=0.9\r\n"
                    f"Accept-Encoding: identity\r\n"
                    f"User-Agent: X3r0Day-Specter/0.1\r\n"
                    f"\r\n"
                )
                writer.write(request.encode())
                await writer.drain()
                raw = await self._read_http_response(reader, probe_timeout)
                if not raw:
                    detail_parts = list(tls_bits)
                    detail_parts.append("accepted TCP but returned no HTTP bytes")
                    attempt_notes.append(
                        f"{scheme.upper()}: {' | '.join(detail_parts)}"
                    )
                    continue

                text = raw.decode(errors="ignore")
                head, _, body = text.partition("\r\n\r\n")
                lines = head.split("\r\n") if head else text.split("\r\n")

                info_parts = list(tls_bits)
                svc_name = "https" if is_ssl else "http"
                status_code = None

                if lines and lines[0].startswith("HTTP/"):
                    info_parts.append(lines[0])
                    parts = lines[0].split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        status_code = int(parts[1])

                for line in lines[1:]:
                    low = line.lower()
                    if low.startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                        info_parts.append(f"Server: {server}")
                        if "nginx" in server.lower():
                            svc_name = "nginx"
                        elif "apache" in server.lower():
                            svc_name = "apache"
                        elif "cloudflare" in server.lower():
                            svc_name = "cloudflare"
                    elif low.startswith("cf-ray:"):
                        info_parts.append("CF-Ray")
                    elif low.startswith("location:"):
                        info_parts.append("Redirect")

                title = _extract_title(body)
                if title:
                    info_parts.append(f"Title: {title}")

                if status_code in HTTP_BLOCK_STATUSES:
                    self._http_probe_blocked = True
                    info_parts.append("probe backoff enabled")

                if attempt_idx > 0:
                    info_parts.append(f"Probe: {scheme.upper()} fallback")

                return SvcInfo(
                    port=port,
                    ok=True,
                    state="open",
                    svc=svc_name,
                    info=" | ".join(info_parts),
                    elapsed=round(time.perf_counter() - t0, 3),
                    n_cmd=n_cmd,
                    raw=text[:800],
                    err=None,
                )
            except asyncio.TimeoutError:
                final_err = "probe-timeout"
                attempt_notes.append(f"{scheme.upper()}: probe timeout")
            except (
                ConnectionResetError,
                BrokenPipeError,
                OSError,
                ssl.SSLError,
            ) as err:
                final_err = "probe-no-banner"
                err_text = str(err).strip() or "connection closed before HTTP response"
                attempt_notes.append(f"{scheme.upper()}: {err_text[:120]}")
            except Exception as err:
                return SvcInfo(
                    port=port,
                    ok=True,
                    state="open",
                    svc=guess_svc(port),
                    info=f"light probe failed: {str(err)[:60]}",
                    elapsed=round(time.perf_counter() - t0, 3),
                    n_cmd=n_cmd,
                    raw="",
                    err=str(err),
                )
            finally:
                if writer is not None:
                    writer.close()
                    if hasattr(writer, "wait_closed"):
                        try:
                            await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                        except Exception:
                            pass

        info_parts = ["no HTTP banner"]
        if len(attempt_notes) > 1:
            info_parts.append("tried HTTPS and HTTP")
        info_parts.extend(attempt_notes)
        if attempt_notes:
            info_parts.append(
                "service may require the other transport or a non-HTTP handshake"
            )

        return self._probe_fallback(
            port,
            t0,
            n_cmd,
            svc="https" if guessed_ssl else "http",
            info=" | ".join(info_parts),
            err=final_err,
        )

    async def _basic(self, ip: str, port: int) -> SvcInfo:
        t0 = time.perf_counter()
        guessed_svc, guess_source = guess_svc_meta(port)

        if port in SSH_PROBE_PORTS or guessed_svc == "ssh":
            return await self._ssh_probe(ip, port)

        if should_try_http_probe(port, guessed_svc, guess_source):
            probe_res = await self._http_probe(ip, port)
            if has_http_probe_signal(probe_res):
                return probe_res

            svc_name = guessed_svc
            if guess_source == "none" or (guess_source == "system" and port >= 1024):
                svc_name = "unknown"
            info_parts: List[str] = []
            if guess_source == "system":
                info_parts.append(f"unverified system service guess: {guessed_svc}")
            elif guess_source == "builtin":
                info_parts.append(
                    f"probe inconclusive; using default service guess: {guessed_svc}"
                )
            elif probe_res.info:
                info_parts.append("service unresolved after HTTP probe")

            if probe_res.info:
                info_parts.append(probe_res.info)

            return SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc=svc_name,
                info=" | ".join(info_parts),
                elapsed=probe_res.elapsed,
                n_cmd=probe_res.n_cmd,
                raw=probe_res.raw,
                err=probe_res.err,
            )

        return SvcInfo(
            port=port,
            ok=True,
            state="open",
            svc=guessed_svc,
            info="",
            elapsed=round(time.perf_counter() - t0, 3),
            n_cmd="",
            raw="",
            err=None,
        )

    async def _resolve(self, host: str):
        loop = asyncio.get_running_loop()
        last_err = None

        for _ in range(2):
            try:
                infos = await loop.getaddrinfo(
                    host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                )
                for family, _socktype, _proto, _canon, sockaddr in infos:
                    if family in {socket.AF_INET, socket.AF_INET6}:
                        return sockaddr[0], family
                raise RuntimeError(f"no supported address family for {host}")
            except Exception as err:
                last_err = err
                await asyncio.sleep(0.1)

        raise RuntimeError(f"DNS resolution failed for {host}: {last_err}")

    async def _scan_epoll(
        self,
        ip: str,
        family: int,
        ports: List[int],
        prog: Progress,
        tid: int,
        live: Live,
        live_ports: List[int],
    ):
        epoll = select.epoll()
        sockets = {}
        pending = deque(ports)
        retries: Dict[int, int] = {}
        profile = self._scan_profile()
        dyn_timeout = self.cfg.c_to
        srtt = 0.0
        rttvar = 0.0
        min_timeout = float(profile.get("timeout_floor", 0.10))
        window_size = profile["window"]
        scan_delay = 0.0

        try:
            while pending or sockets:
                while len(sockets) < window_size and pending:
                    port = pending.popleft()
                    try:
                        sock = socket.socket(family, socket.SOCK_STREAM)
                        sock.setblocking(False)
                    except OSError as err:
                        if err.errno in (23, 24):
                            window_size = max(profile["min_window"], len(sockets))
                            break
                        await self._finish_port(
                            port, "closed", prog, tid, live_ports, live
                        )
                        continue

                    try:
                        sock.connect(sock_addr(ip, port, family))
                    except BlockingIOError:
                        pass
                    except OSError:
                        sock.close()
                        await self._finish_port(
                            port, "closed", prog, tid, live_ports, live
                        )
                        continue

                    fd = sock.fileno()
                    try:
                        epoll.register(
                            fd, select.EPOLLOUT | select.EPOLLERR | select.EPOLLHUP
                        )
                        sockets[fd] = (sock, port, time.perf_counter())
                    except Exception:
                        sock.close()
                        await self._finish_port(
                            port, "closed", prog, tid, live_ports, live
                        )

                now = time.perf_counter()
                try:
                    events = epoll.poll(0.02)
                except Exception:
                    events = []

                saw_timeout = False
                for fd, event in events:
                    entry = sockets.pop(fd, None)
                    if entry is None:
                        continue

                    sock, port, started_at = entry
                    try:
                        epoll.unregister(fd)
                    except Exception:
                        pass

                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    sock.close()
                    rtt = max(now - started_at, 0.001)

                    if srtt == 0.0:
                        srtt = rtt
                        rttvar = rtt / 2.0
                    else:
                        rttvar = (3.0 / 4.0) * rttvar + (1.0 / 4.0) * abs(srtt - rtt)
                        srtt = (7.0 / 8.0) * srtt + (1.0 / 8.0) * rtt

                    dyn_timeout = max(
                        min_timeout, min(self.cfg.c_to, srtt + 4.0 * rttvar)
                    )
                    window_size = min(
                        profile["max_window"], window_size + profile["increase"]
                    )

                    state = "open" if err == 0 and event & select.EPOLLOUT else "closed"
                    await self._finish_port(
                        state=state,
                        port=port,
                        prog=prog,
                        tid=tid,
                        live_ports=live_ports,
                        live=live,
                    )

                now = time.perf_counter()
                expired = []
                for fd, (sock, port, started_at) in list(sockets.items()):
                    if now - started_at > dyn_timeout:
                        expired.append((fd, sock, port))

                for fd, sock, port in expired:
                    saw_timeout = True
                    try:
                        epoll.unregister(fd)
                    except Exception:
                        pass
                    sock.close()
                    del sockets[fd]

                    retry_count = retries.get(port, 0)
                    if retry_count < profile["max_retries"]:
                        retries[port] = retry_count + 1
                        self._st[port] = "retrying"
                        pending.appendleft(port)
                    else:
                        await self._finish_port(
                            port, "filtered", prog, tid, live_ports, live
                        )

                if saw_timeout:
                    window_size = max(profile["min_window"], window_size // 2)
                    if self.cfg.stealth:
                        scan_delay = min(
                            0.08, 0.01 if scan_delay == 0.0 else scan_delay * 2
                        )
                elif scan_delay > 0.0:
                    scan_delay = max(0.0, scan_delay / 2.0)

                await self._maybe_refresh_live(live, prog, live_ports)

                if scan_delay > 0.0:
                    await asyncio.sleep(scan_delay)
                else:
                    await asyncio.sleep(0)
        finally:
            for sock, _port, _started_at in sockets.values():
                sock.close()
            epoll.close()
            await self._maybe_refresh_live(live, prog, live_ports, force=True)

    async def _probe_sock_connect(
        self,
        ip: str,
        family: int,
        port: int,
        timeout: float,
    ):
        loop = asyncio.get_running_loop()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        started_at = time.perf_counter()

        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, sock_addr(ip, port, family)),
                timeout=timeout,
            )
            return "open", time.perf_counter() - started_at, True
        except asyncio.TimeoutError:
            return "timeout", time.perf_counter() - started_at, False
        except OSError:
            return "closed", time.perf_counter() - started_at, True
        finally:
            sock.close()

    async def _ensure_syn_receiver(self):
        if self._raw_sock is None:
            return

        async with self._syn_receiver_lock:
            task = self._syn_receiver_task
            if task is not None and task.done():
                self._syn_receiver_task = None
                self._syn_receiver_running = False

            if self._syn_receiver_task is None:
                self._syn_receiver_running = True
                self._syn_receiver_task = asyncio.create_task(self._syn_receiver())

    async def _stop_syn_receiver(self):
        async with self._syn_receiver_lock:
            task = self._syn_receiver_task
            self._syn_receiver_running = False

        if task is None:
            return

        try:
            await asyncio.wait_for(task, timeout=1.0)
        except asyncio.TimeoutError:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        except asyncio.CancelledError:
            pass
        finally:
            async with self._syn_receiver_lock:
                if self._syn_receiver_task is task:
                    self._syn_receiver_task = None

    async def _syn_receiver(self):
        """Dedicated receiver task for all SYN scan responses"""
        raw_sock = self._raw_sock
        if raw_sock is None:
            self._syn_receiver_running = False
            return

        loop = asyncio.get_running_loop()

        try:
            while self._syn_receiver_running or self._syn_tracking:
                try:
                    data = await loop.sock_recv(raw_sock, 65535)
                except asyncio.CancelledError:
                    raise
                except (BlockingIOError, InterruptedError):
                    await asyncio.sleep(0)
                    continue
                except OSError:
                    if self._syn_receiver_running:
                        await asyncio.sleep(0.01)
                        continue
                    break

                if not data:
                    await asyncio.sleep(0)
                    continue

                response = parse_tcp_response(data)
                if not response:
                    continue

                resp_src_port, resp_dst_port, flags = response

                async with self._syn_tracking_lock:
                    tracking = self._syn_tracking.get(resp_dst_port)
                    if tracking is None:
                        continue

                    dst_port, event, result_holder, started_at = tracking
                    if resp_src_port != dst_port:
                        continue

                    if flags & 0x12 == 0x12:  # SYN-ACK
                        state = "open"
                    elif flags & 0x04:  # RST or RST-ACK
                        state = "closed"
                    else:
                        continue

                    self._syn_tracking.pop(resp_dst_port, None)

                result_holder["state"] = state
                result_holder["rtt"] = time.perf_counter() - started_at
                result_holder["responded"] = True
                event.set()

        finally:
            self._syn_receiver_running = False

    async def _probe_syn_scan(
        self,
        ip: str,
        family: int,
        port: int,
        timeout: float,
        raw_sock: socket.socket,
        src_ip: str,
    ):
        """SYN scan using raw sockets with dedicated receiver"""
        if family != socket.AF_INET:
            # Fall back to connect scan for IPv6
            return await self._probe_sock_connect(ip, family, port, timeout)

        started_at = time.perf_counter()
        loop = asyncio.get_running_loop()

        await self._ensure_syn_receiver()

        event = asyncio.Event()
        result_holder = {"state": "filtered", "rtt": 0.0, "responded": False}

        async with self._syn_tracking_lock:
            src_port = random.randint(1024, 65535)
            while src_port in self._syn_tracking:
                src_port = random.randint(1024, 65535)
            self._syn_tracking[src_port] = (port, event, result_holder, started_at)

        try:
            syn_packet = build_syn_packet(src_ip, ip, src_port, port)
            try:
                await loop.run_in_executor(None, raw_sock.sendto, syn_packet, (ip, 0))
            except OSError:
                return "filtered", time.perf_counter() - started_at, False

            try:
                await asyncio.wait_for(event.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass

            state = result_holder["state"]
            rtt = (
                result_holder["rtt"]
                if result_holder["responded"]
                else (time.perf_counter() - started_at)
            )
            responded = result_holder["responded"]

            return state, rtt, responded

        finally:
            async with self._syn_tracking_lock:
                self._syn_tracking.pop(src_port, None)

    async def _scan_syn(
        self,
        ip: str,
        family: int,
        ports: List[int],
        prog: Progress,
        tid: int,
        live: Live,
        live_ports: List[int],
    ):
        if family != socket.AF_INET or self._raw_sock is None or self._src_ip is None:
            await self._scan_asyncio(ip, family, ports, prog, tid, live, live_ports)
            return

        raw_sock = self._raw_sock
        pending = deque(ports)
        inflight: Dict[int, tuple] = {}
        retries: Dict[int, int] = {}
        profile = self._scan_profile()
        dyn_timeout = self.cfg.c_to
        srtt = 0.0
        rttvar = 0.0
        min_timeout = float(profile.get("timeout_floor", 0.10))
        window_size = profile["window"]
        scan_delay = 0.0
        next_src_port = random.randint(32768, 65535)

        def alloc_src_port() -> int:
            nonlocal next_src_port

            for _ in range(65535 - 1024):
                src_port = next_src_port
                next_src_port += 1
                if next_src_port > 65535:
                    next_src_port = 1024
                if src_port not in inflight:
                    return src_port

            raise RuntimeError("exhausted SYN source ports")

        def update_rtt(rtt: float):
            nonlocal srtt, rttvar, dyn_timeout, window_size, scan_delay

            if srtt == 0.0:
                srtt = rtt
                rttvar = rtt / 2.0
            else:
                rttvar = (3.0 / 4.0) * rttvar + (1.0 / 4.0) * abs(srtt - rtt)
                srtt = (7.0 / 8.0) * srtt + (1.0 / 8.0) * rtt

            dyn_timeout = max(min_timeout, min(self.cfg.c_to, srtt + 4.0 * rttvar))
            window_size = min(profile["max_window"], window_size + profile["increase"])
            if scan_delay > 0.0:
                scan_delay = max(0.0, scan_delay / 2.0)

        try:
            while pending or inflight:
                while len(inflight) < window_size and pending:
                    port = pending.popleft()
                    src_port = alloc_src_port()
                    syn_packet = build_syn_packet(self._src_ip, ip, src_port, port)

                    try:
                        raw_sock.sendto(syn_packet, (ip, 0))
                    except (BlockingIOError, InterruptedError):
                        pending.appendleft(port)
                        break
                    except OSError:
                        await self._finish_port(
                            port, "filtered", prog, tid, live_ports, live
                        )
                        continue

                    inflight[src_port] = (port, time.perf_counter())

                got_response = False
                while True:
                    try:
                        data = raw_sock.recv(65535)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break

                    response = parse_tcp_response(data)
                    if not response:
                        continue

                    resp_src_port, resp_dst_port, flags = response
                    entry = inflight.get(resp_dst_port)
                    if entry is None:
                        continue

                    port, started_at = entry
                    if resp_src_port != port:
                        continue

                    if flags & 0x12 == 0x12:
                        state = "open"
                    elif flags & 0x04:
                        state = "closed"
                    else:
                        continue

                    inflight.pop(resp_dst_port, None)
                    rtt = max(time.perf_counter() - started_at, 0.001)
                    update_rtt(rtt)
                    await self._finish_port(port, state, prog, tid, live_ports, live)
                    got_response = True

                now = time.perf_counter()
                expired = []
                for src_port, (port, started_at) in list(inflight.items()):
                    if now - started_at > dyn_timeout:
                        expired.append((src_port, port))

                saw_timeout = False
                for src_port, port in expired:
                    saw_timeout = True
                    inflight.pop(src_port, None)

                    retry_count = retries.get(port, 0)
                    if retry_count < profile["max_retries"]:
                        retries[port] = retry_count + 1
                        self._st[port] = "retrying"
                        pending.appendleft(port)
                    else:
                        await self._finish_port(
                            port, "filtered", prog, tid, live_ports, live
                        )

                if saw_timeout:
                    window_size = max(profile["min_window"], window_size // 2)
                    if self.cfg.stealth:
                        scan_delay = min(
                            0.08, 0.01 if scan_delay == 0.0 else scan_delay * 2
                        )
                elif scan_delay > 0.0:
                    scan_delay = max(0.0, scan_delay / 2.0)

                await self._maybe_refresh_live(live, prog, live_ports)

                if pending or inflight:
                    if scan_delay > 0.0:
                        await asyncio.sleep(scan_delay)
                    elif got_response:
                        await asyncio.sleep(0)
                    else:
                        await asyncio.sleep(0.001)
        finally:
            await self._maybe_refresh_live(live, prog, live_ports, force=True)

    async def _scan_asyncio(
        self,
        ip: str,
        family: int,
        ports: List[int],
        prog: Progress,
        tid: int,
        live: Live,
        live_ports: List[int],
    ):
        profile = self._scan_profile()
        dyn_timeout = self.cfg.c_to
        srtt = 0.0
        rttvar = 0.0
        min_timeout = float(profile.get("timeout_floor", 0.10))
        dyn_sem = DynamicSemaphore(profile["window"])
        dyn_sem.max_value = profile["max_window"]
        scan_delay = 0.0

        async def scan_port(port: int):
            nonlocal dyn_timeout, srtt, rttvar, scan_delay
            retries = 0

            while True:
                await dyn_sem.acquire()
                try:
                    if self.cfg.syn_scan and self._raw_sock and self._src_ip:
                        state, rtt, responded = await self._probe_syn_scan(
                            ip, family, port, dyn_timeout, self._raw_sock, self._src_ip
                        )
                    else:
                        state, rtt, responded = await self._probe_sock_connect(
                            ip, family, port, dyn_timeout
                        )
                finally:
                    await dyn_sem.release()

                if responded:
                    async with self._lock:
                        if srtt == 0.0:
                            srtt = rtt
                            rttvar = rtt / 2.0
                        else:
                            rttvar = (3.0 / 4.0) * rttvar + (1.0 / 4.0) * abs(
                                srtt - rtt
                            )
                            srtt = (7.0 / 8.0) * srtt + (1.0 / 8.0) * rtt
                        dyn_timeout = max(
                            min_timeout, min(self.cfg.c_to, srtt + 4.0 * rttvar)
                        )
                    await dyn_sem.set_value(
                        min(profile["max_window"], dyn_sem.value + profile["increase"])
                    )
                    if scan_delay > 0.0:
                        scan_delay = max(0.0, scan_delay / 2.0)
                    await self._finish_port(port, state, prog, tid, live_ports, live)
                    break

                retries += 1
                await dyn_sem.set_value(max(profile["min_window"], dyn_sem.value // 2))

                if retries > profile["max_retries"]:
                    await self._finish_port(
                        port, "filtered", prog, tid, live_ports, live
                    )
                    break

                self._st[port] = "retrying"
                if self.cfg.stealth:
                    scan_delay = min(
                        0.08, 0.01 if scan_delay == 0.0 else scan_delay * 2
                    )
                    await asyncio.sleep(scan_delay)

                await self._maybe_refresh_live(live, prog, live_ports)

        await asyncio.gather(*[asyncio.create_task(scan_port(port)) for port in ports])
        await self._maybe_refresh_live(live, prog, live_ports, force=True)

    async def _run_service_detection(self, ip: str):
        if not self._open_ports:
            return

        if not self.cfg.svc_on:
            self._svcs = [
                SvcInfo(
                    port=port,
                    ok=True,
                    state="open",
                    svc=guess_svc(port),
                    info="",
                    elapsed=0.0,
                    n_cmd="",
                    raw="",
                    err=None,
                )
                for port in self._open_ports
            ]
            return

        for port in self._open_ports:
            await self._queue_service_detection(port)

        waiters: List[asyncio.Future] = list(self._svc_tasks)

        if waiters:
            show_progress = any(
                not waiter.done() for waiter in waiters
            ) or self._svc_done < len(self._open_ports)
            waiter = asyncio.gather(*waiters)

            if show_progress and not self.cfg.quiet:
                console.print()
                svc_prog = mk_prog(transient=True)
                with svc_prog:
                    t2 = svc_prog.add_task(
                        "Service detection",
                        total=len(self._open_ports),
                        completed=min(self._svc_done, len(self._open_ports)),
                    )
                    while not waiter.done():
                        svc_prog.update(
                            t2,
                            completed=min(self._svc_done, len(self._open_ports)),
                        )
                        await asyncio.sleep(SVC_PROGRESS_POLL)
                    await waiter
                    svc_prog.update(t2, completed=len(self._open_ports))
            else:
                await waiter

        self._svcs = []
        for port in sorted(self._open_ports):
            self._svcs.append(
                self._svc_results.get(
                    port,
                    SvcInfo(
                        port=port,
                        ok=True,
                        state="open",
                        svc=guess_svc(port),
                        info="",
                        elapsed=0.0,
                        n_cmd="",
                        raw="",
                        err=None,
                    ),
                )
            )

    async def run(self) -> ScanOut:
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        ip, family = await self._resolve(self.cfg.target)
        self._resolved_ip = ip
        use_syn_scan = (
            self.cfg.syn_scan
            and family == socket.AF_INET
            and self._raw_sock is not None
            and self._src_ip is not None
        )
        ports = self._ordered_ports()
        errors: List[str] = []

        live_ports: List[int] = []
        prog = mk_prog(transient=False)
        tid = prog.add_task(f"Scanning {self.cfg.target}", total=len(ports))
        live_console = console
        if self.cfg.quiet:
            live_console = Console(
                file=io.StringIO(),
                highlight=False,
                force_terminal=False,
                color_system=None,
            )

        live = Live(
            build_live_panel(prog, live_ports, self.cfg.target),
            console=live_console,
            refresh_per_second=8,
            transient=True,
        )
        live.start()

        try:
            if self.cfg.sudo_pw is not None:
                err = await self._nmap_discover(
                    self.cfg.target, ports, prog, tid, live, live_ports
                )
                if err:
                    errors.append(f"hybrid discovery fallback: {err}")
                    self._tested = 0
                    self._open = 0
                    self._closed = 0
                    self._filtered = 0
                    self._open_ports = []
                    self._st = {p: "pending" for p in self.cfg.ports}
                    live_ports.clear()
                    prog.update(tid, completed=0)
                    await self._maybe_refresh_live(live, prog, live_ports, force=True)
                    if use_syn_scan:
                        await self._scan_syn(
                            ip, family, ports, prog, tid, live, live_ports
                        )
                    elif hasattr(select, "epoll"):
                        await self._scan_epoll(
                            ip, family, ports, prog, tid, live, live_ports
                        )
                    else:
                        await self._scan_asyncio(
                            ip, family, ports, prog, tid, live, live_ports
                        )
            elif use_syn_scan:
                await self._scan_syn(ip, family, ports, prog, tid, live, live_ports)
            elif hasattr(select, "epoll"):
                await self._scan_epoll(ip, family, ports, prog, tid, live, live_ports)
            else:
                await self._scan_asyncio(ip, family, ports, prog, tid, live, live_ports)
        finally:
            live.stop()
            await self._stop_syn_receiver()
            if self._raw_sock is not None:
                self._raw_sock.close()
                self._raw_sock = None

        self._open_ports.sort()
        await self._run_service_detection(ip)
        self._svcs.sort(key=lambda x: x.port)

        result = ScanOut(
            target=self.cfg.target,
            ip=ip,
            req_ports=self.cfg.ports,
            open_ports=self._open_ports,
            svcs=self._svcs,
            started=started.isoformat(),
            finished=datetime.now(timezone.utc).isoformat(),
            elapsed=round(time.perf_counter() - t0, 3),
            errors=errors,
        )
        result._filtered_count = self._filtered
        result._closed_count = self._closed
        return result


async def scan_quiet(
    target: str,
    ports: List[int],
    *,
    rip: Optional[str] = None,
    concurrency: int = 256,
    timeout: float = 1.0,
    stealth: bool = False,
) -> ScanOut:
    """
    quiet scanner hook for other modules.
    reuses a pre-resolved ip when available and suppresses live ui output.
    """

    cfg = Cfg(
        target=target,
        ports=list(ports),
        c_conc=max(1, min(concurrency, max(1, len(ports)))),
        c_to=timeout,
        s_conc=1,
        n_args=[],
        svc_on=False,
        aggr_on=False,
        sudo_pw=None,
        stealth=stealth,
        syn_scan=False,
        verbose=0,
        quiet=True,
    )

    scanner = Scanner(cfg)
    orig_resolve = scanner._resolve
    orig_console = console

    if rip:
        try:
            family = (
                socket.AF_INET6
                if ipaddress.ip_address(rip).version == 6
                else socket.AF_INET
            )

            async def _resolve_override(_host: str):
                return rip, family

            scanner._resolve = _resolve_override
        except ValueError:
            pass

    try:
        globals()["console"] = Console(
            file=io.StringIO(),
            highlight=False,
            force_terminal=False,
            color_system=None,
        )
        return await scanner.run()
    finally:
        scanner._resolve = orig_resolve
        globals()["console"] = orig_console


# build argument parser
def mk_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="async tcp port scanner with realtime per-port service detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("target", nargs="+", help="target hostnames / ips")
    p.add_argument("-p", "--ports", default=None, help="ports: 22,80,443  or  1-1024")
    p.add_argument(
        "-P",
        "--top-ports",
        type=int,
        choices=[100, 1000],
        default=1000,
        help="nmap top tcp ports by frequency (default: 1000)",
    )
    p.add_argument(
        "-a", "--all-ports", action="store_true", help="scan all tcp ports 1-65535"
    )
    p.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=1000,
        help="max concurrent tcp connect limit (default: 1000)",
    )
    p.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.5,
        help="max tcp connect timeout in seconds (default: 1.5)",
    )
    p.add_argument(
        "-C",
        "--svc-concurrency",
        type=int,
        default=20,
        help="concurrent service scan limit (default: 20)",
    )
    p.add_argument(
        "-S",
        "--aggr-svc-scan",
        action="store_true",
        help="aggressive nmap service scan (-sV -A) on open ports",
    )
    p.add_argument(
        "-M", "--nmap-args", default="-sV --open", help="extra nmap args for -S mode"
    )
    p.add_argument(
        "-U",
        "--sudo-nmap",
        action="store_true",
        help="prompt for sudo; run nmap with elevated privileges and prefer nmap service detection",
    )
    p.add_argument(
        "-N",
        "--no-svc-scan",
        action="store_true",
        help="tcp open-port detection only, skip service identification",
    )
    p.add_argument(
        "--stealth",
        action="store_true",
        help="enable low-noise mode: smaller windows and fewer app-layer probes",
    )
    scan_mode = p.add_mutually_exclusive_group()
    scan_mode.add_argument(
        "--syn-scan",
        action="store_true",
        help="use raw TCP SYN scan (requires root)",
    )
    scan_mode.add_argument(
        "--connect-scan",
        action="store_true",
        help="use full TCP connect scan",
    )
    p.add_argument(
        "-o",
        "--out",
        default=None,
        help="write results to file (HTML by default, JSON if filename ends with .json)",
    )
    p.add_argument(
        "-v",
        action="count",
        default=0,
        help="show extra probe detail (-vv includes raw probe snippets)",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress scan-time banners and progress chatter",
    )
    return p


# main entry point
def run_cli(argv: Optional[List[str]] = None) -> int:
    os.environ["PYTHONUNBUFFERED"] = "1"
    parser = mk_parser()
    args = parser.parse_args(argv)

    targets = [t.strip() for t in args.target if t.strip()]
    if not targets:
        console.print(Text("  ERROR  No target specified.", style=RED))
        return 2
    if args.quiet and args.v:
        console.print(Text("  ERROR  Choose either -v or -q, not both.", style=RED))
        return 2

    # validate
    if args.concurrency < 1 or args.svc_concurrency < 1:
        console.print(Text("  ERROR  Concurrency values must be >= 1.", style=RED))
        return 2
    if args.timeout <= 0:
        console.print(Text("  ERROR  Timeout must be > 0.", style=RED))
        return 2
    if (args.aggr_svc_scan or args.sudo_nmap) and shutil.which("nmap") is None:
        console.print(Text("  ERROR  nmap binary not found in PATH.", style=RED))
        return 2

    # Determine scan mode
    use_syn_scan = args.syn_scan

    # Check for root privileges if SYN scan is enabled
    if use_syn_scan and os.geteuid() != 0:
        console.print()
        console.print(Text("  SYN scan requires root privileges.", style=YELLOW))
        console.print(
            Text(
                "  Use the default connect scan for non-privileged scanning.", style=DIM
            )
        )
        console.print()

        # Prompt for sudo password and re-execute with sudo
        sudo_pw = getpass.getpass("  sudo password: ")

        # Test sudo authentication
        check = subprocess.run(
            ["sudo", "-S", "-p", "", "-v"],
            input=sudo_pw + "\n",
            text=True,
            capture_output=True,
        )

        if check.returncode != 0:
            console.print(Text("  ERROR  sudo authentication failed.", style=RED))
            return 2

        # Re-execute with sudo using the script path
        import sys

        # If running as a module, convert to file path
        if __file__:
            script_path = __file__
        else:
            script_path = sys.argv[0]

        sudo_cmd = ["sudo", "-S", sys.executable, script_path] + (
            argv if argv else sys.argv[1:]
        )
        console.print(Text("  Elevating privileges...", style=DIM))
        console.print()

        proc = subprocess.run(
            sudo_cmd,
            input=sudo_pw + "\n",
            text=True,
        )
        return proc.returncode

    # sudo handling
    sudo_pw = None
    if args.sudo_nmap:
        sudo_pw = getpass.getpass("  sudo password: ")
        check = subprocess.run(
            ["sudo", "-S", "-p", "", "-v"],
            input=sudo_pw + "\n",
            text=True,
            capture_output=True,
        )
        if check.returncode != 0:
            console.print(Text("  ERROR  sudo authentication failed.", style=RED))
            return 2

    # determine ports to scan
    if args.all_ports:
        sel = list(range(1, 65536))
    elif args.ports:
        sel = parse_ports(args.ports)
    else:
        sel = top_ports(args.top_ports)

    if not sel:
        console.print(Text("  ERROR  No valid ports selected.", style=RED))
        return 2

    use_nmap_service_detection = args.aggr_svc_scan or args.sudo_nmap

    # show header
    dummy_cfg = Cfg(
        target="",
        ports=sel,
        c_conc=args.concurrency,
        c_to=args.timeout,
        s_conc=args.svc_concurrency,
        n_args=shlex.split(args.nmap_args),
        svc_on=not args.no_svc_scan,
        aggr_on=use_nmap_service_detection,
        sudo_pw=sudo_pw,
        stealth=args.stealth,
        syn_scan=use_syn_scan,
        verbose=args.v,
        quiet=args.quiet,
    )
    if not args.quiet:
        hdr(targets, len(sel), dummy_cfg)

    # scan each target
    results: List[ScanOut] = []
    for target in targets:
        cfg = Cfg(
            target=target,
            ports=list(sel),
            c_conc=args.concurrency,
            c_to=args.timeout,
            s_conc=args.svc_concurrency,
            n_args=shlex.split(args.nmap_args),
            svc_on=not args.no_svc_scan,
            aggr_on=use_nmap_service_detection,
            sudo_pw=sudo_pw,
            stealth=args.stealth,
            syn_scan=use_syn_scan,
            verbose=args.v,
            quiet=args.quiet,
        )
        try:
            res = asyncio.run(Scanner(cfg).run())
        except Exception as err:
            t = Text()
            t.append("  ERROR  ", style=f"bold {RED}")
            t.append(f"{target}: {err}", style=DIM)
            console.print(t)
            continue
        results.append(res)
        show(res, idx=len(results) - 1, total=len(targets), verbose=args.v)

    # show multi-target summary
    multi_sum(results)

    # write json or html output
    if args.out and results:
        out_path, mode = _out_mode(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if mode == "json":
            payload = (
                [r.to_dict() for r in results]
                if len(results) > 1
                else results[0].to_dict()
            )
            out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        elif mode == "csv":
            out_path.write_text(_csv_scan(results), encoding="utf-8")
        else:
            out_path.write_text(build_html(results), encoding="utf-8")

        if args.v:
            console.print(Text(f"  output mode  {mode}  ->  {out_path}", style=DIMMER))
        t = Text()
        t.append("  Report saved  ", style=DIM)
        t.append(str(out_path), style=CYAN)
        console.print(t)
        console.print()

    return 0


def main():
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
