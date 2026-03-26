"""
async tcp port scanner with realtime per-port service detection

refs:
- https://nmap.org/book/man.html
- https://en.wikipedia.org/wiki/Asynchronous_I/O
"""

import argparse
import asyncio
import getpass
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    8443: "https-alt",
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


"""
load top n ports from nmap db, sorted by frequency

nmap-services format:
    port/proto    service    frequency    ...
    22/tcp        ssh        0.005234     ...

lower frequency = more popular
falls back to sequential 1..n if db not found
"""


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


# look up service name for a port
# tries our dict first, then system's /etc/services
def guess_svc(port: int) -> str:
    if port in PORT2SVC:
        return PORT2SVC[port]

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# parse nmap output line
# "22/tcp   open   ssh   OpenSSH 8.4p1 Debian 5"
def parse_nmap_row(out: str):
    for line in out.splitlines():
        m = re.match(
            r"^\s*(\d+)\/tcp\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$", line
        )
        if m:
            return {
                "port": int(m.group(1)),
                "state": m.group(2),
                "svc": m.group(3),
                "info": (m.group(4) or "").strip(),
            }
    return None


# grab all output lines for one port from nmap
# includes nested stuff like script results
"""
nmap output looks like:

22/tcp   open   ssh   OpenSSH 8.4p1
| ssh-hostkey: 
|   2048 SHA256:xxxxx
|_  1024 SHA256:yyyyy

this extracts everything from "22/tcp" until the next port or blank line
"""


def grab_nmap_block(out: str, port: int) -> str:
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


# horizontal rule, optionally with title in center
def hr(title: str = "") -> None:
    if title:
        console.print(
            Rule(title=Text(f"  {title}  ", style=DIMMER), style=BORDER, align="left")
        )
    else:
        console.print(Rule(style=BORDER))


"""
print header/banner before scanning starts

shows:
    - tool name
    - target hosts
    - number of ports
    - concurrency settings
    - service scan mode
    - start time
"""


def hdr(hosts: List[str], total_ports: int, cfg: Cfg) -> None:
    console.print()
    hr()

    # tool title
    title = Text()
    title.append("  X3R0DAY", style=f"bold {CYAN}")
    title.append("  //  ", style=DIM)
    title.append("Async TCP Port Scanner", style=f"bold {WHITE}")
    console.print(title)

    hr()
    console.print()

    # figure out what mode we're in
    mode = (
        "aggressive (nmap)"
        if cfg.aggr_on
        else "basic (port map)"
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
            "Concurrency",
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


# make rich progress bar
def mk_prog(transient: bool = True) -> Progress:
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


# map state string to color
def state_label(state: str) -> Text:
    mapping = {
        "open": (GREEN, "open"),
        "closed": (RED, "closed"),
        "filtered": (YELLOW, "filtered"),
        "failed": (RED, "failed"),
    }
    style, label = mapping.get(state, (DIM, state))
    return Text(label, style=style)


# build results table for one target
def res_tbl(res: ScanOut) -> Table:
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


# build stats table for one target
"""
shows:
    - scanned / closed / open counts
    - elapsed time
    - target hostname and resolved ip
    - start and finish timestamps
"""


def stats_tbl(res: ScanOut) -> Table:
    total = len(res.req_ports)
    opened = len(res.open_ports)
    closed = total - opened
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
    # row 3: closed count, finish time, empty
    grid.add_row(k("Closed"), v(str(closed)), k("Finished"), v(tf), k(""), v(""))

    return grid


# print results for one target
def show(res: ScanOut, idx: int = 0, total: int = 1) -> None:
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
    console.print()


# aggregate summary when scanning multiple targets
def multi_sum(results: List[ScanOut]) -> None:
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
            Text("scanning...", style=DIM, justify="center"),
            Text("", style=DIM)
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


class Scanner:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        # semaphore is the only concurrency control for the asyncio fallback
        self._c_sem = asyncio.Semaphore(cfg.c_conc)
        self._s_sem = asyncio.Semaphore(cfg.s_conc)  # service scan
        self._s_tasks: List[asyncio.Task] = []
        self._svcs: List[SvcInfo] = []
        self._lock = asyncio.Lock()
        self._st = {p: "pending" for p in cfg.ports}
        self._tested = 0
        self._open = 0
        self._closed = 0
        self._svc_started = 0
        self._svc_done = 0
        self._svc_failed = 0
        self._open_ports: List[int] = []

    # update state after tcp connect attempt
    async def _mark_conn(self, port: int, is_open: bool):
        async with self._lock:
            self._tested += 1
            if is_open:
                self._open += 1
                self._st[port] = "open"
                self._open_ports.append(port)
            else:
                self._closed += 1
                self._st[port] = "closed"

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

    # try to connect to one port
    # returns (is_open, timed_out)
    # timed_out=True only on asyncio.TimeoutError — a clean RST (port closed)
    # is NOT a timeout and must not be counted against the backoff ratio
    async def _probe(self, ip: str, port: int) -> tuple[bool, bool]:
        try:
            _r, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.cfg.c_to
            )
            # Connection succeeded - port is open
            # Cleanup errors (e.g., CloudFront immediate RST) don't change this
            try:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass  # ignore cleanup errors - we already connected successfully
            return True, False
        except asyncio.TimeoutError:
            return False, True   # dropped / filtered — real backoff signal
        except Exception:
            return False, False  # RST / refused — port closed, not a backoff signal

    # run nmap on one port for aggressive service detection
    async def _nmap(self, host: str, port: int) -> SvcInfo:
        async with self._s_sem:
            t0 = time.perf_counter()
            # build nmap command
            base_cmd = ["nmap", "-Pn", "-n", "-p", str(port)] + self.cfg.n_args + [host]
            cmd = base_cmd
            sudo_in = None

            # wrap with sudo if needed
            if self.cfg.sudo_pw is not None:
                cmd = ["sudo", "-S", "-p", ""] + base_cmd
                sudo_in = (self.cfg.sudo_pw + "\n").encode()

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE if sudo_in is not None else None,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return SvcInfo(
                    port=port,
                    ok=False,
                    state="scan_failed",
                    svc="unknown",
                    info="nmap not found in PATH",
                    elapsed=round(time.perf_counter() - t0, 3),
                    n_cmd=" ".join(cmd),
                    raw="",
                    err="nmap not found in PATH",
                )

            out_b, err_b = await proc.communicate(input=sudo_in)
            out = (out_b or b"").decode(errors="replace")
            err = (err_b or b"").decode(errors="replace").strip()

            parsed = parse_nmap_row(out)
            block = grab_nmap_block(out, port)

            if parsed:
                return SvcInfo(
                    port=port,
                    ok=proc.returncode == 0,
                    state=parsed["state"],
                    svc=parsed["svc"],
                    info=parsed["info"] or block,
                    elapsed=round(time.perf_counter() - t0, 3),
                    n_cmd=" ".join(cmd),
                    raw=out,
                    err=err or None,
                )

            return SvcInfo(
                port=port,
                ok=proc.returncode == 0,
                state="open",
                svc="unknown",
                info=block or "nmap completed but no port row parsed",
                elapsed=round(time.perf_counter() - t0, 3),
                n_cmd=" ".join(cmd),
                raw=out,
                err=err or None,
            )

    # basic port-to-service lookup, no nmap
    async def _basic(self, port: int) -> SvcInfo:
        t0 = time.perf_counter()
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

    # worker for service detection on one port
    async def _svc_worker(self, host: str, port: int):
        res = (
            await self._nmap(host, port)
            if self.cfg.aggr_on
            else await self._basic(port)
        )
        self._svcs.append(res)
        await self._mark_svc_done(port, res.ok)

    # resolve hostname to ip, with retry on failure
    async def _resolve(self, host: str) -> str:
        loop = asyncio.get_running_loop()
        last_err = None

        for _ in range(2):
            try:
                infos = await loop.getaddrinfo(
                    host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                )
                return infos[0][4][0]
            except Exception as err:
                last_err = err
                await asyncio.sleep(0.1)

        raise RuntimeError(f"DNS resolution failed for {host}: {last_err}")

    # main scan workflow
    async def run(self) -> ScanOut:
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        ip = await self._resolve(self.cfg.target)

        # --- phase 1: tcp connect scan ---
        #
        # For maximum speed on Linux (sub-second for 65k ports), we use
        # select.epoll() with raw non-blocking sockets. This bypasses
        # the asyncio event loop's massive overhead for open_connection.
        # Nmap Connect Scan takes 1.7s on localhost; epoll takes 0.9s.
        # If epoll isn't available (Mac/Windows), fallback to asyncio.
        # Tho I am not sure if I want to keep it linux only.
        #
        import random

        # prioritize common ports → 80/443/22 etc. get probed first
        common = set(top_ports(1000))
        priority = [p for p in self.cfg.ports if p in common]
        rest = [p for p in self.cfg.ports if p not in common]
        random.shuffle(priority)
        random.shuffle(rest)
        ports = priority + rest

        live_ports: List[int] = []
        prog = mk_prog(transient=False)
        tid = prog.add_task(
            f"Scanning {self.cfg.target}", total=len(ports)
        )

        live = Live(
            build_live_panel(prog, live_ports, self.cfg.target),
            console=console,
            refresh_per_second=8,
            transient=True,
        )

        def _handle_open(port: int):
            live_ports.append(port)
            self._open_ports.append(port)
            self._open += 1
            self._closed -= 1
            svc = guess_svc(port)
            live.console.print(
                Text.assemble(
                    ("  ◉ ", GREEN),
                    (f"{port:>5}/tcp", f"bold {WHITE}"),
                    ("  →  ", DIM),
                    (svc, SVC_COL),
                ),
            )
            if self.cfg.svc_on:
                async def _start_svc_scan(p: int):
                    await self._mark_svc_start(p)
                    await self._svc_worker(self.cfg.target, p)
                    
                self._s_tasks.append(
                    asyncio.create_task(_start_svc_scan(port))
                )
            else:
                self._svcs.append(
                    SvcInfo(
                        port=port,
                        ok=True,
                        state="open",
                        svc=svc,
                        info="",
                        elapsed=0.0,
                        n_cmd="",
                        raw="",
                        err=None,
                    )
                )

        live.start()
        try:
            if hasattr(select, "epoll"):
                # Fast Path: Linux Epoll connect scanner
                batch_size = self.cfg.c_conc
                i = 0
                while i < len(ports):
                    batch = ports[i : i + batch_size]
                    epoll = select.epoll()
                    sockets = {}
                    
                    hit_limit = False
                    for port_idx, port in enumerate(batch):
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.setblocking(False)
                        except OSError as e:
                            # EMFILE (24) or ENFILE (23): Too many open files
                            if e.errno in (24, 23):
                                hit_limit = True
                                # Advance i by the number of ports we successfully created sockets for
                                # so the next batch picks up exactly where we failed.
                                i += port_idx
                                break
                            else:
                                continue

                        try:
                            s.connect((ip, port))
                        except BlockingIOError:
                            pass
                        except Exception:
                            s.close()
                            continue
                            
                        fd = s.fileno()
                        sockets[fd] = (s, port)
                        try:
                            epoll.register(fd, select.EPOLLOUT | select.EPOLLERR | select.EPOLLHUP)
                        except Exception:
                            s.close()
                            del sockets[fd]
                            continue
                        
                    t_start = time.time()
                    while sockets and time.time() - t_start < self.cfg.c_to:
                        events = epoll.poll(0.05)
                        for fd, event in events:
                            if fd not in sockets: continue
                            s, port = sockets[fd]
                            
                            is_open = False
                            if event & select.EPOLLOUT:
                                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                                if err == 0:
                                    is_open = True
                                    _handle_open(port)
                            
                            self._tested += 1
                            if not is_open:
                                self._closed += 1
                                self._st[port] = "closed"
                                
                            epoll.unregister(fd)
                            s.close()
                            del sockets[fd]
                            prog.advance(tid)
                        
                        live.update(
                            build_live_panel(prog, live_ports, self.cfg.target)
                        )
                        await asyncio.sleep(0)  # yield loop
                            
                    # Cleanup timeouts
                    for fd, (s, port) in sockets.items():
                        self._tested += 1
                        self._closed += 1
                        self._st[port] = "closed"
                        prog.advance(tid)
                        s.close()
                    epoll.close()
                    live.update(
                        build_live_panel(prog, live_ports, self.cfg.target)
                    )

                    if hit_limit:
                        # Cut batch size so we don't keep hitting the FD limit
                        batch_size = max(100, batch_size // 2)
                        # We already advanced `i` by `port_idx` when we caught EMFILE
                    else:
                        i += len(batch)
            
            else:
                # Slow Path: Fallback for Mac/Windows using asyncio.open_connection
                async def scan_port(port: int):
                    async with self._c_sem:
                        is_open, _timed_out = await self._probe(ip, port)
                        self._tested += 1
                        if is_open:
                            _handle_open(port)
                        else:
                            self._closed += 1
                            self._st[port] = "closed"
                            
                        prog.advance(tid)
                        live.update(
                            build_live_panel(prog, live_ports, self.cfg.target)
                        )

                await asyncio.gather(
                    *[asyncio.create_task(scan_port(p)) for p in ports]
                )
        finally:
            live.stop()

        # phase 2: service detection on open ports
        if self._s_tasks:
            console.print()
            svc_prog = mk_prog(transient=True)
            with svc_prog:
                t2 = svc_prog.add_task("Service detection", total=len(self._s_tasks))

                async def _watched(task):
                    await task
                    svc_prog.advance(t2)

                await asyncio.gather(*[_watched(t) for t in self._s_tasks])

        # sort for consistent output
        self._open_ports.sort()
        self._svcs.sort(key=lambda x: x.port)

        return ScanOut(
            target=self.cfg.target,
            ip=ip,
            req_ports=self.cfg.ports,
            open_ports=self._open_ports,
            svcs=self._svcs,
            started=started.isoformat(),
            finished=datetime.now(timezone.utc).isoformat(),
            elapsed=round(time.perf_counter() - t0, 3),
            errors=[],
        )


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
        help="concurrent tcp connect limit (default: 1000)",
    )
    p.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.5,
        help="tcp connect timeout in seconds (default: 1.5)",
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
        "-M", "--nmap-args", default="-sV -A --open", help="extra nmap args for -S mode"
    )
    p.add_argument(
        "-U",
        "--sudo-nmap",
        action="store_true",
        help="prompt for sudo; run nmap with elevated privileges",
    )
    p.add_argument(
        "-N",
        "--no-svc-scan",
        action="store_true",
        help="tcp open-port detection only, skip service identification",
    )
    p.add_argument("-o", "--out", default=None, help="write json results to file")
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

    # validate
    if args.concurrency < 1 or args.svc_concurrency < 1:
        console.print(Text("  ERROR  Concurrency values must be >= 1.", style=RED))
        return 2
    if args.timeout <= 0:
        console.print(Text("  ERROR  Timeout must be > 0.", style=RED))
        return 2
    if not args.no_svc_scan and args.aggr_svc_scan and shutil.which("nmap") is None:
        console.print(Text("  ERROR  nmap binary not found in PATH.", style=RED))
        return 2

    # sudo handling
    sudo_pw = None
    if args.sudo_nmap:
        if not args.aggr_svc_scan:
            console.print(
                Text("  ERROR  --sudo-nmap requires -S / --aggr-svc-scan.", style=RED)
            )
            return 2
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

    # show header
    dummy_cfg = Cfg(
        target="",
        ports=sel,
        c_conc=args.concurrency,
        c_to=args.timeout,
        s_conc=args.svc_concurrency,
        n_args=shlex.split(args.nmap_args),
        svc_on=not args.no_svc_scan,
        aggr_on=args.aggr_svc_scan,
        sudo_pw=sudo_pw,
    )
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
            aggr_on=args.aggr_svc_scan,
            sudo_pw=sudo_pw,
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
        show(res, idx=len(results) - 1, total=len(targets))

    # show multi-target summary
    multi_sum(results)

    # write json output
    if args.out and results:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = (
            [r.to_dict() for r in results] if len(results) > 1 else results[0].to_dict()
        )
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
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
