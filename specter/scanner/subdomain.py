"""
async subdomain enumerator: passive sources + brute force + async port scanning + page scraping

refs:
- https://crt.sh/?q=%25.domain&output=json
- https://api.hackertarget.com/hostsearch/?q=domain
- https://otx.alienvault.com/api/v1/indicators/domain/X/passive_dns
- https://urlscan.io/api/v1/search/?q=domain:X&size=200
- https://rapiddns.io/subdomain/X?full=1
- https://api.shodan.io/dns/domain/X?key=KEY
- https://en.wikipedia.org/wiki/Certificate_Transparency
"""

import argparse
import asyncio
import csv
import html
import io
import json
import re
import socket
import ssl
import struct
import secrets
import time
import traceback
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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

from .port_scan import scan_quiet

# output goes here
console = Console(highlight=False)

# colors, mirrors port_scan.py exactly
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

# passive source endpoints
CRTSH_URL = "https://crt.sh/?q=%25.{d}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={d}"
ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{d}&size=200"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/{d}?full=1"
SHODAN_DNS_URL = "https://api.shodan.io/dns/domain/{d}?key={k}"

# web ports checked on each resolved subdomain
WEB_PORTS = [80, 443, 8080, 8443, 8888, 3000, 5000, 4443]

# http timeout for passive source fetches (seconds)
# generous: crt.sh can be slow on large domains
HTTP_TO = 30.0
HTTP_W_MIN = 8
HTTP_W_MAX = 64
SCAN_TO = 1.0

# DNS_PORT: standard DNS port (53)
# DNS_TO: socket timeout in seconds for DNS queries
# DNS_PKT_MAX: maximum UDP packet size (bytes)
# DNS_TRIES: number of retry attempts per nameserver
# DNS_CNAME_MAX: maximum CNAME chain depth to follow before giving up
# DNS_QTYPE_A: query type for IPv4 address records (RFC 1035)
# DNS_QTYPE_CNAME: query type for canonical name aliases (RFC 1035)
# DNS_QTYPE_AAAA: query type for IPv6 address records (RFC 3596)
# DNS_IN: DNS class for Internet (IN) records (RFC 1035)
DNS_PORT = 53
DNS_TO = 2.0
DNS_PKT_MAX = 2048
DNS_TRIES = 2
DNS_CNAME_MAX = 6
DNS_QTYPE_A = 1
DNS_QTYPE_CNAME = 5
DNS_QTYPE_AAAA = 28
DNS_IN = 1

# http user-agent for all outbound requests
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"

# ssl context used for ALL outbound https: no cert verification
# required because we hit many sources including self-signed scraped targets
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# wordlist for brute-force mode (--brute)
WORDLIST: List[str] = [
    "www",
    "mail",
    "ftp",
    "smtp",
    "pop",
    "ns1",
    "ns2",
    "ns3",
    "webmail",
    "remote",
    "blog",
    "portal",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "vpn",
    "m",
    "mobile",
    "app",
    "store",
    "forum",
    "support",
    "help",
    "cdn",
    "static",
    "media",
    "img",
    "images",
    "assets",
    "docs",
    "wiki",
    "git",
    "gitlab",
    "github",
    "jira",
    "confluence",
    "jenkins",
    "ci",
    "db",
    "mysql",
    "mongo",
    "redis",
    "elastic",
    "kibana",
    "grafana",
    "prometheus",
    "metrics",
    "status",
    "health",
    "monitor",
    "dashboard",
    "beta",
    "alpha",
    "old",
    "new",
    "v1",
    "v2",
    "v3",
    "prod",
    "uat",
    "qa",
    "sandbox",
    "demo",
    "preview",
    "internal",
    "intranet",
    "corp",
    "secure",
    "ssl",
    "web",
    "www2",
    "web2",
    "mx",
    "mx1",
    "mx2",
    "smtp2",
    "pop3",
    "imap",
    "exchange",
    "owa",
    "autodiscover",
    "proxy",
    "lb",
    "load",
    "gateway",
    "edge",
    "fw",
    "firewall",
    "server",
    "srv",
    "node",
    "cluster",
    "k8s",
    "kube",
    "docker",
    "aws",
    "gcp",
    "azure",
    "cloud",
    "s3",
    "bucket",
    "vault",
    "login",
    "auth",
    "sso",
    "oauth",
    "id",
    "account",
    "accounts",
    "billing",
    "pay",
    "payment",
    "shop",
    "checkout",
    "cart",
    "crm",
    "erp",
    "hr",
    "finance",
    "legal",
    "marketing",
    "search",
    "es",
    "solr",
    "data",
    "analytics",
    "upload",
    "download",
    "files",
    "backup",
    "archive",
    "news",
    "video",
    "live",
    "stream",
    "player",
    "ads",
    "promo",
]


# minimal HTML parser: extracts title text from scraped pages
class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in = False

    def handle_data(self, data):
        if self._in:
            self.title += data


class _DnsErr(RuntimeError):
    pass


class _DnsFallback(RuntimeError):
    pass


@dataclass
class _DnsRes:
    ans: List[str]
    fallback: bool = False


def _load_ns() -> List[str]:
    conf = Path("/etc/resolv.conf")
    if not conf.exists():
        return []

    nss: List[str] = []
    for line in conf.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith("nameserver"):
            continue

        parts = line.split()
        if len(parts) >= 2:
            nss.append(parts[1])

    return nss


def _dns_addr(ns: str):
    fam = socket.AF_INET6 if ":" in ns else socket.AF_INET
    if fam == socket.AF_INET6:
        return fam, (ns, DNS_PORT, 0, 0)
    return fam, (ns, DNS_PORT)


def _enc_name(name: str) -> bytes:
    labels = [label for label in name.strip(".").split(".") if label]
    return (
        b"".join(
            len(label.encode("idna")).to_bytes(1, "big") + label.encode("idna")
            for label in labels
        )
        + b"\x00"
    )


def _dec_name(pkt: bytes, off: int) -> Tuple[str, int]:
    labels: List[str] = []
    cur = off
    next_off = None
    seen: Set[int] = set()

    while True:
        if cur >= len(pkt):
            raise _DnsErr("dns name exceeds packet bounds")

        length = pkt[cur]
        if length & 0xC0 == 0xC0:
            if cur + 1 >= len(pkt):
                raise _DnsErr("dns pointer truncated")
            ptr = ((length & 0x3F) << 8) | pkt[cur + 1]
            if ptr in seen:
                raise _DnsErr("dns pointer loop")
            seen.add(ptr)
            if next_off is None:
                next_off = cur + 2
            cur = ptr
            continue

        if length == 0:
            cur += 1
            break

        cur += 1
        if cur + length > len(pkt):
            raise _DnsErr("dns label exceeds packet bounds")
        labels.append(pkt[cur : cur + length].decode("ascii", errors="ignore"))
        cur += length

    return ".".join(labels), next_off if next_off is not None else cur


def _mk_query(name: str, qtype: int) -> Tuple[int, bytes]:
    txid = secrets.randbelow(65536)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _enc_name(name) + struct.pack("!HH", qtype, DNS_IN)
    return txid, header + question


def _parse_resp(
    pkt: bytes, txid: int, qtype: int
) -> Tuple[List[str], List[str], bool, int]:
    if len(pkt) < 12:
        raise _DnsErr("dns packet too short")

    resp_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", pkt[:12]
    )
    if resp_id != txid:
        raise _DnsErr("dns txid mismatch")

    trunc = bool(flags & 0x0200)
    rcode = flags & 0x000F
    off = 12

    for _ in range(qdcount):
        _, off = _dec_name(pkt, off)
        off += 4
        if off > len(pkt):
            raise _DnsErr("dns question truncated")

    ans: List[str] = []
    cnames: List[str] = []

    for _ in range(ancount):
        _, off = _dec_name(pkt, off)
        if off + 10 > len(pkt):
            raise _DnsErr("dns answer header truncated")

        rr_type, rr_class, _ttl, rdlen = struct.unpack("!HHLH", pkt[off : off + 10])
        off += 10
        if off + rdlen > len(pkt):
            raise _DnsErr("dns rdata truncated")

        rd_off = off
        rdata = pkt[off : off + rdlen]
        off += rdlen

        if rr_class != DNS_IN:
            continue

        if rr_type == qtype:
            if qtype == DNS_QTYPE_A and rdlen == 4:
                ans.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif qtype == DNS_QTYPE_AAAA and rdlen == 16:
                ans.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rr_type == DNS_QTYPE_CNAME:
            cname, _ = _dec_name(pkt, rd_off)
            if cname:
                cnames.append(cname.lower().strip("."))

    return ans, cnames, trunc, rcode


# small udp-first resolver.
# if a server truncates or acts weird, we fall back to libc and move on.
class _Dns:
    def __init__(self, to: float = DNS_TO):
        self._to = to
        self._ns = _load_ns()

    async def _query(self, ns: str, name: str, qtype: int) -> _DnsRes:
        loop = asyncio.get_running_loop()
        txid, query = _mk_query(name, qtype)
        fam, addr = _dns_addr(ns)
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.setblocking(False)

        try:
            await loop.sock_sendto(sock, query, addr)
            pkt, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, DNS_PKT_MAX), timeout=self._to
            )
        finally:
            sock.close()

        ans, cnames, trunc, rcode = _parse_resp(pkt, txid, qtype)
        if trunc:
            return _DnsRes([], fallback=True)
        if ans:
            return _DnsRes(ans)
        if cnames:
            return _DnsRes(cnames)
        if rcode in {2, 5}:
            return _DnsRes([], fallback=True)
        return _DnsRes([])

    async def _lookup(self, name: str, qtype: int, depth: int = 0) -> _DnsRes:
        if depth > DNS_CNAME_MAX:
            return _DnsRes([], fallback=True)
        if not self._ns:
            return _DnsRes([], fallback=True)

        need_fallback = False
        for ns in self._ns:
            for _ in range(DNS_TRIES):
                try:
                    res = await self._query(ns, name, qtype)
                except (OSError, asyncio.TimeoutError, _DnsErr):
                    need_fallback = True
                    continue

                if res.ans:
                    if qtype in {DNS_QTYPE_A, DNS_QTYPE_AAAA} and all(
                        not re.match(r"^\d+\.\d+\.\d+\.\d+$", val) and ":" not in val
                        for val in res.ans
                    ):
                        return await self._lookup(res.ans[0], qtype, depth + 1)
                    return res

                if res.fallback:
                    need_fallback = True
                    continue

                return res

        return _DnsRes([], fallback=need_fallback)

    async def resolve(self, host: str) -> str:
        a_res, aaaa_res = await asyncio.gather(
            self._lookup(host, DNS_QTYPE_A),
            self._lookup(host, DNS_QTYPE_AAAA),
        )

        if a_res.ans:
            return a_res.ans[0]
        if aaaa_res.ans:
            return aaaa_res.ans[0]
        if a_res.fallback or aaaa_res.fallback:
            raise _DnsFallback(host)
        return ""


# result from resolving + scanning one subdomain
@dataclass
class SubHit:
    subdomain: str
    ip: str  # resolved ipv4/v6, empty string if no dns
    sources: List[str]  # which sources found this subdomain
    ports: List[int]  # open web ports found by the internal scanner
    status: int  # http status code  (0 = not scraped / unreachable)
    title: str  # HTML <title> from scraped page
    server: str  # server response header
    tech: List[str]  # detected tech hints from headers + body
    elapsed: float  # total seconds for this subdomain's full workflow
    err: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


# complete enumeration result for one domain
@dataclass
class SubRun:
    domain: str
    subdomains: List[SubHit]
    total_found: int
    total_resolved: int
    started: str
    finished: str
    elapsed: float
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        d["subdomains"] = [s.to_dict() for s in self.subdomains]
        return d


# scan config passed into SubScanner
@dataclass
class SubCfg:
    domain: str
    shodan_key: Optional[str]
    brute: bool
    wordlist: Optional[Path]
    nmap_on: bool
    scrape_on: bool
    resolve_c: int
    nmap_c: int
    http_to: float
    debug: bool
    verbose: int = 0
    quiet: bool = False


SubInfo = SubHit
SubScanOut = SubRun
Cfg = SubCfg


def hr(title: str = "") -> None:
    if title:
        console.print(
            Rule(title=Text(f"  {title}  ", style=DIMMER), style=BORDER, align="left")
        )
    else:
        console.print(Rule(style=BORDER))


def hdr(domain: str, cfg: SubCfg) -> None:
    console.print()
    hr()

    title = Text()
    title.append("  X3R0DAY", style=f"bold {CYAN}")
    title.append("  //  ", style=DIM)
    title.append("Async Subdomain Enumerator", style=f"bold {WHITE}")
    console.print(title)

    hr()
    console.print()

    sources = ["crt.sh", "hackertarget", "alienvault", "urlscan", "rapiddns"]
    if cfg.shodan_key:
        sources.insert(0, "shodan")
    if cfg.brute:
        sources.append("bruteforce")

    scan_mode = "enabled" if cfg.nmap_on else "disabled"
    scrape_mode = "enabled" if cfg.scrape_on else "disabled"

    grid = Table.grid(padding=(0, 0))
    grid.add_column(min_width=16)
    grid.add_column(min_width=38)
    grid.add_column(min_width=6)
    grid.add_column(min_width=16)
    grid.add_column()

    rows = [
        ("Domain", domain, "Port Scan", scan_mode),
        ("Sources", ", ".join(sources), "Scrape", scrape_mode),
        (
            "Resolve",
            f"{cfg.resolve_c} concurrent",
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


def live_disc_tbl(subs: List[SubHit], domain: str) -> Table:
    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style=f"bold {WHITE}",
        border_style=CYAN,
        title=f"[bold {WHITE}]Subdomains Discovered  •  {domain}[/bold {WHITE}]",
        title_style=f"bold {WHITE}",
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("SUBDOMAIN", style=GREEN, justify="left", min_width=40, no_wrap=True)
    tbl.add_column("IP", style=DIM, justify="left", width=16, no_wrap=True)
    tbl.add_column("SOURCES", style=SVC_COL, justify="left", min_width=20, no_wrap=True)

    if not subs:
        tbl.add_row(Text("enumerating...", style=DIM), Text(""), Text(""))
    else:
        for s in subs[-18:]:
            tbl.add_row(s.subdomain, s.ip or "resolving...", ", ".join(s.sources[:3]))

    return tbl


def build_live_panel(progress: Progress, subs: List[SubHit], domain: str) -> Group:
    parts: List[Any] = [progress]
    if subs:
        parts.append(Text(""))
        parts.append(live_disc_tbl(subs, domain))
    return Group(*parts)


def _status_style(code: int) -> Tuple[str, str]:
    if code == 0:
        return DIM, "-"
    if 200 <= code < 300:
        return GREEN, str(code)
    if 300 <= code < 400:
        return YELLOW, str(code)
    if code >= 400:
        return RED, str(code)
    return DIM, str(code)


def _fmt_display_ts(raw: str) -> str:
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return raw[:19].replace("T", "  ")

    if dt.tzinfo is not None:
        dt = dt.astimezone()
    return dt.strftime("%Y-%m-%d  %H:%M:%S")


def sub_tbl(run: SubRun) -> Table:
    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {DIM}",
        border_style=BORDER,
        show_edge=True,
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("SUBDOMAIN", style=WHITE, justify="left", min_width=34, no_wrap=True)
    tbl.add_column("IP", style=DIM, justify="left", width=16, no_wrap=True)
    tbl.add_column("PORTS", style=GREEN, justify="left", width=24, no_wrap=True)
    tbl.add_column("STATUS", justify="center", width=8, no_wrap=True)
    tbl.add_column("TITLE", style=DETAIL, justify="left", min_width=28, max_width=46)
    tbl.add_column("SERVER", style=DIM, justify="left", min_width=12, max_width=20)

    for s in run.subdomains:
        ports_str = ", ".join(str(p) for p in s.ports) if s.ports else "-"
        st_style, st_val = _status_style(s.status)
        title = s.title.strip()
        if len(title) > 46:
            title = title[:43] + "..."
        server = s.server[:20] if s.server else "-"

        tbl.add_row(
            s.subdomain,
            s.ip or Text("unresolved", style=DIM),
            ports_str,
            Text(st_val, style=st_style),
            title or Text("-", style=DIM),
            server,
        )

    return tbl


"""
stats grid: found / resolved / unresolved counts, elapsed, timestamps
"""


def sum_tbl(run: SubRun) -> Table:
    total = run.total_found
    resolved = run.total_resolved
    unres = total - resolved
    with_web = sum(1 for s in run.subdomains if s.ports)
    ts = _fmt_display_ts(run.started)
    tf = _fmt_display_ts(run.finished)

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

    grid.add_row(
        k("Found"),
        v(f"{total:,} subdomains"),
        k("Elapsed"),
        v(f"{run.elapsed:.3f}s"),
        k("Domain"),
        v(run.domain),
    )
    grid.add_row(
        k("Resolved"),
        v(str(resolved)),
        k("Started"),
        v(ts),
        k("Web Ports"),
        v(str(with_web)),
    )
    grid.add_row(k("No DNS"), v(str(unres)), k("Finished"), v(tf), k(""), v(""))

    return grid


def show_run(run: SubRun) -> None:
    console.print()

    console.print(
        Panel(
            Padding(sum_tbl(run), (0, 1)),
            title=f"[bold {WHITE}]Scan Summary[/bold {WHITE}]",
            border_style=BORDER,
            box=box.ROUNDED,
            expand=True,
        )
    )

    if run.subdomains:
        console.print(
            Panel(
                Padding(sub_tbl(run), (0, 1)),
                title=f"[bold {WHITE}]Subdomains  •  {run.domain}[/bold {WHITE}]",
                border_style=CYAN,
                box=box.ROUNDED,
                expand=True,
            )
        )
    else:
        console.print(
            Panel(
                Padding(Text("No subdomains discovered.", style=DIM), (0, 1)),
                title=f"[bold {WHITE}]Subdomains  •  {run.domain}[/bold {WHITE}]",
                border_style=BORDER,
                box=box.ROUNDED,
                expand=True,
            )
        )

    console.print()


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


def _sub_csv(run: SubRun) -> str:
    buf = io.StringIO()
    fields = [
        "domain",
        "subdomain",
        "ip",
        "sources",
        "ports",
        "status",
        "title",
        "server",
        "tech",
        "elapsed",
        "err",
    ]
    wr = csv.DictWriter(buf, fieldnames=fields)
    wr.writeheader()

    rows = run.subdomains or [
        SubHit(
            subdomain="",
            ip="",
            sources=[],
            ports=[],
            status=0,
            title="",
            server="",
            tech=[],
            elapsed=0.0,
            err="",
        )
    ]
    for sub in rows:
        wr.writerow(
            {
                "domain": run.domain,
                "subdomain": sub.subdomain,
                "ip": sub.ip,
                "sources": "|".join(sub.sources),
                "ports": ",".join(str(p) for p in sub.ports),
                "status": sub.status,
                "title": sub.title,
                "server": sub.server,
                "tech": "|".join(sub.tech),
                "elapsed": sub.elapsed,
                "err": sub.err or "",
            }
        )

    return buf.getvalue()


def build_sub_html(run: SubRun) -> str:
    found = run.total_found
    resolved = run.total_resolved
    web_hits = sum(1 for s in run.subdomains if s.ports)
    lines = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "  <title>X3R0DAY Subdomain Report</title>",
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
        "    .wrap { max-width: 1100px; margin: 0 auto; }",
        "    h1 {",
        "      font-size: 16px;",
        "      font-weight: 600;",
        "      color: #e0e0e0;",
        "      margin-bottom: 8px;",
        "    }",
        "    .meta { font-size: 12px; color: #707070; margin-bottom: 24px; }",
        "    hr { border: none; border-top: 1px solid #2a2a2a; margin: 24px 0; }",
        "    .domain { margin-bottom: 16px; }",
        "    .domain-name { font-size: 15px; font-weight: 500; color: #c0c0c0; }",
        "    .stats { display: flex; gap: 24px; font-size: 13px; margin-bottom: 20px; }",
        "    .stats span { color: #606060; }",
        "    .stats strong { color: #a0a0a0; margin-left: 4px; }",
        "    .stats .hits strong { color: #6a9955; }",
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
        "    .sub { color: #9cdcfe; word-break: break-all; }",
        "    .ip { font-family: monospace; color: #808080; font-size: 13px; }",
        "    .status-2 { color: #6a9955; }",
        "    .status-3 { color: #dcdcaa; }",
        "    .status-4 { color: #f14c4c; }",
        "    .ports { font-family: monospace; color: #808080; font-size: 12px; }",
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
        "    <h1>Subdomain Report</h1>",
        f"    <p class='meta'>X3R0DAY Specter &middot; {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>",
    ]

    lines.append("    <hr>")
    lines.append("    <div class='domain'>")
    lines.append(f"      <div class='domain-name'>{html.escape(run.domain)}</div>")
    lines.append("    </div>")

    lines.append("    <div class='stats'>")
    lines.append(f"      <span>Found<strong>{found}</strong></span>")
    lines.append(f"      <span>Resolved<strong>{resolved}</strong></span>")
    lines.append(
        f"      <span>No DNS<strong>{max(found - resolved, 0)}</strong></span>"
    )
    lines.append(f"      <span class='hits'>Web Hits<strong>{web_hits}</strong></span>")
    lines.append(f"      <span>{run.elapsed:.2f}s</span>")
    lines.append("    </div>")

    if not run.subdomains:
        lines.append("    <p class='empty'>No subdomains discovered</p>")
    else:
        lines.append("    <table>")
        lines.append(
            "      <thead><tr><th>Subdomain</th><th style='width:120px'>IP</th><th style='width:80px'>Status</th><th style='width:100px'>Ports</th><th>Info</th></tr></thead>"
        )
        lines.append("      <tbody>")

        for sub in run.subdomains:
            status_cls = "info"
            if 200 <= sub.status < 300:
                status_cls = "status-2"
            elif 300 <= sub.status < 400:
                status_cls = "status-3"
            elif sub.status >= 400:
                status_cls = "status-4"

            status_str = str(sub.status) if sub.status else "-"
            ports_str = ", ".join(str(p) for p in sub.ports) if sub.ports else "-"
            title_short = sub.title[:60] + "..." if len(sub.title) > 60 else sub.title
            title_full = sub.title

            lines.append("      <tr>")
            lines.append(f"        <td class='sub'>{html.escape(sub.subdomain)}</td>")
            lines.append(f"        <td class='ip'>{html.escape(sub.ip or '-')}</td>")
            lines.append(f"        <td class='{status_cls}'>{status_str}</td>")
            lines.append(f"        <td class='ports'>{html.escape(ports_str)}</td>")
            lines.append("        <td class='info'>")

            if len(title_full) > 60:
                lines.append(f"          {html.escape(title_short)}")
                lines.append(f"          <details>")
                lines.append(f"            <summary>show more</summary>")
                lines.append(
                    f"            <div class='detail-box'>Title: {html.escape(title_full)}"
                )
                if sub.server:
                    lines.append(f"Server: {html.escape(sub.server)}")
                if sub.tech:
                    lines.append(f"Tech: {html.escape(', '.join(sub.tech))}")
                if sub.err:
                    lines.append(f"Error: {html.escape(sub.err)}")
                lines.append(f"            </div>")
                lines.append(f"          </details>")
            else:
                info_parts = []
                if sub.title:
                    info_parts.append(sub.title)
                if sub.server:
                    info_parts.append(f"({sub.server})")
                lines.append(f"          {html.escape(' '.join(info_parts) or '-')}")

            lines.append("        </td>")
            lines.append("      </tr>")

        lines.append("      </tbody>")
        lines.append("    </table>")

    if run.errors:
        lines.append("    <details style='margin-top: 16px;'>")
        lines.append("      <summary>Show Errors</summary>")
        lines.append("      <div class='detail-box'>")
        for err in run.errors:
            lines.append(html.escape(err))
        lines.append("      </div>")
        lines.append("    </details>")

    lines.append("  </div>")
    lines.append("</body>")
    lines.append("</html>")

    return "\n".join(lines)


"""
blocking http get: always uses relaxed SSL context, follows redirects,
caps body at max_bytes.

returns (status_code, body_bytes, headers_dict, error_string)
status is 0 on connection / timeout failure, and error_string will be populated.
"""


def _http_get(
    url: str,
    timeout: float = HTTP_TO,
    max_bytes: int = 5 << 20,  # 5MB default limit
) -> Tuple[int, bytes, Dict[str, str], str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read(max_bytes) if max_bytes > 0 else resp.read()
            return resp.status, body, dict(resp.headers), ""
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(65536), dict(exc.headers), str(exc)
        except Exception:
            return exc.code, b"", {}, str(exc)
    except Exception as exc:
        return 0, b"", {}, str(exc)


class SubScanner:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._found: Set[str] = set()
        self._lock = asyncio.Lock()
        self._resolve_sem = asyncio.Semaphore(cfg.resolve_c)
        self._nmap_sem = asyncio.Semaphore(cfg.nmap_c)
        self._http_w = max(HTTP_W_MIN, min(HTTP_W_MAX, cfg.resolve_c))
        self._http_sem = asyncio.Semaphore(self._http_w)
        self._http_pool = ThreadPoolExecutor(
            max_workers=self._http_w, thread_name_prefix="sub-http"
        )
        self._dns_pool = ThreadPoolExecutor(
            max_workers=max(4, min(32, cfg.resolve_c)),
            thread_name_prefix="sub-dns-fallback",
        )
        self._dns = _Dns()
        self._res_cache: Dict[str, str] = {}
        self._errors: List[str] = []
        self._total_raw = 0

    def _v(self, msg: str):
        if self.cfg.verbose > 0 and not self.cfg.quiet:
            console.print(Text(f"  {msg}", style=DIMMER))

    def _err(self, msg: str):
        self._errors.append(msg)
        if self.cfg.verbose > 0 and not self.cfg.quiet:
            console.print(Text(f"  !  {msg}", style=YELLOW))

    # keep blocking urllib work off the event loop
    async def _aget(
        self,
        url: str,
        to: float = HTTP_TO,
        max_b: int = 5 << 20,
    ) -> Tuple[int, bytes, Dict[str, str], str]:
        async with self._http_sem:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                self._http_pool, lambda: _http_get(url, to, max_b)
            )

    # libc fallback for truncated replies or dns servers that misbehave
    async def _sys_resolve(self, host: str) -> str:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.run_in_executor(
                    self._dns_pool,
                    lambda: socket.getaddrinfo(
                        host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                    ),
                ),
                timeout=4.0,
            )
        except Exception:
            return ""

        for family, _socktype, _proto, _canonname, sockaddr in infos:
            if family in {socket.AF_INET, socket.AF_INET6}:
                return sockaddr[0]
        return ""

    def close(self) -> None:
        self._http_pool.shutdown(wait=False, cancel_futures=True)
        self._dns_pool.shutdown(wait=False, cancel_futures=True)

    async def _src_crtsh(self, domain: str) -> List[Tuple[str, str]]:
        url = CRTSH_URL.format(d=domain)
        try:
            # crt.sh can be painfully slow on larger domains
            code, body, _, err = await self._aget(url, to=90.0, max_b=-1)
            if not body:
                self._err(f"crt.sh: empty response (http {code}), {err}")
                return []
            rows = json.loads(body.decode("utf-8", errors="replace"))
            subs: Set[str] = set()
            for row in rows:
                for val in str(row.get("name_value", "")).splitlines():
                    val = val.strip().lower().lstrip("*.")
                    if val.endswith(f".{domain}") or val == domain:
                        subs.add(val)
            return [(s, "crt.sh") for s in subs]
        except json.JSONDecodeError as exc:
            self._err(f"crt.sh: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._err(f"crt.sh: {exc}")
            return []

    async def _src_hackertarget(self, domain: str) -> List[Tuple[str, str]]:
        url = HACKERTARGET_URL.format(d=domain)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"hackertarget: empty response (http {code}), {err}")
                return []
            text = body.decode("utf-8", errors="replace").strip()
            if text.lower().startswith("error") or "api count" in text.lower():
                self._err(f"hackertarget: rate limited, {text[:80]}")
                return []
            subs: Set[str] = set()
            for line in text.splitlines():
                parts = line.split(",")
                if parts:
                    s = parts[0].strip().lower()
                    if s.endswith(f".{domain}") or s == domain:
                        subs.add(s)
            return [(s, "hackertarget") for s in subs]
        except Exception as exc:
            self._err(f"hackertarget: {exc}")
            return []

    async def _src_alienvault(self, domain: str) -> List[Tuple[str, str]]:
        url = ALIENVAULT_URL.format(d=domain)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"alienvault: empty response (http {code}) {err}")
                return []
            data = json.loads(body.decode("utf-8", errors="replace"))
            subs: Set[str] = set()
            for rec in data.get("passive_dns", []):
                hostname = str(rec.get("hostname", "")).strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
            return [(s, "alienvault") for s in subs]
        except json.JSONDecodeError as exc:
            self._err(f"alienvault: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._err(f"alienvault: {exc}")
            return []

    async def _src_urlscan(self, domain: str) -> List[Tuple[str, str]]:
        url = URLSCAN_URL.format(d=domain)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"urlscan: empty response (http {code}) {err}")
                return []
            data = json.loads(body.decode("utf-8", errors="replace"))
            subs: Set[str] = set()
            for result in data.get("results", []):
                for key in ("task", "page"):
                    dm = result.get(key, {}).get("domain", "")
                    if dm.endswith(f".{domain}") or dm == domain:
                        subs.add(dm.lower())
            return [(s, "urlscan") for s in subs]
        except json.JSONDecodeError as exc:
            self._err(f"urlscan: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._err(f"urlscan: {exc}")
            return []

    async def _src_rapiddns(self, domain: str) -> List[Tuple[str, str]]:
        url = RAPIDDNS_URL.format(d=domain)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"rapiddns: empty response (http {code}) {err}")
                return []
            text = body.decode("utf-8", errors="replace")
            subs: Set[str] = set()
            pat = r"<td[^>]*>\s*([\w.\-]+\." + re.escape(domain) + r")\s*</td>"
            for m in re.finditer(pat, text):
                s = m.group(1).strip().lower()
                if s.endswith(f".{domain}") or s == domain:
                    subs.add(s)
            # fallback: plain-text lines
            for line in text.splitlines():
                line = line.strip().lower()
                if line.endswith(f".{domain}") and re.match(r"^[\w.\-]+$", line):
                    subs.add(line)
            return [(s, "rapiddns") for s in subs]
        except Exception as exc:
            self._err(f"rapiddns: {exc}")
            return []

    async def _src_shodan(self, domain: str, key: str) -> List[Tuple[str, str]]:
        url = SHODAN_DNS_URL.format(d=domain, k=key)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"shodan: empty response (http {code}) {err}")
                return []
            data = json.loads(body.decode("utf-8", errors="replace"))
            if "error" in data:
                self._err(f"shodan: {data['error']}")
                return []
            subs: Set[str] = set()
            for sub in data.get("subdomains", []):
                subs.add(f"{sub}.{domain}".lower())
            for rec in data.get("data", []):
                subdomain = rec.get("subdomain", "")
                if subdomain:
                    subs.add(f"{subdomain}.{domain}".lower())
            return [(s, "shodan") for s in subs]
        except json.JSONDecodeError as exc:
            self._err(f"shodan: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._err(f"shodan: {exc}")
            return []

    async def _src_brute(self, domain: str, words: List[str]) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        lock = asyncio.Lock()

        async def _try(word: str):
            candidate = f"{word}.{domain}"
            async with self._lock:
                if candidate in self._found:
                    return
            if await self._resolve(candidate):
                async with lock:
                    results.append((candidate, "bruteforce"))

        await asyncio.gather(*[_try(w) for w in words])
        return results

    # dns resolution

    async def _resolve(self, host: str) -> str:
        if host in self._res_cache:
            return self._res_cache[host]

        async with self._resolve_sem:
            try:
                if host in self._res_cache:
                    return self._res_cache[host]

                try:
                    ip = await self._dns.resolve(host)
                except _DnsFallback:
                    ip = await self._sys_resolve(host)

                self._res_cache[host] = ip
                return ip
            except Exception:
                self._res_cache[host] = ""
                return ""

    async def _scan_web(self, sub: str, ip: str) -> List[int]:
        if not self.cfg.nmap_on:
            return []

        async with self._nmap_sem:
            try:
                res = await scan_quiet(
                    sub,
                    WEB_PORTS,
                    rip=ip,
                    concurrency=len(WEB_PORTS),
                    timeout=SCAN_TO,
                )
            except Exception as exc:
                self._err(f"port scan [{sub}]: {exc}")
                return []

            for err in res.errors:
                self._err(f"port scan [{sub}]: {err}")
            if self.cfg.verbose > 0:
                ports = ", ".join(str(p) for p in sorted(res.open_ports)) or "-"
                self._v(f"scan  {sub}  ->  {ports}")
            return sorted(res.open_ports)

    # web scraping

    async def _scrape_port(
        self, sub: str, port: int, https: bool
    ) -> Tuple[int, str, str, List[str]]:
        scheme = "https" if https else "http"
        url = f"{scheme}://{sub}/" if port in (80, 443) else f"{scheme}://{sub}:{port}/"

        code, body, hdrs, err = await self._aget(url, to=self.cfg.http_to, max_b=65536)

        if code == 0:
            if err and self.cfg.verbose > 0:
                self._v(f"scrape  {url}  ->  {err[:80]}")
            return 0, "", "", []

        # extract <title>
        title = ""
        try:
            parser = _TitleParser()
            parser.feed(body[:16384].decode("utf-8", errors="replace"))
            title = " ".join(parser.title.split()).strip()
        except Exception:
            pass

        hl = {k.lower(): v for k, v in hdrs.items()}
        server = hl.get("server", "")

        # tech detection: headers first, then body patterns
        tech: List[str] = []
        for hdr_name in ("x-powered-by", "x-generator", "x-cms", "x-drupal-cache"):
            val = hl.get(hdr_name, "")
            if val and val not in tech:
                tech.append(val)

        snip = body[:8192].decode("utf-8", errors="replace").lower()
        patterns = {
            "WordPress": r"wp-content|wp-includes",
            "Drupal": r"drupal\.js|drupal\.settings",
            "Joomla": r"/components/com_",
            "Laravel": r"laravel_session",
            "Django": r"csrfmiddlewaretoken",
            "React": r"react\.development|react-dom",
            "Angular": r"ng-version|angular\.js",
            "Vue": r"vue\.js|__vue__",
            "Bootstrap": r"bootstrap\.min\.css|bootstrap\.bundle",
            "jQuery": r"jquery\.min\.js|jquery-",
            "Next.js": r"__next|_next/static",
            "Nuxt": r"__nuxt|_nuxt/",
            "Cloudflare": r"cloudflare",
        }
        for name, pat in patterns.items():
            if re.search(pat, snip) and name not in tech:
                tech.append(name)

        if self.cfg.verbose > 0:
            bits = [f"scrape  {url}", f"code={code}"]
            if title:
                bits.append(f"title={title[:50]}")
            if server:
                bits.append(f"server={server[:32]}")
            self._v("  ".join(bits))

        return code, title, server, tech

    """
    try all open ports on a subdomain, prefer https before http
    stops at first port that returns a usable status code
    """

    async def _scrape(
        self, sub: str, open_ports: List[int]
    ) -> Tuple[int, str, str, List[str]]:
        if not self.cfg.scrape_on or not open_ports:
            return 0, "", "", []

        priority = sorted(open_ports, key=lambda p: (p not in (443, 8443, 4443), p))

        for port in priority:
            https = port in (443, 8443, 4443)
            code, title, server, tech = await self._scrape_port(sub, port, https)
            if code > 0:
                return code, title, server, tech

        return 0, "", "", []

    # per-subdomain workflow

    async def _process_sub(
        self,
        sub: str,
        sources: List[str],
        prog: Progress,
        tid: Any,
        live: Live,
        live_subs: List[SubHit],
    ) -> SubHit:
        t0 = time.perf_counter()

        ip = await self._resolve(sub)

        if ip:
            open_ports = await self._scan_web(sub, ip)
            code, title, server, tech = await self._scrape(sub, open_ports)
            sub_err = (
                "scrape failed"
                if self.cfg.scrape_on and open_ports and code == 0
                else None
            )
        else:
            open_ports = []
            code, title, server, tech = 0, "", "", []
            sub_err = "no dns"

        info = SubHit(
            subdomain=sub,
            ip=ip,
            sources=sources,
            ports=open_ports,
            status=code,
            title=title,
            server=server,
            tech=tech,
            elapsed=round(time.perf_counter() - t0, 3),
            err=sub_err,
        )

        async with self._lock:
            live_subs.append(info)

        prog.advance(tid)
        live.update(build_live_panel(prog, live_subs, self.cfg.domain))

        return info

    # main entry point

    async def run(self) -> SubRun:
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        domain = self.cfg.domain

        # phase 1: passive enumeration
        #
        # all sources fire simultaneously; results merged into sub -> [sources]
        # per-source counts printed immediately so you can see what's working
        #

        if not self.cfg.quiet:
            console.print()
            hr("Passive Enumeration")
            console.print()

        source_coros = [
            self._src_crtsh(domain),
            self._src_hackertarget(domain),
            self._src_alienvault(domain),
            self._src_urlscan(domain),
            self._src_rapiddns(domain),
        ]
        src_names = ["crt.sh", "hackertarget", "alienvault", "urlscan", "rapiddns"]

        if self.cfg.shodan_key:
            source_coros.insert(0, self._src_shodan(domain, self.cfg.shodan_key))
            src_names.insert(0, "shodan")

        # all sources in parallel
        batch = await asyncio.gather(*source_coros, return_exceptions=True)

        # merge + print per-source result counts
        sub_sources: Dict[str, List[str]] = {}
        if not self.cfg.quiet:
            console.print()

        for name, result in zip(src_names, batch):
            if isinstance(result, Exception):
                self._err(f"{name}: unhandled exception, {result}")
                if not self.cfg.quiet:
                    console.print(
                        Text.assemble(
                            ("  ✗ ", RED),
                            (f"{name:<16}", WHITE),
                            ("  error", DIM),
                        )
                    )
                continue

            count = 0
            for sub, src in result:
                sub = sub.strip().lower()
                if not sub:
                    continue
                self._total_raw += 1
                count += 1
                if sub not in sub_sources:
                    sub_sources[sub] = []
                if src not in sub_sources[sub]:
                    sub_sources[sub].append(src)

            color = GREEN if count else DIMMER
            count_label = f"{count} results" if count else "0 results"
            if not self.cfg.quiet:
                console.print(
                    Text.assemble(
                        ("  ◉ " if count else "  ○ ", color),
                        (f"{name:<16}", WHITE),
                        ("  →  ", DIM),
                        (count_label, CYAN if count else DIM),
                    )
                )

        self._found = set(sub_sources.keys())
        dedup_count = len(self._found)

        if not self.cfg.quiet:
            console.print()
            console.print(
                Text.assemble(
                    ("  total unique subdomains: ", DIM),
                    (str(dedup_count), f"bold {WHITE}"),
                )
            )
            console.print()

        # surface source errors right after enumeration
        if self._errors and not self.cfg.quiet:
            for e in self._errors:
                console.print(Text(f"  WARN  {e}", style=YELLOW))
            console.print()
            self._errors.clear()

        # phase 2: brute force (optional)
        if self.cfg.brute:
            if not self.cfg.quiet:
                hr("Brute Force")
                console.print()

            words: List[str] = list(WORDLIST)
            if self.cfg.wordlist and self.cfg.wordlist.exists():
                extra = self.cfg.wordlist.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                words = list(set(words + [w.strip() for w in extra if w.strip()]))

            if not self.cfg.quiet:
                console.print(
                    Text(f"  → trying {len(words):,} words against {domain}", style=DIM)
                )
            brute_results = await self._src_brute(domain, words)

            for sub, src in brute_results:
                self._total_raw += 1
                if sub not in sub_sources:
                    sub_sources[sub] = []
                if src not in sub_sources[sub]:
                    sub_sources[sub].append(src)

            self._found = set(sub_sources.keys())
            if not self.cfg.quiet:
                console.print(
                    Text(
                        f"  → found {len(brute_results)} new subdomains via brute force",
                        style=DIM,
                    )
                )
                console.print()

        subs_list = sorted(sub_sources.keys())

        if not subs_list:
            return SubRun(
                domain=domain,
                subdomains=[],
                total_found=dedup_count,
                total_resolved=0,
                started=started.isoformat(),
                finished=datetime.now(timezone.utc).isoformat(),
                elapsed=round(time.perf_counter() - t0, 3),
                errors=self._errors,
            )

        # phase 3: parallel resolve + port scan + scrape
        #
        # each subdomain: resolve dns → port scan + scrape in parallel
        # _resolve_sem and _nmap_sem prevent thundering-herd

        if not self.cfg.quiet:
            hr("Resolve  ·  Port Scan  ·  Scrape")
            console.print()

        live_subs: List[SubHit] = []
        prog = mk_prog(transient=False)
        tid = prog.add_task(
            f"Processing {len(subs_list)} subdomains", total=len(subs_list)
        )

        live_console = console
        if self.cfg.quiet:
            live_console = Console(
                file=io.StringIO(),
                highlight=False,
                force_terminal=False,
                color_system=None,
            )

        live = Live(
            build_live_panel(prog, live_subs, domain),
            console=live_console,
            refresh_per_second=8,
            transient=True,
        )

        all_results: List[SubHit] = []

        async def _run_one(sub: str):
            info = await self._process_sub(
                sub, sub_sources[sub], prog, tid, live, live_subs
            )
            all_results.append(info)
            ip_part = info.ip or "unresolved"
            src_part = ", ".join(info.sources[:2])
            if not self.cfg.quiet:
                live.console.print(
                    Text.assemble(
                        ("  ◉ ", GREEN),
                        (f"{sub:<46}", f"bold {WHITE}"),
                        ("  →  ", DIM),
                        (ip_part, SVC_COL),
                        ("  ", DIM),
                        (f"[{src_part}]", DIMMER),
                    )
                )
            if self.cfg.verbose > 0 and not self.cfg.quiet:
                live.console.print(
                    Text(
                        f"      ports={','.join(str(p) for p in info.ports) or '-'}  "
                        f"status={info.status or '-'}  "
                        f"title={(info.title or '-')[:60]}",
                        style=DIMMER,
                    )
                )

        live.start()
        try:
            await asyncio.gather(*[asyncio.create_task(_run_one(s)) for s in subs_list])
        finally:
            live.stop()

        all_results.sort(key=lambda x: x.subdomain)
        resolved = sum(1 for r in all_results if r.ip)

        return SubRun(
            domain=domain,
            subdomains=all_results,
            total_found=len(all_results),
            total_resolved=resolved,
            started=started.isoformat(),
            finished=datetime.now(timezone.utc).isoformat(),
            elapsed=round(time.perf_counter() - t0, 3),
            errors=self._errors,
        )


def build_parser(prog: Optional[str] = None) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="async subdomain enumerator: passive sources + async port scans + scraping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("domain", help="target apex domain  (e.g. example.com)")
    p.add_argument("-K", "--shodan-key", default=None, help="shodan api key")
    p.add_argument(
        "-b",
        "--brute",
        action="store_true",
        help="brute force common subdomain prefixes after passive enumeration",
    )
    p.add_argument(
        "-w",
        "--wordlist",
        type=Path,
        default=None,
        help="custom wordlist file for brute force (one word per line)",
    )
    p.add_argument(
        "-N",
        "--no-port-scan",
        "--no-nmap",
        dest="no_nmap",
        action="store_true",
        help="skip web port scanning on resolved subdomains",
    )
    p.add_argument(
        "-W", "--no-scrape", action="store_true", help="skip http page scraping"
    )
    p.add_argument("-M", "--nmap-args", default="", help=argparse.SUPPRESS)
    p.add_argument(
        "-c",
        "--resolve-concurrency",
        type=int,
        default=200,
        help="concurrent dns resolution limit (default: 200)",
    )
    p.add_argument(
        "-C",
        "--scan-concurrency",
        "--nmap-concurrency",
        dest="nmap_concurrency",
        type=int,
        default=30,
        help="parallel per-host port scan limit (default: 30)",
    )
    p.add_argument(
        "-t",
        "--http-timeout",
        type=float,
        default=8.0,
        help="http scrape timeout in seconds (default: 8.0)",
    )
    p.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="show extra error detail and tracebacks",
    )
    p.add_argument(
        "-o",
        "--out",
        default=None,
        help="write results to file (.html default, .json/.csv by suffix)",
    )
    p.add_argument(
        "-v",
        action="count",
        default=0,
        help="show extra source/report detail",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress scan-time banners and progress chatter",
    )
    return p


def run_cli(argv: Optional[List[str]] = None, prog: Optional[str] = None) -> int:
    parser = build_parser(prog=prog)
    args = parser.parse_args(argv)

    # strip scheme if you typed a full url
    domain = re.sub(r"^https?://", "", args.domain.strip().lower()).split("/")[0]

    if not domain:
        console.print(Text("  ERROR  No domain specified.", style=RED))
        return 2
    if args.quiet and args.v:
        console.print(Text("  ERROR  Choose either -v or -q, not both.", style=RED))
        return 2

    if args.resolve_concurrency < 1 or args.nmap_concurrency < 1:
        console.print(Text("  ERROR  Concurrency values must be >= 1.", style=RED))
        return 2

    cfg = Cfg(
        domain=domain,
        shodan_key=args.shodan_key,
        brute=args.brute,
        wordlist=args.wordlist,
        nmap_on=not args.no_nmap,
        scrape_on=not args.no_scrape,
        resolve_c=args.resolve_concurrency,
        nmap_c=args.nmap_concurrency,
        http_to=args.http_timeout,
        debug=args.debug,
        verbose=args.v,
        quiet=args.quiet,
    )

    if not args.quiet:
        hdr(domain, cfg)
    scanner = SubScanner(cfg)

    try:
        run = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        console.print()
        console.print(Text("  Interrupted.", style=YELLOW))
        return 130
    except Exception as err:
        t = Text()
        t.append("  ERROR  ", style=f"bold {RED}")
        t.append(str(err), style=DIM)
        console.print(t)
        if args.debug:
            console.print(Text(traceback.format_exc(), style=DIMMER))
        return 1
    finally:
        scanner.close()

    show_run(run)

    if run.errors:
        hr("Source Errors")
        console.print()
        for e in run.errors:
            console.print(Text(f"  {e}", style=DIMMER))
        console.print()

    if args.out:
        out_path, mode = _out_mode(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if mode == "json":
            out_path.write_text(
                json.dumps(run.to_dict(), indent=2), encoding="utf-8"
            )
        elif mode == "csv":
            out_path.write_text(_sub_csv(run), encoding="utf-8")
        else:
            out_path.write_text(build_sub_html(run), encoding="utf-8")
        if args.v:
            console.print(Text(f"  output mode  {mode}  ->  {out_path}", style=DIMMER))
        t = Text()
        t.append("  Report saved  ", style=DIM)
        t.append(str(out_path), style=CYAN)
        console.print(t)
        console.print()

    return 0


# compatibility aliases
res_tbl = sub_tbl
stats_tbl = sum_tbl
show = show_run
_csv_sub = _sub_csv
build_html = build_sub_html
mk_parser = build_parser


def main():
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
