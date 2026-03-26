"""
async subdomain enumerator: passive sources + brute force + parallel nmap + page scraping

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
import json
import re
import shlex
import shutil
import socket
import ssl
import time
import traceback
import urllib.error
import urllib.request
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

# web ports nmap checks on each resolved subdomain
WEB_PORTS = [80, 443, 8080, 8443, 8888, 3000, 5000, 4443]

# http timeout for passive source fetches (seconds)
# generous: crt.sh can be slow on large domains
HTTP_TO = 30.0

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


# result from resolving + scanning one subdomain
@dataclass
class SubInfo:
    subdomain: str
    ip: str  # resolved ipv4/v6, empty string if no dns
    sources: List[str]  # which sources found this subdomain
    ports: List[int]  # open web ports found by nmap
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
class SubScanOut:
    domain: str
    subdomains: List[SubInfo]
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
class Cfg:
    domain: str
    shodan_key: Optional[str]
    brute: bool
    wordlist: Optional[Path]
    nmap_on: bool
    scrape_on: bool
    n_args: List[str]
    resolve_c: int
    nmap_c: int
    http_to: float
    debug: bool


def hr(title: str = "") -> None:
    if title:
        console.print(
            Rule(title=Text(f"  {title}  ", style=DIMMER), style=BORDER, align="left")
        )
    else:
        console.print(Rule(style=BORDER))


def hdr(domain: str, cfg: Cfg) -> None:
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

    nmap_mode = "enabled" if cfg.nmap_on else "disabled"
    scrape_mode = "enabled" if cfg.scrape_on else "disabled"

    grid = Table.grid(padding=(0, 0))
    grid.add_column(min_width=16)
    grid.add_column(min_width=38)
    grid.add_column(min_width=6)
    grid.add_column(min_width=16)
    grid.add_column()

    rows = [
        ("Domain", domain, "Nmap Scan", nmap_mode),
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


def live_disc_tbl(subs: List[SubInfo], domain: str) -> Table:
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


def build_live_panel(progress: Progress, subs: List[SubInfo], domain: str) -> Group:
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


def res_tbl(res: SubScanOut) -> Table:
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

    for s in res.subdomains:
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


def stats_tbl(res: SubScanOut) -> Table:
    total = res.total_found
    resolved = res.total_resolved
    unres = total - resolved
    with_web = sum(1 for s in res.subdomains if s.ports)
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

    grid.add_row(
        k("Found"),
        v(f"{total:,} subdomains"),
        k("Elapsed"),
        v(f"{res.elapsed:.3f}s"),
        k("Domain"),
        v(res.domain),
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


def show(res: SubScanOut) -> None:
    console.print()

    console.print(
        Panel(
            Padding(stats_tbl(res), (0, 1)),
            title=f"[bold {WHITE}]Scan Summary[/bold {WHITE}]",
            border_style=BORDER,
            box=box.ROUNDED,
            expand=True,
        )
    )

    if res.subdomains:
        console.print(
            Panel(
                Padding(res_tbl(res), (0, 1)),
                title=f"[bold {WHITE}]Subdomains  •  {res.domain}[/bold {WHITE}]",
                border_style=CYAN,
                box=box.ROUNDED,
                expand=True,
            )
        )
    else:
        console.print(
            Panel(
                Padding(Text("No subdomains discovered.", style=DIM), (0, 1)),
                title=f"[bold {WHITE}]Subdomains  •  {res.domain}[/bold {WHITE}]",
                border_style=BORDER,
                box=box.ROUNDED,
                expand=True,
            )
        )

    console.print()


"""
blocking http get: always uses relaxed SSL context, follows redirects,
caps body at max_bytes. called via run_in_executor so asyncio never blocks.

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


# async wrapper: all source fetches and scrapes go through here
async def _aget(
    url: str,
    timeout: float = HTTP_TO,
    max_bytes: int = 5 << 20,
) -> Tuple[int, bytes, Dict[str, str], str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: _http_get(url, timeout, max_bytes))


class SubScanner:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self._found: Set[str] = set()
        self._lock = asyncio.Lock()
        self._resolve_sem = asyncio.Semaphore(cfg.resolve_c)
        self._nmap_sem = asyncio.Semaphore(cfg.nmap_c)
        self._errors: List[str] = []
        self._total_raw = 0

    async def _src_crtsh(self, domain: str) -> List[Tuple[str, str]]:
        url = CRTSH_URL.format(d=domain)
        try:
            # Increased timeout to 90s, and set max_bytes to -1 for unlimited buffer
            code, body, _, err = await _aget(url, timeout=90.0, max_bytes=-1)
            if not body:
                self._errors.append(f"crt.sh: empty response (http {code}), {err}")
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
            self._errors.append(f"crt.sh: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._errors.append(f"crt.sh: {exc}")
            return []

    async def _src_hackertarget(self, domain: str) -> List[Tuple[str, str]]:
        url = HACKERTARGET_URL.format(d=domain)
        try:
            code, body, _, err = await _aget(url)
            if not body:
                self._errors.append(
                    f"hackertarget: empty response (http {code}), {err}"
                )
                return []
            text = body.decode("utf-8", errors="replace").strip()
            if text.lower().startswith("error") or "api count" in text.lower():
                self._errors.append(f"hackertarget: rate limited, {text[:80]}")
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
            self._errors.append(f"hackertarget: {exc}")
            return []

    async def _src_alienvault(self, domain: str) -> List[Tuple[str, str]]:
        url = ALIENVAULT_URL.format(d=domain)
        try:
            code, body, _, err = await _aget(url)
            if not body:
                self._errors.append(f"alienvault: empty response (http {code}) {err}")
                return []
            data = json.loads(body.decode("utf-8", errors="replace"))
            subs: Set[str] = set()
            for rec in data.get("passive_dns", []):
                hostname = str(rec.get("hostname", "")).strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
            return [(s, "alienvault") for s in subs]
        except json.JSONDecodeError as exc:
            self._errors.append(f"alienvault: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._errors.append(f"alienvault: {exc}")
            return []

    async def _src_urlscan(self, domain: str) -> List[Tuple[str, str]]:
        url = URLSCAN_URL.format(d=domain)
        try:
            code, body, _, err = await _aget(url)
            if not body:
                self._errors.append(f"urlscan: empty response (http {code}) {err}")
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
            self._errors.append(f"urlscan: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._errors.append(f"urlscan: {exc}")
            return []

    async def _src_rapiddns(self, domain: str) -> List[Tuple[str, str]]:
        url = RAPIDDNS_URL.format(d=domain)
        try:
            code, body, _, err = await _aget(url)
            if not body:
                self._errors.append(f"rapiddns: empty response (http {code}) {err}")
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
            self._errors.append(f"rapiddns: {exc}")
            return []

    async def _src_shodan(self, domain: str, key: str) -> List[Tuple[str, str]]:
        url = SHODAN_DNS_URL.format(d=domain, k=key)
        try:
            code, body, _, err = await _aget(url)
            if not body:
                self._errors.append(f"shodan: empty response (http {code}) {err}")
                return []
            data = json.loads(body.decode("utf-8", errors="replace"))
            if "error" in data:
                self._errors.append(f"shodan: {data['error']}")
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
            self._errors.append(f"shodan: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._errors.append(f"shodan: {exc}")
            return []

    async def _src_brute(self, domain: str, words: List[str]) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        lock = asyncio.Lock()

        async def _try(word: str):
            candidate = f"{word}.{domain}"
            async with self._lock:
                if candidate in self._found:
                    return
            async with self._resolve_sem:
                try:
                    loop = asyncio.get_running_loop()
                    await asyncio.wait_for(
                        loop.getaddrinfo(candidate, None), timeout=3.0
                    )
                    async with lock:
                        results.append((candidate, "bruteforce"))
                except Exception:
                    pass

        await asyncio.gather(*[_try(w) for w in words])
        return results

    # dns resolution

    async def _resolve(self, host: str) -> str:
        async with self._resolve_sem:
            loop = asyncio.get_running_loop()
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
                    timeout=4.0,
                )
                return infos[0][4][0]
            except Exception:
                return ""

    async def _nmap_sub(self, ip: str) -> List[int]:
        if not self.cfg.nmap_on or not shutil.which("nmap"):
            return []

        async with self._nmap_sem:
            ports_str = ",".join(str(p) for p in WEB_PORTS)
            cmd = (
                ["nmap", "-Pn", "-n", "--open", "-p", ports_str]
                + self.cfg.n_args
                + [ip]
            )

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return []

            out_b, _ = await proc.communicate()
            out = (out_b or b"").decode(errors="replace")

            open_ports = []
            for line in out.splitlines():
                m = re.match(r"^\s*(\d+)/tcp\s+open", line)
                if m:
                    open_ports.append(int(m.group(1)))
            return open_ports

    # web scraping

    async def _scrape_port(
        self, sub: str, port: int, https: bool
    ) -> Tuple[int, str, str, List[str]]:
        scheme = "https" if https else "http"
        url = f"{scheme}://{sub}/" if port in (80, 443) else f"{scheme}://{sub}:{port}/"

        code, body, hdrs, _ = await _aget(
            url, timeout=self.cfg.http_to, max_bytes=65536
        )

        if code == 0:
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
        live_subs: List[SubInfo],
    ) -> SubInfo:
        t0 = time.perf_counter()

        ip = await self._resolve(sub)

        if ip:
            nmap_task = asyncio.create_task(self._nmap_sub(ip))
            open_ports = await nmap_task
            code, title, server, tech = await self._scrape(sub, open_ports)
        else:
            open_ports = []
            code, title, server, tech = 0, "", "", []

        info = SubInfo(
            subdomain=sub,
            ip=ip,
            sources=sources,
            ports=open_ports,
            status=code,
            title=title,
            server=server,
            tech=tech,
            elapsed=round(time.perf_counter() - t0, 3),
        )

        async with self._lock:
            live_subs.append(info)

        prog.advance(tid)
        live.update(build_live_panel(prog, live_subs, self.cfg.domain))

        return info

    # main entry point

    async def run(self) -> SubScanOut:
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        domain = self.cfg.domain

        # phase 1: passive enumeration
        #
        # all sources fire simultaneously; results merged into sub -> [sources]
        # per-source counts printed immediately so you can see what's working
        #

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
        console.print()

        for name, result in zip(src_names, batch):
            if isinstance(result, Exception):
                self._errors.append(f"{name}: unhandled exception, {result}")
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

        console.print()
        console.print(
            Text.assemble(
                ("  total unique subdomains: ", DIM),
                (str(dedup_count), f"bold {WHITE}"),
            )
        )
        console.print()

        # surface source errors right after enumeration
        if self._errors:
            for e in self._errors:
                console.print(Text(f"  ⚠  {e}", style=YELLOW))
            console.print()
            self._errors.clear()

        # phase 2: brute force (optional)
        if self.cfg.brute:
            hr("Brute Force")
            console.print()

            words: List[str] = list(WORDLIST)
            if self.cfg.wordlist and self.cfg.wordlist.exists():
                extra = self.cfg.wordlist.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                words = list(set(words + [w.strip() for w in extra if w.strip()]))

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
            console.print(
                Text(
                    f"  → found {len(brute_results)} new subdomains via brute force",
                    style=DIM,
                )
            )
            console.print()

        subs_list = sorted(sub_sources.keys())

        if not subs_list:
            return SubScanOut(
                domain=domain,
                subdomains=[],
                total_found=self._total_raw,
                total_resolved=0,
                started=started.isoformat(),
                finished=datetime.now(timezone.utc).isoformat(),
                elapsed=round(time.perf_counter() - t0, 3),
                errors=self._errors,
            )

        # phase 3: parallel resolve + nmap + scrape
        #
        # each subdomain: resolve dns → nmap + scrape in parallel
        # _resolve_sem and _nmap_sem prevent thundering-herd

        hr("Resolve  ·  Nmap  ·  Scrape")
        console.print()

        live_subs: List[SubInfo] = []
        prog = mk_prog(transient=False)
        tid = prog.add_task(
            f"Processing {len(subs_list)} subdomains", total=len(subs_list)
        )

        live = Live(
            build_live_panel(prog, live_subs, domain),
            console=console,
            refresh_per_second=8,
            transient=True,
        )

        all_results: List[SubInfo] = []

        async def _run_one(sub: str):
            info = await self._process_sub(
                sub, sub_sources[sub], prog, tid, live, live_subs
            )
            all_results.append(info)
            ip_part = info.ip or "unresolved"
            src_part = ", ".join(info.sources[:2])
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

        live.start()
        try:
            await asyncio.gather(*[asyncio.create_task(_run_one(s)) for s in subs_list])
        finally:
            live.stop()

        all_results.sort(key=lambda x: x.subdomain)
        resolved = sum(1 for r in all_results if r.ip)

        return SubScanOut(
            domain=domain,
            subdomains=all_results,
            total_found=len(all_results),
            total_resolved=resolved,
            started=started.isoformat(),
            finished=datetime.now(timezone.utc).isoformat(),
            elapsed=round(time.perf_counter() - t0, 3),
            errors=self._errors,
        )


def mk_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="async subdomain enumerator: passive sources + nmap + scraping",
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
        "--no-nmap",
        action="store_true",
        help="skip nmap web port scan on resolved subdomains",
    )
    p.add_argument(
        "-W", "--no-scrape", action="store_true", help="skip http page scraping"
    )
    p.add_argument(
        "-M", "--nmap-args", default="-T4", help="extra nmap arguments (default: -T4)"
    )
    p.add_argument(
        "-c",
        "--resolve-concurrency",
        type=int,
        default=200,
        help="concurrent dns resolution limit (default: 200)",
    )
    p.add_argument(
        "-C",
        "--nmap-concurrency",
        type=int,
        default=30,
        help="parallel nmap scan limit (default: 30)",
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
    p.add_argument("-o", "--out", default=None, help="write json results to file")
    return p


def run_cli(argv: Optional[List[str]] = None) -> int:
    parser = mk_parser()
    args = parser.parse_args(argv)

    # strip scheme if you typed a full url
    domain = re.sub(r"^https?://", "", args.domain.strip().lower()).split("/")[0]

    if not domain:
        console.print(Text("  ERROR  No domain specified.", style=RED))
        return 2

    if args.resolve_concurrency < 1 or args.nmap_concurrency < 1:
        console.print(Text("  ERROR  Concurrency values must be >= 1.", style=RED))
        return 2

    if not args.no_nmap and shutil.which("nmap") is None:
        console.print(
            Text(
                "  WARNING  nmap not found in PATH, nmap scanning disabled.",
                style=YELLOW,
            )
        )
        args.no_nmap = True

    cfg = Cfg(
        domain=domain,
        shodan_key=args.shodan_key,
        brute=args.brute,
        wordlist=args.wordlist,
        nmap_on=not args.no_nmap,
        scrape_on=not args.no_scrape,
        n_args=shlex.split(args.nmap_args),
        resolve_c=args.resolve_concurrency,
        nmap_c=args.nmap_concurrency,
        http_to=args.http_timeout,
        debug=args.debug,
    )

    hdr(domain, cfg)

    try:
        result = asyncio.run(SubScanner(cfg).run())
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

    show(result)

    if result.errors:
        hr("Source Errors")
        console.print()
        for e in result.errors:
            console.print(Text(f"  {e}", style=DIMMER))
        console.print()

    if args.out and result.subdomains:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
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
