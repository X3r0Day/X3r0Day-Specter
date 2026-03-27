# X3r0Day-Specter

Subdomain enumeration and TCP port scanning.

[![X3r0Day](https://img.shields.io/badge/part%20of-X3r0Day%20Project-purple?style=flat-square)](https://x3r0day.me)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

```
   _____ ____   ___    __ ______    ___  ____  
  / ___/|    \ /  _]  /  ]      |  /  _]|    \ 
 (   \_ |  o  )  [_  /  /|      | /  [_ |  D  )
  \__  ||   _/    _]/  / |_|  |_||    _]|    / 
  /  \ ||  | |   [_/   \_  |  |  |   [_ |    \ 
  \    ||  | |     \     | |  |  |     ||  .  \
   \___||__| |_____|\____| |__|  |_____||__|\_|
```

## Install

```bash
pip install rich
```

## Quick start

```bash
# Subdomain enumeration
python3 main.py subdomain example.com

# Subdomain with brute force
python3 main.py subdomain example.com -b

# Save subdomain report
python3 main.py subdomain example.com -o subdomains.html

# Port scan
python3 main.py scanme.nmap.org

# Specific ports
python3 main.py target.com -p 22,80,443
```

## Commands

| Command | Description |
|---------|-------------|
| `python3 main.py subdomain <domain>` | Enumerate subdomains |
| `python3 main.py scan <target>` | TCP port scan |
| `python3 main.py <target>` | Default: TCP port scan |

## Subdomain Enumeration

### Examples

```bash
# Passive enumeration
python3 main.py subdomain example.com

# With brute force
python3 main.py subdomain example.com -b

# Custom wordlist
python3 main.py subdomain example.com -b -w words.txt

# Add Shodan
python3 main.py subdomain example.com -K "$SHODAN_KEY"

# Skip web port checks
python3 main.py subdomain example.com -N

# Skip page scraping
python3 main.py subdomain example.com -W

# Save report
python3 main.py subdomain example.com -o subdomains.html
```

### Workflow

1. Pull candidates from passive sources in parallel
2. Deduplicate, track sources per subdomain
3. Optionally brute-force prefixes
4. Resolve to IP
5. Check common web ports
6. Scrape title, server, tech from responsive hosts

### Passive sources

| Source | Default | Notes |
|--------|---------|-------|
| `crt.sh` | Yes | Certificate Transparency logs |
| `hackertarget` | Yes | Host search API |
| `alienvault` | Yes | OTX Passive DNS |
| `urlscan` | Yes | Indexed domains |
| `rapiddns` | Yes | DNS data |
| `shodan` | No | Add with `-K` |
| `bruteforce` | No | Add with `-b` |

### Args

#### Positional

| Arg | Type | Description |
|-----|------|-------------|
| `domain` | string | Target domain (e.g. `example.com`) |

#### Discovery

| Short | Long | Type | Default | Description |
|-------|------|------|---------|-------------|
| `-K` | `--shodan-key` | string | - | Shodan API key |
| `-b` | `--brute` | flag | - | Brute force prefixes |
| `-w` | `--wordlist` | path | - | Custom wordlist |
| `-N` | `--no-port-scan` | flag | - | Skip web port checks |
| `-W` | `--no-scrape` | flag | - | Skip page scraping |

#### Performance & Output

| Short | Long | Type | Default | Description |
|-------|------|------|---------|-------------|
| `-c` | `--resolve-concurrency` | int | 200 | Concurrent DNS lookups |
| `-C` | `--scan-concurrency` | int | 30 | Concurrent port scans |
| `-t` | `--http-timeout` | float | 8.0 | HTTP timeout (seconds) |
| `-o` | `--out` | path | - | Output file (html/csv/json) |
| `-v` | - | flag | - | Verbose output |
| `-q` | `--quiet` | flag | - | Suppress progress |

### JSON output

```json
{
  "domain": "example.com",
  "subdomains": [
    {
      "subdomain": "www.example.com",
      "ip": "192.168.1.1",
      "sources": ["crt.sh", "urlscan"],
      "ports": [80, 443],
      "status": 200,
      "title": "Example Domain",
      "server": "ECS",
      "tech": [],
      "elapsed": 0.812,
      "err": null
    }
  ],
  "total_found": 12,
  "total_resolved": 8,
  "started": "2026-03-24T10:30:00Z",
  "finished": "2026-03-24T10:30:04Z",
  "elapsed": 4.219,
  "errors": []
}
```

## TCP Port Scanning

### Examples

```bash
# Basic scan (default: top 1000 ports)
python3 main.py scanme.nmap.org

# Specific ports
python3 main.py target.com -p 22,80,443,8080

# Top 100 ports
python3 main.py target.com -P 100

# All ports
python3 main.py target.com -a

# Stealth mode
python3 main.py target.com --stealth

# SYN scan (requires root)
python3 main.py target.com --syn-scan

# Aggressive service detection
python3 main.py target.com -S -U

# Save report
python3 main.py target.com -o results.html
```

### Behavior

- Resolves hostname, scans TCP ports, probes services
- Basic mode: HTTP hints, SSH banners, TLS cert data
- `-S` uses nmap for deeper service detection
- `--stealth` reduces noise and concurrency
- `--syn-scan` sends raw SYN packets (needs root)

### Args

#### Positional

| Arg | Type | Description |
|-----|------|-------------|
| `target` | string | Hostname or IP to scan |

#### Port selection

| Short | Long | Type | Default | Description |
|-------|------|------|---------|-------------|
| `-p` | `--ports` | string | - | Specific ports: `22,80,443` or range `1-1024` |
| `-P` | `--top-ports` | int | 1000 | Scan top N ports |
| `-a` | `--all-ports` | flag | - | Scan all 65535 ports |

#### Scan & Service detection

| Short | Long | Type | Default | Description |
|-------|------|------|---------|-------------|
| `-c` | `--concurrency` | int | 1000 | Concurrent connections |
| `-t` | `--timeout` | float | 1.5 | Connect timeout (seconds) |
| `-C` | `--svc-concurrency` | int | 20 | Concurrent service probes |
| `-S` | `--aggr-svc-scan` | flag | - | Use nmap for service detection |
| `-M` | `--nmap-args` | string | `-sV --open` | nmap arguments |
| `-U` | `--sudo-nmap` | flag | - | Run nmap with sudo |
| `-N` | `--no-svc-scan` | flag | - | Skip service detection |
| - | `--stealth` | flag | - | Lower-noise profile |
| - | `--syn-scan` | flag | - | Raw SYN scan (needs root) |

#### Output

| Short | Long | Type | Default | Description |
|-------|------|------|---------|-------------|
| `-o` | `--out` | path | - | Output file |
| `-v` | - | flag | - | Verbose; `-vv` for raw output |
| `-q` | `--quiet` | flag | - | Suppress progress |

### JSON output

```json
{
  "target": "scanme.nmap.org",
  "ip": "192.168.1.0",
  "req_ports": [1, 2, 3],
  "open_ports": [22, 80, 9929],
  "svcs": [
    {
      "port": 22,
      "ok": true,
      "state": "open",
      "svc": "ssh",
      "info": "Banner: SSH-2.0-OpenSSH_9.7",
      "elapsed": 0.023,
      "n_cmd": "light ssh probe",
      "raw": "SSH-2.0-OpenSSH_9.7",
      "err": null
    }
  ],
  "started": "2026-03-24T10:30:00Z",
  "finished": "2026-03-24T10:30:02Z",
  "elapsed": 2.345,
  "errors": []
}
```

## Requirements

- Python 3.10+
- Rich (`pip install rich`)
- Nmap (optional, for aggressive mode)

`--syn-scan` needs root. `--sudo-nmap` prompts for sudo when using nmap.

## Project structure

```
x3r0day-specter/
├── main.py
├── src/
│   ├── scanner/
│   │   ├── port_scan.py
│   │   └── subdomain.py
│   └── core/
│       └── results.py
├── PLAN.md
└── README.md
```

## Links

- [GitHub](https://github.com/x3r0day/x3r0day-specter)
- [Website](https://x3r0day.me)

---

MIT License. See [LICENSE](LICENSE).
