# X3r0Day-Specter Plan

## Done

- Async TCP port scanner
- Multi-target scanning
- Basic service detection (port lookup)
- Native probes (HTTP title, SSH banner, TLS cert)
- Aggressive service detection (nmap)
- JSON output
- CSV/HTML reports
- Rich terminal UI
- Verbosity flags (-v, -q)
- Multi-target summary table
- Error handling

## Todo

1. SQLite storage - save scan history
2. diff command - compare scans
3. CIDR target parsing
4. Graceful interrupt
5. Confidence scoring
6. Refactor the codebase to have shared libs (IMP)

## Ideas

- Webhook notifications
- HTML dashboard
- Concurrent host scanning
- Idle/hide scan modes
