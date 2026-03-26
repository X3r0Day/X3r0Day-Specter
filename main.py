##################################################################################
# Part of X3r0Day Project. See LICENSE.md for licensing information.
# MIT License - Commercial use, Modification, Distribution, Private use allowed.
##################################################################################

"""
cli entry point for x3r0day security toolkit
"""

import sys

from src.scanner.port_scan import run_cli as run_port_scan
from src.scanner.subdomain import run_cli as run_subdomain

banner = r"""
  _____ ____   ___    __ ______    ___  ____  
 / ___/|    \ /  _]  /  ]      |  /  _]|    \ 
(   \_ |  o  )  [_  /  /|      | /  [_ |  D  )
 \__  ||   _/    _]/  / |_|  |_||    _]|    / 
 /  \ ||  | |   [_/   \_  |  |  |   [_ |    \ 
 \    ||  | |     \     | |  |  |     ||  .  \
  \___||__| |_____|\____| |__|  |_____||__|\_|

                                by - X3r0Day | x3r0day.me
"""

USAGE = """
commands:
  scan       <target> [opts]   async tcp port scanner
  subdomain  <domain> [opts]   async subdomain enumerator

run 'x3r0day <command> --help' for command-specific options
"""


def main():
    argv = sys.argv[1:]

    if not argv:
        print(banner)
        print(USAGE)
        return 0

    if argv[0] == "banner":
        print(banner)
        return 0

    if argv[0] in ("scan", "portscan"):
        return run_port_scan(argv[1:])

    if argv[0] in ("subdomain", "sub", "enum"):
        return run_subdomain(argv[1:])

    return run_port_scan(argv)


if __name__ == "__main__":
    raise SystemExit(main())
