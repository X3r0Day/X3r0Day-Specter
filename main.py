##################################################################################
# Part of X3r0Day Project. See LICENSE.md for licensing information.
# MIT License - Commercial use, Modification, Distribution, Private use allowed.
##################################################################################

"""
compatibility shim for repo-local execution
"""

from specter.cli import main


if __name__ == "__main__":
    raise SystemExit(main(prog="python3 main.py"))
