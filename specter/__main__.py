"""
module entry point for `python -m specter`
"""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main(prog="python -m specter"))
