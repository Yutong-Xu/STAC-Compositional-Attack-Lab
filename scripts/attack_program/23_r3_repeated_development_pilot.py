"""Reconstructed entrypoint; new run inputs required, no historical run defaults."""

import sys

from stac_attack_lab.attack_program.campaign_cli import main

if __name__ == "__main__":
    raise SystemExit(main(["--kind", "repeated", *sys.argv[1:]]))
