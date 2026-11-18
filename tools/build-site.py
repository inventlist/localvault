#!/usr/bin/env python3
"""Build the portable Kuickr site from its single authored HTML source."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "site/landing.html").read_text()
tokens = (ROOT / "site/nodepad-tokens.css").read_text()
assert source.count("/* NODEPAD_TOKENS */") == 1
output = ROOT / ".kuickr-build"
output.mkdir(exist_ok=True)
(output / "index.html").write_text(source.replace("/* NODEPAD_TOKENS */", tokens))
print(output / "index.html")
