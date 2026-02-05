#!/usr/bin/env python3
"""Matchlock Python SDK Example - Secret MITM Demo

Usage: cd matchlock && python3 examples/python/main.py
With secrets: ANTHROPIC_API_KEY=sk-xxx python3 examples/python/main.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "sdk" / "python"))

from matchlock import Client, Config, CreateOptions, Secret

# Use ./bin/matchlock relative to current directory (run from project root)
config = Config(binary_path="./bin/matchlock", use_sudo=True)

opts = CreateOptions(image="standard")
if api_key := os.environ.get("ANTHROPIC_API_KEY"):
    opts.secrets = [Secret(name="ANTHROPIC_API_KEY", value=api_key, hosts=["api.anthropic.com"])]
    print("Secret MITM enabled for api.anthropic.com")

with Client(config) as client:
    vm_id = client.create(opts)
    print(f"Created VM: {vm_id}\n")

    # Test basic connectivity
    result = client.exec("ping -c 1 8.8.8.8 2>&1 | tail -2")
    print(f"Network: {result.stdout.strip()}")

    # If API key configured, show placeholder and test API
    if os.environ.get("ANTHROPIC_API_KEY"):
        result = client.exec("echo ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY")
        print(f"\n{result.stdout.strip()}")
        print("(Real key is replaced by MITM proxy in HTTP requests)")

        print("\nTesting Anthropic API...")
        result = client.exec('''curl -s https://api.anthropic.com/v1/messages \
            -H "Content-Type: application/json" \
            -H "x-api-key: $ANTHROPIC_API_KEY" \
            -H "anthropic-version: 2023-06-01" \
            -d '{"model":"claude-3-haiku-20240307","max_tokens":50,"messages":[{"role":"user","content":"Say hello in exactly 3 words"}]}' ''')
        print(f"Response: {result.stdout}")
