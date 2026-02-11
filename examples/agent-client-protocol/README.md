# Agent Client Protocol

This example demonstrates how connect to an AI Agent running in a matchlock sandbox from a local streamlit application using [Agent Client Protocol](https://agentclientprotocol.com/get-started/introduction)

## Build the Image

### Using Docker

Currently this is the fastest way of building the image:

```bash
docker build -t acp:latest examples/agent-client-protocol
docker save acp:latest | matchlock image import acp:latest
```

### Using Matchlock

You can use `matchlock` if you don't have Docker installed:

```bash
# `--build-cache-size 30000` so that you can repeatedly build reliably without running out of device space
# Otherwise you can omit it, and later on introduce it as matchlock automatically grows the disk
matchlock build -t acp:latest --build-cache-size 30000 examples/agent-client-protocol
```

## Run the Agent from the Streamlit App

```bash
uv run examples/agent-client-protocol/main.py
```
