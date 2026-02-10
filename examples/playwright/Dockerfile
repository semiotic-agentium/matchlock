FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System deps + Node.js 22 + Chromium runtime deps (single layer)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    libnss3 \
    libatk1.0-0t64 \
    libatk-bridge2.0-0t64 \
    libcups2t64 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2t64 \
    libatspi2.0-0t64 \
    libwayland-client0 \
    fonts-liberation \
    fonts-noto-color-emoji \
    xdg-utils \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Create non-root agent user
RUN useradd -m -s /bin/bash agent

# Install Claude Code + Playwright MCP + Chromium as agent user
USER agent
ENV NPM_CONFIG_PREFIX=/home/agent/.npm-global
ENV PATH="/home/agent/.npm-global/bin:$PATH"
RUN npm install -g @anthropic-ai/claude-code \
    && npx @playwright/mcp@latest --help || true \
    && npx playwright install chromium \
    && npm cache clean --force \
    && rm -rf /tmp/* /home/agent/.npm

# Pre-configure Playwright MCP server
USER root
RUN mkdir -p /home/agent/.claude /workspace && chown -R agent:agent /home/agent/.claude /workspace
COPY claude-settings.json /etc/matchlock-mcp.json
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER agent
WORKDIR /workspace
