# syntax=docker/dockerfile:1.7
#
# agent-redblue-ci runtime image.
#
# Principles:
#   1. Every tool version is pinned. Renovate bumps the pins; reviewers check the SHA/digest.
#   2. Binaries are fetched from the tool's own GitHub release, checksum-verified where
#      upstream publishes checksums, and copied into the final stage. No curl|bash.
#   3. No `pip install` / `npm install` at runtime. The final stage has a pre-populated
#      venv and pre-fetched node_modules.
#   4. The final stage runs as non-root uid 10001 / gid 10001 ("redblue").
#
# NOTE: This Dockerfile is the scaffold. Actual tool versions are TODO markers to be
# resolved by a follow-up PR that locks exact SHAs + checksums against upstream signed
# releases. Do not build-publish this image without resolving every TODO.

# ── Stage 1: python-tool-builder ─────────────────────────────────────────────
FROM python:3.12.7-slim-bookworm AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# System deps needed only to compile Python wheels, not shipped in final image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential=12.9 \
        git=1:2.39.5-0+deb12u2 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create a venv that we'll copy into the final stage wholesale.
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# Copy our project's pyproject first for cacheability.
COPY pyproject.toml /build/
COPY src /build/src

# Install our own package + pinned Python tooling into the venv.
# TODO: pin exact versions via pip-tools / uv lock file; do not use unbound versions.
RUN pip install --no-cache-dir \
        "semgrep==1.95.0" \
        "checkov==3.2.312" \
        "pip-audit==2.8.0" \
        "osv-scanner==0.0.0" \
 && pip install --no-cache-dir -e /build

# ── Stage 2: binary-fetcher ──────────────────────────────────────────────────
# Fetch statically-linked binary tools into /tools. Checksums enforced.
FROM debian:12-slim AS binary-fetcher

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl=7.88.1-10+deb12u8 ca-certificates=20230311 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# Every block below must include:
#   - A specific release tag (NOT @latest).
#   - A SHA256 checksum matching the upstream signed release.
#   - Extraction to /tools/<name>.
# Blocks marked TODO are pin placeholders; do not ship without filling in.

# gitleaks (Zricethezav/gitleaks)  TODO: pin exact version + checksum
# RUN curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.X.Y/gitleaks_8.X.Y_linux_${TARGETARCH}.tar.gz -o /tmp/gitleaks.tgz \
#  && echo "<sha256>  /tmp/gitleaks.tgz" | sha256sum -c - \
#  && tar -xzf /tmp/gitleaks.tgz -C /tools gitleaks \
#  && rm /tmp/gitleaks.tgz

# trufflehog (trufflesecurity/trufflehog)  TODO: pin
# RUN curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.X.Y/trufflehog_3.X.Y_linux_${TARGETARCH}.tar.gz -o /tmp/th.tgz \
#  && echo "<sha256>  /tmp/th.tgz" | sha256sum -c - \
#  && tar -xzf /tmp/th.tgz -C /tools trufflehog \
#  && rm /tmp/th.tgz

# syft (anchore/syft)  TODO: pin
# osv-scanner (google/osv-scanner)  TODO: pin
# zizmor (zizmorcore/zizmor)  TODO: pin
# actionlint (rhysd/actionlint)  TODO: pin

# Placeholder shell stubs so the scaffold image builds for CI self-test.
# Each stub exits 0 and emits an empty JSON array on stdout — replaced by real
# binaries as pins are resolved.
RUN set -eux; \
    for bin in gitleaks trufflehog syft osv-scanner zizmor actionlint; do \
        printf '#!/bin/sh\nexec echo "[]"\n' > /tools/${bin}; \
        chmod +x /tools/${bin}; \
    done

# ── Stage 3: final runtime ───────────────────────────────────────────────────
FROM python:3.12.7-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/sameermohan-git/agent-redblue-ci" \
      org.opencontainers.image.description="Red-team / blue-team CI audit for agentic-AI apps" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="agent-redblue-ci"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        git=1:2.39.5-0+deb12u2 \
        ca-certificates=20230311 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 redblue \
 && useradd --uid 10001 --gid 10001 --shell /sbin/nologin --home-dir /home/redblue --create-home redblue

# Copy the pre-built Python venv (our package + pinned Python tooling).
COPY --from=python-builder /opt/venv /opt/venv

# Copy fetched (or stubbed) binaries.
COPY --from=binary-fetcher /tools/ /usr/local/bin/

# Copy source (for taxonomy, payloads, etc. that are accessed at runtime).
COPY --chown=redblue:redblue src /app/src
COPY --chown=redblue:redblue config /app/config

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENT_REDBLUE_ROOT=/app

USER redblue
WORKDIR /github/workspace

ENTRYPOINT ["python", "-m", "src.orchestrator"]
