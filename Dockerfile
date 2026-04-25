# syntax=docker/dockerfile:1.7
#
# purplegate runtime image.
#
# Principles:
#   1. Every tool version is pinned. Renovate bumps the pins; reviewers check
#      the new version against upstream signed release notes.
#   2. Binaries are fetched from the tool's own GitHub release and verified
#      against the upstream-published checksums file. No `curl | bash`.
#      For osv-scanner (no checksum asset), we use `go install` which pins
#      via the Go module proxy's go.sum integrity check.
#   3. No `pip install` at runtime. The final stage has a pre-populated venv.
#   4. The final stage runs as non-root uid 10001 / gid 10001 ("purplegate").
#
# Scanner versions last verified against upstream: 2026-04-24.
# Bumps are proposed by Renovate; reviewers must verify the new version
# against the tool's upstream release notes before merging.

# ── Stage 1: binary-fetcher ──────────────────────────────────────────────────
# Fetches statically-linked binaries from each tool's GitHub release and
# verifies each against a checksum. Uses the upstream-published
# checksums.txt where available; for tools without one (osv-scanner) the
# SHA256 was computed locally and is pinned in the RUN block (reproducible
# via `curl ... | sha256sum`).

FROM debian:12-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252 AS binary-fetcher

ARG TARGETARCH=amd64
ARG TARGETOS=linux
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        tar \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# Helper pattern used for each tool with a published checksums file:
#   1. Download the release tarball.
#   2. Download the release's `<tool>_<ver>_checksums.txt`.
#   3. Filter the checksums file to the single line for our asset.
#   4. Run `sha256sum -c` against that single-line filter.
#   5. Extract the binary. Fail fast on any step.

# ── gitleaks v8.30.1 (MIT) ────────────────────────────────────────────────
#   https://github.com/gitleaks/gitleaks
ARG GITLEAKS_VERSION=8.30.1
RUN set -eux; \
    cd /tmp && \
    case "${TARGETARCH}" in amd64) asset="x64" ;; arm64) asset="arm64" ;; *) exit 1 ;; esac && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${asset}.tar.gz" -o gitleaks.tgz && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" -o gitleaks.sums && \
    awk -v f="gitleaks_${GITLEAKS_VERSION}_linux_${asset}.tar.gz" '$2==f {print $1"  gitleaks.tgz"}' gitleaks.sums | sha256sum -c - && \
    tar -xzf gitleaks.tgz -C /tools gitleaks && \
    rm -f gitleaks.tgz gitleaks.sums

# ── trufflehog v3.95.2 (AGPL-3.0) ──────────────────────────────────────────
#   https://github.com/trufflesecurity/trufflehog
#   NOTE: AGPL-3.0 binary — we invoke, we do not modify or redistribute source.
#   See LICENSE-3RD-PARTY.md in the repo for the full attribution list.
ARG TRUFFLEHOG_VERSION=3.95.2
RUN set -eux; \
    cd /tmp && \
    case "${TARGETARCH}" in amd64) asset="amd64" ;; arm64) asset="arm64" ;; *) exit 1 ;; esac && \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${asset}.tar.gz" -o trufflehog.tgz && \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" -o trufflehog.sums && \
    awk -v f="trufflehog_${TRUFFLEHOG_VERSION}_linux_${asset}.tar.gz" '$2==f {print $1"  trufflehog.tgz"}' trufflehog.sums | sha256sum -c - && \
    tar -xzf trufflehog.tgz -C /tools trufflehog && \
    rm -f trufflehog.tgz trufflehog.sums

# ── syft v1.43.0 (Apache-2.0) ──────────────────────────────────────────────
#   https://github.com/anchore/syft
ARG SYFT_VERSION=1.43.0
RUN set -eux; \
    cd /tmp && \
    case "${TARGETARCH}" in amd64) asset="amd64" ;; arm64) asset="arm64" ;; *) exit 1 ;; esac && \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${asset}.tar.gz" -o syft.tgz && \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt" -o syft.sums && \
    awk -v f="syft_${SYFT_VERSION}_linux_${asset}.tar.gz" '$2==f {print $1"  syft.tgz"}' syft.sums | sha256sum -c - && \
    tar -xzf syft.tgz -C /tools syft && \
    rm -f syft.tgz syft.sums

# ── actionlint v1.7.12 (MIT) ───────────────────────────────────────────────
#   https://github.com/rhysd/actionlint
ARG ACTIONLINT_VERSION=1.7.12
RUN set -eux; \
    cd /tmp && \
    case "${TARGETARCH}" in amd64) asset="amd64" ;; arm64) asset="arm64" ;; *) exit 1 ;; esac && \
    curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${asset}.tar.gz" -o actionlint.tgz && \
    curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_checksums.txt" -o actionlint.sums && \
    awk -v f="actionlint_${ACTIONLINT_VERSION}_linux_${asset}.tar.gz" '$2==f {print $1"  actionlint.tgz"}' actionlint.sums | sha256sum -c - && \
    tar -xzf actionlint.tgz -C /tools actionlint && \
    rm -f actionlint.tgz actionlint.sums

# ── osv-scanner v2.3.5 (Apache-2.0) ────────────────────────────────────────
#   https://github.com/google/osv-scanner
#   Upstream does not publish a checksums.txt asset with their releases, so
#   SHA256 values below were computed by curl-ing the binaries from the v2.3.5
#   release and running `sha256sum` locally (2026-04-24). Anyone can
#   reproduce:
#     curl -fsSL https://github.com/google/osv-scanner/releases/download/v2.3.5/osv-scanner_linux_<arch> | sha256sum
ARG OSV_SCANNER_VERSION=2.3.5
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) osv_sha="bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b" ;; \
      arm64) osv_sha="fa46ad2b3954db5d5335303d45de921613393285d9a93c140b63b40e35e9ce50" ;; \
      *) exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH}" -o /tools/osv-scanner; \
    echo "${osv_sha}  /tools/osv-scanner" | sha256sum -c -; \
    chmod +x /tools/osv-scanner

# ── Stage 2: python-builder ──────────────────────────────────────────────────
# Installs our own package into /opt/venv, and each pinned Python scanner
# into its own isolated pipx venv at /opt/pipx/venvs/<tool>. Isolation is
# required because the scanners have mutually incompatible transitive
# dependencies (e.g. semgrep pins tomli~=2.0.1, pip-audit pins >=2.2.1).

FROM python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Our own package — pydantic, httpx, click, yaml, jsonschema (all compatible).
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY pyproject.toml /build/
COPY README.md /build/README.md
COPY LICENSE /build/LICENSE
COPY src /build/src
RUN pip install --no-cache-dir -e /build

# Isolated scanner venvs via pipx. Each tool gets its own venv under
# /opt/pipx/venvs/<tool>; each entry-point symlinked into /opt/pipx/bin.
# Versions verified against PyPI on 2026-04-24. Renovate proposes bumps;
# reviewers verify each bump against upstream release notes before merge.
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/opt/pipx/bin
RUN pip install --no-cache-dir pipx \
 && pipx install --python /usr/local/bin/python "semgrep==1.161.0" \
 && pipx install --python /usr/local/bin/python "checkov==3.2.524" \
 && pipx install --python /usr/local/bin/python "zizmor==1.24.1" \
 && pipx install --python /usr/local/bin/python "pip-audit==2.10.0"

# ── Stage 3: final runtime ───────────────────────────────────────────────────
FROM python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d

LABEL org.opencontainers.image.source="https://github.com/sameermohan-git/purplegate" \
      org.opencontainers.image.description="Red/blue-team CI gate for agentic-AI apps" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="purplegate"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 purplegate \
 && useradd --uid 10001 --gid 10001 --shell /sbin/nologin --home-dir /home/purplegate --create-home purplegate

# Copy the pre-built Python venv (our own package).
COPY --from=python-builder /opt/venv /opt/venv

# Copy the pipx-installed scanner venvs + symlinks.
COPY --from=python-builder /opt/pipx /opt/pipx

# Copy fetched Go binaries.
COPY --from=binary-fetcher /tools/ /usr/local/bin/

# Copy source files used at runtime (taxonomy YAML, payload packs).
COPY --chown=purplegate:purplegate src /app/src
COPY --chown=purplegate:purplegate config /app/config

ENV PATH=/opt/venv/bin:/opt/pipx/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PURPLEGATE_ROOT=/app

USER purplegate
WORKDIR /github/workspace

ENTRYPOINT ["python", "-m", "src.orchestrator"]
