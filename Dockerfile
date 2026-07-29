# syntax=docker/dockerfile:1
ARG PYTHON_VERSION
FROM ghcr.io/astral-sh/uv:python${PYTHON_VERSION}-trixie AS base

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"


FROM base AS builder

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache \
    uv sync --frozen --no-dev --no-install-project

COPY src/ src/
RUN --mount=type=cache,target=/root/.cache \
    --mount=type=bind,source=.git,target=/app/.git,readonly \
    uv sync --frozen --no-dev


FROM base

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    openssl \
    curl \
    ca-certificates \
    libcap2-bin \
    bash

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install MediaMTX
ARG MEDIAMTX_VERSION=1.9.3
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
        amd64) ARCH="amd64" ;; \
        arm64) ARCH="arm64v8" ;; \
        arm) ARCH="armv7" ;; \
        *) ARCH="amd64" ;; \
    esac && \
    curl -fsSL "https://github.com/bluenviron/mediamtx/releases/download/v${MEDIAMTX_VERSION}/mediamtx_v${MEDIAMTX_VERSION}_linux_${ARCH}.tar.gz" | \
    tar -xz -C /usr/local/bin mediamtx && \
    chmod +x /usr/local/bin/mediamtx

# Allow binding to privileged ports (<1024) as non-root
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/python3.14 && \
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/mediamtx

ARG UID=10001
RUN useradd -l -m -r -d /app -u "${UID}" appuser
USER appuser
WORKDIR /app

COPY --from=builder --chown=${UID} /app /app

ENV PRINTER_IP="" \
    ACCESS_CODE="" \
    SERIAL_NUMBER="" \
    BIND_ADDRESS="0.0.0.0" \
    SERVICES="" \
    ENABLE_ALL=""

EXPOSE 322 6000 8883 990

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f pandaproxy || exit 1

CMD [ "python", "-m", "pandaproxy" ]
