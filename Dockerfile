# syntax=docker/dockerfile:1
ARG PYTHON_VERSION
ARG ALPINE_VERSION
FROM ghcr.io/astral-sh/uv:python${PYTHON_VERSION}-alpine${ALPINE_VERSION} AS base

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"


FROM base AS builder
ENV UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

RUN apk add --no-cache \
    curl \
    gcc \
    musl-dev \
    libffi-dev

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache \
    uv sync --frozen --no-dev --no-install-project

ARG VERSION=0.0.0-dev
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${VERSION}

COPY src/ src/
RUN --mount=type=cache,target=/root/.cache \
    uv sync --frozen --no-dev

# Install MediaMTX
ARG MEDIAMTX_VERSION
ARG ARCH=amd64
RUN curl -fsSL "https://github.com/bluenviron/mediamtx/releases/download/v${MEDIAMTX_VERSION}/mediamtx_v${MEDIAMTX_VERSION}_linux_${ARCH}.tar.gz" -o /tmp/mediamtx.tar.gz && \
    tar -xz -C /tmp -f /tmp/mediamtx.tar.gz


FROM base
ENV PRINTER_IP="" \
    ACCESS_CODE="" \
    SERIAL_NUMBER="" \
    BIND_ADDRESS="0.0.0.0" \
    SERVICES="" \
    ENABLE_ALL=""

RUN apk add --no-cache \
    ffmpeg \
    openssl \
    ca-certificates \
    libcap

COPY --from=builder --chmod=0755 /tmp/mediamtx /usr/local/bin/mediamtx

# Allow binding to privileged ports (<1024) as non-root
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/python3.14 && \
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/mediamtx

ARG UID=65532
RUN adduser -D -H -h /app -u "${UID}" pandaproxy
USER pandaproxy
WORKDIR /app

COPY --from=builder --chown=${UID} /app /app
COPY --chown=${UID} printer.cer /app/printer.cer

EXPOSE 322 990 6000 8883

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f pandaproxy || exit 1

CMD ["pandaproxy"]
