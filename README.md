# PandaProxy

BambuLab Multi-Service Proxy - Proxy camera, MQTT, and FTP from BambuLab printers to multiple clients.

[![build](https://github.com/JulienDeveaux/pandaproxy/actions/workflows/docker.yml/badge.svg)](https://github.com/JulienDeveaux/pandaproxy/actions/workflows/docker.yml)
![AI-Powered](https://img.shields.io/badge/Developed%20with-AI-blue?style=for-the-badge&logo=claude&logoColor=white)

> **⚠️ Alpha Software** - This project is heavily under development and very much in an alpha state. Expect bugs, breaking changes, and incomplete features.

> **Fork** of [gitlab.com/nerdycraft/pandaproxy](https://gitlab.com/nerdycraft/pandaproxy),
> adding passive-mode FTPS with a queue, and a merged MQTT state cache.
> See [What this fork changes](#what-this-fork-changes).

## About This Project

This is a **hobby project** that originated from my own needs. I had several services (like OctoApp, Bambuddy, and others) all trying to connect to my BambuLab printer simultaneously, which was overloading the printer's limited connection capacity. PandaProxy was born to solve this problem by acting as a single connection to the printer that can serve multiple clients.

### RTSPS Camera Support (X1/H2/P2 Printers)

The RTSPS camera proxy feature is **completely untested** as I only own a P1S printer which uses the Chamber Image protocol. If you have an X1, H2, or P2 series printer, your feedback would be invaluable!

### Contributing

Contributions are very welcome! Whether it's:

- **Pull requests** with bug fixes or new features
- **Issues** reporting bugs (especially with test cases!)
- **Testing** on printer models I don't have access to

Please don't hesitate to open an issue or PR on GitHub.

## Overview

BambuLab printers in LAN Mode with Development Mode enabled expose several services:

- **Camera (RTSPS)** on port 322 - X1, X1C, X1E, H2C, H2D, H2D Pro, H2S, P2S
- **Camera (Chamber Image)** on port 6000 - A1, A1 Mini, P1P, P1S
- **MQTT** on port 8883 (MQTTS) - Printer control and status for all models
- **FTP** on port 990 (implicit FTPS) - File uploads (gcode, 3mf) for all models

These services have limited simultaneous connection support. PandaProxy acts as a transparent man-in-the-middle proxy that:

1. **Automatically detects** the camera protocol used by your printer
2. Maintains connections to the printer's services
3. Serves **multiple clients** using the same protocols
4. Clients connect to PandaProxy as if they were connecting directly to the printer

## Features

- **Multiservice proxy**: Camera, MQTT, and FTP in one application
- **Automatic camera type detection** - no manual configuration needed
- **Chamber image proxy** (port 6000) for A1/P1 printers with TLS
- **RTSP proxy** (port 322) for X1/H2/P2 printers using FFmpeg + MediaMTX
- **MQTT proxy** (port 8883) with a merged state cache, so a late client gets
  full state without asking the printer for its own `pushall`
- **FTP proxy** (port 990, implicit TLS) with passive mode and a queue that
  serialises access to the printer
- Same authentication (access code) as the printer
- Automatic reconnection on connection loss
- Docker support with Alpine-based image

## Requirements

### For Local CLI Usage

- Python 3.13+
- OpenSSL (for TLS certificate generation)
- FFmpeg (for RTSP camera proxy only)
- MediaMTX (for RTSP camera proxy only) - [Download from GitHub](https://github.com/bluenviron/mediamtx/releases)

### For Docker

- Docker & Docker Compose
- All dependencies are included in the image

## Installation

### Using uv (recommended)

```bash
# Clone this fork
git clone https://github.com/JulienDeveaux/pandaproxy.git
cd pandaproxy

# Track upstream so changes can be pulled in later
git remote add upstream https://gitlab.com/nerdycraft/pandaproxy.git

# Install with uv
uv sync

# Run
uv run pandaproxy --help
```

### Using pip

```bash
pip install .
pandaproxy --help
```

## Usage

### CLI

```bash
# Camera only (default) - camera type is automatically detected
pandaproxy -p 10.0.0.100 -a 12345678 -s 01P00A000000001

# Enable all services (camera, mqtt, ftp)
pandaproxy -p 10.0.0.100 -a 12345678 -s 01P00A000000001 --enable-all

# Enable specific services
pandaproxy -p 10.0.0.100 -a 12345678 -s 01P00A000000001 --services camera,mqtt


# Verbose logging
pandaproxy -p 10.0.0.100 -a 12345678 -s 01P00A000000001 -v
```

### CLI Options

| Option            | Short | Environment Variable | Description                                               |
| ----------------- | ----- | -------------------- | --------------------------------------------------------- |
| `--printer-ip`    | `-p`  | `PRINTER_IP`         | IP address of the BambuLab printer                        |
| `--access-code`   | `-a`  | `ACCESS_CODE`        | Access code (found in printer settings)                   |
| `--serial-number` | `-s`  | `SERIAL_NUMBER`      | Printer serial number                                     |
| `--bind`          | `-b`  | `BIND_ADDRESS`       | Address to bind proxy servers (default: 0.0.0.0)          |
| `--services`      |       | `SERVICES`           | Comma-separated services: camera,mqtt,ftp                 |
| `--enable-all`    |       | `ENABLE_ALL`         | Enable all services                                       |
| `--advertise-ip`  |       | `ADVERTISE_IP`       | Address to advertise to clients (see below)                |
| `--ssdp-targets`  |       | `SSDP_TARGETS`       | Where to announce the proxy so slicers can find it         |
| `--ssdp-dev-model`|       | `SSDP_DEV_MODEL`     | Model code announced (default: C12, the P1S)               |
| `--ssdp-dev-name` |       | `SSDP_DEV_NAME`      | Name shown in the slicer's device list                     |
| `--ssdp-dev-version`|     | `SSDP_DEV_VERSION`   | Firmware version announced (default: whatever MQTT reports)|
| `--ssdp-interval` |       | `SSDP_INTERVAL`      | Seconds between announcements (default: 2)                 |
| `--data-port-start`|      | `FTP_DATA_PORT_START`| First passive FTP data port (default: 2000)                |
| `--data-port-end` |       | `FTP_DATA_PORT_END`  | Last passive FTP data port (default: 2019)                 |
| `--cert`          |       | `PRINTER_CERT`       | Path to the printer CA certificate (default: printer.cer) |
| `--verbose`       | `-v`  |                      | Enable debug logging                                      |

### Letting BambuStudio find the proxy

BambuStudio populates its LAN device list **only** from SSDP announcements
received on UDP 2021, and then dials the address the announcement names.
Typing an address by hand is not enough: the proxy stays invisible, and
selecting the printer fails instantly with `code -1` without a socket even
being opened. Set `SSDP_TARGETS` to the machines running a slicer and the
proxy announces itself to them.

A bridged container cannot broadcast onto the LAN, which is why the targets
are listed explicitly rather than broadcast; pass `broadcast` instead when the
container has its own LAN address (host or macvlan networking).

ha-bambulab and other clients have no such constraint - they dial whatever
they are configured with, so this only matters for slicers.

The real printer keeps announcing its own address under the same serial, so
the two compete for the same entry. Announcing more often than it does
(`SSDP_INTERVAL`, default 2s) wins in practice, but it is a race.

### Making BambuStudio trust the proxy

Finding the proxy is only half of it. BambuStudio verifies the MQTT
certificate against its own bundled trust store and answers a self-signed one
with a fatal `unknown_ca` alert - the connection dies during the handshake,
before a single MQTT packet is exchanged. Nothing the proxy sends can satisfy
it, because Bambu's own roots (`BBL CA`, `BBL CA2 RSA`, `BBL CA2 ECC`) will
never sign a certificate for us.

So the proxy runs a small certificate authority of its own. On first start it
writes two files next to the certificates:

    certs/pandaproxy-ca.crt    the authority - this is the one to distribute
    certs/pandaproxy-ca.key    its private key - keep it on the proxy, only there

and issues the certificate it presents from that authority, reissuing it
whenever it is missing, signed by a different authority, or does not cover the
current `ADVERTISE_IP`. The path is logged at startup.

To make a slicer accept it, append the authority's certificate to
BambuStudio's trust store:

```bash
scripts/trust-in-bambustudio.sh certs/pandaproxy-ca.crt
```

It is idempotent - it compares fingerprints, so re-running it adds nothing -
and takes the app path as a second argument for non-default installs. The
manual equivalent is a plain append:

```bash
# macOS
cat certs/pandaproxy-ca.crt >> \
  /Applications/BambuStudio.app/Contents/Resources/cert/printer.cer

# Linux (AppImage: inside the extracted tree; package: under /usr/share)
cat certs/pandaproxy-ca.crt >> /usr/share/BambuStudio/cert/printer.cer
```

Restart BambuStudio afterwards. Confirmed working against BambuStudio
02.08.02.60 on macOS: Studio reads this file and honours an anchor added to it.
Four things worth knowing:

- **It is per machine.** Every workstation that slices needs the same step.
- **Updates discard it.** The app bundle is replaced wholesale by Homebrew cask
  upgrades and by Studio's own updater, so re-run the script after each one.
- **It invalidates the app signature**, because the trust store is a sealed
  resource. macOS still launches an app it has already assessed; if it refuses,
  either `codesign --force --deep --sign - <app>` or reinstall it.
- **It is a real trust decision.** Studio will accept *any* certificate this
  authority signs, so `pandaproxy-ca.key` must stay on the proxy and nowhere
  else. Never copy the `.key` alongside the `.crt`.

Clients that can skip verification do not need any of this - ha-bambulab
connects to the proxy as-is.

### Advertising the right address

The proxy tells clients where to find the "printer": in FTP `PASV` replies, and
in the printer address carried by MQTT reports. By default it uses the address
the client connected to, which is correct on host or macvlan networking.

**Under Docker bridge networking that address is the container's own private
address**, which no LAN client can reach - passive transfers and slicer uploads
would be sent nowhere. Set `ADVERTISE_IP` to the Docker host's LAN address.
The proxy logs a warning if it detects Docker and the option is unset.

### Environment Variables

All options can be set via environment variables:

```bash
export PRINTER_IP=10.0.0.100
export ACCESS_CODE=12345678
export SERIAL_NUMBER=01P00A000000001
export BIND_ADDRESS=0.0.0.0
export SERVICES=camera,mqtt,ftp
# Or use ENABLE_ALL=1 to enable all services

pandaproxy
```

### Docker

```bash
# Copy example env file
cp .env.example .env

# Edit with your printer details
nano .env

# Run
docker compose up -d
docker compose logs -f
```

`compose.yaml` publishes ports on the Docker host. It ends with a commented
macvlan block if you would rather give the proxy its own LAN address.

Or run directly:

```bash
docker run -d \
  -e PRINTER_IP=10.0.0.100 \
  -e ACCESS_CODE=12345678 \
  -e SERIAL_NUMBER=01P00A000000001 \
  -e ADVERTISE_IP=10.0.0.10 \
  -e ENABLE_ALL=1 \
  -p 8883:8883 \
  -p 990:990 \
  -p 2000-2019:2000-2019 \
  -p 6000:6000 \
  ghcr.io/juliendeveaux/pandaproxy:latest
```

`ADVERTISE_IP` is the Docker **host's** LAN address, not the container's:
published ports mean bridge networking, where the container's own address is
unreachable. `2000-2019` carries passive FTP data connections; omit it and
every transfer fails after the control channel connected. The range is sized
for concurrent *clients*, not transfers: a port is reserved when `PASV` is
answered, so a client still waiting its turn in the queue already holds one. Drop `-p 322:322`
on a P1S.

## Connecting Clients

Once PandaProxy is running, connect your clients to the proxy instead of the printer:

### Camera - Chamber Image (A1/P1 printers)

Clients connect to `<proxy-ip>:6000` using TLS with the same binary authentication protocol.
This is typically used by BambuLab apps and compatible third-party software.

### Camera - RTSPS (X1/H2/P2 printers)

```
rtsps://bblp:<access_code>@<proxy-ip>:322/stream
```

Example with VLC:

```bash
vlc rtsps://bblp:12345678@10.0.0.50:322/stream
```

### MQTT (All printers)

Connect to `<proxy-ip>:8883` using MQTTS (MQTT over TLS):

- Username: `bblp`
- Password: Your access code

Example with mosquitto_sub:

```bash
mosquitto_sub -h 10.0.0.50 -p 8883 \
  --cafile /path/to/ca.crt --insecure \
  -u bblp -P 12345678 \
  -t "device/01P00A000000001/report"
```

### FTP (All printers)

Connect to `<proxy-ip>:990` using implicit FTPS:

- Username: `bblp`
- Password: Your access code

Example with lftp:

```bash
lftp -u bblp,12345678 ftps://10.0.0.50:990
```

## Architecture

```
┌─────────────┐                 ┌──────────────┐                  ┌─────────┐
│  BambuLab   │◄───Connection───│  PandaProxy  │◄───Connections───│ Clients │
│   Printer   │                 │              │                  │         │
└─────────────┘                 └──────────────┘                  └─────────┘
    :322 RTSPS                      :322 RTSPS     (X1/H2/P2 Camera)
    :6000 TLS                       :6000 TLS      (A1/P1 Camera)
    :8883 MQTTS                     :8883 MQTTS    (Control/Status)
    :990 FTPS                       :990 FTPS      (File Uploads)
```

### How It Works

1. **Camera Proxy**: Auto-detects camera type and starts appropriate proxy
   - Chamber Image: Pure Python asyncio TLS proxy with fan-out
   - RTSP: FFmpeg pulls from printer, MediaMTX serves clients

2. **MQTT Proxy**: Uses TCP proxy with TLS termination
   - Accepts client connections with TLS
   - Forwards traffic bidirectionally to printer's MQTT broker
   - Transparently handles MQTT traffic

3. **FTP Proxy**: speaks FTP rather than relaying bytes, terminating TLS on
   both sides
   - Rewrites `PASV`/`EPSV` to point back at the proxy
   - Answers the login itself, then queues until a printer slot frees up, so
     clients wait instead of failing
   - Uploads outrank listings; an idle session releases its slot and
     reattaches on the next command

## What this fork changes

All three target one symptom: BambuStudio failing to send a model with a
generic network error while other clients are talking to the printer.

**A real FTPS proxy instead of a byte relay.** Upstream forwards raw TCP, so it
cannot read the printer's `227 Entering Passive Mode` reply, which advertises
the *printer's* address - the client connects there directly and bypasses the
proxy. Its own CLI banner said `active mode only`. This fork terminates TLS on
both sides and rewrites `PASV`/`EPSV`. Against a P1S: the printer offered
`10.0.0.18:2024`, the client got the proxy's port, the transfer completed.

**A queue, with the login answered locally.** The printer accepts very few
concurrent FTP sessions, and a client arriving when they are exhausted just
gets a connection failure. The proxy now answers the greeting and login itself,
then queues until a slot frees up, so a client waits inside its first command
instead of erroring. Uploads are served before listings: a failed upload costs
a manual retry, an interrupted listing is refetched unnoticed. An idle session
releases its slot after 30s and reattaches on the next command, replaying the
settings the client had set. Measured with three concurrent clients: 3.7s,
7.2s, 10.7s - one session on the printer at a time.

Passive requests are answered locally and the printer is only contacted when
the transfer command arrives. That is what makes the upload priority reachable
at all - a slot taken by the `PASV` that precedes every `STOR` could only ever
be claimed at normal priority - and it means a client that asks for a port and
then disappears never opens a printer session.

**A merged MQTT state cache.** The printer sends full state only in reply to a
`pushall`; everything after is a small delta. A late client would have to ask
for its own dump, so N clients meant N dumps - the load a proxy should remove.
The proxy issues one `pushall` per upstream connection, merges the deltas, and
replays a full report to each new subscriber. The cache is dropped when
upstream is lost, since a stale snapshot is worse than none.

It also rewrites `net.info[*].ip`, where the printer reports its own address as
a little-endian uint32. Slicers read it to pick an upload target, so leaving it
alone would let a client bypass the queue. Each client is told the address it
reached the proxy on.

### Known gaps

No real client has been driven through this proxy yet - it has been exercised
with `ftplib` and `paho` against a live P1S, not with BambuStudio, ha-bambulab
or PrintGuard. The camera fan-out is untouched upstream code. Long-running
behaviour (reconnects, leaks, sustained queueing) is unverified.

The proxy is IPv4-only where it matters: the printer reports its own address
as an IPv4 uint32 and `PASV` can only express IPv4, so a client reaching the
proxy over genuine IPv6 is refused. IPv4 clients on a dual-stack listener are
fine - their mapped addresses are unwrapped. Set `ADVERTISE_IP` if you bind
`::` and want a definite address.

The passive data ports accept only the address holding the control session,
but under Docker bridge networking the userland proxy rewrites the source of
both connections to the bridge gateway, so that check cannot discriminate
there. It is effective on host and macvlan networking; everywhere, only one
connection per passive port is admitted.

The data channel is relayed as raw bytes, so a `PROT P` client negotiates TLS
with the **printer**, not the proxy. A P1S was measured not to require session
reuse there, which is what makes the relay viable - but a client that itself
insists on reusing the control session, or on the certificate matching the
host it dialled, would fail on the data channel while the control channel
worked. `ftplib` does not; lftp and BambuStudio have not been tested.

## Service Ports

| Service           | Printer Port | Proxy Port | Protocol      |
| ----------------- | ------------ | ---------- | ------------- |
| Camera (X1/H2/P2) | 322          | 322        | RTSPS         |
| Camera (A1/P1)    | 6000         | 6000       | TLS Binary    |
| MQTT              | 8883         | 8883       | MQTTS         |
| FTP Control       | 990          | 990        | Implicit FTPS |
| FTP Data (PASV)   | assigned     | 2000-2019  | TCP relay     |

The passive data range must be reachable, or transfers fail after the control
channel has already connected. On Docker's bridge network, publish it
(`-p 2000-2019:2000-2019`) and set `ADVERTISE_IP`. `compose.yaml` publishes
the range; `ADVERTISE_IP` goes in your `.env`.

## Printer Model Support

| Model                  | Camera          | MQTT | FTP |
| ---------------------- | --------------- | ---- | --- |
| X1, X1C, X1E           | RTSPS (:322)    | ✓    | ✓   |
| H2C, H2D, H2D Pro, H2S | RTSPS (:322)    | ✓    | ✓   |
| P2S                    | RTSPS (:322)    | ✓    | ✓   |
| A1, A1 Mini            | Chamber (:6000) | ✓    | ✓   |
| P1P, P1S               | Chamber (:6000) | ✓    | ✓   |

## Troubleshooting

### Camera connection fails

- Verify the printer IP and access code
- Ensure the printer has LAN Mode and Development Mode enabled
- Check if the camera port is accessible on the printer
- For RTSP: Verify FFmpeg and MediaMTX are installed
- Try running with `-v` for verbose logs

### MQTT connection fails

- Verify the printer IP and access code
- Ensure the printer has LAN Mode enabled
- Check if port 8883 is accessible on the printer
- Verify OpenSSL is installed for TLS cert generation

### FTP connection fails

- Verify the printer IP and access code
- Ensure the printer has LAN Mode enabled
- Check if port 990 is accessible on the printer
- Use implicit FTPS mode (not explicit FTPS)
- Passive mode works, but the data range (2000-2019) must be reachable.
  Transfers failing after a successful login is usually an unpublished range
- `ftplib.FTP_TLS.storbinary` hangs against BambuLab firmware, which never
  answers the data channel's TLS `close_notify` (with or without the proxy).
  Use `transfercmd` + `sendall` + `close` + `voidresp` instead

### Privileged ports (322, 990, 6000)

On Linux, binding to ports below 1024 requires root or capabilities:

```bash
# Option 1: Run as root (not recommended)
sudo pandaproxy ...

# Option 2: Use setcap (recommended for production)
sudo setcap 'cap_net_bind_service=+ep' $(which python3)

# Option 3: Use Docker (handles this automatically)
docker compose up -d
```

## License

MIT License
