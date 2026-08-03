# pandaproxy - Agent Review Conventions

This file is read by AI code review agents. It describes project-specific patterns and rules that must be enforced during MR review. These are real bugs when violated, not style preferences.

## Project Overview

pandaproxy is a Python 3.13 asyncio-based multi-service proxy for BambuLab 3D printers. It multiplexes multiple client connections onto single upstream printer connections for MQTT (port 8883), FTP (port 990), Chamber Camera (port 6000), and RTSP (port 322). All network I/O is async (asyncio streams). Ruff enforces formatting - skip style comments.

---

## Critical Rules - Flag Any Violation

### 1. All Network Connections Require Timeouts

`asyncio.open_connection()` must always be wrapped in `asyncio.wait_for(..., timeout=X)`. Without a timeout, upstream connections to unreachable printers hang indefinitely and block the reconnection loop.

```python
# CORRECT
reader, writer = await asyncio.wait_for(
    asyncio.open_connection(host, port, ssl=ctx),
    timeout=10.0,
)

# WRONG - can hang forever
reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
```

### 2. StreamWriter Closure Must Use `close_writer()` Helper

`writer.close()` alone does not flush - `wait_closed()` is required. With SSL, `wait_closed()` can itself hang, so a timeout and transport abort are needed. Always use the `close_writer(writer)` helper from `pandaproxy.helper` which handles this correctly.

```python
# CORRECT
from pandaproxy.helper import close_writer

await close_writer(writer)

# WRONG - resource leak on SSL, may hang
writer.close()
# ALSO WRONG - hangs on SSL connections
writer.close()
await writer.wait_closed()
```

### 3. Reconnection Loops Must Check `self._running`

Before sleeping and reconnecting, check `if self._running:` to prevent reconnection spam after shutdown has been initiated.

```python
# CORRECT
if self._running:
    await asyncio.sleep(RECONNECT_DELAY)
    # reconnect...

# WRONG - reconnects even during shutdown
await asyncio.sleep(RECONNECT_DELAY)
```

### 4. Shared State Requires Locks

All writes to shared dictionaries (`_clients`, `_upstream_client`) must hold the corresponding `asyncio.Lock`. Read-modify-write sequences without a lock are race conditions in concurrent client fan-out.

```python
# CORRECT
async with self._upstream_lock:
    self._upstream_client = client

# WRONG - race condition
self._upstream_client = client
```

### 5. Background Tasks Must Not Fail Silently

All background task entry points must capture the current task reference and handle exceptions explicitly. An unhandled exception terminates the task and silently stops proxying.

```python
# CORRECT
async def run_upstream_loop(self):
    self._upstream_task = asyncio.current_task()
    try:
        await self._upstream_connection_loop()
    except asyncio.CancelledError:
        logger.debug("upstream loop cancelled")
    except Exception:
        logger.exception("Unexpected crash in upstream loop")


# WRONG - unhandled exception kills the loop silently
async def run_upstream_loop(self):
    await self._upstream_connection_loop()
```

### 6. Task Creation Order - After `start()` Completes

Background tasks must be created AFTER `await proxy.start()` returns. Background tasks check `self._running` which is set inside `start()`. Creating tasks before `start()` completes means they see `_running=False` and exit immediately.

```python
# CORRECT
await proxy.start()
task = asyncio.create_task(proxy.run_upstream_loop())

# WRONG - task sees _running=False, exits immediately
task = asyncio.create_task(proxy.run_upstream_loop())
await proxy.start()
```

### 7. Blocking Calls Require `asyncio.to_thread()`

Any blocking I/O or CPU-bound call must use `asyncio.to_thread(fn, *args)`. Never use `get_event_loop().run_in_executor()`.

```python
# CORRECT
result = await asyncio.to_thread(blocking_fn, arg)

# WRONG
loop = asyncio.get_event_loop()
result = await loop.run_in_executor(None, blocking_fn, arg)
```

### 8. Access Codes Must Be Masked in Logs

Never log the printer access code in plaintext. Mask before logging with `.replace(self.access_code, "****")`.

```python
# CORRECT
logger.debug("Command: %s", payload.replace(self.access_code, "****"))

# WRONG - credential leak
logger.debug("Command: %s", payload)
```

### 9. Per-Client Queue Overflows Must Disconnect Slow Clients

When a per-client queue is full, drop the frame/packet AND disconnect the slow client. Silently dropping without disconnecting leaves the client in a partially-functioning state indefinitely.

### 10. SSL Certificate Verification Must Use Bundled CA

Upstream SSL contexts must use `ctx.load_verify_locations()` with the bundled `printer.cer`. `ssl.CERT_NONE` (no verification) is a real security issue and must be flagged.

---

## Intentional Patterns - Do NOT Flag

These are correct by design. Flagging any of them is a false positive.

- **`ssl.SSLContext` with `check_hostname = False`** - BambuLab printers are accessed by raw IP address; hostname verification is structurally impossible. `verify_mode = ssl.CERT_REQUIRED` with the bundled CA bundle still enforces certificate trust. Do not flag `check_hostname=False` as a security issue.

- **`asyncio.gather(*tasks, return_exceptions=True)` with discarded return values** - used for cleanup/cancellation fan-out where all tasks must be awaited even if some fail. Return values are intentionally discarded. Do not flag as "unchecked return value" or "ignored exceptions".

- **`ssl.SSLError` caught, logged, and connection dropped in proxy handlers** - for a pass-through proxy, logging and dropping the connection is complete error handling when TLS fails mid-connection. The upstream/downstream pair is already disrupted. Do not flag as "incomplete error handling".

- **`asyncio.wait([t1, t2], return_when=FIRST_COMPLETED)` for bidirectional forwarding** - when one direction closes, the other is cancelled. This is the correct pattern for FTP and similar bidirectional proxies.

- **`StreamFanout.broadcast()` snapshots clients inside lock, sends outside lock** - prevents deadlock when a slow client's send() blocks. The snapshot is safe. Do not flag as "lock held too briefly" or "unlocked shared state".

- **Per-client queue size limits (maxsize=100 for chamber, 200 for MQTT)** - intentional memory cap. When full, drop + disconnect the slow client. Do not suggest unbounded queues.
