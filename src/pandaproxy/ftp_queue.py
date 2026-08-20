"""Fair queueing and data-port allocation for the FTPS proxy.

BambuLab printers accept few concurrent FTP sessions; a client arriving when
they are exhausted gets a bare connection failure, which is what BambuStudio
reports as a generic network error mid-upload. The proxy keeps at most
``max_concurrent`` sessions open and makes everyone else wait - invisibly,
since the login is answered locally and queueing only starts when a command
actually needs the printer.
"""

from __future__ import annotations

import asyncio
import contextlib
import heapq
import itertools
import logging

logger = logging.getLogger(__name__)

# Lower value = served first. Uploads win: a failed upload costs a manual
# retry, an interrupted listing is refetched unnoticed.
PRIORITY_UPLOAD = 0
PRIORITY_NORMAL = 10


class SessionQueue:
    """Priority FIFO limiting how many sessions may touch the printer at once.

    Ties break on arrival order, so equal-priority waiters keep strict FIFO
    and nothing starves.
    """

    def __init__(self, max_concurrent: int = 1) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        self.max_concurrent = max_concurrent
        self._active = 0
        self._waiters: list[tuple[int, int, asyncio.Future[None]]] = []
        self._counter = itertools.count()

    @property
    def active(self) -> int:
        """Number of sessions currently holding a slot."""
        return self._active

    @property
    def waiting(self) -> int:
        """Number of sessions queued for a slot."""
        return len(self._waiters)

    async def acquire(self, priority: int = PRIORITY_NORMAL) -> None:
        """Take a slot, waiting for one to free up if necessary.

        No lock guards the bookkeeping: the event loop is single-threaded and
        none of the critical sections await, so a lock would add nothing -
        while making the cancellation path below suspend, where a second
        cancellation could skip the compensation and lose a slot for good.
        """
        if self._active < self.max_concurrent:
            self._active += 1
            return

        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        heapq.heappush(self._waiters, (priority, next(self._counter), future))
        logger.info(
            "Printer busy, queued (position %d, priority %d)",
            len(self._waiters),
            priority,
        )
        try:
            await future
        except asyncio.CancelledError:
            # Caller gave up (client disconnected). Drop our entry so the slot
            # is not handed to a future nobody awaits; and if release() already
            # completed us, hand the slot straight back.
            self._waiters = [w for w in self._waiters if w[2] is not future]
            heapq.heapify(self._waiters)
            if future.done() and not future.cancelled():
                self._active -= 1
                self._wake_next()
            raise

    def release(self) -> None:
        """Give the slot back and hand it to the highest-priority waiter.

        Synchronous on purpose: callers release from ``finally`` blocks that
        may already be unwinding a cancellation, where an await could be
        skipped and the slot lost.
        """
        self._active -= 1
        if self._active < 0:
            logger.error("SessionQueue released more times than acquired")
            self._active = 0
        self._wake_next()

    def _wake_next(self) -> None:
        """Promote the next waiter."""
        while self._waiters and self._active < self.max_concurrent:
            _priority, _seq, future = heapq.heappop(self._waiters)
            if not future.done():
                self._active += 1
                future.set_result(None)
                return

    @contextlib.asynccontextmanager
    async def slot(self, priority: int = PRIORITY_NORMAL):
        """Hold a slot for the duration of the block."""
        await self.acquire(priority)
        try:
            yield
        finally:
            self.release()


class DataPortPool:
    """Hands out listening ports for passive-mode data connections.

    The range is fixed, not ephemeral: only a declared range can be published
    with ``-p`` from a container.
    """

    def __init__(self, start: int, end: int) -> None:
        if start > end:
            raise ValueError("start must not be greater than end")
        self._free: list[int] = list(range(start, end + 1))
        self._in_use: set[int] = set()
        self.start = start
        self.end = end

    @property
    def available(self) -> int:
        """How many ports are currently free."""
        return len(self._free)

    def acquire(self) -> int | None:
        """Reserve a port, or None if the pool is exhausted."""
        if not self._free:
            logger.warning(
                "Data port pool exhausted (%d-%d all in use)", self.start, self.end
            )
            return None
        port = self._free.pop(0)
        self._in_use.add(port)
        return port

    def release(self, port: int) -> None:
        """Return a port to the pool.

        Synchronous so it cannot be skipped by a cancellation unwinding
        through the ``finally`` that calls it.
        """
        if port in self._in_use:
            self._in_use.discard(port)
            # Append, not insert: cycling avoids reusing a port still
            # lingering in TIME_WAIT.
            self._free.append(port)
