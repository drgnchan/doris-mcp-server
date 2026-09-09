# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Regression tests for issue #223 (global pool recovery deadlock).

``_recover_pool_with_lock()`` used to acquire ``_recovery_lock`` and then call
``_recover_pool()``, which acquires ``pool_recovery_lock``. Both names were
aliased to the same non-reentrant ``asyncio.Lock``, so recovery waited forever
on a lock held by its own caller and every query ended in a tool-level
timeout. Every test here fails (deadlock -> TimeoutError) against the buggy
implementation.
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.utils import db as db_module
from doris_mcp_server.utils.db import DorisConnectionManager

# A recovery that needs longer than this is deadlocked, not slow.
RECOVERY_TIMEOUT = 2.0


class FakeDatabaseConfig:
    host = "127.0.0.1"
    port = 9030
    user = "test_user"
    password = "test_password"
    database = "test_db"
    charset = "UTF8MB4"
    connection_timeout = 5
    min_connections = 0
    max_connections = 5
    max_connection_age = 3600


class FakeConfig:
    database = FakeDatabaseConfig()


class FakeRawConnection:
    """Stand-in for an aiomysql connection."""

    def __init__(self):
        self.closed = False


class FakePool:
    """Minimal stand-in for an aiomysql pool."""

    def __init__(self, closed=False, acquire_error=None):
        self.closed = closed
        self.acquire_error = acquire_error
        self.close_calls = 0
        self.raw = FakeRawConnection()

    def close(self):
        self.close_calls += 1
        self.closed = True

    async def wait_closed(self):
        return None

    async def acquire(self):
        if self.acquire_error is not None:
            raise self.acquire_error
        return self.raw

    def release(self, connection):
        return None


def make_manager(pool=None):
    """Build a real manager (real lock wiring) with a fake pool."""
    manager = DorisConnectionManager(FakeConfig())
    manager.pool = pool
    # Keep recovery fast and offline: no real health probing or warmup.
    manager._test_pool_health = AsyncMock(return_value=True)
    manager._warmup_pool = AsyncMock()
    return manager


@pytest.fixture
def fake_create_pool(monkeypatch):
    """Patch aiomysql.create_pool and record concurrency."""
    state = {"calls": 0, "active": 0, "max_active": 0, "pools": []}

    async def _create_pool(**kwargs):
        state["calls"] += 1
        state["active"] += 1
        state["max_active"] = max(state["max_active"], state["active"])
        try:
            await asyncio.sleep(0.05)
            pool = FakePool()
            state["pools"].append(pool)
            return pool
        finally:
            state["active"] -= 1

    monkeypatch.setattr(db_module.aiomysql, "create_pool", _create_pool)
    return state


def test_recovery_lock_is_not_aliased_to_another_lock():
    """The recovery lock must be the single owner guarding recovery."""
    manager = DorisConnectionManager(FakeConfig())

    other_locks = [
        name
        for name, value in vars(manager).items()
        if name != "pool_recovery_lock" and isinstance(value, asyncio.Lock)
    ]

    assert manager.pool_recovery_lock not in [
        vars(manager)[name] for name in other_locks
    ]


@pytest.mark.asyncio
async def test_recovery_when_pool_is_missing(fake_create_pool):
    """Case 1: no global pool -> recovery must recreate it, not hang."""
    manager = make_manager(pool=None)

    connection = await asyncio.wait_for(
        manager.get_connection("session-missing-pool"), timeout=RECOVERY_TIMEOUT
    )

    assert connection is not None
    assert manager.pool is not None
    assert manager.pool.closed is False
    assert fake_create_pool["calls"] == 1
    assert manager.pool_recovering is False


@pytest.mark.asyncio
async def test_recovery_when_pool_is_closed(fake_create_pool):
    """Case 2: closed pool -> recovery must replace it, not hang."""
    closed_pool = FakePool(closed=True)
    manager = make_manager(pool=closed_pool)

    connection = await asyncio.wait_for(
        manager.get_connection("session-closed-pool"), timeout=RECOVERY_TIMEOUT
    )

    assert connection is not None
    assert manager.pool is not closed_pool
    assert manager.pool.closed is False
    assert fake_create_pool["calls"] == 1


@pytest.mark.asyncio
async def test_recovery_after_acquisition_timeout(fake_create_pool):
    """Case 3: acquire timeout -> one bounded recovery attempt."""
    timing_out_pool = FakePool(acquire_error=asyncio.TimeoutError())
    manager = make_manager(pool=timing_out_pool)

    connection = await asyncio.wait_for(
        manager.get_connection("session-timeout"), timeout=RECOVERY_TIMEOUT
    )

    assert connection is not None
    assert manager.pool is not timing_out_pool
    assert fake_create_pool["calls"] == 1


@pytest.mark.asyncio
async def test_concurrent_recovery_is_serialized_and_bounded(fake_create_pool):
    """Case 4: concurrent recovery requests complete and never overlap."""
    manager = make_manager(pool=None)

    await asyncio.wait_for(
        asyncio.gather(*[manager._recover_pool_with_lock() for _ in range(5)]),
        timeout=RECOVERY_TIMEOUT * 5,
    )

    assert manager.pool is not None
    assert manager.pool_recovering is False
    # pool_recovery_lock serializes recovery: only one active at a time.
    assert fake_create_pool["max_active"] == 1
