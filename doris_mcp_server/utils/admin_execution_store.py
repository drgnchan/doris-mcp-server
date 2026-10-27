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

"""Single-active durable request deduplication, not an approval/workflow store."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

from filelock import FileLock

from ..tools.admin_statements import AdminError


class AdminExecutionStore:
    """Keep all keys until explicit offline retention; unknown is never retried."""

    def __init__(self, path: str) -> None:
        target = Path(path).expanduser()
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.is_symlink():
            raise AdminError("ADMIN_STORE_UNSAFE_PATH")
        fd = os.open(target, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            mode = os.fstat(fd).st_mode
            if not stat.S_ISREG(mode) or mode & 0o077:
                raise AdminError("ADMIN_STORE_PRIVATE_PERMISSIONS_REQUIRED")
        finally:
            os.close(fd)
        self._lock = FileLock(str(target) + ".lock")
        self._lock.acquire(timeout=0)
        try:
            self._db = sqlite3.connect(str(target), isolation_level=None)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("""CREATE TABLE IF NOT EXISTS executions (
                principal TEXT NOT NULL, route TEXT NOT NULL, request_key TEXT NOT NULL,
                digest TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(principal, route, request_key))""")
            self._db.execute("PRAGMA user_version=1")
            rows = self._db.execute(
                "SELECT principal, route, request_key, result FROM executions"
            ).fetchall()
            for principal, route, key, result in rows:
                record = json.loads(result)
                if record["execution_status"] == "in_flight":
                    record["execution_status"] = "outcome_unknown"
                    self.finish(principal, route, key, record)
        except BaseException:
            self._lock.release()
            raise

    def claim(
        self, principal: str, route: str, key: str, digest: str, action: str
    ) -> tuple[bool, dict[str, Any]]:
        record = {
            "action": action,
            "idempotency_key": key,
            "execution_status": "in_flight",
            "verification_status": "not_checked",
            "warnings": [],
        }
        inserted = self._db.execute(
            "INSERT OR IGNORE INTO executions(principal,route,request_key,digest,action,result) VALUES(?,?,?,?,?,?)",
            (principal, route, key, digest, action, json.dumps(record)),
        ).rowcount
        row = self._db.execute(
            "SELECT digest,result FROM executions WHERE principal=? AND route=? AND request_key=?",
            (principal, route, key),
        ).fetchone()
        if row is None or row[0] != digest:
            raise AdminError("ADMIN_IDEMPOTENCY_CONFLICT")
        return bool(inserted), json.loads(row[1])

    def get(self, principal: str, route: str, key: str) -> dict[str, Any]:
        row = self._db.execute(
            "SELECT result FROM executions WHERE principal=? AND route=? AND request_key=?",
            (principal, route, key),
        ).fetchone()
        if row is None:
            raise AdminError("ADMIN_EXECUTION_NOT_FOUND")
        result: dict[str, Any] = json.loads(row[0])
        return result

    def finish(
        self, principal: str, route: str, key: str, result: dict[str, Any]
    ) -> None:
        self._db.execute(
            "UPDATE executions SET result=? WHERE principal=? AND route=? AND request_key=?",
            (json.dumps(result, ensure_ascii=False), principal, route, key),
        )

    def close(self) -> None:
        self._db.close()
        self._lock.release()
