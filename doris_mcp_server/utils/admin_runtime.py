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

"""Direct access-management runtime: identity, deduplication, one SQL, audit."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import stat
from typing import Any

from ..tools.admin_domain import authorize_admin
from ..tools.admin_statements import AdminError, compile_statement
from .admin_execution_store import AdminExecutionStore
from .logger import get_audit_logger
from .security import get_current_auth_context


class AdminRuntime:
    def __init__(self, manager: Any) -> None:
        self.manager = manager
        self.config = manager.config.administration
        self.store: AdminExecutionStore | None = None

    def start(self) -> None:
        if self.config.enabled and self.store is None:
            if not self.config.state_path:
                raise AdminError("ADMIN_STATE_PATH_REQUIRED")
            self.store = AdminExecutionStore(self.config.state_path)

    def close(self) -> None:
        if self.store is not None:
            self.store.close()
            self.store = None

    def _password(self, reference: str, principal: str, user: dict[str, Any]) -> str:
        if not self.config.password_file:
            raise AdminError("ADMIN_PASSWORD_SOURCE_UNCONFIGURED")
        try:
            fd = os.open(self.config.password_file, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r", encoding="utf-8") as source:
                info = os.fstat(source.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_mode & 0o077
                    or info.st_size > 1048576
                ):
                    raise AdminError("ADMIN_PASSWORD_SOURCE_UNSAFE")
                mapping = json.load(source)
            entry = mapping[reference]
            if (
                entry["principal"] != principal
                or entry["user"] != user
                or not entry["version"]
            ):
                raise AdminError("ADMIN_PASSWORD_REFERENCE_FORBIDDEN")
            # The version is part of the public alias; aliases are immutable.
            if not reference.endswith("@" + entry["version"]):
                raise AdminError("ADMIN_PASSWORD_REFERENCE_VERSION_REQUIRED")
            password = entry["password"]
            if (
                not isinstance(password, str)
                or not 1 <= len(password) <= 1024
                or "\x00" in password
            ):
                raise AdminError("ADMIN_PASSWORD_SOURCE_INVALID")
            return password
        except AdminError:
            raise
        except Exception:
            raise AdminError("ADMIN_PASSWORD_REFERENCE_UNAVAILABLE") from None

    def _route(self, context: Any) -> str:
        identity = self.manager.get_route_identity(context)
        database = self.manager.get_database_config_for_auth_context(context)
        user = context.doris_user or database.user
        # Exclude pool generations and bearer hashes: retries survive restarts/refresh.
        return hashlib.sha256(
            f"{identity.endpoint_fingerprint}:{user}".encode()
        ).hexdigest()

    def _protect_identity(self, arguments: dict[str, Any], context: Any) -> None:
        action = arguments["action"]
        if action.startswith("show_") or action == "get_execution_status":
            return
        database = self.manager.get_database_config_for_auth_context(context)
        protected = {"root", "admin", database.user, getattr(context, "doris_user", "")}
        protected.update(getattr(self.config, "protected_users", ()))
        user = arguments.get("user") or arguments.get("grantee", {})
        username = arguments.get(
            "username", user.get("name") if user.get("type", "user") == "user" else None
        )
        if username in protected:
            raise AdminError("ADMIN_PROTECTED_IDENTITY")
        if arguments.get("role") in {"admin", "operator"} and action in {
            "drop_role",
            "alter_role",
        }:
            raise AdminError("ADMIN_PROTECTED_ROLE")

    async def execute(self, child: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.config.enabled is not True:
            raise AdminError("ADMIN_DISABLED")
        context = get_current_auth_context()
        statement = compile_statement(child, arguments)
        principal = authorize_admin(context, statement.action)
        for extra in statement.extra_actions:
            authorize_admin(context, extra)
        self._protect_identity(arguments, context)
        route = self._route(context)
        if arguments.get("dry_run"):
            return {
                "action": statement.action,
                "execution_status": "dry_run",
                "verification_status": "not_checked",
                "sql": statement.display_sql,
                "warnings": list(statement.warnings),
            }
        self.start()
        if self.store is None:
            raise AdminError("ADMIN_STORE_UNAVAILABLE")
        key = arguments.get("idempotency_key", "")
        if statement.action == "get_execution_status":
            record = self.store.get(principal, route, key)
            return record
        canonical = {
            k: v
            for k, v in arguments.items()
            if k not in {"idempotency_key", "dry_run"}
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if not statement.read_only:
            claimed, record = self.store.claim(
                principal, route, key, digest, statement.action
            )
            if not claimed:
                return record
        else:
            record = {
                "action": statement.action,
                "execution_status": "in_flight",
                "verification_status": "not_checked",
                "warnings": [],
            }
        session = "admin_" + secrets.token_hex(12)
        connection = None
        sent = False
        try:
            password = (
                self._password(statement.password_ref, principal, arguments["user"])
                if statement.password_ref
                else None
            )
            async with asyncio.timeout(30):
                connection = await self.manager.get_connection(session)
                # Let the target Doris validate syntax and feature compatibility.
                sent = True
                result = await connection.execute_management(
                    child, arguments, context, password=password
                )
                record.update(result)
                record["execution_status"] = "succeeded"
        except asyncio.CancelledError:
            record["execution_status"] = "outcome_unknown" if sent else "failed"
            record["error_code"] = "ADMIN_REQUEST_CANCELLED"
            raise
        except AdminError as exc:
            record["execution_status"] = "outcome_unknown" if sent else "failed"
            record["error_code"] = exc.code
        except Exception as exc:
            # Driver ERR packets prove rejection; transport errors do not.
            from pymysql import MySQLError

            code = exc.args[0] if isinstance(exc, MySQLError) and exc.args else None
            definite = isinstance(code, int) and 0 < code < 2000
            record["execution_status"] = (
                "failed" if not sent or definite else "outcome_unknown"
            )
            record["error_code"] = (
                f"DORIS_ERROR_{code}"
                if definite
                else "ADMIN_EXECUTION_UNCERTAIN"
                if sent
                else "ADMIN_CONNECTION_FAILED"
            )
        finally:
            record["target"] = {
                name: arguments[name]
                for name in (
                    "user",
                    "grantee",
                    "role",
                    "roles",
                    "object",
                    "privileges",
                    "table",
                    "policy",
                    "target",
                    "mode",
                    "username",
                    "default_role",
                    "properties",
                    "password_policy",
                    "unlock",
                )
                if name in arguments
            }
            record["warnings"] = list(statement.warnings)
            if not statement.read_only:
                # This also runs on cancellation. Never mark a lost write retryable.
                self.store.finish(principal, route, key, record)
            get_audit_logger().info(
                "event=admin_execution principal=%s route=%s action=%s key_digest=%s status=%s target=%s",
                hashlib.sha256(principal.encode()).hexdigest(),
                route,
                statement.action,
                hashlib.sha256(key.encode()).hexdigest(),
                record["execution_status"],
                json.dumps(record["target"], ensure_ascii=True),
            )
            if connection is not None:
                # Never reuse a management connection after credential/privilege changes.
                connection.is_healthy = False
                try:
                    await connection.connection.ensure_closed()
                    await self.manager.release_connection(session, connection)
                except Exception:
                    get_audit_logger().warning("event=admin_connection_cleanup_failed")
        return record
