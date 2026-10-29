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

"""Stateless business-write runtime: one submission, no automatic retry."""

import asyncio
import hashlib
import secrets
import time
from typing import Any

from ..tools.write_domain import authorize_write
from ..tools.write_statements import WriteError, compile_write
from .db import DEFINITE_MUTATION_REJECTION_CODES, DorisMutationRejectedError
from .logger import get_audit_logger
from .security import get_current_auth_context


class WriteRuntime:
    def __init__(self, manager: Any) -> None:
        self.manager = manager

    async def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.manager.config.writing.enabled is not True:
            raise WriteError("WRITE_DISABLED")
        context = get_current_auth_context()
        statement = compile_write(arguments)
        principal = authorize_write(context, statement.action)
        session = "write_" + secrets.token_hex(12)
        route = self.manager.get_route_identity(context).endpoint_fingerprint
        record: dict[str, Any] = {
            "action": statement.action,
            "request_id": session,
            "execution_status": "outcome_unknown",
            "verification_status": "not_checked",
            "target": statement.target,
            "sources": list(statement.sources),
            "warnings": list(statement.warnings),
        }
        connection, sent = None, False
        started = time.monotonic()

        def submitted() -> None:
            nonlocal sent
            sent = True

        try:
            async with asyncio.timeout(30):
                connection = await self.manager.get_connection(session)
                record.update(
                    await connection.execute_write(
                        arguments, context, on_submit=submitted
                    )
                )
        except asyncio.CancelledError:
            record.update(
                execution_status="outcome_unknown" if sent else "failed",
                error_code="WRITE_REQUEST_CANCELLED",
            )
            raise
        except WriteError as exc:
            record.update(
                execution_status="outcome_unknown" if sent else "failed",
                error_code=exc.code,
            )
        except Exception as exc:
            from pymysql import MySQLError

            code = exc.args[0] if isinstance(exc, MySQLError) and exc.args else None
            server_error = isinstance(code, int) and 0 < code < 2000
            definite = code in DEFINITE_MUTATION_REJECTION_CODES or isinstance(
                exc, DorisMutationRejectedError
            )
            record.update(
                execution_status="failed"
                if not sent or definite
                else "outcome_unknown",
                error_code=f"DORIS_ERROR_{code}"
                if server_error
                else "WRITE_EXECUTION_UNCERTAIN"
                if sent
                else "WRITE_CONNECTION_FAILED",
            )
        finally:
            get_audit_logger().info(
                "event=business_write request_id=%s principal=%s route=%s action=%s target=%s status=%s duration_ms=%s error_code=%s",
                session,
                hashlib.sha256(principal.encode()).hexdigest(),
                route,
                statement.action,
                statement.target,
                record["execution_status"],
                round((time.monotonic() - started) * 1000),
                record.get("error_code", ""),
            )
            if connection is not None:
                connection.is_healthy = False
                try:
                    await self.manager.release_connection(session, connection)
                except Exception:
                    get_audit_logger().warning(
                        "event=write_connection_cleanup_failed request_id=%s", session
                    )
        return record
