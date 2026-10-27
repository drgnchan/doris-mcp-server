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

"""Opt-in destructive acceptance against a loopback-only disposable Doris.

Run DORIS_ADMIN_E2E=1 uv run pytest -q --no-cov test/integration/test_admin_doris.py.
Uses only 127.0.0.1, a separately configured local port, and randomly named objects.
Never enable this against a forwarded/shared/production database.
"""

import json
import os
import secrets
from contextlib import suppress

import pymysql
import pytest
from mcp.shared.exceptions import MCPError

from doris_mcp_server.tools.admin_statements import ACTION_FIELDS, CHILD_ACTIONS
from doris_mcp_server.utils.secret_policy import build_token_digest
from test.integration.test_real_doris_transports import (
    RealDorisSettings,
    _authenticated_http_client,
    _server_environment,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("DORIS_ADMIN_E2E") != "1",
        reason="explicit disposable local Doris opt-in required",
    ),
]


@pytest.mark.asyncio
async def test_all_management_operations_over_authenticated_http(tmp_path):
    port = int(os.getenv("DORIS_ADMIN_TEST_PORT", "19030"))
    suffix = secrets.token_hex(5)
    database, username, role = (
        f"mcp_admin_{suffix}_{kind}" for kind in ("db", "user", "role")
    )
    user = {"name": username, "host": "%"}
    first_password, second_password = (
        secrets.token_urlsafe(24),
        secrets.token_urlsafe(24),
    )
    bearer = secrets.token_urlsafe(48)
    connection = pymysql.connect(
        host="127.0.0.1", port=port, user="root", password="", autocommit=True
    )
    settings = RealDorisSettings("127.0.0.1", port, "root", "", database)
    token_file = tmp_path / "tokens.json"
    password_file = tmp_path / "passwords.json"
    password_file.write_text(
        json.dumps(
            {
                f"test@{version}": {
                    "principal": "token::admin-test",
                    "user": user,
                    "version": version,
                    "password": password,
                }
                for version, password in (
                    ("v1", first_password),
                    ("v2", second_password),
                )
            }
        )
    )
    password_file.chmod(0o600)
    base_token = {
        "token_id": "admin-test",
        "token_digest": build_token_digest(bearer, "sha256"),
        "created_at": "2026-07-30T00:00:00Z",
        "expires_at": None,
        "is_active": True,
        "database_config": {
            "host": "127.0.0.1",
            "port": port,
            "user": "root",
            "password": "",
            "database": database,
        },
        "admin_actions": list(ACTION_FIELDS),
    }
    token_file.write_text(json.dumps({"version": "2.0", "tokens": [base_token]}))
    token_file.chmod(0o600)
    environment = _server_environment(settings, user="root", password="")
    environment.update(
        {
            "ENABLE_TOKEN_AUTH": "true",
            "TOKEN_FILE_PATH": str(token_file),
            "MCP_ADMIN_DOMAIN_ENABLED": "true",
            "MCP_ADMIN_STATE_PATH": str(tmp_path / "executions.db"),
            "MCP_ADMIN_PASSWORD_FILE": str(password_file),
            "TOKEN_DB_VALIDATION_TTL_SECONDS": "60",
        }
    )
    seen = set()
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE `{database}`")
            cursor.execute(
                f"CREATE TABLE `{database}`.`items` (id INT) DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES ('replication_num'='1')"
            )
            cursor.execute(f"INSERT INTO `{database}`.`items` VALUES (1), (2)")
        async with _authenticated_http_client(
            environment, bearer_token=bearer
        ) as client:
            discovered = await client.call_tool("doris_admin", {})
            manifest = json.loads(discovered.content[0].text)
            assert len(manifest["children"]) == 7

            async def call(action, **arguments):
                child = next(
                    c for c, actions in CHILD_ACTIONS.items() if action in actions
                )
                arguments = {"action": action, **arguments}
                if child.startswith("manage_"):
                    arguments.setdefault("idempotency_key", secrets.token_hex(16))
                result = await client.call_tool(
                    "doris_admin",
                    {
                        "child_tool": child,
                        "manifest_version": manifest["manifest_version"],
                        "arguments": arguments,
                    },
                )
                payload = json.loads(result.content[0].text)
                assert payload.get("mode") == "result", payload
                data = payload["data"]
                assert data["execution_status"] == "succeeded", data
                assert first_password not in json.dumps(
                    data
                ) and second_password not in json.dumps(data)
                seen.add(action)
                return data, arguments

            _, original = await call("create_role", role=role, comment="test role")
            await call(
                "create_role", **{k: v for k, v in original.items() if k != "action"}
            )  # same key, not CREATE twice
            await call("alter_role", role=role, comment="changed")
            await call(
                "create_user", user=user, password_ref="test@v1", default_role=role
            )
            await call("grant_roles", user=user, roles=[role])
            await call("revoke_roles", user=user, roles=[role])
            object_table = {
                "type": "data_object",
                "scope": "table",
                "catalog": "internal",
                "database": database,
                "table": "items",
            }
            grantee = {"type": "user", **user}
            role_grantee = {"type": "role", "name": role}
            await call(
                "grant_privileges",
                grantee=role_grantee,
                privileges=["SELECT_PRIV"],
                object=object_table,
            )
            await call(
                "revoke_privileges",
                grantee=role_grantee,
                privileges=["SELECT_PRIV"],
                object=object_table,
            )
            await call(
                "grant_privileges",
                grantee=grantee,
                privileges=["SELECT_PRIV"],
                object=object_table,
            )
            for scope in (
                {"type": "data_object", "scope": "catalog", "catalog": "internal"},
                {
                    "type": "data_object",
                    "scope": "database",
                    "catalog": "internal",
                    "database": database,
                },
                {**object_table, "scope": "column", "columns": ["id"]},
            ):
                await call(
                    "grant_privileges",
                    grantee=grantee,
                    privileges=["SELECT_PRIV"],
                    object=scope,
                )
                await call(
                    "revoke_privileges",
                    grantee=grantee,
                    privileges=["SELECT_PRIV"],
                    object=scope,
                )
            # Every data privilege has a real legal representative, then is revoked.
            for privilege in (
                "SHOW_VIEW_PRIV",
                "LOAD_PRIV",
                "CREATE_PRIV",
                "ALTER_PRIV",
                "DROP_PRIV",
                "GRANT_PRIV",
                "ADMIN_PRIV",
                "NODE_PRIV",
            ):
                scope = {"type": "data_object", "scope": "global"}
                await call(
                    "grant_privileges",
                    grantee=grantee,
                    privileges=[privilege],
                    object=scope,
                )
                await call(
                    "revoke_privileges",
                    grantee=grantee,
                    privileges=[privilege],
                    object=scope,
                )
            group = {"type": "workload_group", "name": "normal"}
            await call(
                "grant_privileges",
                grantee=grantee,
                privileges=["USAGE_PRIV"],
                object=group,
            )
            await call(
                "revoke_privileges",
                grantee=grantee,
                privileges=["USAGE_PRIV"],
                object=group,
            )
            await call(
                "alter_user",
                user=user,
                password_policy={
                    "failed_login_attempts": 3,
                    "lock_time": {"interval": 1, "unit": "DAY"},
                },
            )
            await call("alter_user", user=user, unlock=True)
            await call("alter_user", user=user, comment="changed")
            await call("set_password", user=user, password_ref="test@v2")
            await call(
                "set_property",
                username=username,
                properties={"max_user_connections": 100},
            )
            for action in (
                "show_grants",
                "show_all_grants",
                "show_roles",
                "show_privileges",
                "show_property",
                "show_all_properties",
                "show_row_policy",
            ):
                await call(
                    action,
                    **(
                        {"user": user}
                        if action == "show_grants"
                        else {"username": username}
                        if action == "show_property"
                        else {}
                    ),
                )
            table = {"database": database, "table": "items"}
            target = {"type": "user", "name": username}
            for name, mode, predicate in (
                ("restrict_test", "RESTRICTIVE", "id > 0"),
                ("permit_test", "PERMISSIVE", "id = 1"),
            ):
                await call(
                    "create_row_policy",
                    policy=name,
                    table=table,
                    target=target,
                    mode=mode,
                    predicate=predicate,
                )
            with pymysql.connect(
                host="127.0.0.1",
                port=port,
                user=username,
                password=second_password,
                database=database,
            ) as user_connection:
                with user_connection.cursor() as cursor:
                    cursor.execute("SELECT id FROM items")
                    assert cursor.fetchall() == ((1,),)
            await call("show_row_policy", target=target)
            for name in ("permit_test", "restrict_test"):
                await call("drop_row_policy", policy=name, table=table, target=target)
            await call(
                "revoke_privileges",
                grantee=grantee,
                privileges=["SELECT_PRIV"],
                object=object_table,
            )
            await call("drop_user", user=user)
            await call("drop_role", role=role)
        assert {
            action
            for action in ACTION_FIELDS
            if action.startswith(
                ("create_", "drop_", "grant_", "revoke_", "alter_", "set_")
            )
        } <= seen

        # An old token bound to the very same root route is NOT a management grant.
        base_token.pop("admin_actions")
        token_file.write_text(json.dumps({"version": "2.0", "tokens": [base_token]}))
        async with _authenticated_http_client(
            environment, bearer_token=bearer
        ) as client:
            with pytest.raises(MCPError, match="error response"):
                await client.call_tool("doris_admin", {})

        # Flat exposure takes the same authorization/execution path over HTTP.
        base_token["admin_actions"] = ["create_role", "drop_role"]
        token_file.write_text(json.dumps({"version": "2.0", "tokens": [base_token]}))
        environment["MCP_TOOL_EXPOSURE_MODE"] = "flat"
        async with _authenticated_http_client(
            environment, bearer_token=bearer
        ) as client:
            result = await client.call_tool(
                "doris_admin_manage_roles",
                {
                    "action": "create_role",
                    "role": role,
                    "idempotency_key": "flat-create",
                },
            )
            assert (
                json.loads(result.content[0].text)["data"]["execution_status"]
                == "succeeded"
            )
            result = await client.call_tool(
                "doris_admin_manage_roles",
                {"action": "drop_role", "role": role, "idempotency_key": "flat-drop"},
            )
            assert (
                json.loads(result.content[0].text)["data"]["execution_status"]
                == "succeeded"
            )
        # MCP permission is not a substitute for the actual routed Doris RBAC.
        with connection.cursor() as cursor:
            cursor.execute(
                "CREATE USER %s@'%%' IDENTIFIED BY %s", (username, second_password)
            )
        base_token["database_config"].update(
            user=username, password=second_password, database="information_schema"
        )
        token_file.write_text(json.dumps({"version": "2.0", "tokens": [base_token]}))
        async with _authenticated_http_client(
            environment, bearer_token=bearer
        ) as client:
            result = await client.call_tool(
                "doris_admin_manage_roles",
                {
                    "action": "create_role",
                    "role": role,
                    "idempotency_key": "native-denial",
                },
            )
            data = json.loads(result.content[0].text)["data"]
            assert data["execution_status"] == "failed"
            assert data["error_code"].startswith("DORIS_ERROR_")
    finally:
        with connection.cursor() as cursor:
            for sql in (
                f"DROP USER IF EXISTS '{username}'@'%'",
                f"DROP ROLE IF EXISTS `{role}`",
                f"DROP DATABASE IF EXISTS `{database}`",
            ):
                with suppress(pymysql.MySQLError):
                    cursor.execute(sql)
        connection.close()
