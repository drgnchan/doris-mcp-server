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

"""Core direct-management scenarios and authorization/replay regressions."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from pymysql import ProgrammingError

from doris_mcp_server.auth.doris_oauth_scope_policy import DorisOAuthScopePolicy
from doris_mcp_server.tools.admin_domain import ADMIN_DOMAIN, allowed_actions
from doris_mcp_server.tools.admin_predicate import compile_predicate
from doris_mcp_server.tools.admin_statements import (
    ACTION_FIELDS,
    CHILD_ACTIONS,
    AdminError,
    action_scope,
    compile_statement,
)
from doris_mcp_server.tools.domain_catalog import DORIS_DOMAIN_CATALOG
from doris_mcp_server.tools.domain_dispatcher import ToolNotFoundError
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.admin_execution_store import AdminExecutionStore
from doris_mcp_server.utils.admin_runtime import AdminRuntime
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import DorisConnection
from doris_mcp_server.utils.query_runtime import QueryRuntimeFailure
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)

USER = {"name": "alice", "host": "%"}
SAMPLES = {
    "grant_privileges": {
        "grantee": {"type": "user", **USER},
        "privileges": ["SELECT_PRIV"],
        "object": {
            "type": "data_object",
            "scope": "table",
            "catalog": "internal",
            "database": "db",
            "table": "tbl",
        },
    },
    "revoke_privileges": {
        "grantee": {"type": "role", "name": "analyst"},
        "privileges": ["LOAD_PRIV"],
        "object": {
            "type": "data_object",
            "scope": "database",
            "catalog": "internal",
            "database": "db",
        },
    },
    "grant_roles": {"user": USER, "roles": ["analyst"]},
    "revoke_roles": {"user": USER, "roles": ["analyst"]},
    "create_role": {"role": "analyst", "comment": "team's role"},
    "drop_role": {"role": "analyst"},
    "alter_role": {"role": "analyst", "comment": "new comment"},
    "create_user": {
        "user": USER,
        "password_ref": "alice@v1",
        "default_role": "analyst",
    },
    "drop_user": {"user": USER},
    "alter_user": {
        "user": USER,
        "password_policy": {
            "failed_login_attempts": 3,
            "lock_time": {"interval": 1, "unit": "DAY"},
        },
    },
    "set_password": {"user": USER, "password_ref": "alice@v1"},
    "set_property": {
        "username": "alice",
        "properties": {"max_user_connections": 100, "default_workload_group": "normal"},
    },
    "create_row_policy": {
        "policy": "p",
        "table": {"database": "db", "table": "tbl"},
        "target": {"type": "user", "name": "alice"},
        "mode": "RESTRICTIVE",
        "predicate": "tenant_id = 1 AND name IS NOT NULL",
    },
    "drop_row_policy": {"policy": "p", "table": {"database": "db", "table": "tbl"}},
}


def child_for(action):
    return next(c for c, actions in CHILD_ACTIONS.items() if action in actions)


def request(action, **updates):
    return {
        "action": action,
        **SAMPLES.get(action, {}),
        "idempotency_key": "test-key",
        **updates,
    }


def context():
    return AuthContext(
        user_id="controller",
        auth_method="token",
        permissions=[f"child:call:doris_admin:{c}" for c in CHILD_ACTIONS]
        + [action_scope(a) for a in ACTION_FIELDS],
    )


@pytest.fixture
def backend(tmp_path):
    manager = Mock()
    manager.config = DorisConfig()
    manager.config.administration.enabled = True
    manager.config.administration.state_path = str(tmp_path / "executions.db")
    manager.config.database.user = "root"
    manager.get_database_config_for_auth_context.return_value = manager.config.database
    manager.get_route_identity.return_value = SimpleNamespace(
        endpoint_fingerprint="local-test"
    )
    conn = Mock()
    conn.execute = AsyncMock(
        return_value=SimpleNamespace(
            data=[{"version": "doris-4.0.7-rc02 (Cloud Mode)"}]
        )
    )
    conn.execute_management = AsyncMock(return_value={"rows": [], "truncated": False})
    conn.connection.ensure_closed = AsyncMock()
    manager.get_connection = AsyncMock(return_value=conn)
    manager.release_connection = AsyncMock()
    token = set_current_auth_context(context())
    runtime = AdminRuntime(manager)
    yield manager, conn, runtime
    runtime.close()
    reset_auth_context(token)


@pytest.mark.parametrize("action", SAMPLES)
def test_all_fourteen_operations_compile(action):
    statement = compile_statement(child_for(action), request(action))
    assert statement.sql
    assert statement.action == action
    assert "approval" not in statement.sql.lower()


@pytest.mark.parametrize(
    "privilege",
    [
        "SELECT_PRIV",
        "SHOW_VIEW_PRIV",
        "LOAD_PRIV",
        "CREATE_PRIV",
        "ALTER_PRIV",
        "DROP_PRIV",
        "GRANT_PRIV",
        "ADMIN_PRIV",
        "NODE_PRIV",
    ],
)
def test_all_data_privileges(privilege):
    args = request(
        "grant_privileges",
        privileges=[privilege],
        object={"type": "data_object", "scope": "global"},
    )
    assert (
        f"GRANT {privilege} ON *.*.*"
        in compile_statement("manage_privileges", args).sql
    )


@pytest.mark.parametrize(
    "kind", ["resource", "workload_group", "compute_group", "storage_vault"]
)
def test_resource_scopes(kind):
    args = request(
        "grant_privileges",
        privileges=["USAGE_PRIV"],
        object={"type": kind, "all_objects": True},
    )
    assert "USAGE_PRIV" in compile_statement("manage_privileges", args).sql


def test_column_scope_and_invalid_privileges():
    args = request("grant_privileges")
    args["object"] = {**args["object"], "scope": "column", "columns": ["name"]}
    assert "SELECT_PRIV(`name`)" in compile_statement("manage_privileges", args).sql
    with pytest.raises(AdminError):
        compile_statement("manage_privileges", {**args, "privileges": ["ADMIN_PRIV"]})


def test_strict_action_fields_and_compound_effects():
    assert compile_statement("manage_users", request("create_user")).extra_actions == (
        "grant_roles",
    )
    with pytest.raises(AdminError):
        compile_statement("manage_roles", request("create_role", predicate="1=1"))
    with pytest.raises(AdminError):
        compile_statement("manage_users", request("drop_user", password_ref="hidden"))
    args = {
        "action": "alter_user",
        "user": USER,
        "password_ref": "alice@v1",
        "idempotency_key": "x",
    }
    assert compile_statement("manage_users", args).extra_actions == ("set_password",)


@pytest.mark.parametrize(
    "predicate",
    [
        "1=1); DROP USER alice; --",
        "EXISTS(SELECT 1)",
        "sleep(5) = 0",
        "load_file('/etc/passwd') IS NOT NULL",
        "x IN (SELECT x FROM secrets)",
    ],
)
def test_policy_injection_and_side_effects_rejected(predicate):
    with pytest.raises(AdminError):
        compile_predicate(predicate)


def test_supported_predicate():
    assert "CAST" in compile_predicate(
        "CAST(tenant_id AS BIGINT) IN (1, 2) AND LOWER(name) = 'a'"
    )


@pytest.mark.asyncio
async def test_direct_execution_and_replay(backend):
    _, conn, runtime = backend
    results = await asyncio.gather(
        *(runtime.execute("manage_roles", request("create_role")) for _ in range(3))
    )
    assert results[0]["execution_status"] == "succeeded"
    conn.execute.assert_not_awaited()  # No version probe or management-only gate.
    assert conn.execute_management.await_count == 1
    runtime.close()
    assert (await runtime.execute("manage_roles", request("create_role")))[
        "execution_status"
    ] == "succeeded"
    assert conn.execute_management.await_count == 1
    with pytest.raises(AdminError, match="IDEMPOTENCY_CONFLICT"):
        await runtime.execute("manage_roles", request("create_role", role="different"))


@pytest.mark.asyncio
async def test_backend_rejection_reported_and_not_retried(backend):
    _, conn, runtime = backend
    conn.execute_management.side_effect = ProgrammingError(1235, "Unsupported feature")
    result = await runtime.execute("manage_roles", request("create_role"))
    assert result["execution_status"] == "failed"
    assert result["error_code"] == "DORIS_ERROR_1235"
    assert await runtime.execute("manage_roles", request("create_role")) == result
    conn.execute.assert_not_awaited()
    assert conn.execute_management.await_count == 1


@pytest.mark.asyncio
async def test_optional_dry_run_no_submission(backend):
    manager, conn, runtime = backend
    result = await runtime.execute(
        "manage_users",
        {
            "action": "set_password",
            "user": USER,
            "password_ref": "alice@v1",
            "dry_run": True,
        },
    )
    assert result["execution_status"] == "dry_run"
    assert "<redacted>" in result["sql"]
    manager.get_connection.assert_not_called()
    conn.execute_management.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_is_not_retried_and_status_is_private(backend):
    _, conn, runtime = backend
    conn.execute_management.side_effect = TimeoutError()
    result = await runtime.execute("manage_roles", request("create_role"))
    assert result["execution_status"] == "outcome_unknown"
    assert (await runtime.execute("manage_roles", request("create_role"))) == result
    assert conn.execute_management.await_count == 1
    assert (
        await runtime.execute(
            "get_execution_status",
            {"action": "get_execution_status", "idempotency_key": "test-key"},
        )
    ) == result
    other = context()
    other.user_id = "other"
    token = set_current_auth_context(other)
    try:
        with pytest.raises(AdminError, match="NOT_FOUND"):
            await runtime.execute(
                "get_execution_status",
                {"action": "get_execution_status", "idempotency_key": "test-key"},
            )
    finally:
        reset_auth_context(token)


def test_restart_inflight_is_unknown(tmp_path):
    path = str(tmp_path / "store.db")
    store = AdminExecutionStore(path)
    store.claim("p", "r", "k", "d", "create_role")
    store.close()
    store = AdminExecutionStore(path)
    assert store.get("p", "r", "k")["execution_status"] == "outcome_unknown"
    assert store.claim("p", "r", "k", "d", "create_role")[0] is False
    store.close()


@pytest.mark.asyncio
async def test_password_reference_bound_to_principal_and_target(backend, tmp_path):
    manager, conn, runtime = backend
    path = tmp_path / "passwords.json"
    path.write_text(
        json.dumps(
            {
                "alice@v1": {
                    "principal": "token::controller",
                    "user": USER,
                    "version": "v1",
                    "password": "secret-not-in-result",
                }
            }
        )
    )
    path.chmod(0o600)
    manager.config.administration.password_file = str(path)
    result = await runtime.execute("manage_users", request("set_password"))
    assert result["execution_status"] == "succeeded"
    assert "secret-not-in-result" not in json.dumps(result)
    assert "secret-not-in-result" not in Path(
        manager.config.administration.state_path
    ).read_bytes().decode(errors="ignore")
    assert (
        conn.execute_management.call_args.kwargs["password"] == "secret-not-in-result"
    )
    denied = await runtime.execute(
        "manage_users",
        request(
            "set_password", user={"name": "bob", "host": "%"}, idempotency_key="other"
        ),
    )
    assert denied["error_code"] == "ADMIN_PASSWORD_REFERENCE_FORBIDDEN"
    assert conn.execute_management.await_count == 1


@pytest.mark.asyncio
async def test_no_implicit_permission_or_compound_bypass(backend):
    _, conn, runtime = backend
    limited = AuthContext(
        user_id="limited",
        auth_method="token",
        permissions=[
            "admin",
            "write_data",
            "child:call:doris_admin:manage_users",
            action_scope("create_user"),
        ],
    )
    token = set_current_auth_context(limited)
    try:
        with pytest.raises(AdminError, match="FORBIDDEN"):
            await runtime.execute("manage_users", request("create_user"))
        assert not allowed_actions(None, "manage_users")
        conn.execute_management.assert_not_called()
    finally:
        reset_auth_context(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["hierarchical", "flat"])
async def test_default_disabled_and_enabled_dispatch(backend, mode):
    manager, conn, _ = backend
    manager.config.administration.enabled = False
    tools = DorisToolsManager(manager, tool_exposure_mode=mode)
    assert len(DORIS_DOMAIN_CATALOG.domains) == 8
    assert not any(t.name.startswith("doris_admin") for t in await tools.list_tools())
    with pytest.raises(ToolNotFoundError):
        await tools.call_tool("doris_admin", {})
    manager.config.administration.enabled = True
    tools = DorisToolsManager(manager, tool_exposure_mode=mode)
    try:
        if mode == "hierarchical":
            manifest = json.loads(await tools.call_tool("doris_admin", {}))
            assert len(manifest["children"]) == 7
            name, arguments = (
                "doris_admin",
                {
                    "child_tool": "manage_roles",
                    "manifest_version": manifest["manifest_version"],
                    "arguments": request("create_role"),
                },
            )
        else:
            name, arguments = "doris_admin_manage_roles", request("create_role")
        result = json.loads(await tools.call_tool(name, arguments))
        assert result["data"]["execution_status"] == "succeeded"
        assert conn.execute_management.await_count == 1
    finally:
        tools.admin_runtime.close()


@pytest.mark.asyncio
async def test_management_sink_does_not_open_readonly_execute():
    raw = Mock()
    cursor = AsyncMock()
    cursor.description = None
    raw.cursor = AsyncMock(return_value=cursor)
    raw.ensure_closed = AsyncMock()
    connection = DorisConnection(raw, "test")
    with pytest.raises(QueryRuntimeFailure):
        await connection.execute("CREATE ROLE 'x'")
    cursor.execute.assert_not_called()
    await connection.execute_management(
        "manage_roles", request("create_role"), context()
    )
    assert (
        cursor.execute.call_args.args[0]
        == "CREATE ROLE `analyst` COMMENT 'team''s role'"
    )
    with pytest.raises(AdminError):
        await connection.execute_management(
            "manage_roles", request("create_role", sql="DROP USER root"), context()
        )


def test_oauth_requires_explicit_admin_scope_and_config():
    config = DorisConfig()
    config.security.doris_oauth_child_tools_enabled = True
    config.security.doris_oauth_child_tool_allowlist.append("doris_admin.manage_roles")
    config.security.doris_oauth_admin_action_allowlist = ["create_role"]
    policy = DorisOAuthScopePolicy(config.security)
    assert action_scope("create_role") in policy.server_allowed_scopes
    assert action_scope("create_role") not in policy.server_default_scopes
    assert action_scope("drop_role") not in policy.server_allowed_scopes
    assert ADMIN_DOMAIN.annotations.requires_confirmation is False
