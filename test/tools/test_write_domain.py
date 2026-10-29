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
"""Business-write acceptance boundaries, authorization and single submission."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import aiomysql
import pytest
from pymysql import OperationalError, ProgrammingError

from doris_mcp_server.auth.doris_oauth_scope_policy import DorisOAuthScopePolicy
from doris_mcp_server.auth.token_manager import TokenManager
from doris_mcp_server.tools.domain_dispatcher import ToolNotFoundError
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.tools.write_domain import action_scope, allowed_actions
from doris_mcp_server.tools.write_statements import (
    WRITE_ACTIONS,
    WriteError,
    compile_write,
)
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import DorisConnection, DorisConnectionManager
from doris_mcp_server.utils.query_runtime import QueryRuntimeFailure
from doris_mcp_server.utils.secret_policy import build_token_digest
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)
from doris_mcp_server.utils.write_runtime import WriteRuntime

DDL = "CREATE TABLE internal.db.t (id BIGINT NOT NULL, v INT) ENGINE=OLAP UNIQUE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES ('replication_num'='1')"
INSERT = "INSERT INTO internal.db.t VALUES (1, 10)"
UPDATE = "UPDATE internal.db.t SET v=20 WHERE id=1"
DESTRUCTIVE = [
    ("delete", "DELETE FROM internal.db.t WHERE id=1"),
    ("drop_table", "DROP TABLE internal.db.t"),
    ("truncate_table", "TRUNCATE TABLE internal.db.t"),
]


def context(actions=WRITE_ACTIONS, method="token"):
    scopes = [
        "child:call:doris_write:execute_write",
        *(action_scope(a) for a in actions),
    ]
    return AuthContext(
        user_id="writer", auth_method=method, permissions=scopes, oauth_scopes=scopes
    )


@pytest.mark.parametrize(
    "action,sql",
    [
        *DESTRUCTIVE,
        ("insert", INSERT),
        (
            "insert",
            "INSERT INTO internal.db.t SELECT s.id, SUM(s.v) FROM internal.src.s s JOIN internal.src.u u ON s.id=u.id GROUP BY s.id",
        ),
        (
            "insert",
            "INSERT INTO internal.db.t WITH c AS (SELECT * FROM internal.src.s) SELECT id,v FROM c WHERE id IN (SELECT id FROM internal.src.u)",
        ),
        ("update", UPDATE),
        ("create_table", DDL),
        ("create_table", DDL.replace("UNIQUE KEY", "DUPLICATE KEY")),
    ],
)
def test_accepted_grammar(action, sql):
    statement = compile_write({"action": action, "sql": sql})
    assert statement.target == "`internal`.`db`.`t`"
    assert compile_write({"action": action, "sql": statement.sql}).sql == statement.sql


@pytest.mark.parametrize(
    "action,sql",
    [
        ("delete", "DELETE FROM internal.db.t"),
        ("delete", "DELETE FROM internal.db.t WHERE id IN (SELECT id FROM internal.db.s)"),
        ("delete", "DELETE FROM internal.db.t USING internal.db.s WHERE t.id=s.id"),
        ("delete", "DELETE FROM internal.db.t WHERE id=1 LIMIT 1"),
        ("delete", "DELETE FROM internal.db.t PARTITION(p1) WHERE id=1"),
        ("drop_table", "DROP TABLE internal.db.t FORCE"),
        ("drop_table", "DROP TABLE IF EXISTS internal.db.t"),
        ("drop_table", "DROP TABLE internal.db.t, internal.db.s"),
        ("drop_table", "DROP VIEW internal.db.t"),
        ("drop_table", "DROP DATABASE db"),
        ("truncate_table", "TRUNCATE TABLE internal.db.t, internal.db.s"),
        ("truncate_table", "TRUNCATE TABLE internal.db.t PARTITION(p1)"),
        ("truncate_table", "TRUNCATE TABLE external.db.t"),
        ("delete", "DROP TABLE internal.db.t"),
        ("insert", INSERT + "; DELETE FROM internal.db.t"),
        ("insert", "INSERT OVERWRITE TABLE internal.db.t SELECT * FROM internal.src.s"),
        (
            "insert",
            "INSERT INTO internal.db.t SELECT * FROM s3('uri'='s3://private/x')",
        ),
        ("insert", "INSERT INTO internal.db.t SELECT * FROM external.db.s"),
        (
            "insert",
            "INSERT INTO internal.db.t SELECT * FROM (SELECT * FROM external.db.s) q",
        ),
        (
            "insert",
            "INSERT INTO internal.db.t WITH s AS (SELECT * FROM external.db.s) SELECT * FROM s",
        ),
        (
            "insert",
            "INSERT INTO internal.db.t SELECT * FROM (WITH c AS (SELECT * FROM internal.src.s) SELECT * FROM c) x JOIN c ON 1=1",
        ),
        (
            "insert",
            "INSERT INTO internal.db.t SELECT * FROM internal.src.s INTO OUTFILE '/tmp/export'",
        ),
        ("insert", "INSERT INTO internal.db.t SELECT load_file('/etc/passwd')"),
        ("insert", "INSERT INTO internal.db.t SELECT sleep(10)"),
        ("insert", "INSERT INTO db.t VALUES (1,2)"),
        ("insert", "GRANT SELECT_PRIV ON *.*.* TO ROLE r"),
        ("update", "UPDATE internal.db.t SET v=1"),
        ("update", "UPDATE internal.db.t SET v=(SELECT 1) WHERE id=1"),
        ("update", "UPDATE internal.db.t SET v=v+1 WHERE id=1"),
        ("create_table", "CREATE TABLE internal.db.t AS SELECT * FROM internal.src.s"),
        ("create_table", "CREATE TABLE internal.db.t LIKE internal.src.s"),
        ("create_table", DDL.replace("ENGINE=OLAP", "ENGINE=MYSQL")),
        ("create_table", DDL.replace("'replication_num'='1'", "'resource'='external'")),
    ],
)
def test_rejects_unsupported_or_hidden_effects(action, sql):
    with pytest.raises(WriteError):
        compile_write({"action": action, "sql": sql})


@pytest.fixture
def backend():
    manager = Mock()
    manager.config = DorisConfig()
    manager.config.writing.enabled = True
    manager.get_route_identity.return_value = SimpleNamespace(
        endpoint_fingerprint="test-route"
    )
    raw = Mock()
    cursor = AsyncMock()
    cursor.rowcount = 1
    cursor._result = SimpleNamespace(message=b"{'status':'VISIBLE', 'txnId':123}")
    cursor.fetchone.return_value = {"Table": "t", "Create Table": DDL}
    raw.cursor = AsyncMock(return_value=cursor)
    raw.ensure_closed = AsyncMock()
    connection = DorisConnection(raw, "test")
    manager.get_connection = AsyncMock(return_value=connection)
    manager.release_connection = AsyncMock()
    token = set_current_auth_context(context())
    try:
        yield manager, cursor, connection, WriteRuntime(manager)
    finally:
        reset_auth_context(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("action,sql", DESTRUCTIVE)
async def test_destructive_sink_authorization_dryrun_and_single_send(backend, action, sql):
    _, cursor, connection, runtime = backend
    with pytest.raises(QueryRuntimeFailure):
        await connection.execute(sql)
    for method in ("token", "jwt", "external_oauth", "doris_oauth"):
        denied = context(("insert", "update", "create_table"), method)
        denied.permissions.extend(["admin", "write_data"])
        denied.doris_oauth_child_tools_enabled = True
        denied.doris_oauth_child_tool_allowlist = ["doris_write.execute_write"]
        with pytest.raises(WriteError, match="FORBIDDEN"):
            await connection.execute_write({"action": action, "sql": sql}, denied)
    cursor.execute.assert_not_called()
    args = {"action": action, "sql": sql}
    assert (await runtime.execute({**args, "dry_run": True}))["execution_status"] == "dry_run"
    cursor.execute.assert_awaited_once_with("SHOW CREATE TABLE `internal`.`db`.`t`")
    cursor.execute.reset_mock()
    assert (await runtime.execute(args))["execution_status"] == "succeeded"
    assert cursor.execute.await_count == 2
    assert cursor.execute.call_args.args[0] == compile_write(args).sql


@pytest.mark.asyncio
@pytest.mark.parametrize("action,sql", DESTRUCTIVE)
@pytest.mark.parametrize("ddl", ["CREATE VIEW internal.db.t AS SELECT 1", DDL.replace("ENGINE=OLAP", "ENGINE=MYSQL")])
async def test_destructive_metadata_denial(backend, action, sql, ddl):
    _, cursor, _, runtime = backend
    cursor.fetchone.return_value = {"Create Table": ddl}
    assert (await runtime.execute({"action": action, "sql": sql}))["execution_status"] == "failed"
    assert cursor.execute.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("action,sql", DESTRUCTIVE)
@pytest.mark.parametrize("error", [TimeoutError(), OperationalError(1105, "private"), OperationalError(2013, "private")])
async def test_destructive_unknown_does_not_retry(backend, action, sql, error):
    _, cursor, _, runtime = backend
    cursor.execute.side_effect = [None, error]
    result = await runtime.execute({"action": action, "sql": sql})
    assert result["execution_status"] == "outcome_unknown"
    assert cursor.execute.await_count == 2
    assert "private" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["SEMI", "ANTI"])
@pytest.mark.parametrize("rhs", ["external.db.r", "r"])
async def test_semi_anti_rhs_rejected_before_sql(backend, kind, rhs):
    _, cursor, connection, _ = backend
    sql = f"INSERT INTO internal.db.t SELECT a.id,a.v FROM internal.db.a a LEFT {kind} JOIN {rhs} r ON a.id=r.id"
    with pytest.raises(WriteError):
        await connection.execute_write({"action": "insert", "sql": sql}, context())
    cursor.execute.assert_not_called()


@pytest.mark.parametrize("kind", ["SEMI", "ANTI"])
def test_semi_anti_physical_and_cte_sources_survive_generation(kind):
    body = f"SELECT a.id,a.v FROM internal.db.a a LEFT {kind} JOIN internal.db.r r ON a.id=r.id"
    expected = ("`internal`.`db`.`a`", "`internal`.`db`.`r`")
    for query in (
        body,
        "WITH c AS (SELECT * FROM internal.db.r) "
        + body.replace("internal.db.r r", "c r"),
    ):
        statement = compile_write(
            {"action": "insert", "sql": "INSERT INTO internal.db.t " + query}
        )
        assert statement.sources == expected
        assert (
            compile_write({"action": "insert", "sql": statement.sql}).sources
            == expected
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["SEMI", "ANTI"])
@pytest.mark.parametrize(
    "rhs_ddl",
    [
        DDL.replace("ENGINE=OLAP", "ENGINE=MYSQL"),
        "CREATE VIEW internal.db.r AS SELECT 1",
    ],
)
async def test_semi_anti_rhs_metadata_checked_before_write(backend, kind, rhs_ddl):
    _, cursor, _, runtime = backend
    cursor.fetchone.side_effect = [{"Create Table": ddl} for ddl in (DDL, DDL, rhs_ddl)]
    sql = f"INSERT INTO internal.db.t SELECT a.id,a.v FROM internal.db.a a LEFT {kind} JOIN internal.db.r r ON a.id=r.id"
    result = await runtime.execute({"action": "insert", "sql": sql})
    assert result["execution_status"] == "failed"
    assert (
        cursor.execute.call_args_list[-1].args[0]
        == "SHOW CREATE TABLE `internal`.`db`.`r`"
    )
    assert cursor.execute.await_count == 3
    assert all(
        c.args[0].startswith("SHOW CREATE TABLE") for c in cursor.execute.call_args_list
    )


@pytest.mark.asyncio
async def test_sink_success_dryrun_legacy_key_and_readonly_guard(backend):
    _, cursor, connection, runtime = backend
    args = {"action": "insert", "sql": INSERT}
    with pytest.raises(QueryRuntimeFailure):
        await connection.execute(INSERT)
    cursor.execute.assert_not_called()
    with pytest.raises(WriteError, match="IDEMPOTENCY"):
        await connection.execute_write({**args, "idempotency_key": "old"}, context())
    assert (await runtime.execute({**args, "dry_run": True}))[
        "execution_status"
    ] == "dry_run"
    assert all(
        c.args[0].startswith("SHOW CREATE TABLE") for c in cursor.execute.call_args_list
    )
    cursor.execute.reset_mock()
    result = await runtime.execute(args)
    assert result["execution_status"] == "succeeded"
    assert result["transaction_id"] == "123"
    assert result["affected_rows"] == 1
    assert result["verification_status"] == "not_checked"
    assert cursor.execute.await_count == 2  # metadata + one write
    await runtime.execute(args)  # explicit new invocation is a new submission
    assert cursor.execute.await_count == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message,status,visibility",
    [
        (b"{'status':'COMMITTED', 'txnId':12}", "succeeded", "not_confirmed"),
        (
            bytes([len(b"{'status':'VISIBLE', 'txnId':12}")])
            + b"{'status':'VISIBLE', 'txnId':12}",
            "succeeded",
            "visible",
        ),
        (b"\x00", "succeeded", "not_checked"),
        (b"unexpected secret business result", "outcome_unknown", "not_checked"),
    ],
)
async def test_insert_publication_is_not_overclaimed(
    backend, message, status, visibility
):
    _, cursor, _, runtime = backend
    cursor._result.message = message
    result = await runtime.execute({"action": "insert", "sql": INSERT})
    assert result["execution_status"] == status
    assert result["data_visibility"] == visibility
    assert "secret business" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("length,encoded", [(123, True), (124, False)])
async def test_insert_message_length_prefix_is_not_a_json_marker(
    backend, length, encoded
):
    _, cursor, _, runtime = backend
    prefix, suffix = "{'label':'", "', 'status':'VISIBLE', 'txnId':'12'}"
    payload = (prefix + "x" * (length - len(prefix) - len(suffix)) + suffix).encode()
    assert len(payload) == length
    cursor._result.message = bytes([length]) + payload if encoded else payload
    result = await runtime.execute({"action": "insert", "sql": INSERT})
    assert result["execution_status"] == "succeeded"
    assert result["data_visibility"] == "visible"
    assert result["transaction_id"] == "12"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,status",
    [
        (TimeoutError(), "outcome_unknown"),
        (OperationalError(2013, "secret SQL"), "outcome_unknown"),
        (OperationalError(1105, "commitTxn() failed: secret SQL"), "outcome_unknown"),
        (
            OperationalError(
                1105,
                "errCode = 2, detailMessage = Permission denied: user ['secret SQL'@'%'] does not have privilege for [priv predicate: OR, Admin_priv,Select_priv] command on [internal].[db].[src].[id]",
            ),
            "failed",
        ),
        (
            OperationalError(
                1105,
                "errCode = 2, detailMessage = LOAD command denied to user 'secret SQL'@'host' for table 'db.t'",
            ),
            "failed",
        ),
        (
            OperationalError(
                1105,
                "errCode = 2, detailMessage = commitTxn() failed: errCode = 2, detailMessage = LOAD command denied to user 'secret SQL'@'host' for table 'db.t'",
            ),
            "outcome_unknown",
        ),
        (ProgrammingError(1064, "secret SQL"), "failed"),
        (ProgrammingError(1142, "secret SQL"), "failed"),
    ],
)
async def test_error_after_submission_is_not_retried(backend, error, status):
    _, cursor, _, runtime = backend
    cursor.execute.side_effect = [None, error]
    result = await runtime.execute({"action": "insert", "sql": INSERT})
    assert result["execution_status"] == status
    assert cursor.execute.await_count == 2
    assert "secret SQL" not in json.dumps(result)


@pytest.mark.asyncio
async def test_1105_before_submission_is_a_failure(backend):
    _, cursor, _, runtime = backend
    cursor.execute.side_effect = OperationalError(1105, "secret SQL")
    result = await runtime.execute({"action": "insert", "sql": INSERT})
    assert result["execution_status"] == "failed"
    assert result["error_code"] == "DORIS_ERROR_1105"
    assert cursor.execute.await_count == 1
    assert cursor.execute.call_args.args[0].startswith("SHOW CREATE TABLE")
    assert "secret SQL" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", ["write", "admin"])
@pytest.mark.parametrize("cancelled", [False, True])
async def test_mutation_cleanup_discards_owner_lease_without_quit_drain(
    backend, domain, cancelled
):
    from doris_mcp_server.utils.admin_runtime import AdminRuntime
    from test.tools.test_admin_domain import context as admin_context
    from test.tools.test_admin_domain import request

    manager, cursor, _, runtime = backend
    loop = asyncio.get_running_loop()
    raw = aiomysql.Connection(loop=loop)
    writer = Mock()
    writer.drain = AsyncMock(side_effect=ConnectionResetError("reset during QUIT"))
    raw._writer = writer
    raw.cursor = AsyncMock(return_value=cursor)
    cursor.description = None
    raw.ensure_closed = AsyncMock(wraps=raw.ensure_closed)
    pool = aiomysql.Pool(minsize=0, maxsize=1, echo=False, pool_recycle=-1, loop=loop)
    pool._used.add(raw)  # An acquired lease, without connecting to a database.
    connection = DorisConnection(raw, "cleanup", owner_pool=pool)
    manager.get_connection.return_value = connection
    owner_manager = DorisConnectionManager(manager.config)
    manager.release_connection = AsyncMock(wraps=owner_manager.release_connection)
    token = None
    try:
        if domain == "admin":
            manager.config.administration.enabled = True
            manager.get_database_config_for_auth_context.return_value = (
                manager.config.database
            )
            token = set_current_auth_context(admin_context())
            runtime = AdminRuntime(manager)
            call = runtime.execute("manage_roles", request("create_role"))
            cursor.execute.side_effect = asyncio.CancelledError() if cancelled else None
        else:
            call = runtime.execute({"action": "insert", "sql": INSERT})
            cursor.execute.side_effect = (
                [None, asyncio.CancelledError()] if cancelled else None
            )
        if cancelled:
            with pytest.raises(asyncio.CancelledError):
                await call
        else:
            assert (await call)["execution_status"] == "succeeded"
        assert raw.closed
        assert pool.size == 0 and not pool._used and not pool._free
        manager.release_connection.assert_awaited_once()
        writer.drain.assert_not_awaited()
        raw.ensure_closed.assert_not_awaited()
    finally:
        if token is not None:
            reset_auth_context(token)
        raw.close()
        if raw in pool._used:
            pool.release(raw)
        pool.close()
        await pool.wait_closed()


@pytest.mark.asyncio
async def test_cancellation_has_no_retry(backend):
    _, cursor, connection, runtime = backend
    cursor.execute.side_effect = [None, asyncio.CancelledError()]
    with pytest.raises(asyncio.CancelledError):
        await runtime.execute({"action": "insert", "sql": INSERT})
    assert cursor.execute.await_count == 2
    connection.connection.close.assert_called_once()
    backend[0].release_connection.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ddl,sql",
    [
        (DDL.replace("UNIQUE KEY", "DUPLICATE KEY"), UPDATE),
        (DDL, "UPDATE internal.db.t SET id=2 WHERE id=1"),
        ("CREATE VIEW internal.db.t AS SELECT * FROM external.db.t", INSERT),
    ],
)
async def test_metadata_checks_precede_mutation(backend, ddl, sql):
    _, cursor, _, runtime = backend
    cursor.fetchone.return_value = {"Create Table": ddl}
    result = await runtime.execute(
        {"action": "insert" if sql == INSERT else "update", "sql": sql}
    )
    assert result["execution_status"] == "failed"
    assert cursor.execute.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["hierarchical", "flat"])
async def test_write_discovery_dispatch_and_no_implicit_permissions(backend, mode):
    manager, cursor, _, _ = backend
    manager.config.writing.enabled = False
    tools = DorisToolsManager(manager, tool_exposure_mode=mode)
    assert not any(t.name.startswith("doris_write") for t in await tools.list_tools())
    with pytest.raises(ToolNotFoundError):
        await tools.call_tool("doris_write", {})
    manager.config.writing.enabled = True
    tools = DorisToolsManager(manager, tool_exposure_mode=mode)
    token = set_current_auth_context(context(("insert",)))
    try:
        if mode == "hierarchical":
            manifest = json.loads(await tools.call_tool("doris_write", {}))
            assert manifest["children"][0]["input_schema"]["properties"]["action"][
                "enum"
            ] == ["insert"]
            result = json.loads(
                await tools.call_tool(
                    "doris_write",
                    {
                        "child_tool": "execute_write",
                        "manifest_version": manifest["manifest_version"],
                        "arguments": {"action": "insert", "sql": INSERT},
                    },
                )
            )
        else:
            result = json.loads(
                await tools.call_tool(
                    "doris_write_execute_write", {"action": "insert", "sql": INSERT}
                )
            )
        assert result["data"]["execution_status"] == "succeeded"
    finally:
        reset_auth_context(token)
    for method in ("token", "jwt", "external_oauth"):
        assert allowed_actions(context(("insert",), method)) == ("insert",)
    denied = AuthContext(
        user_id="admin",
        auth_method="token",
        permissions=["admin", "write_data", "child:call:doris_admin:manage_privileges"],
    )
    assert not allowed_actions(denied)
    with pytest.raises(WriteError, match="FORBIDDEN"):
        await DorisConnection(Mock(), "deny").execute_write(
            {"action": "insert", "sql": INSERT}, denied
        )


def test_both_optional_domains_fit_existing_discovery_budget():
    from doris_mcp_server.tools.admin_domain import ADMIN_DOMAIN
    from doris_mcp_server.tools.domain_catalog import (
        DORIS_DOMAIN_CATALOG,
        DorisDomainCatalog,
    )
    from doris_mcp_server.tools.domain_manifest import (
        MAX_TOP_LEVEL_TOOL_LIST_BYTES,
        DomainManifestService,
    )
    from doris_mcp_server.tools.write_domain import WRITE_DOMAIN

    catalog = DorisDomainCatalog(
        domains=(*DORIS_DOMAIN_CATALOG.domains, ADMIN_DOMAIN, WRITE_DOMAIN),
        legacy_migrations=DORIS_DOMAIN_CATALOG.legacy_migrations,
    )
    service = DomainManifestService(catalog=catalog)
    assert len(catalog.domains) == 10
    assert sum(len(d.children) for d in catalog.domains) == 62
    assert service.top_level_tool_list_bytes <= MAX_TOP_LEVEL_TOOL_LIST_BYTES


@pytest.mark.parametrize("action", ["insert", "delete", "drop_table", "truncate_table"])
def test_write_config_and_oauth_are_explicit(action):
    config = DorisConfig()
    assert not config.writing.enabled
    config.security.doris_oauth_child_tools_enabled = True
    config.security.doris_oauth_child_tool_allowlist.append("doris_write.execute_write")
    config.security.doris_oauth_write_action_allowlist = [action]
    policy = DorisOAuthScopePolicy(config.security)
    assert action_scope(action) in policy.server_allowed_scopes
    assert action_scope(action) not in policy.server_default_scopes
    assert action_scope("update") not in policy.server_allowed_scopes
    assert config.to_dict()["writing"] == {"enabled": False}


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["insert", "delete", "drop_table", "truncate_table"])
async def test_static_token_write_actions_roundtrip(tmp_path, action):
    secret = "doris-write-test-secret-long-enough-for-static-auth"
    path = tmp_path / "tokens.json"
    path.write_text(
        json.dumps(
            {
                "version": "2.0",
                "tokens": [
                    {
                        "token_id": "writer",
                        "token_digest": build_token_digest(secret, "sha256"),
                        "created_at": "2026-07-30T00:00:00Z",
                        "expires_at": None,
                        "is_active": True,
                        "write_actions": [action],
                    }
                ],
            }
        )
    )
    config = DorisConfig()
    config.security.token_file_path = str(path)
    manager = TokenManager(config)
    try:
        result = await manager.validate_token(secret)
        assert result.is_valid and result.token_info.write_actions == (action,)
        await manager.save_tokens_to_file()
        assert json.loads(path.read_text())["tokens"][0]["write_actions"] == [action]
    finally:
        manager.stop_hot_reload()
