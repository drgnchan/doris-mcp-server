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
"""Opt-in writes on disposable loopback Doris only; never use a shared cluster."""

import json
import os
import secrets
from contextlib import suppress

import pymysql
import pytest

from doris_mcp_server.utils.secret_policy import build_token_digest
from test.integration.test_real_doris_transports import (
    RealDorisSettings,
    _authenticated_http_client,
    _server_environment,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("DORIS_WRITE_E2E") != "1",
        reason="disposable local Doris opt-in required",
    ),
]


@pytest.mark.asyncio
async def test_business_writes_and_native_permissions_over_http(tmp_path):
    port = int(os.getenv("DORIS_WRITE_TEST_PORT", "19030"))
    suffix = secrets.token_hex(5)
    source_db, target_db, username = (
        f"mcp_write_{suffix}_{s}" for s in ("src", "dst", "user")
    )
    bearer, password = secrets.token_urlsafe(48), secrets.token_urlsafe(24)
    connection = pymysql.connect(
        host="127.0.0.1", port=port, user="root", password="", autocommit=True
    )
    token_file = tmp_path / "tokens.json"
    record = {
        "token_id": "write-test",
        "token_digest": build_token_digest(bearer, "sha256"),
        "created_at": "2026-07-30T00:00:00Z",
        "expires_at": None,
        "is_active": True,
        "write_actions": ["insert", "update", "create_table"],
        "database_config": {
            "host": "127.0.0.1",
            "port": port,
            "user": "root",
            "password": "",
            "database": target_db,
        },
    }

    def save_token():
        token_file.write_text(json.dumps({"version": "2.0", "tokens": [record]}))
        token_file.chmod(0o600)

    settings = RealDorisSettings("127.0.0.1", port, "root", "", target_db)
    environment = _server_environment(settings, user="root", password="")
    environment.update(
        ENABLE_TOKEN_AUTH="true",
        TOKEN_FILE_PATH=str(token_file),
        MCP_WRITE_DOMAIN_ENABLED="true",
        MCP_ADMIN_DOMAIN_ENABLED="false",
    )

    def query(sql):
        with connection.cursor() as cursor:
            cursor.execute(sql)
            return cursor.fetchall()

    try:
        query(f"CREATE DATABASE {source_db}")
        query(f"CREATE DATABASE {target_db}")
        save_token()
        async with _authenticated_http_client(
            environment, bearer_token=bearer
        ) as client:
            discovery = await client.call_tool("doris_write", {})
            manifest = json.loads(discovery.content[0].text)
            assert [c["name"] for c in manifest["children"]] == ["execute_write"]

            async def write(action, sql, **kwargs):
                raw = await client.call_tool(
                    "doris_write",
                    {
                        "child_tool": "execute_write",
                        "manifest_version": manifest["manifest_version"],
                        "arguments": {"action": action, "sql": sql, **kwargs},
                    },
                )
                payload = json.loads(raw.content[0].text)
                assert payload["mode"] == "result", payload
                data = payload["data"]
                assert data["execution_status"] == (
                    "dry_run" if kwargs.get("dry_run") else "succeeded"
                ), data
                return data

            for db, model in [(source_db, "DUPLICATE"), (target_db, "UNIQUE")]:
                await write(
                    "create_table",
                    f"CREATE TABLE internal.{db}.items (id BIGINT NOT NULL, v INT) ENGINE=OLAP {model} KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES ('replication_num'='1')",
                )
            inserted = await write(
                "insert",
                f"INSERT INTO internal.{source_db}.items VALUES (1, 10), (1, 20), (2, 30)",
            )
            assert inserted["affected_rows"] == 3
            await write(
                "insert",
                f"INSERT INTO internal.{target_db}.items WITH s AS (SELECT id, SUM(v) AS v FROM internal.{source_db}.items WHERE id > 0 GROUP BY id) SELECT * FROM s",
            )
            assert query(f"SELECT id,v FROM {target_db}.items ORDER BY id") == (
                (1, 30),
                (2, 30),
            )
            await write(
                "insert",
                f"INSERT INTO internal.{target_db}.items SELECT s.id, s.v FROM internal.{target_db}.items s JOIN (SELECT DISTINCT id FROM internal.{source_db}.items) k ON s.id=k.id WHERE s.id=2",
            )
            await write(
                "update", f"UPDATE internal.{target_db}.items SET v=40 WHERE id=1"
            )
            await write(
                "insert", f"INSERT INTO internal.{target_db}.items VALUES (1, 50)"
            )
            await write(
                "update",
                f"UPDATE internal.{target_db}.items SET v=99 WHERE id=1",
                dry_run=True,
            )
            assert query(f"SELECT id,v FROM {target_db}.items ORDER BY id") == (
                (1, 50),
                (2, 30),
            )
            assert not list(tmp_path.glob("*.db*"))

        environment["MCP_TOOL_EXPOSURE_MODE"] = "flat"
        async with _authenticated_http_client(
            environment, bearer_token=bearer
        ) as client:
            raw = await client.call_tool(
                "doris_write_execute_write",
                {
                    "action": "insert",
                    "sql": f"INSERT INTO internal.{target_db}.items VALUES (3, 60)",
                },
            )
            assert (
                json.loads(raw.content[0].text)["data"]["execution_status"]
                == "succeeded"
            )
        with connection.cursor() as cursor:
            cursor.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (username, password))
        # Permit metadata visibility, but omit source SELECT; no alternate identity.
        query(f"GRANT LOAD_PRIV ON internal.{source_db}.items TO '{username}'@'%'")
        query(
            f"GRANT LOAD_PRIV,SELECT_PRIV ON internal.{target_db}.items TO '{username}'@'%'"
        )
        record["database_config"].update(user=username, password=password)
        save_token()
        sql = f"INSERT INTO internal.{target_db}.items SELECT id,v FROM internal.{source_db}.items"
        for missing in ("source_read", "target_write"):
            if missing == "target_write":
                query(
                    f"GRANT SELECT_PRIV ON internal.{source_db}.items TO '{username}'@'%'"
                )
                query(
                    f"REVOKE LOAD_PRIV ON internal.{target_db}.items FROM '{username}'@'%'"
                )
            async with _authenticated_http_client(
                environment, bearer_token=bearer
            ) as client:
                raw = await client.call_tool(
                    "doris_write_execute_write", {"action": "insert", "sql": sql}
                )
                data = json.loads(raw.content[0].text)["data"]
                assert data["execution_status"] == "failed", (missing, data)
                assert data["error_code"].startswith("DORIS_ERROR_"), data
            assert query(f"SELECT id,v FROM {target_db}.items ORDER BY id") == (
                (1, 50),
                (2, 30),
                (3, 60),
            )
        # New actions require explicit grants even for the existing write token.
        record["write_actions"].extend(["delete", "drop_table", "truncate_table"])
        save_token()
        # MCP action grants cannot bypass native Doris permissions. This user
        # retains SELECT only on the target after the denial checks above.
        async with _authenticated_http_client(environment, bearer_token=bearer) as client:
            for action, sql in (
                ("delete", f"DELETE FROM internal.{target_db}.items WHERE id=1"),
                ("truncate_table", f"TRUNCATE TABLE internal.{target_db}.items"),
                ("drop_table", f"DROP TABLE internal.{target_db}.items"),
            ):
                raw = await client.call_tool(
                    "doris_write_execute_write", {"action": action, "sql": sql}
                )
                data = json.loads(raw.content[0].text)["data"]
                assert data["execution_status"] == "failed", (action, data)
                assert data["error_code"].startswith("DORIS_ERROR_"), data
                assert query(f"SELECT id,v FROM {target_db}.items ORDER BY id") == (
                    (1, 50), (2, 30), (3, 60)
                )
        record["database_config"].update(user="root", password="")
        save_token()
        for mode in ("hierarchical", "flat"):
            environment["MCP_TOOL_EXPOSURE_MODE"] = mode
            async with _authenticated_http_client(environment, bearer_token=bearer) as client:
                if mode == "hierarchical":
                    raw = await client.call_tool("doris_write", {})
                    manifest = json.loads(raw.content[0].text)

                async def mutate(action, sql, dry_run=False):
                    arguments = {"action": action, "sql": sql, "dry_run": dry_run}
                    tool = "doris_write_execute_write"
                    if mode == "hierarchical":
                        tool = "doris_write"
                        arguments = {
                            "child_tool": "execute_write",
                            "manifest_version": manifest["manifest_version"],
                            "arguments": arguments,
                        }
                    raw = await client.call_tool(tool, arguments)
                    data = json.loads(raw.content[0].text)["data"]
                    assert data["execution_status"] == ("dry_run" if dry_run else "succeeded"), data

                table = f"internal.{target_db}.items"
                for action, sql in (
                    ("delete", f"DELETE FROM {table} WHERE id=1"),
                    ("truncate_table", f"TRUNCATE TABLE {table}"),
                    ("drop_table", f"DROP TABLE {table}"),
                ):
                    await mutate(action, sql, dry_run=True)
                    assert query(f"SELECT COUNT(*) FROM {table}")[0][0] == 3
                await mutate("delete", f"DELETE FROM {table} WHERE id=1")
                assert query(f"SELECT id FROM {table} ORDER BY id") == ((2,), (3,))
                await mutate("truncate_table", f"TRUNCATE TABLE {table}")
                assert query(f"SELECT COUNT(*) FROM {table}") == ((0,),)
                await mutate("drop_table", f"DROP TABLE {table}")
                assert query(f"SHOW TABLES FROM {target_db}") == ()
                if mode == "hierarchical":
                    query(f"CREATE TABLE {table} LIKE internal.{source_db}.items")
                    query(f"INSERT INTO {table} VALUES (1,50),(2,30),(3,60)")
    finally:
        for sql in (
            f"DROP USER IF EXISTS '{username}'@'%'",
            f"DROP DATABASE IF EXISTS {target_db}",
            f"DROP DATABASE IF EXISTS {source_db}",
        ):
            with suppress(pymysql.MySQLError):
                query(sql)
        connection.close()
