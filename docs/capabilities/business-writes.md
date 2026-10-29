<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Direct access management
# Business writes

[English](business-writes.md) | [简体中文](business-writes.zh-CN.md)

## Scope and defaults

The default-off `doris_write` domain has one child, `execute_write`. Enabling
only this extension produces 9/56 domains/children; enabling Admin as well gives
10/62. The original 8/55 catalog stays read-only. There is no approval service,
mandatory preview, execution database, idempotency key or persistent status API.

| Action | Supported grammar |
|---|---|
| insert | INSERT VALUES (up to 1,000 value rows) and INSERT SELECT |
| update | One Unique Key table, WHERE required, literal assignments to value columns |
| create_table | Internal OLAP Unique/Duplicate Key table with explicit columns and HASH distribution |
| delete | One internal OLAP base table; WHERE required; no joins or subqueries |
| drop_table | DROP TABLE on one internal OLAP base table; no IF EXISTS or FORCE |
| truncate_table | TRUNCATE TABLE on one whole internal OLAP base table |

Fully qualify physical tables as `internal.database.table`. INSERT SELECT supports
internal cross-database sources, projection, filtering, joins, aggregates,
subqueries and non-recursive CTEs, with bounded ASTs and an allowlist of built-in
scalar/aggregate functions. Unsupported functions/grammar fail closed. Physical
sources, including SEMI/ANTI JOIN right-hand tables, are resolved separately from
CTE aliases and rechecked after SQL generation. Existing targets and sources
must be OLAP base tables; views and external engines are rejected after metadata
inspection on the same connection. SELECT runs inside Doris, not in the client.

INSERT OVERWRITE, CTAS, CREATE LIKE, partition clauses, external resources,
ALTER TABLE, multi-table deletion, DROP modifiers, management SQL, multiple statements and
cross-call transactions are excluded. CREATE supports scalar column types and
replication_num, enable_unique_key_merge_on_write, compression and storage_format
properties. The live discovered schema and parser are authoritative.

INSERT includes Unique Key upsert, not an append-only promise. WHERE does not
impose an affected-row ceiling. Requests are at most 64 KiB with a 30-second call
timeout. No forced pre-count or source-query preview is performed.

## Enablement and authorization

Set `MCP_WRITE_DOMAIN_ENABLED=true` (or `writing.enabled: true` in configuration).
In a protected existing static-token record, explicitly add:

```json
{"write_actions": ["insert", "update", "create_table"]}
```

The example above grants only the original three actions. DELETE, DROP TABLE and
TRUNCATE TABLE each require a separate explicit `delete`, `drop_table` or
`truncate_table` grant; existing tokens gain none of them automatically.
DROP/TRUNCATE affect the entire table and provide no automatic recovery. Metadata
inspection requires the table to exist, including for dry_run.

Missing actions mean no write permission. Ordinary/admin permissions do not imply
write actions. JWT/external OAuth need `child:call:doris_write:execute_write`
and `action:call:doris_write:<action>`. Doris OAuth additionally needs its child
switch, `doris_write.execute_write` in `DORIS_OAUTH_CHILD_TOOL_ALLOWLIST` and
exact actions in `DORIS_OAUTH_WRITE_ACTION_ALLOWLIST`. These scopes must be explicitly
requested and are not included in default grants.

All reads/writes use the request's existing Doris identity and route. Native RBAC
checks source read and target write rights; MCP grants do not replace them. No
root fallback, secondary object ACL system or automatic credential switching exists.

## Calls and results

Discover `doris_write`, then use its manifest and `execute_write` child:

```json
{
  "child_tool": "execute_write",
  "manifest_version": "<discovered-version>",
  "arguments": {
    "action": "insert",
    "sql": "INSERT INTO internal.example.target SELECT id, SUM(amount) FROM internal.example.source GROUP BY id",
    "dry_run": false
  }
}
```

Flat mode uses `doris_write_execute_write`. dry_run is optional: it validates
syntax, authorization and required table metadata without running the source
query or submitting a write. It does not certify native DML/DDL privileges or later
execution. No approval or second confirmation is introduced.

Each explicit call is a new execution. Writes are never automatically retried.
Results distinguish succeeded, failed, dry_run and outcome_unknown. Only known
authorization/syntax/object-resolution rejections establish failure after submission;
generic server errors such as 1105 remain outcome_unknown, except narrowly
recognized complete native permission-denial messages. Raw diagnostics stay private.
Before submission,
metadata or connection errors are failures. An uncertain response is not proof of rollback; use read-only inspection/Doris information
before deciding whether to submit anything again. A request_id correlates audit
logs only. There is no cross-request deduplication or exactly-once guarantee.

Doris OK transaction data is decoded when present: VISIBLE reports publication;
COMMITTED reports commit with data_visibility=not_confirmed. Unrecognized nonempty
transaction messages are outcome_unknown. affected_rows and transaction_id are
returned only when available, and verification_status remains not_checked until
an independent read. SQL text, business values and credentials are not written to
the execution audit or returned in driver errors. After use, the socket is closed
directly and its captured pool lease is released, without waiting for COM_QUIT.
Length-coded OK info and raw transaction text are both decoded, including a length
byte equal to the opening brace.

## Verification and migration

Both transports share the same authorization/runtime; old read-only tokens remain
unable to write. No new dependency is required. There is no automatic version
probe or claim of Cloud certification. Isolated local acceptance uses official
Doris 3.1.3 FE/BE (storage-compute coupled), not production or STG:

```bash
DORIS_WRITE_E2E=1 uv run pytest -q --no-cov -W error test/integration/test_write_doris.py
```

The opt-in test includes DELETE/TRUNCATE/DROP with dry runs and independent read-back
over hierarchical/flat HTTP, plus native Doris permission denials for all three
actions despite explicit MCP grants. This suite passed against isolated official
Doris 3.1.3 FE/BE; this does not certify Cloud mode.
The test also covers hierarchical/flat HTTP, create/insert/update/read-back, cross-database
INSERT SELECT with CTE/aggregation/join, upsert, dry run and native denial on both
source and target. Unit tests cover statement restrictions, exact scopes, legacy
key rejection, cancellation/uncertain results, no automatic retry and OK-packet
publication decoding. Production enabling remains a separate deployment choice.
For the simultaneous Admin breaking change see [administration migration](administration.md#migrating-from-durable-administration).
