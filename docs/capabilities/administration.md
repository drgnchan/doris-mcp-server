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

[English](administration.md) | [简体中文](administration.zh-CN.md)

## Scope and defaults

The optional `doris_admin` domain adds seven children (9 domains / 62 children
when enabled). The default remains 8/55 read-only. No approval service, confirmation
token, mandatory preview, arbitrary SQL, multi-statement job or automatic retry is
introduced. Every management call uses the authenticated request's existing Doris
route. SQL success is not a proof of effective access or terminated sessions.

All 14 operation families are implemented: object grant/revoke, role membership
grant/revoke, create/drop/alter role, create/drop/alter user, set password, set
property, and create/drop row policy. All ten privilege names and the data-object,
Resource, Workload Group, Compute Group and Storage Vault scopes are modeled.
Doris must support the requested combination. Metadata queries include SHOW GRANTS,
SHOW ALL GRANTS, SHOW ROLES, SHOW PRIVILEGES, SHOW PROPERTY, SHOW ALL PROPERTIES and
SHOW ROW POLICY. Column scope supports SELECT only.

## Enablement and authorization

Configure one active worker and a private durable local volume:

```yaml
administration:
  enabled: true
  state_path: /var/lib/doris-mcp/executions.db
  password_file: /run/secrets/doris-management.json
```

Equivalent environment:

```dotenv
MCP_ADMIN_DOMAIN_ENABLED=true
MCP_ADMIN_STATE_PATH=/var/lib/doris-mcp/executions.db
MCP_ADMIN_PASSWORD_FILE=/run/secrets/doris-management.json
```

The password file is optional for operations that do not set a password. The old
`MCP_ADMIN_REQUIRE_CONFIRMATION` setting no longer configures an approval workflow.
Do not enable management on a shared service account unless every delegated caller
is trusted for its full backend authority. Ordinary tokens do not inherit these
capabilities. Built-in identities and the current execution identity are protected;
use a different, deliberately configured maintenance identity for account changes.
Unauthenticated HTTP and stdio without explicit authenticated identity cannot write.

For a static token, manually add an exact `admin_actions` array to its existing,
owner-only token-file record, for example `["create_role", "alter_role", "show_roles", "get_execution_status"]`.
Token authentication derives the exact child/action permissions. Existing records
without this field keep their existing read behavior. The HTTP token-creation API
does not silently issue administration rights.

JWT/external OAuth require both `child:call:doris_admin:<child>` and
`action:call:doris_admin:<action>`. Configure the issuer/allowed scopes explicitly.
Doris OAuth additionally requires the existing child-tools switch, explicit
`doris_admin.<child>` entries in `DORIS_OAUTH_CHILD_TOOL_ALLOWLIST` and exact action
names in `DORIS_OAUTH_ADMIN_ACTION_ALLOWLIST`. Admin scopes are not automatically
included in default grants: the client must request them explicitly.

CREATE USER with a default role additionally requires grant_roles. ALTER USER
password changes require set_password. GRANT TO ROLE also requires create_role,
even for an existing role, because a concurrent deletion can trigger implicit
creation. Server rules do not replace Doris RBAC; there is no root fallback.

## Calls and results

Discover `doris_admin` first; use its current manifest version and authorized schema.
Flat mode exposes the same handlers as `doris_admin_<child>`.

```json
{
  "child_tool": "manage_roles",
  "manifest_version": "<discovered-version>",
  "arguments": {
    "action": "create_role",
    "role": "example_analyst",
    "comment": "Analyst access",
    "idempotency_key": "<unique-key-saved-before-first-send>"
  }
}
```

`dry_run=true` only compiles/validates the request and returns redacted SQL. It
neither reserves the key nor promises later backend success. Otherwise the call
executes directly; use the same key on response loss. `get_execution_status` accepts
`action=get_execution_status` and the key, and only returns the same principal/route's record.

Results distinguish `succeeded`, `failed`, `in_flight` and `outcome_unknown`.
A restarted in-flight record becomes unknown and is never resubmitted. Changing a
key creates a new request; this is not end-to-end exactly-once. Records are retained
until explicit offline maintenance; unknown records must not be removed to retry.
No distributed/NFS SQLite deployment is supported. A second active writer fails.

Queries are bounded to 1,000 rows / 1 MiB; calls have a 30-second timeout. Results
report `verification_status=not_checked`; use inspect_access for further evidence.
Revoking a binding does not remove broader/role access. SET PROPERTY affects every
host identity with the same username. ALTER USER accepts one legal property group
per call. Row policies accept a bounded Doris-expression AST, not arbitrary SQL,
subqueries, UDFs, comments or side-effect functions. Discovery is the schema authority.

## Passwords

A trusted operator supplies a mode-0600 JSON file outside the repository. Example
structure only (the placeholder is not a deployable password):

```json
{
  "example@v1": {
    "principal": "token::example-token-id",
    "user": {"name": "example_user", "host": "%"},
    "version": "v1",
    "password": "<provided-out-of-band>"
  }
}
```

Set `password_ref=example@v1` with that exact user identity. Reference aliases are
immutable: use a new version when the value changes. MCP cannot read arbitrary paths,
generate/distribute passwords or return password values/hashes. It does not test
password login or revoke all existing sessions. Management sockets are closed after
use; external tokens and existing connections require their own lifecycle management.

## Verification and limits

The opt-in test `test/integration/test_admin_doris.py` uses loopback-only disposable
Doris, real authenticated HTTP, hierarchical/flat exposure, all 14 operations,
all privilege types, column/table/database/catalog/global scopes, both row-policy
modes, password login, native permission denial and old-token denial. Run only on
an isolated local FE/BE with port 19030:

```bash
DORIS_ADMIN_E2E=1 uv run pytest -q --no-cov -W error test/integration/test_admin_doris.py
```

Local evidence: official `apache/doris:fe-3.1.3` and `be-3.1.3` report
`doris-3.1.3-rc01-be1b1227a8`, **storage-compute coupled**, not Cloud. Cloud compute
and storage-vault statements are implemented but not certified by this local run.
The read-only feature matrix is not reused as write certification. Other patches,
external-resource combinations and account-domain matching need environment-specific
verification; unknown/unsupported backend semantics are not reported as success.
