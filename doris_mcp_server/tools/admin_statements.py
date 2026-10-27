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

"""Closed, structured access-management language; no caller SQL statements."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from jsonschema import Draft202012Validator

PRIVILEGES = (
    "SELECT_PRIV",
    "SHOW_VIEW_PRIV",
    "LOAD_PRIV",
    "CREATE_PRIV",
    "ALTER_PRIV",
    "DROP_PRIV",
    "USAGE_PRIV",
    "GRANT_PRIV",
    "ADMIN_PRIV",
    "NODE_PRIV",
)
CHILD_ACTIONS = {
    "manage_privileges": ("grant_privileges", "revoke_privileges"),
    "manage_role_membership": ("grant_roles", "revoke_roles"),
    "manage_roles": ("create_role", "drop_role", "alter_role"),
    "manage_users": (
        "create_user",
        "drop_user",
        "alter_user",
        "set_password",
        "set_property",
    ),
    "manage_row_policies": ("create_row_policy", "drop_row_policy"),
    "inspect_access": (
        "show_grants",
        "show_all_grants",
        "show_roles",
        "show_privileges",
        "show_property",
        "show_all_properties",
        "show_row_policy",
    ),
    "get_execution_status": ("get_execution_status",),
}
READ_ACTIONS = frozenset(CHILD_ACTIONS["inspect_access"] + ("get_execution_status",))
BIND_MARKER = "__DORIS_MCP_BIND_VALUE__"


class AdminError(ValueError):
    """Stable, value-free errors safe for logs and MCP output."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def text(max_length: int = 256) -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": max_length}


def enum(*values: str) -> dict[str, Any]:
    return {"type": "string", "enum": list(values)}


def obj(properties: dict[str, Any], *required: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


def array(items: dict[str, Any], maximum: int = 64) -> dict[str, Any]:
    return {
        "type": "array",
        "items": items,
        "minItems": 1,
        "maxItems": maximum,
        "uniqueItems": True,
    }


USER = obj(
    {"name": text(), "host": text(), "domain_host": {"type": "boolean"}}, "name", "host"
)
GRANTEE = obj(
    {
        "type": enum("user", "role"),
        "name": text(),
        "host": text(),
        "domain_host": {"type": "boolean"},
    },
    "type",
    "name",
)
OBJECT = obj(
    {
        "type": enum(
            "data_object",
            "resource",
            "workload_group",
            "compute_group",
            "storage_vault",
        ),
        "scope": enum("global", "catalog", "database", "table", "column"),
        "catalog": text(),
        "database": text(),
        "table": text(),
        "columns": array(text()),
        "name": text(),
        "all_objects": {"type": "boolean"},
    },
    "type",
)
POLICY_TARGET = obj({"type": enum("user", "role"), "name": text()}, "type", "name")
TABLE = obj({"database": text(), "table": text()}, "database", "table")
PASSWORD_POLICY = obj(
    {
        "history": {
            "oneOf": [{"type": "integer", "minimum": 0, "maximum": 24}, enum("DEFAULT")]
        },
        "expire": {
            "oneOf": [
                enum("DEFAULT", "NEVER"),
                obj(
                    {
                        "interval": {"type": "integer", "minimum": 1},
                        "unit": enum("DAY", "HOUR", "SECOND"),
                    },
                    "interval",
                    "unit",
                ),
            ]
        },
        "failed_login_attempts": {"type": "integer", "minimum": 0, "maximum": 32767},
        "lock_time": {
            "oneOf": [
                enum("UNBOUNDED"),
                obj(
                    {
                        "interval": {"type": "integer", "minimum": 0},
                        "unit": enum("DAY", "HOUR", "SECOND"),
                    },
                    "interval",
                    "unit",
                ),
            ]
        },
    }
)
# Doris user property names are deliberately finite. This is not a generic SET.
PROPERTIES = obj(
    {
        "max_user_connections": {"type": "integer", "minimum": 1, "maximum": 10000},
        "max_query_instances": {"type": "integer", "minimum": -1},
        "cpu_resource_limit": {"type": "integer", "minimum": -1},
        "exec_mem_limit": {"type": "integer", "minimum": -1},
        "query_timeout": {"type": "integer", "minimum": 1},
        "insert_timeout": {"type": "integer", "minimum": 1},
        "resource_tags.location": {"type": "string", "maxLength": 1024},
        "default_workload_group": text(),
        "default_compute_group": text(),
        "sql_block_rules": {"type": "string", "maxLength": 1024},
    }
)
PROPERTIES["minProperties"] = 1

# One source for action fields, public schemas and strict runtime validation.
ACTION_FIELDS: dict[str, tuple[dict[str, Any], tuple[str, ...]]] = {
    "grant_privileges": (
        {
            "grantee": GRANTEE,
            "privileges": array(enum(*PRIVILEGES), 10),
            "object": OBJECT,
        },
        ("grantee", "privileges", "object"),
    ),
    "revoke_privileges": (
        {
            "grantee": GRANTEE,
            "privileges": array(enum(*PRIVILEGES), 10),
            "object": OBJECT,
        },
        ("grantee", "privileges", "object"),
    ),
    "grant_roles": ({"user": USER, "roles": array(text())}, ("user", "roles")),
    "revoke_roles": ({"user": USER, "roles": array(text())}, ("user", "roles")),
    "create_role": ({"role": text(), "comment": text(1024)}, ("role",)),
    "drop_role": ({"role": text()}, ("role",)),
    "alter_role": ({"role": text(), "comment": text(1024)}, ("role", "comment")),
    "create_user": (
        {
            "user": USER,
            "password_ref": text(),
            "default_role": text(),
            "password_policy": PASSWORD_POLICY,
            "comment": text(1024),
        },
        ("user", "password_ref"),
    ),
    "drop_user": ({"user": USER}, ("user",)),
    "alter_user": (
        {
            "user": USER,
            "password_ref": text(),
            "password_policy": PASSWORD_POLICY,
            "unlock": {"type": "boolean", "const": True},
            "comment": text(1024),
        },
        ("user",),
    ),
    "set_password": ({"user": USER, "password_ref": text()}, ("user", "password_ref")),
    "set_property": (
        {"username": text(), "properties": PROPERTIES},
        ("username", "properties"),
    ),
    "create_row_policy": (
        {
            "policy": text(),
            "table": TABLE,
            "target": POLICY_TARGET,
            "mode": enum("RESTRICTIVE", "PERMISSIVE"),
            "predicate": text(4096),
        },
        ("policy", "table", "target", "mode", "predicate"),
    ),
    "drop_row_policy": (
        {"policy": text(), "table": TABLE, "target": POLICY_TARGET},
        ("policy", "table"),
    ),
    "show_grants": ({"user": USER}, ()),
    "show_all_grants": ({}, ()),
    "show_roles": ({}, ()),
    "show_privileges": ({}, ()),
    "show_property": ({"username": text()}, ()),
    "show_all_properties": ({}, ()),
    "show_row_policy": ({"target": POLICY_TARGET}, ()),
    "get_execution_status": ({"idempotency_key": text(128)}, ("idempotency_key",)),
}


def action_scope(action: str) -> str:
    return f"action:call:doris_admin:{action}"


def action_schema(action: str) -> dict[str, Any]:
    fields, required = ACTION_FIELDS[action]
    properties = {"action": {"const": action}, **fields}
    if action not in READ_ACTIONS:
        properties.update(
            {
                "dry_run": {"type": "boolean", "default": False},
                "idempotency_key": text(128),
            }
        )
    return obj(properties, "action", *required)


def child_schema(child: str, actions: tuple[str, ...] | None = None) -> dict[str, Any]:
    # Shared properties keep the user-management schema below the 4 KiB budget.
    selected = actions or CHILD_ACTIONS[child]
    properties: dict[str, Any] = {}
    branches = []
    for action in selected:
        schema = action_schema(action)
        properties.update(schema["properties"])
        branches.append(
            {
                "properties": {"action": {"const": action}},
                "required": schema["required"],
            }
        )
    properties["action"] = enum(*selected)
    result = obj(properties, "action")
    result["oneOf"] = branches
    return result


@lru_cache(maxsize=32)
def _validator(action: str) -> Draft202012Validator:
    return Draft202012Validator(action_schema(action))


def validate_request(child: str, arguments: dict[str, Any]) -> str:
    action = arguments.get("action")
    if not isinstance(action, str) or action not in CHILD_ACTIONS.get(child, ()):
        raise AdminError("ADMIN_ACTION_INVALID")
    if not _validator(action).is_valid(arguments):
        raise AdminError("ADMIN_ARGUMENT_INVALID")
    if (
        action not in READ_ACTIONS
        and not arguments.get("dry_run")
        and not arguments.get("idempotency_key")
    ):
        raise AdminError("ADMIN_IDEMPOTENCY_KEY_REQUIRED")
    return action


def literal(value: str) -> str:
    # Disallow backslashes so quoting works under both MySQL sql_mode settings.
    if any(ord(c) < 32 for c in value) or "\\" in value or BIND_MARKER in value:
        raise AdminError("ADMIN_LITERAL_INVALID")
    return "'" + value.replace("'", "''") + "'"


def identifier(value: str) -> str:
    if (
        not value
        or value in {"*", "%"}
        or any(ord(c) < 32 for c in value)
        or "\\" in value
    ):
        raise AdminError("ADMIN_IDENTIFIER_INVALID")
    return "`" + value.replace("`", "``") + "`"


def user_identity(user: dict[str, Any]) -> str:
    host = literal(user["host"])
    if user.get("domain_host"):
        host = f"[{host}]"
    return f"{literal(user['name'])}@{host}"


def grantee_sql(target: dict[str, Any]) -> str:
    if target["type"] == "role":
        if "host" in target or "domain_host" in target:
            raise AdminError("ADMIN_ROLE_IDENTITY_INVALID")
        return "ROLE " + literal(target["name"])
    if "host" not in target:
        raise AdminError("ADMIN_USER_HOST_REQUIRED")
    return user_identity(target)


def policy_target(target: dict[str, Any]) -> str:
    return ("ROLE " if target["type"] == "role" else "") + identifier(target["name"])


def object_sql(value: dict[str, Any], privileges: list[str]) -> tuple[str, str]:
    kind = value["type"]
    privs = ", ".join(privileges)
    if kind != "data_object":
        if set(value) - {"type", "name", "all_objects"}:
            raise AdminError("ADMIN_OBJECT_INVALID")
        if not set(privileges) <= {"USAGE_PRIV", "GRANT_PRIV"}:
            raise AdminError("ADMIN_PRIVILEGE_SCOPE_INVALID")
        all_objects = value.get("all_objects", False)
        if all_objects == ("name" in value):
            raise AdminError("ADMIN_OBJECT_INVALID")
        if all_objects:
            name = (
                "*"
                if kind == "resource"
                else literal("%" if kind == "workload_group" else "*")
            )
        else:
            if value["name"] in {"*", "%"}:
                raise AdminError("ADMIN_EXPLICIT_ALL_OBJECTS_REQUIRED")
            name = literal(value["name"])
        return f"{kind.replace('_', ' ').upper()} {name}", privs
    scope = value.get("scope")
    levels = {"global": 0, "catalog": 1, "database": 2, "table": 3, "column": 3}
    if scope not in levels:
        raise AdminError("ADMIN_OBJECT_SCOPE_INVALID")
    keys = ("catalog", "database", "table")
    needed = set(keys[: levels[scope]])
    allowed = {"type", "scope"} | needed | ({"columns"} if scope == "column" else set())
    if set(value) != allowed:
        raise AdminError("ADMIN_OBJECT_INVALID")
    if "USAGE_PRIV" in privileges or (
        scope != "global" and {"ADMIN_PRIV", "NODE_PRIV"} & set(privileges)
    ):
        raise AdminError("ADMIN_PRIVILEGE_SCOPE_INVALID")
    if scope == "column":
        if privileges != ["SELECT_PRIV"]:
            raise AdminError("ADMIN_COLUMN_PRIVILEGE_INVALID")
        privs = (
            "SELECT_PRIV(" + ", ".join(identifier(c) for c in value["columns"]) + ")"
        )
    return ".".join(identifier(value[k]) if k in needed else "*" for k in keys), privs


def password_policy(value: dict[str, Any]) -> str:
    parts = []
    if "history" in value:
        parts.append(f"PASSWORD_HISTORY {value['history']}")
    if "expire" in value:
        expire = value["expire"]
        if isinstance(expire, dict):
            expire = f"INTERVAL {expire['interval']} {expire['unit']}"
        parts.append(f"PASSWORD_EXPIRE {expire}")
    if "failed_login_attempts" in value:
        parts.append(f"FAILED_LOGIN_ATTEMPTS {value['failed_login_attempts']}")
    if "lock_time" in value:
        lock = value["lock_time"]
        if isinstance(lock, dict):
            lock = f"{lock['interval']} {lock['unit']}"
        parts.append(f"PASSWORD_LOCK_TIME {lock}")
    return " ".join(parts)


@dataclass(frozen=True)
class ManagementStatement:
    action: str
    sql: str = field(repr=False)
    extra_actions: tuple[str, ...] = ()
    password_ref: str | None = field(default=None, repr=False)
    warnings: tuple[str, ...] = ()

    @property
    def read_only(self) -> bool:
        return self.action in READ_ACTIONS

    @property
    def display_sql(self) -> str:
        return self.sql.replace(BIND_MARKER, "'<redacted>'")


def compile_statement(child: str, args: dict[str, Any]) -> ManagementStatement:
    action = validate_request(child, args)
    extra: list[str] = []
    warnings: list[str] = []
    sql = ""
    if action in {"grant_privileges", "revoke_privileges"}:
        target, privs = object_sql(args["object"], args["privileges"])
        verb, prep = (
            ("GRANT", "TO") if action == "grant_privileges" else ("REVOKE", "FROM")
        )
        sql = f"{verb} {privs} ON {target} {prep} {grantee_sql(args['grantee'])}"
        if action == "grant_privileges" and args["grantee"]["type"] == "role":
            # Doris can create a missing role. A precheck is not race-free.
            extra.append("create_role")
        if action == "revoke_privileges":
            warnings.append(
                "Revoking this binding does not remove inherited or broader privileges."
            )
    elif action in {"grant_roles", "revoke_roles"}:
        verb, prep = ("GRANT", "TO") if action == "grant_roles" else ("REVOKE", "FROM")
        roles = ", ".join(literal(role) for role in args["roles"])
        sql = f"{verb} {roles} {prep} {user_identity(args['user'])}"
    elif action in {"create_role", "drop_role", "alter_role"}:
        sql = f"{action.split('_')[0].upper()} ROLE {identifier(args['role'])}"
        if "comment" in args:
            sql += " COMMENT " + literal(args["comment"])
    elif action in {"create_user", "drop_user", "alter_user", "set_password"}:
        target = user_identity(args["user"])
        if action == "set_password":
            sql = f"SET PASSWORD FOR {target} = PASSWORD({BIND_MARKER})"
        else:
            sql = f"{action.split('_')[0].upper()} USER {target}"
            if "password_ref" in args:
                sql += f" IDENTIFIED BY {BIND_MARKER}"
            if "default_role" in args:
                sql += " DEFAULT ROLE " + literal(args["default_role"])
                extra.append("grant_roles")
            if action == "alter_user":
                groups = sum(
                    k in args
                    for k in ("password_ref", "password_policy", "unlock", "comment")
                )
                if groups != 1:
                    raise AdminError("ADMIN_ALTER_USER_SINGLE_PROPERTY_GROUP_REQUIRED")
                if "password_ref" in args:
                    extra.append("set_password")
            if "password_policy" in args:
                policy = password_policy(args["password_policy"])
                if not policy:
                    raise AdminError("ADMIN_PASSWORD_POLICY_EMPTY")
                sql += " " + policy
            if args.get("unlock"):
                sql += " ACCOUNT_UNLOCK"
            if "comment" in args:
                sql += " COMMENT " + literal(args["comment"])
    elif action == "set_property":
        pairs = ", ".join(
            f"{literal(k)} = {literal(str(v))}"
            for k, v in sorted(args["properties"].items())
        )
        sql = f"SET PROPERTY FOR {literal(args['username'])} {pairs}"
        warnings.append(
            "User properties affect every host identity with this username."
        )
    elif action in {"create_row_policy", "drop_row_policy"}:
        table = args["table"]
        table_name = f"{identifier(table['database'])}.{identifier(table['table'])}"
        sql = f"{action.split('_')[0].upper()} ROW POLICY {identifier(args['policy'])} ON {table_name}"
        if action == "create_row_policy":
            from .admin_predicate import compile_predicate

            sql += f" AS {args['mode']} TO {policy_target(args['target'])} USING ({compile_predicate(args['predicate'])})"
        elif "target" in args:
            sql += " FOR " + policy_target(args["target"])
        warnings.append(
            "Row policies compose with other policies; this operation is not an effective-access proof."
        )
    elif action == "show_grants":
        sql = "SHOW GRANTS" + (
            " FOR " + user_identity(args["user"]) if "user" in args else ""
        )
    elif action == "show_property":
        sql = "SHOW PROPERTY" + (
            " FOR " + literal(args["username"]) if "username" in args else ""
        )
    elif action == "show_row_policy":
        sql = "SHOW ROW POLICY" + (
            " FOR " + policy_target(args["target"]) if "target" in args else ""
        )
    elif action in {
        "show_all_grants",
        "show_roles",
        "show_privileges",
        "show_all_properties",
    }:
        sql = action.replace("_", " ").upper()
    elif action != "get_execution_status":
        raise AdminError("ADMIN_ACTION_INVALID")
    return ManagementStatement(
        action, sql, tuple(extra), args.get("password_ref"), tuple(warnings)
    )
