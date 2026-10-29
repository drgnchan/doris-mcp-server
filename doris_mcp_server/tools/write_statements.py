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

"""Bounded, fail-closed Doris business-write grammar. No raw-SQL fallback."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from jsonschema import Draft202012Validator
from sqlglot import exp
from sqlglot.dialects.doris import Doris
from sqlglot.optimizer.scope import Scope, traverse_scope
from sqlglot.parsers.doris import DorisParser


class WriteError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


WRITE_ACTIONS = ("insert", "update", "create_table", "delete", "drop_table", "truncate_table")
WRITE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "action": {"type": "string", "enum": list(WRITE_ACTIONS)},
        "sql": {"type": "string", "minLength": 1, "maxLength": 65536},
        "dry_run": {"type": "boolean", "default": False},
    },
    "required": ["action", "sql"],
}
_VALIDATOR = Draft202012Validator(WRITE_SCHEMA)
_SCALARS = set("Identifier Literal Null Boolean Neg".split())
_EXPRESSIONS = _SCALARS | set(
    "Column Star Alias Paren Tuple And Or Not EQ NEQ GT GTE LT LTE Is Between In Like "
    "Add Sub Mul Div Mod Cast TryCast DataType DataTypeParam Lower Upper Length Abs "
    "Coalesce Nullif Trim Substring Case If Distinct Count Sum Avg Min Max Round".split()
)
_QUERIES = _EXPRESSIONS | set(
    "Select From Where Join Group Having Order Ordered Limit Offset Table TableAlias "
    "Subquery CTE With Union Intersect Except Exists".split()
)
_DDL = _SCALARS | set(
    "Create Schema Table ColumnDef DataType DataTypeParam ColumnConstraint "
    "NotNullColumnConstraint DefaultColumnConstraint Properties Property EngineProperty "
    "Var UniqueKeyProperty DuplicateKeyProperty DistributedByProperty".split()
)
_TYPES = {
    "BOOLEAN",
    "TINYINT",
    "SMALLINT",
    "INT",
    "BIGINT",
    "LARGEINT",
    "FLOAT",
    "DOUBLE",
    "DECIMAL",
    "DATE",
    "DATETIME",
    "CHAR",
    "VARCHAR",
    "TEXT",
}
_PROPERTIES = {
    "replication_num",
    "enable_unique_key_merge_on_write",
    "compression",
    "storage_format",
}


class _Parser(DorisParser):
    def _parse_command(self) -> exp.Command:
        # SQLGlot's fallback logs the original SQL; never emit caller data there.
        raise WriteError("WRITE_SQL_UNSUPPORTED")


def parse_sql(sql: str) -> exp.Expr:
    try:
        parsed = _Parser().parse(Doris().tokenize(sql), sql)
        if len(parsed) != 1 or parsed[0] is None:
            raise WriteError("WRITE_SINGLE_STATEMENT_REQUIRED")
        return parsed[0]
    except WriteError:
        raise
    except Exception:
        raise WriteError("WRITE_SQL_INVALID") from None


def _args(node: exp.Expr, allowed: set[str]) -> None:
    if any(value and name not in allowed for name, value in node.args.items()):
        raise WriteError("WRITE_SQL_UNSUPPORTED")


def _nodes(tree: exp.Expr, allowed: set[str]) -> None:
    nodes = list(tree.walk())
    if len(nodes) > 8192:
        raise WriteError("WRITE_SQL_TOO_LARGE")
    for node in nodes:
        if type(node).__name__ not in allowed or node.comments:
            raise WriteError("WRITE_SQL_UNSUPPORTED")
        depth, parent = 0, node.parent
        while parent is not None:
            depth, parent = depth + 1, parent.parent
            if depth > 64:
                raise WriteError("WRITE_SQL_TOO_DEEP")
        if isinstance(node, exp.Identifier) and (
            not node.name or any(ord(c) < 32 for c in node.name)
        ):
            raise WriteError("WRITE_IDENTIFIER_INVALID")


def _table(table: exp.Expr) -> str:
    if not isinstance(table, exp.Table):
        raise WriteError("WRITE_TABLE_REQUIRED")
    _args(table, {"this", "db", "catalog", "alias"})
    if not all(
        isinstance(table.args.get(k), exp.Identifier) for k in ("this", "db", "catalog")
    ):
        raise WriteError("WRITE_QUALIFIED_TABLE_REQUIRED")
    if any(
        not part.name or any(ord(c) < 32 for c in part.name) for part in table.parts
    ):
        raise WriteError("WRITE_IDENTIFIER_INVALID")
    if table.catalog != "internal":
        raise WriteError("WRITE_INTERNAL_CATALOG_REQUIRED")
    return ".".join(
        exp.to_identifier(n, quoted=True).sql(dialect="doris")
        for n in (table.catalog, table.db, table.name)
    )


def _query(tree: exp.Expr) -> tuple[str, ...]:
    _nodes(tree, _QUERIES)
    for select in tree.find_all(exp.Select):
        _args(
            select,
            {
                "expressions",
                "from_",
                "joins",
                "where",
                "group",
                "having",
                "order",
                "limit",
                "offset",
                "distinct",
                "with_",
            },
        )
    for cte in tree.find_all(exp.With):
        _args(cte, {"expressions"})  # No recursive CTEs.
    sources: set[str] = set()
    # Scope resolution prevents an out-of-scope CTE name from disguising a table.
    for scope in traverse_scope(tree):
        # selected_sources deliberately excludes SEMI/ANTI RHS tables. Resolve
        # every FROM/JOIN reference instead, retaining CTE/subquery scoping.
        names: set[str] = set()
        for name, _ in scope.references:
            if name in names:
                raise WriteError("WRITE_SQL_INVALID")
            names.add(name)
            source = scope.sources.get(name)
            if isinstance(source, exp.Table):
                sources.add(_table(source))
            elif not isinstance(source, Scope):
                raise WriteError("WRITE_SQL_INVALID")
    if len(sources) > 64:
        raise WriteError("WRITE_TOO_MANY_SOURCES")
    return tuple(sorted(sources))


@dataclass(frozen=True, slots=True)
class WriteStatement:
    action: str
    sql: str = field(repr=False)
    target: str
    sources: tuple[str, ...] = ()
    update_columns: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


def compile_write(arguments: dict[str, Any]) -> WriteStatement:
    if "idempotency_key" in arguments:
        raise WriteError("WRITE_IDEMPOTENCY_UNSUPPORTED")
    if not _VALIDATOR.is_valid(arguments):
        raise WriteError("WRITE_ARGUMENT_INVALID")
    sql, action = arguments["sql"], arguments["action"]
    if len(sql.encode("utf-8")) > 65536 or any(
        s in sql for s in ("\\", "\x00", "/*", "*/", "--")
    ):
        raise WriteError("WRITE_SQL_INVALID")
    try:
        tree = parse_sql(sql)
        if (
            type(tree)
            is not {
                "insert": exp.Insert,
                "update": exp.Update,
                "create_table": exp.Create,
                "delete": exp.Delete,
                "drop_table": exp.Drop,
                "truncate_table": exp.TruncateTable,
            }[action]
        ):
            raise WriteError("WRITE_ACTION_MISMATCH")
        if isinstance(tree, exp.Drop):
            _args(tree, {"tables", "kind"})
            tables = tree.args.get("tables") or []
            if tree.args.get("kind") != "TABLE" or len(tables) != 1:
                raise WriteError("WRITE_SINGLE_TABLE_REQUIRED")
            target_node = tables[0]
        elif isinstance(tree, exp.TruncateTable):
            _args(tree, {"expressions"})
            if len(tree.expressions) != 1:
                raise WriteError("WRITE_SINGLE_TABLE_REQUIRED")
            target_node = tree.expressions[0]
        else:
            target_node = tree.this.this if isinstance(tree.this, exp.Schema) else tree.this
        target = _table(target_node)
        if target_node.args.get("alias"):
            raise WriteError("WRITE_TARGET_ALIAS_UNSUPPORTED")
        sources: tuple[str, ...] = ()
        columns: tuple[str, ...] = ()
        warnings: tuple[str, ...] = ()
        if isinstance(tree, exp.Insert):
            _args(tree, {"this", "expression"})
            if isinstance(tree.this, exp.Schema):
                if not all(type(c) is exp.Identifier for c in tree.this.expressions):
                    raise WriteError("WRITE_INSERT_COLUMNS_INVALID")
            body = tree.expression
            if isinstance(body, exp.Values):
                _nodes(
                    tree, _SCALARS | {"Insert", "Schema", "Table", "Values", "Tuple"}
                )
                if not 1 <= len(body.expressions) <= 1000:
                    raise WriteError("WRITE_VALUES_LIMIT")
                for row in body.expressions:
                    if not isinstance(row, exp.Tuple) or not row.expressions:
                        raise WriteError("WRITE_VALUES_INVALID")
            elif isinstance(body, exp.Select | exp.SetOperation):
                sources = _query(body)
            else:
                raise WriteError("WRITE_INSERT_SOURCE_UNSUPPORTED")
            warnings = (
                "INSERT into a Unique Key table may update existing rows (upsert).",
            )
        elif isinstance(tree, exp.Update):
            _args(tree, {"this", "expressions", "where"})
            if tree.args.get("where") is None:
                raise WriteError("WRITE_UPDATE_WHERE_REQUIRED")
            _nodes(tree, _EXPRESSIONS | {"Update", "Table", "Where"})
            names = []
            for assignment in tree.expressions:
                if (
                    not isinstance(assignment, exp.EQ)
                    or not isinstance(assignment.this, exp.Column)
                    or assignment.this.table
                ):
                    raise WriteError("WRITE_UPDATE_ASSIGNMENT_INVALID")
                _nodes(assignment.expression, _SCALARS - {"Identifier"})
                names.append(assignment.this.name)
            if not names or len(names) != len(set(names)):
                raise WriteError("WRITE_UPDATE_ASSIGNMENT_INVALID")
            columns = tuple(names)
            warnings = ("WHERE does not impose an affected-row limit.",)
        elif isinstance(tree, exp.Delete):
            _args(tree, {"this", "where"})
            if tree.args.get("where") is None:
                raise WriteError("WRITE_DELETE_WHERE_REQUIRED")
            _nodes(tree, _EXPRESSIONS | {"Delete", "Table", "Where"})
            warnings = ("WHERE does not impose an affected-row limit.",)
        elif isinstance(tree, exp.Drop | exp.TruncateTable):
            _nodes(tree, _SCALARS | {"Drop", "TruncateTable", "Table"})
            warnings = (
                "This operation affects the entire table; no automatic recovery is provided.",
            )
        else:
            _args(tree, {"this", "kind", "properties", "exists"})
            if tree.args.get("kind") != "TABLE" or not isinstance(
                tree.this, exp.Schema
            ):
                raise WriteError("WRITE_CREATE_TABLE_REQUIRED")
            _nodes(tree, _DDL)
            defs = tree.this.expressions
            if not defs or not all(isinstance(c, exp.ColumnDef) for c in defs):
                raise WriteError("WRITE_COLUMNS_REQUIRED")
            for dtype in tree.find_all(exp.DataType):
                if dtype.this.value not in _TYPES or dtype.args.get("nested"):
                    raise WriteError("WRITE_COLUMN_TYPE_UNSUPPORTED")
            properties = tree.args.get("properties")
            if not isinstance(properties, exp.Properties):
                raise WriteError("WRITE_TABLE_PROPERTIES_REQUIRED")
            keys = [
                p
                for p in properties.expressions
                if isinstance(p, exp.UniqueKeyProperty | exp.DuplicateKeyProperty)
            ]
            distribution = list(tree.find_all(exp.DistributedByProperty))
            if (
                len(keys) != 1
                or len(distribution) != 1
                or distribution[0].args.get("kind") != "HASH"
            ):
                raise WriteError("WRITE_KEY_DISTRIBUTION_REQUIRED")
            for engine in tree.find_all(exp.EngineProperty):
                if engine.this.name.upper() != "OLAP":
                    raise WriteError("WRITE_OLAP_REQUIRED")
            for prop in properties.expressions:
                if type(prop) is exp.Property and (
                    prop.name not in _PROPERTIES
                    or not isinstance(prop.args.get("value"), exp.Literal)
                ):
                    raise WriteError("WRITE_TABLE_PROPERTY_UNSUPPORTED")
        # Generation may rewrite joins into subqueries. Check that the SQL sent
        # to Doris still uses exactly the validated physical sources.
        rendered = tree.sql(dialect="doris", identify=True)
        if isinstance(tree, exp.Insert) and isinstance(
            tree.expression, exp.Select | exp.SetOperation
        ):
            generated = parse_sql(rendered)
            if (
                not isinstance(generated, exp.Insert)
                or not isinstance(generated.expression, exp.Select | exp.SetOperation)
                or _query(generated.expression) != sources
            ):
                raise WriteError("WRITE_SOURCE_VALIDATION_FAILED")
        return WriteStatement(
            action,
            rendered,
            target,
            sources,
            columns,
            warnings,
        )
    except WriteError:
        raise
    except Exception:
        raise WriteError("WRITE_SQL_INVALID") from None


def validate_table_metadata(
    ddl: str, statement: WriteStatement, *, target: bool
) -> None:
    """Reject views/external engines and validate UPDATE's key columns on Doris metadata."""
    tree = parse_sql(ddl)
    if not isinstance(tree, exp.Create) or tree.args.get("kind") != "TABLE":
        raise WriteError("WRITE_BASE_TABLE_REQUIRED")
    engines = list(tree.find_all(exp.EngineProperty))
    if len(engines) != 1 or engines[0].this.name.upper() != "OLAP":
        raise WriteError("WRITE_OLAP_REQUIRED")
    if target and statement.action == "update":
        keys = list(tree.find_all(exp.UniqueKeyProperty))
        if len(keys) != 1:
            raise WriteError("WRITE_UPDATE_UNIQUE_KEY_REQUIRED")
        key_names = {c.name.lower() for c in keys[0].expressions}
        all_names = {c.name.lower() for c in tree.find_all(exp.ColumnDef)}
        for name in statement.update_columns:
            if name.lower() in key_names or name.lower() not in all_names:
                raise WriteError("WRITE_UPDATE_VALUE_COLUMN_REQUIRED")
