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

"""Small expression allowlist, using SQLGlot's Doris parser, not caller SQL."""

import sqlglot

from .admin_statements import AdminError

_ALLOWED = frozenset(
    {
        "Column",
        "Identifier",
        "Literal",
        "Null",
        "Boolean",
        "Paren",
        "Tuple",
        "And",
        "Or",
        "Not",
        "EQ",
        "NEQ",
        "GT",
        "GTE",
        "LT",
        "LTE",
        "Is",
        "Between",
        "In",
        "Like",
        "Add",
        "Sub",
        "Mul",
        "Div",
        "Mod",
        "Neg",
        "Cast",
        "TryCast",
        "DataType",
        "DataTypeParam",
        "Lower",
        "Upper",
        "Length",
        "Abs",
        "Coalesce",
        "Nullif",
        "Trim",
        "Substring",
    }
)


def compile_predicate(predicate: str) -> str:
    """Accept one bounded, side-effect-free expression; emit validated AST SQL."""
    if len(predicate) > 4096 or any(
        s in predicate for s in (";", "--", "/*", "*/", "\\", "\x00")
    ):
        raise AdminError("ADMIN_PREDICATE_INVALID")
    try:
        parsed = sqlglot.parse(predicate, read="doris")
        if len(parsed) != 1 or parsed[0] is None:
            raise AdminError("ADMIN_PREDICATE_INVALID")
        expression = parsed[0]
        nodes = list(expression.walk())
        if len(nodes) > 256 or any(
            type(node).__name__ not in _ALLOWED for node in nodes
        ):
            raise AdminError("ADMIN_PREDICATE_UNSUPPORTED")
        for node in nodes:
            depth = 0
            parent = node.parent
            while parent is not None:
                depth += 1
                if depth > 32:
                    raise AdminError("ADMIN_PREDICATE_TOO_DEEP")
                parent = parent.parent
        return expression.sql(dialect="doris", identify=True)
    except AdminError:
        raise
    except Exception:
        raise AdminError("ADMIN_PREDICATE_INVALID") from None
