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


"""Opt-in business writes with exact action authorization."""

from typing import Any

from .admin_domain import ADMIN_ACTION_ANNOTATIONS, principal_key
from .admin_statements import AdminError
from .domain_models import (
    Availability,
    AvailabilityStatus,
    CapabilityVariant,
    ChildSupportContract,
    ChildToolDefinition,
    DomainDefinition,
    UnavailableBehavior,
)
from .write_statements import WRITE_ACTIONS, WRITE_SCHEMA, WriteError


def action_scope(action: str) -> str:
    return f"action:call:doris_write:{action}"


def allowed_actions(context: Any) -> tuple[str, ...]:
    try:
        principal_key(context)
    except AdminError:
        return ()
    scopes = set(
        getattr(context, "oauth_scopes", ())
        if context.auth_method in {"external_oauth", "doris_oauth"}
        else getattr(context, "permissions", ())
    )
    if "child:call:doris_write:execute_write" not in scopes:
        return ()
    if context.auth_method == "doris_oauth" and (
        not getattr(context, "doris_oauth_child_tools_enabled", False)
        or "doris_write.execute_write"
        not in getattr(context, "doris_oauth_child_tool_allowlist", ())
    ):
        return ()
    return tuple(a for a in WRITE_ACTIONS if action_scope(a) in scopes)


def authorize_write(context: Any, action: str) -> str:
    if action not in allowed_actions(context):
        raise WriteError("WRITE_ACTION_FORBIDDEN")
    return principal_key(context)


def filtered_child(child: ChildToolDefinition, context: Any) -> ChildToolDefinition:
    actions = allowed_actions(context)
    schema = {
        **WRITE_SCHEMA,
        "properties": {
            **WRITE_SCHEMA["properties"],
            "action": {"type": "string", "enum": list(actions)},
        },
    }
    return child.model_copy(update={"input_schema": schema})


WRITE_DOMAIN = DomainDefinition(
    name="doris_write",
    title="Doris Business Writes",
    description="Opt-in business writes: INSERT VALUES/SELECT, UPDATE, CREATE TABLE, DELETE, DROP TABLE and TRUNCATE TABLE on internal OLAP tables. Exact write authorization required; no automatic retries or cross-request deduplication.",
    annotations=ADMIN_ACTION_ANNOTATIONS,
    enablement_policy="config:writing:enabled",
    discovery_policy="domain:discover:doris_write",
    children=(
        ChildToolDefinition(
            name="execute_write",
            title="Execute business write",
            canonical_description="Submit one INSERT VALUES/SELECT, single-table UPDATE/DELETE with WHERE, basic OLAP CREATE TABLE, DROP TABLE or TRUNCATE TABLE. DROP/TRUNCATE accept one whole table without modifiers. Fully qualify physical tables in internal. INSERT includes Unique Key upsert. dry_run does not execute writes. A lost response is not proof of rollback; never automatically retry. No idempotency_key or persistent status API.",
            input_schema=WRITE_SCHEMA,
            output_schema={
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "execution_status": {"type": "string"},
                    "verification_status": {"type": "string"},
                    "warnings": {"type": "array", "items": {"type": "string"}},
                },
                "required": [
                    "action",
                    "execution_status",
                    "verification_status",
                    "warnings",
                ],
                "additionalProperties": True,
            },
            handler_name="child:doris_write:execute_write",
            authorization_policy="child:call:doris_write:execute_write",
            annotations=ADMIN_ACTION_ANNOTATIONS,
            support_contract=ChildSupportContract(
                rule_id="doris_write.execute_write",
                variants=(
                    CapabilityVariant(
                        name="native_write",
                        supported_ranges=(">=2.0.0",),
                        source_references=(
                            "https://doris.apache.org/docs/3.x/sql-manual/sql-statements/data-modification/DML/INSERT/",
                        ),
                        callable_when_degraded=True,
                    ),
                ),
                unavailable_behavior=UnavailableBehavior.SHOW_DISABLED,
            ),
        ),
    ),
)


class WriteAvailabilityProvider:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate

    async def resolve_domain(
        self,
        domain: DomainDefinition,
        children: tuple[ChildToolDefinition, ...],
        auth_context: Any,
    ) -> Any:
        from .domain_manifest import DomainAvailabilityResolution

        resolver = getattr(self.delegate, "resolve_domain", None)
        if domain.name != "doris_write" and callable(resolver):
            return await resolver(domain, children, auth_context)
        return DomainAvailabilityResolution(
            availabilities={
                c.name: await self.availability_for(domain, c, auth_context)
                for c in children
            },
            generation_fingerprint="write-stateless-v1"
            if domain.name == "doris_write"
            else "",
        )

    async def availability_for(
        self, domain: DomainDefinition, child: ChildToolDefinition, auth_context: Any
    ) -> Availability:
        if domain.name != "doris_write":
            result: Availability = await self.delegate.availability_for(
                domain, child, auth_context
            )
            return result
        permitted = bool(allowed_actions(auth_context))
        return Availability(
            status=AvailabilityStatus.DEGRADED
            if permitted
            else AvailabilityStatus.UNKNOWN,
            callable=permitted,
            reason_code="WRITE_NATIVE_RBAC" if permitted else "WRITE_ACTION_FORBIDDEN",
            active_variant="native_write" if permitted else None,
            evidence_sources=("explicit_configuration", "action_authorization"),
            limitations=(
                "Doris enforces native RBAC and feature compatibility at execution time. Dry run does not certify execution; no automatic retry or cross-request deduplication.",
            ),
        )
