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

"""Opt-in, authenticated direct access management. No approval protocol."""

from __future__ import annotations

from typing import Any

from .admin_statements import (
    CHILD_ACTIONS,
    AdminError,
    action_scope,
    child_schema,
)
from .domain_models import (
    Availability,
    AvailabilityStatus,
    CapabilityVariant,
    ChildSupportContract,
    ChildToolDefinition,
    DomainDefinition,
    ToolContractAnnotations,
    UnavailableBehavior,
)

ADMIN_DOMAIN_NAME = "doris_admin"
ADMIN_DOMAIN_DISCOVERY_SCOPE = "domain:discover:doris_admin"
ADMIN_ACTION_ANNOTATIONS = ToolContractAnnotations(
    read_only=False,
    idempotent=False,
    destructive=True,
    open_world=False,
    requires_confirmation=False,
)
_READ = ToolContractAnnotations(
    read_only=True,
    idempotent=True,
    destructive=False,
    open_world=False,
    requires_confirmation=False,
)


def principal_key(context: Any) -> str:
    if context is None or getattr(context, "auth_method", "") not in {
        "token",
        "jwt",
        "external_oauth",
        "doris_oauth",
    }:
        raise AdminError("ADMIN_AUTHENTICATION_REQUIRED")
    user = getattr(context, "user_id", "") or getattr(context, "doris_user", "")
    if not isinstance(user, str) or not user:
        raise AdminError("ADMIN_AUTHENTICATION_REQUIRED")
    # Issuer prevents collisions between federated identities. Never use bearer text.
    return f"{context.auth_method}:{getattr(context, 'oauth_issuer', '')}:{user}"


def allowed_actions(context: Any, child: str) -> tuple[str, ...]:
    try:
        principal_key(context)
    except AdminError:
        return ()
    scopes = set(
        getattr(context, "oauth_scopes", ())
        if context.auth_method in {"external_oauth", "doris_oauth"}
        else getattr(context, "permissions", ())
    )
    if f"child:call:doris_admin:{child}" not in scopes:
        return ()
    if context.auth_method == "doris_oauth" and (
        not getattr(context, "doris_oauth_child_tools_enabled", False)
        or f"doris_admin.{child}"
        not in getattr(context, "doris_oauth_child_tool_allowlist", ())
    ):
        return ()
    return tuple(a for a in CHILD_ACTIONS[child] if action_scope(a) in scopes)


def authorize_admin(context: Any, action: str) -> str:
    principal = principal_key(context)
    child = next((c for c, actions in CHILD_ACTIONS.items() if action in actions), None)
    if child is None or action not in allowed_actions(context, child):
        raise AdminError("ADMIN_ACTION_FORBIDDEN")
    return principal


def filtered_child(child: ChildToolDefinition, context: Any) -> ChildToolDefinition:
    actions = allowed_actions(context, child.name)
    return (
        child.model_copy(update={"input_schema": child_schema(child.name, actions)})
        if actions
        else child
    )


def administration_config_errors(
    *, enabled: Any, state_path: Any = "", password_file: Any = ""
) -> tuple[str, ...]:
    errors = []
    if not isinstance(enabled, bool):
        errors.append("Administration enabled flag must be boolean")
    if not isinstance(state_path, str) or (enabled and not state_path.strip()):
        errors.append("Administration state_path is required when enabled")
    if not isinstance(password_file, str):
        errors.append("Administration password_file must be a path string")
    return tuple(errors)


def _child(name: str) -> ChildToolDefinition:
    return ChildToolDefinition(
        name=name,
        title=name.replace("_", " ").title(),
        canonical_description=(
            "Authenticated Doris access management. One structured operation per call; "
            "dry_run is optional, approval is not required. Reuse the same idempotency_key "
            "after response loss. SQL success does not prove effective access."
            if name.startswith("manage_")
            else "Inspect bounded access metadata or your own durable execution result."
        ),
        input_schema=child_schema(name),
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
        handler_name=f"child:doris_admin:{name}",
        authorization_policy=f"child:call:doris_admin:{name}",
        annotations=_READ
        if name in {"inspect_access", "get_execution_status"}
        else ADMIN_ACTION_ANNOTATIONS,
        support_contract=ChildSupportContract(
            rule_id=f"doris_admin.{name}",
            variants=(
                CapabilityVariant(
                    name="native_management",
                    supported_ranges=(">=2.0.0",),
                    source_references=(
                        "https://doris.apache.org/docs/3.x/sql-manual/sql-statements/account-management/",
                    ),
                    callable_when_degraded=True,
                ),
            ),
            unavailable_behavior=UnavailableBehavior.SHOW_DISABLED,
        ),
    )


ADMIN_DOMAIN = DomainDefinition(
    name=ADMIN_DOMAIN_NAME,
    title="Doris Administration",
    description="Opt-in access management using the authenticated caller's Doris route. Direct execution, no approval workflow.",
    annotations=ADMIN_ACTION_ANNOTATIONS,
    children=tuple(_child(name) for name in CHILD_ACTIONS),
    enablement_policy="config:administration:enabled",
    discovery_policy=ADMIN_DOMAIN_DISCOVERY_SCOPE,
)


class AdminAvailabilityProvider:
    """Keep the read-only capability matrix/certification completely separate."""

    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate

    async def availability_for(
        self, domain: DomainDefinition, child: ChildToolDefinition, auth_context: Any
    ) -> Availability:
        if domain.name != ADMIN_DOMAIN_NAME:
            result: Availability = await self.delegate.availability_for(
                domain, child, auth_context
            )
            return result
        permitted = bool(allowed_actions(auth_context, child.name))
        return Availability(
            status=AvailabilityStatus.DEGRADED
            if permitted
            else AvailabilityStatus.UNKNOWN,
            callable=permitted,
            reason_code="ADMIN_NATIVE_RBAC" if permitted else "ADMIN_ACTION_FORBIDDEN",
            active_variant="native_management" if permitted else None,
            evidence_sources=("explicit_configuration", "action_authorization"),
            limitations=(
                "The target Doris validates syntax, feature compatibility and native RBAC at execution time; no management-specific version gate or write certification is implied.",
            ),
        )

    async def resolve_domain(
        self,
        domain: DomainDefinition,
        children: tuple[ChildToolDefinition, ...],
        auth_context: Any,
    ) -> Any:
        from .domain_manifest import DomainAvailabilityResolution

        resolver = getattr(self.delegate, "resolve_domain", None)
        if domain.name != ADMIN_DOMAIN_NAME and callable(resolver):
            return await resolver(domain, children, auth_context)
        return DomainAvailabilityResolution(
            availabilities={
                child.name: await self.availability_for(domain, child, auth_context)
                for child in children
            },
            generation_fingerprint="admin-direct-v1"
            if domain.name == ADMIN_DOMAIN_NAME
            else "",
        )
