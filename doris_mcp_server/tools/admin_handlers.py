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

"""Exact Admin child bindings shared by flat and hierarchical transports."""

from typing import Any

from ..utils.admin_runtime import AdminRuntime
from .admin_statements import AdminError


class AdminToolHandlersMixin:
    admin_runtime: AdminRuntime | None

    async def _run_admin(self, child: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.admin_runtime is None:
            raise AdminError("ADMIN_DISABLED")
        return await self.admin_runtime.execute(child, arguments)

    async def _formal_doris_admin_manage_privileges_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._run_admin("manage_privileges", arguments)

    async def _formal_doris_admin_manage_role_membership_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._run_admin("manage_role_membership", arguments)

    async def _formal_doris_admin_manage_roles_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._run_admin("manage_roles", arguments)

    async def _formal_doris_admin_manage_users_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._run_admin("manage_users", arguments)

    async def _formal_doris_admin_manage_row_policies_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._run_admin("manage_row_policies", arguments)

    async def _formal_doris_admin_inspect_access_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._run_admin("inspect_access", arguments)
