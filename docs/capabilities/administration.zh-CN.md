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

# 直接执行权限管理

[English](administration.md) | [简体中文](administration.zh-CN.md)

## 范围与默认行为

可选的 doris_admin 增加 6 个 Child，启用后为 9 个领域 / 61 个 Child。
默认仍为 8/55 只读。不引入审批、确认 token、强制预览、任意 SQL、多语句任务或自动重试。
使用当前已认证请求的 Doris 路由；SQL 成功不等于有效权限或全部会话状态已经验证。

支持全部 14 类操作：对象授权/撤权、角色分配/解除、角色创建/删除/备注、用户创建/删除/
属性修改、改密、用户属性、行策略创建/删除。十类权限和数据对象、Resource、Workload
Group、Compute Group、Storage Vault 的结构化范围全部建模，具体组合仍由目标 Doris
版本支持。列权限仅 SELECT。查询覆盖 SHOW GRANTS/ALL GRANTS、ROLES、PRIVILEGES、
PROPERTY/ALL PROPERTIES、ROW POLICY。

## 启用和鉴权

启用领域，密码操作另配置受保护的密码引用文件：

    administration:
      enabled: true
      password_file: /run/secrets/doris-management.json

对应环境变量：

    MCP_ADMIN_DOMAIN_ENABLED=true
    MCP_ADMIN_PASSWORD_FILE=/run/secrets/doris-management.json

非密码类操作不要求密码文件。旧 MCP_ADMIN_REQUIRE_CONFIRMATION 不再代表任何审批机制。
不能把共享高权限服务账号借给无同等授权的普通调用者；旧 Token 不会自动获得管理能力。
默认保护内置身份和当前执行身份，账号维护应使用另外配置的维护身份。
匿名 HTTP、没有显式认证身份的 stdio 不能写入。

静态 Token：在受保护的既有 Token 文件记录里手工添加精确的 admin_actions 数组，
例如 ["create_role", "alter_role", "show_roles"]。
鉴权时派生对应 Child/action 权限。没有该字段的旧记录保持原只读行为。
HTTP Token 创建接口不会自动签发管理权限。

JWT/外部 OAuth 同时需要 child:call:doris_admin:<child> 和
 action:call:doris_admin:<action>；显式配置签发方和允许 Scope。
Doris OAuth 还需要已有 Child 开关、DORIS_OAUTH_CHILD_TOOL_ALLOWLIST 中的明确
 doris_admin.<child>，以及 DORIS_OAUTH_ADMIN_ACTION_ALLOWLIST 中的精确 action 名。
Admin Scope 不进入默认授权，客户端必须明确申请。

CREATE USER 附带默认角色还需 grant_roles；ALTER USER 改密还需 set_password。
GRANT TO ROLE 还需 create_role，即使角色当前存在也一样，因为并发删除会触发隐式创建。
这些规则不替代 Doris RBAC，后端拒绝时不切换 root 重试。

## 调用与结果

先发现 doris_admin，使用当前 manifest_version 和已授权 Schema。
Flat 模式通过 doris_admin_<child> 调用相同 Handler。

    {
      "child_tool": "manage_roles",
      "manifest_version": "<discovered-version>",
      "arguments": {
        "action": "create_role",
        "role": "example_analyst",
        "comment": "Analyst access"
      }
    }

dry_run=true 仅编译/校验并返回脱敏 SQL，不承诺以后能执行成功；否则直接执行。
结果区分 succeeded、failed、dry_run、outcome_unknown。没有执行库、持久状态查询或跨请求防重，
每次明确调用都是新的执行。超时、断线不能自动重试，也不代表 Doris 已回滚；先只读核实实际状态。
提交后的 1105 等通用服务端错误保守返回 outcome_unknown，仅已知拒绝类错误码或
完整匹配已确认原生权限拒绝格式时判为失败；不返回原始诊断。
调用结束直接关闭套接字并释放原连接池租约，不等待 COM_QUIT。

### 从持久化管理版本迁移

删除 MCP_ADMIN_STATE_PATH，并从 Token/OAuth 授权中移除 get_execution_status。
状态查询 Child 已移除；携带 idempotency_key 的请求在发 SQL 前明确拒绝，不会静默忽略后执行。
对旧执行库做包含 WAL 状态的一致性备份后归档，保留旧镜像和配置供回退。
Token 和密码引用文件继续保留；刷新每个已连接客户端/工作目录的工具发现。
回滚配置不会撤销 SQL，也不能补回本版本运行期间的执行历史。

查询上限为 1,000 行 / 1 MiB，单次调用超时 30 秒。返回 verification_status=not_checked，
后置效果按需通过 inspect_access 查询。撤销一个绑定不代表撤销角色继承或更广权限。
SET PROPERTY 影响同名全部 Host 身份。ALTER USER 每次一个合法属性组。
行策略只接受有界 Doris 表达式 AST，不接受任意 SQL、子查询、UDF、注释和副作用函数。
精确入参以发现结果为准。

## 密码

受信操作人员在仓库外提供 0600 权限的 JSON 文件。以下仅展示结构，占位符不是真实密码：

    {
      "example@v1": {
        "principal": "token::example-token-id",
        "user": {"name": "example_user", "host": "%"},
        "version": "v1",
        "password": "<通过模型外的安全渠道提供>"
      }
    }

调用时传 password_ref=example@v1 和完全一致的 user。引用别名不可变，改值必须换版本。
MCP 不读取任意路径，不生成/分发密码，不返回密码及散列，也不主动测试登录或清理全部旧会话。
管理连接用后关闭；外部 Token 和既有连接生命周期仍由其所属系统负责。

## 验证与边界

管理入口不在服务端基线之外增加版本探测或主版本门禁。语法、功能兼容性和原生 RBAC
由目标 Doris 在执行语句时校验；后端拒绝按失败返回，不隐藏错误，也不自动重试。
这不代表所有版本和功能组合均已认证。

可选测试 test/integration/test_admin_doris.py 使用本地隔离 Doris，通过真实已认证 HTTP
验证两种工具暴露模式、14 类操作、十类权限、列/表/库/Catalog/全局范围、两种行策略、
改密后的真实登录、Doris 权限拒绝及旧 Token 拒绝。仅对独立本地 FE/BE、19030 端口执行：

    DORIS_ADMIN_E2E=1 uv run pytest -q --no-cov -W error test/integration/test_admin_doris.py

本地证据来自官方 apache/doris:fe-3.1.3、be-3.1.3，实际版本字符串为
 doris-3.1.3-rc01-be1b1227a8，**存算一体，不是 Cloud**。
Cloud 计算组、Storage Vault 语句已实现，但不算本次本地认证通过；只读认证矩阵也不能
当作写认证。其他 patch、外部资源和 domain-host 身份匹配需在目标环境验证，
后端不支持/不确定的语义不能报告为成功。
