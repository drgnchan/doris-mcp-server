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
# 业务写入

[English](business-writes.md) | [简体中文](business-writes.zh-CN.md)

## 范围与默认行为

默认关闭的 `doris_write` 只有一个 Child：`execute_write`。仅启用它为 9/56，
同时启用 Admin 为 10/62；原 8/55 能力保持只读。没有审批、强制预览、执行库、幂等 key 或持久状态查询。

| 动作 | 支持范围 |
|---|---|
| insert | INSERT VALUES（最多 1,000 行值）和 INSERT SELECT |
| update | 单个 Unique Key 表，必须带 WHERE，只给普通值列赋字面量 |
| create_table | 内部 OLAP Unique/Duplicate Key 表，明确列定义及 HASH 分桶 |
| delete | 单张内部 OLAP 基表，必须带 WHERE，不支持 JOIN 或子查询 |
| drop_table | 单张内部 OLAP 基表的 DROP TABLE，不支持 IF EXISTS 或 FORCE |
| truncate_table | 单张内部 OLAP 基表的整表 TRUNCATE TABLE |

真实表必须完整限定为 `internal.database.table`。INSERT SELECT 支持内部跨库、投影、过滤、
JOIN、聚合、子查询和非递归 CTE；使用有界 AST 与内置标量/聚合函数白名单，未知语法和函数拒绝。
作用域解析区分源表与 CTE 别名，包含 SEMI/ANTI JOIN 右表，并在 SQL 生成后复核源表集合；在同一连接检查已有目标和源的元数据，仅允许 OLAP 基表，
拒绝视图和外部引擎。源 SELECT 在 Doris 内执行，不把数据取回客户端再逐行插入。

不包含 INSERT OVERWRITE、CTAS、CREATE LIKE、分区子句、外部资源、多表删除、
ALTER TABLE、DROP 修饰符、管理 SQL、多语句或跨调用事务。CREATE 支持基础标量列类型，以及
replication_num、enable_unique_key_merge_on_write、compression、storage_format 属性。
精确边界以当前发现 Schema 和解析器为准。

INSERT 包含 Unique Key upsert，不保证仅追加。WHERE 不保证影响少量行。
请求上限 64 KiB，调用超时 30 秒；不强制 COUNT 或预览源查询。

## 启用和鉴权

设置 `MCP_WRITE_DOMAIN_ENABLED=true`，或配置 `writing.enabled: true`。
在受保护的既有静态 Token 记录中显式添加：

```json
{"write_actions": ["insert", "update", "create_table"]}
```

上面的示例仅授权原有三个动作。DELETE、DROP TABLE、TRUNCATE TABLE 分别需要独立的
`delete`、`drop_table`、`truncate_table` 授权，旧 Token 不会自动获得。DROP/TRUNCATE
影响整张表，不提供自动恢复；元数据检查要求目标表存在，dry_run 也一样。

未列出的动作不允许，普通/Admin 权限不自动获得写权限。JWT/外部 OAuth 同时需要
`child:call:doris_write:execute_write` 和 `action:call:doris_write:<action>`。
Doris OAuth 还需要 Child 开关、DORIS_OAUTH_CHILD_TOOL_ALLOWLIST 中的
`doris_write.execute_write`，以及 DORIS_OAUTH_WRITE_ACTION_ALLOWLIST 中的精确动作。
这些 scopes 不进入默认授权，必须明确请求。

所有读写使用请求既有的 Doris 身份和路由；源对象读权限、目标写权限由 Doris 检查，
MCP 授权不替代原生 RBAC。不切换 root 或其他身份重试，也不另建一套对象 ACL 系统。

## 调用与结果

先发现 doris_write，再按当前 manifest 调用 execute_write：

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

Flat 模式为 doris_write_execute_write。dry_run 可选，只校验语法、MCP 授权和必要元数据，
不执行源查询或写入；不能证明原生 DML/DDL 权限或之后一定成功。不增加审批或二次确认。

每次明确调用都是一次新执行，不自动重试。结果区分 succeeded、failed、dry_run、outcome_unknown；
提交后仅明确的权限、语法、对象解析等拒绝错误可确定为失败；1105 等通用服务端错误
保守返回 outcome_unknown，只有完整匹配已确认原生权限拒绝格式时才归为失败，
原始诊断仍不对外返回。提交前的元数据或连接错误仍返回失败。
响应不确定不代表已经回滚，应先通过只读检查或 Doris 原生信息核实。
request_id 仅用于审计关联，没有跨请求防重或 exactly-once 保证。

若 Doris OK 响应含事务信息，VISIBLE 表示已发布；COMMITTED 表示已提交但
`data_visibility=not_confirmed`。非空但无法识别的事务信息返回 outcome_unknown。
影响行数、事务 ID 按实际可得信息返回；未独立读回时 verification_status 始终为 not_checked。
执行审计与驱动错误不记录/返回 SQL 原文、业务值或凭据；每次调用结束直接关闭套接字，
释放原连接池租约，不等待 COM_QUIT。OK 消息兼容长度编码和原始事务文本，
长度字节等于左花括号时也能正确解析。

## 验证与迁移

两种工具暴露模式使用同一授权和执行路径，旧只读 Token 不能写入。无需新增依赖，
不增加主版本探测，也不宣称已经完成 Cloud 认证。真实验收仅针对本机隔离的官方 3.1.3 FE/BE
（存算一体），没有部署或测试写入生产/STG：

```bash
DORIS_WRITE_E2E=1 uv run pytest -q --no-cov -W error test/integration/test_write_doris.py
```

可选集成测试覆盖层级/Flat HTTP 下 DELETE/TRUNCATE/DROP、dry-run 和独立读回，
以及已获 MCP 动作授权但缺少 Doris 原生权限时三个动作均被拒绝。该测试已在隔离的
官方 Doris 3.1.3 FE/BE 上通过，不代表 Cloud 模式认证。
原有场景覆盖层级/Flat HTTP、建表/插入/更新/独立读回、跨库 INSERT SELECT 的 CTE/聚合/JOIN、
upsert、dry-run 和源/目标原生权限拒绝。单元测试覆盖语法限制、精确授权、旧 key 拒绝、
取消/未知结果、不自动重试及 OK 包事务解析。生产开启属于独立部署决策。
同时发生的 Admin 破坏性变更见[权限管理迁移](administration.zh-CN.md)。
