# -*- coding: UTF-8 -*-
"""SQL 安全校验公共安全模块（1.10.0 安全补丁）

供 sqlcheck API 与工单创建共用：
1. check_sql_security: 报错回显/副作用函数黑名单 + 危险 DDL 黑名单
2. masked_engine_error: 引擎异常统一脱敏，原文进日志带 ref

定位说明：正则黑名单可被注释/大小写/编码变形绕过，属纵深防御而非安全边界；
真正的边界是实例级授权、goInception AST 审核规则（enable_drop_table/
enable_drop_database 默认 false）、报错脱敏与数据库账号最小权限。
"""
import hashlib
import logging
import re
import uuid

from common.config import SysConfig

logger = logging.getLogger("default")

# 报错回显型/副作用型函数（error-based 注入信道）
DANGEROUS_FUNC_PATTERN = re.compile(
    r"GTID_SUBSET|GTID_SUBTRACT|UPDATEXML|EXTRACTVALUE|"
    r"EXPLAIN\s+ANALYZE|LOAD_FILE|BENCHMARK\s*\(|SLEEP\s*\(|"
    r"INTO\s+(OUTFILE|DUMPFILE)",
    re.IGNORECASE,
)

# 危险 DDL（代码层硬拦截；goInception 侧另有 AST 级默认禁止，双层防御）
DANGEROUS_DDL_PATTERN = re.compile(
    r"\bDROP\s+(DATABASE|SCHEMA|TABLE)\b|\bTRUNCATE\s+(TABLE\s+)?\w",
    re.IGNORECASE,
)


def sql_digest(sql: str) -> str:
    """SQL 摘要（hash+截断），用于拦截/脱敏日志的事后排查，避免全文入日志"""
    sha = hashlib.sha256(sql.encode("utf-8", "replace")).hexdigest()[:12]
    return f"sha256={sha} sql={sql[:200]!r}"


def check_sql_security(sql: str, user=None, instance_id=None):
    """危险 SQL 公共校验，命中抛 ValueError。

    - 函数黑名单：始终启用（纵深防御）
    - DDL 黑名单：系统配置 sql_block_dangerous_ddl=false 可关闭
      （默认开启；确有审批后删表需求的团队可关，goInception 规则仍兜底）
    """
    context = f"user={getattr(user, 'username', None)} instance={instance_id}"
    if DANGEROUS_FUNC_PATTERN.search(sql):
        logger.warning(f"sql security blocked dangerous function {context} {sql_digest(sql)}")
        raise ValueError("SQL 含不允许的函数或语法")
    if SysConfig().get("sql_block_dangerous_ddl", True) and DANGEROUS_DDL_PATTERN.search(sql):
        logger.warning(f"sql security blocked dangerous DDL {context} {sql_digest(sql)}")
        raise ValueError("SQL 含禁止的危险DDL（DROP DATABASE/TABLE、TRUNCATE）")


def masked_engine_error(e: Exception, context: str = "") -> str:
    """引擎/后端异常统一脱敏：原文+堆栈仅进服务端日志，前端只拿 ref。

    防止连接失败、goInception 抛错等未经 execute_check 脱敏的异常路径
    把原生错误（可能含敏感信息）直接回传客户端。
    """
    ref = uuid.uuid4().hex[:8]
    logger.warning(f"engine error masked ref={ref} {context} error={e}", exc_info=True)
    return f"SQL检查/执行异常（详情已脱敏，排查请联系管理员，ref={ref}）"