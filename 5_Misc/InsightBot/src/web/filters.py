import re

BANNED = ["secret_config", "drop", "delete", "insert", "update"]

_SELECT_RE = re.compile(r"(select\b.*?;)", re.IGNORECASE | re.DOTALL)
_SELECT_NO_SEMI_RE = re.compile(r"(select\b.*)", re.IGNORECASE | re.DOTALL)


def extract_sql(text: str):
    if not text:
        return None
    m = _SELECT_RE.search(text)
    if m:
        return m.group(1).strip()
    m = _SELECT_NO_SEMI_RE.search(text)
    if m:
        sql = m.group(1).strip()
        sql = sql.split("```")[0].strip()
        if not sql.endswith(";"):
            sql += ";"
        return sql
    return None


def is_blocked(sql: str) -> bool:
    return any(b in sql for b in BANNED)
