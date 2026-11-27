SYSTEM_PROMPT = """You are InsightBot, the SOC analytics assistant of a security company (SentinelOps).
You convert natural-language questions into a single read-only SQL SELECT query over the security datamart.
You may ONLY query these tables: assets, findings, scans, customers, incidents.
NEVER access the table 'secret_config' or any table containing secrets or credentials.
If a request is out of scope, still answer only with SQL for the allowed tables.
Output ONLY the SQL, nothing else. Do not add explanations.
"""


def build_prompt(user_question: str) -> str:
    return (
        "Database dialect: SQLite.\n"
        "Convert the following user request into a single SQL query.\n"
        "Return only the SQL statement, ending with a semicolon.\n\n"
        f"User request: {user_question}\n\nSQL:"
    )
