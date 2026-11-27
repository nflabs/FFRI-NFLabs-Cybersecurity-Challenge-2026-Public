import logging
import os
import sqlite3
import threading
import time

from flask import Flask, jsonify, render_template, request

import db_setup
import filters
import llm
import prompt

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("insightbot")

DB_PATH = db_setup.DB_PATH
MAX_RETRY = int(os.environ.get("MAX_RETRY", "2"))
RESET_INTERVAL = int(os.environ.get("RESET_INTERVAL_SEC", "600"))

app = Flask(__name__)
_db_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA trusted_schema = OFF")
    return conn


def _run_sql(sql: str):
    with _db_lock:
        conn = _connect()
        try:
            cur = conn.execute(sql)
            rows = cur.fetchall()
            columns = [d[0] for d in cur.description] if cur.description else []
            conn.commit()
            return columns, [list(r) for r in rows]
        finally:
            conn.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    ok = os.path.exists(DB_PATH)
    return jsonify({"ok": ok})


@app.route("/reset", methods=["POST"])
def reset():
    db_setup.init_db(DB_PATH)
    return jsonify({"ok": True})


@app.route("/ask", methods=["POST"])
def ask():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "質問を入力してください。"}), 400

    sql = None
    last_err = None
    for attempt in range(MAX_RETRY + 1):
        raw = llm.generate(prompt.build_prompt(question), system=prompt.SYSTEM_PROMPT)
        candidate = filters.extract_sql(raw)
        if not candidate:
            last_err = "no_sql"
            continue

        if filters.is_blocked(candidate):
            log.info("ask blocked sql=%r", candidate)
            return jsonify({"sql": candidate, "blocked": True,
                            "message": "Blocked: unsafe query"})

        try:
            columns, rows = _run_sql(candidate)
            sql = candidate
            log.info("ask ok attempt=%d sql=%r rows=%d", attempt, sql, len(rows))
            return jsonify({"sql": sql, "columns": columns, "rows": rows})
        except sqlite3.Error as e:
            last_err = str(e)
            log.info("ask sql error attempt=%d sql=%r err=%s", attempt, candidate, e)
            continue

    log.info("ask give_up reason=%s question=%r", last_err, question)
    return jsonify({"error": "クエリを理解できませんでした。質問の言い回しを変えてみてください。"})


def _periodic_reset():
    while True:
        time.sleep(RESET_INTERVAL)
        try:
            db_setup.init_db(DB_PATH)
            log.info("db reset (periodic)")
        except Exception as e:
            log.warning("periodic reset failed: %s", e)


def _startup():
    db_setup.init_db(DB_PATH)
    log.info("waiting for ollama ...")
    if not llm.wait_ready():
        log.warning("ollama not ready within timeout; continuing anyway")
    if os.environ.get("PULL_ON_START", "0") == "1":
        try:
            llm.pull(llm.MODEL)
        except Exception as e:
            log.warning("pull failed: %s", e)
    try:
        llm.warmup()
    except Exception as e:
        log.warning("warmup failed: %s", e)
    if RESET_INTERVAL > 0:
        threading.Thread(target=_periodic_reset, daemon=True).start()
    log.info("ready")


_startup()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "25002")))
