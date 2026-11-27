#!/usr/bin/env python3
import argparse
import html
import json
import math
import mimetypes
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


CORRECT_ANSWER = "長崎空港"
FLAG = "flag{n1c3_41rp0r7_1d}"
ATTEMPT_LIMIT = 2
MAX_BODY_BYTES = 4096
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_DB_PATH = Path(__file__).with_name("submissions.sqlite3")
AIRPORT_IMAGE_PATH = (Path(__file__).resolve().parent / "public" / "airport.jpg").resolve()
PHOTO_PUBLIC_DIR = (Path(__file__).resolve().parent / "public" / "photo-recovery").resolve()
PHOTO_REFERENCE_LATITUDE = 35.60
PHOTO_REFERENCE_LONGITUDE = 139.80
PHOTO_COORDINATE_DECIMAL_PLACES = 2
PHOTO_FLAG = "flag{n1c3_g30l0c4710n}"
PHOTO_ANSWER_PATTERN = re.compile(
    r"^\s*\{?\s*([+-]?\d+(?:\.\d+)?)\s*,\s*"
    r"([+-]?\d+(?:\.\d+)?)\s*\}?\s*$"
)


@dataclass(frozen=True)
class SubmissionResult:
    ok: bool
    message: str
    attempts_used: int
    attempts_remaining: int
    flag: str | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                answer TEXT NOT NULL,
                correct INTEGER NOT NULL CHECK (correct IN (0, 1)),
                within_limit INTEGER NOT NULL DEFAULT 1
                    CHECK (within_limit IN (0, 1)),
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            """
        )
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(submissions)").fetchall()
        }
        if "within_limit" not in columns:
            conn.execute(
                """
                ALTER TABLE submissions
                ADD COLUMN within_limit INTEGER NOT NULL DEFAULT 1
                    CHECK (within_limit IN (0, 1))
                """
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_submissions_user_id ON submissions(user_id)"
        )


def normalize_text(value: str) -> str:
    return value.strip()


def validate_user_id(user_id: str) -> str | None:
    if not user_id:
        return "IDを入力してください。"
    if len(user_id) > 64:
        return "IDは64文字以内で入力してください。"
    return None


def coordinate_prefix_matches(value: float, reference: float) -> bool:
    scale = 10**PHOTO_COORDINATE_DECIMAL_PLACES
    return math.trunc(value * scale) == math.trunc(reference * scale)


def check_photo_answer(answer: str) -> tuple[bool, str, int]:
    match = PHOTO_ANSWER_PATTERN.fullmatch(answer)
    if not match:
        return False, "{緯度, 経度} の形式で入力してください。", 400

    latitude = float(match.group(1))
    longitude = float(match.group(2))
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return False, "緯度または経度の範囲が不正です。", 400

    if coordinate_prefix_matches(
        latitude, PHOTO_REFERENCE_LATITUDE
    ) and coordinate_prefix_matches(longitude, PHOTO_REFERENCE_LONGITUDE):
        return True, f"Correct! Flag: {PHOTO_FLAG}", 200
    return False, "Incorrect. 画像と公開情報をもう一度照合してください。", 200


def count_attempts(conn: sqlite3.Connection, user_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM submissions WHERE user_id = ? AND within_limit = 1",
        (user_id,),
    ).fetchone()
    return int(row[0])


def record_submission(db_path: Path, raw_user_id: str, raw_answer: str) -> SubmissionResult:
    user_id = normalize_text(raw_user_id)
    answer = normalize_text(raw_answer)

    user_error = validate_user_id(user_id)
    if user_error:
        return SubmissionResult(
            ok=False,
            message=user_error,
            attempts_used=0,
            attempts_remaining=ATTEMPT_LIMIT,
        )
    if not answer:
        return SubmissionResult(
            ok=False,
            message="回答を入力してください。",
            attempts_used=0,
            attempts_remaining=ATTEMPT_LIMIT,
        )

    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE")
        used_before = count_attempts(conn, user_id)
        created_at = now_iso()
        is_correct = answer == CORRECT_ANSWER
        within_limit = used_before < ATTEMPT_LIMIT
        conn.execute(
            "INSERT OR IGNORE INTO users (user_id, created_at) VALUES (?, ?)",
            (user_id, created_at),
        )
        conn.execute(
            """
            INSERT INTO submissions
                (user_id, answer, correct, within_limit, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, answer, 1 if is_correct else 0, 1 if within_limit else 0, created_at),
        )

        if not within_limit:
            return SubmissionResult(
                ok=False,
                message="このIDは回答上限の2回に達しています。入力内容は記録しました。",
                attempts_used=ATTEMPT_LIMIT,
                attempts_remaining=0,
            )

        attempts_used = used_before + 1
        attempts_remaining = max(ATTEMPT_LIMIT - attempts_used, 0)

    if is_correct:
        return SubmissionResult(
            ok=True,
            message="正解です。",
            attempts_used=attempts_used,
            attempts_remaining=attempts_remaining,
            flag=FLAG,
        )

    if attempts_remaining == 0:
        message = "不正解です。このIDは回答上限の2回に達しました。"
    else:
        message = "不正解です。もう1回回答できます。"
    return SubmissionResult(
        ok=False,
        message=message,
        attempts_used=attempts_used,
        attempts_remaining=attempts_remaining,
    )


def check_airport_answer(raw_answer: str) -> SubmissionResult:
    answer = normalize_text(raw_answer)
    if not answer:
        return SubmissionResult(False, "回答を入力してください。", 0, 0)
    if answer == CORRECT_ANSWER:
        return SubmissionResult(True, "正解です。", 0, 0, FLAG)
    return SubmissionResult(False, "不正解です。", 0, 0)


def render_page(result: SubmissionResult | None = None) -> bytes:
    message_html = ""
    if result is not None:
        status_class = "success" if result.ok else "error"
        flag_html = ""
        if result.flag:
            flag_html = f'<p class="flag">{html.escape(result.flag)}</p>'
        message_html = f"""
        <section class="notice {status_class}" aria-live="polite">
          <p>{html.escape(result.message)}</p>
          {flag_html}
        </section>
        """

    return f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Airport Identification | Whereabouts</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #07110f;
      --panel: #0c1c18;
      --panel-soft: #102720;
      --line: rgba(181, 255, 218, 0.17);
      --text: #eefbf5;
      --muted: #9eb9ad;
      --accent: #68f0b2;
      --accent-dark: #09251b;
      --error: #ff9b9b;
      --success: #73f4b8;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system,
        BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 28px;
      color: var(--text);
      background:
        radial-gradient(circle at 84% 0%, rgba(47, 181, 125, 0.16), transparent 34rem),
        linear-gradient(180deg, #081512 0%, var(--bg) 60%);
    }}

    body::before {{
      position: fixed;
      inset: 0;
      z-index: -1;
      content: "";
      opacity: 0.14;
      background-image:
        linear-gradient(rgba(255, 255, 255, 0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.025) 1px, transparent 1px);
      background-size: 32px 32px;
    }}

    main {{
      width: min(100%, 620px);
      padding: clamp(26px, 6vw, 46px);
      border: 1px solid var(--line);
      border-radius: 3px;
      background: linear-gradient(140deg, rgba(16, 39, 32, 0.95), rgba(8, 22, 18, 0.96));
      box-shadow: 0 28px 80px rgba(0, 0, 0, 0.34);
    }}

    .portal-link {{
      display: inline-block;
      margin-bottom: 34px;
      color: var(--accent);
      font-size: 0.9rem;
      font-weight: 700;
      text-decoration: none;
    }}

    .portal-link:hover,
    .portal-link:focus-visible {{
      text-decoration: underline;
    }}

    .eyebrow {{
      margin: 0 0 12px;
      color: var(--accent);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.76rem;
      font-weight: 700;
      letter-spacing: 0.18em;
    }}

    h1 {{
      margin: 0 0 14px;
      font-size: clamp(2rem, 7vw, 3.2rem);
      line-height: 1.05;
      letter-spacing: -0.055em;
    }}

    .lead {{
      margin: 0 0 30px;
      color: #bfd3ca;
      line-height: 1.8;
    }}

    .challenge-image {{
      margin: 0 0 30px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 2px;
      background: rgba(3, 13, 10, 0.72);
    }}

    .challenge-image a {{
      display: block;
      cursor: zoom-in;
    }}

    .challenge-image img {{
      display: block;
      width: 100%;
      max-height: 680px;
      object-fit: contain;
    }}

    .challenge-image figcaption {{
      margin-top: 10px;
      color: var(--muted);
      font-size: 0.8rem;
      text-align: center;
    }}

    form {{
      display: grid;
      gap: 20px;
      padding-top: 6px;
    }}

    label {{
      display: grid;
      gap: 9px;
      font-weight: 700;
    }}

    input {{
      width: 100%;
      min-height: 50px;
      padding: 13px 15px;
      border: 1px solid rgba(181, 255, 218, 0.26);
      border-radius: 2px;
      outline: none;
      color: var(--text);
      background: rgba(3, 13, 10, 0.78);
      font: inherit;
    }}

    input:focus {{
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(104, 240, 178, 0.12);
    }}

    button {{
      min-height: 52px;
      margin-top: 4px;
      border: 1px solid var(--accent);
      border-radius: 2px;
      color: var(--accent-dark);
      background: var(--accent);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-weight: 900;
      letter-spacing: 0.08em;
      cursor: pointer;
      transition: background 150ms ease, transform 150ms ease;
    }}

    button:hover,
    button:focus-visible {{
      background: #a2ffd3;
      transform: translateY(-1px);
    }}

    .notice {{
      margin: 24px 0 0;
      padding: 16px 18px;
      border: 1px solid;
      border-radius: 2px;
      background: rgba(3, 13, 10, 0.5);
    }}

    .notice p {{
      margin: 0;
      line-height: 1.6;
    }}

    .notice .attempts {{
      margin-top: 7px;
      color: var(--muted);
      font-size: 0.86rem;
    }}

    .success {{
      border-color: rgba(115, 244, 184, 0.6);
      color: var(--success);
    }}

    .error {{
      border-color: rgba(255, 155, 155, 0.55);
      color: var(--error);
    }}

    .flag {{
      margin-top: 11px !important;
      color: var(--success);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 1.25rem;
      font-weight: 800;
      overflow-wrap: anywhere;
    }}

    @media (max-width: 560px) {{
      body {{ padding: 14px; }}
      main {{ padding: 25px 20px; }}
      .portal-link {{ margin-bottom: 26px; }}
    }}
  </style>
</head>
<body>
  <main>
    <a class="portal-link" href="/">← ミッション選択へ戻る</a>
    <p class="eyebrow">MISSION 01</p>
    <h1>Airport Identification</h1>
    <p class="lead">画像を調査し、撮影された空港の名称を特定してください。特定した空港について、公式サイトに記述されている公式名称を回答してください。</p>
    <figure class="challenge-image">
      <a href="/airport/image.jpg" target="_blank" rel="noopener">
        <img src="/airport/image.jpg" alt="空港を特定するための問題画像">
      </a>
      <figcaption>画像をクリックすると別タブで表示します。</figcaption>
    </figure>
    <form method="post" action="/airport/submit" autocomplete="off">
      <label>
        回答（空港名）
        <input name="answer" placeholder="〇〇空港" required>
      </label>
      <button type="submit">送信</button>
    </form>
    {message_html}
  </main>
</body>
</html>
""".encode("utf-8")


def render_portal() -> bytes:
    return """<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Whereabouts</title>
  <style>
    :root { color-scheme: dark; --bg:#07110f; --panel:#10231d; --line:rgba(181,255,218,.18); --text:#eefbf5; --muted:#a2b9af; --accent:#68f0b2; }
    * { box-sizing: border-box; }
    body { min-height:100vh; margin:0; display:grid; place-items:center; padding:28px; color:var(--text); background:radial-gradient(circle at 85% 5%,rgba(47,181,125,.2),transparent 35rem),var(--bg); font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(900px,100%); }
    .eyebrow { margin:0 0 12px; color:var(--accent); font:700 .78rem ui-monospace,monospace; letter-spacing:.18em; }
    h1 { margin:0; font-size:clamp(2.8rem,9vw,6rem); letter-spacing:-.06em; }
    .lead { margin:18px 0 42px; color:var(--muted); line-height:1.7; }
    .challenges { display:grid; grid-template-columns:repeat(2,1fr); gap:20px; }
    .challenge { display:flex; min-height:230px; flex-direction:column; padding:28px; border:1px solid var(--line); border-radius:4px; color:var(--text); background:linear-gradient(145deg,rgba(16,35,29,.96),rgba(8,22,18,.96)); text-decoration:none; transition:transform .16s ease,border-color .16s ease; }
    .challenge:hover,.challenge:focus-visible { border-color:var(--accent); outline:none; transform:translateY(-4px); }
    .number { color:var(--accent); font:700 .78rem ui-monospace,monospace; }
    h2 { margin:22px 0 10px; font-size:1.7rem; }
    .challenge p { margin:0; color:var(--muted); line-height:1.65; }
    .open { margin-top:auto; padding-top:24px; color:var(--accent); font-weight:800; }
    @media (max-width:650px) { .challenges { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <main>
    <h1>Whereabouts</h1>
    <p class="lead">挑戦するミッションを選択してください。</p>
    <div class="challenges">
      <a class="challenge" href="/airport">
        <span class="number">MISSION 01</span>
        <h2>Airport Identification</h2>
        <p>画像を調査し、撮影された空港の名称を特定してください。</p>
        <span class="open">OPEN MISSHON →</span>
      </a>
      <a class="challenge" href="/photo-recovery/">
        <span class="number">MISSION 02</span>
        <h2>Photo Recovery</h2>
        <p>実際に撮影された写真を見つけ、その地点を特定してください。</p>
        <span class="open">OPEN MISSION →</span>
      </a>
    </div>
  </main>
</body>
</html>
""".encode("utf-8")


class FlagFormHandler(BaseHTTPRequestHandler):
    db_path: Path = DEFAULT_DB_PATH

    def send_html(self, body: bytes, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: dict[str, object], status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_photo_file(self, relative_path: str) -> None:
        relative_path = relative_path or "index.html"
        target = (PHOTO_PUBLIC_DIR / relative_path).resolve()
        if target != PHOTO_PUBLIC_DIR and PHOTO_PUBLIC_DIR not in target.parents:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self.send_html(render_portal())
            return
        if path == "/airport":
            self.send_html(render_page())
            return
        if path == "/airport/image.jpg":
            if not AIRPORT_IMAGE_PATH.is_file():
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            body = AIRPORT_IMAGE_PATH.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/photo-recovery":
            self.send_response(HTTPStatus.PERMANENT_REDIRECT)
            self.send_header("Location", "/photo-recovery/")
            self.end_headers()
            return
        if path.startswith("/photo-recovery/"):
            self.send_photo_file(path.removeprefix("/photo-recovery/"))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/photo-recovery/api/submit":
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_json({"ok": False, "message": "不正なリクエストです。"}, 400)
                return
            if content_length < 1 or content_length > 2048:
                self.send_json({"ok": False, "message": "回答を入力してください。"}, 400)
                return
            try:
                payload = json.loads(self.rfile.read(content_length))
                answer = str(payload.get("answer", ""))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_json({"ok": False, "message": "不正なリクエストです。"}, 400)
                return
            ok, message, status = check_photo_answer(answer)
            self.send_json({"ok": ok, "message": message}, status)
            return

        if path not in {"/airport/submit", "/submit"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if content_length > MAX_BODY_BYTES:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = parse_qs(body, keep_blank_values=True)
        answer = params.get("answer", [""])[0]
        result = check_airport_answer(answer)
        self.send_html(render_page(result))

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")

def serve(host: str, port: int, db_path: Path) -> None:
    with ThreadingHTTPServer((host, port), FlagFormHandler) as server:
        print(f"listening on http://{host}:{port}", flush=True)
        server.serve_forever()


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.sqlite3"

        first = record_submission(db_path, "alice", "長崎空港")
        if not first.ok or first.flag != FLAG or first.attempts_used != 1:
            print("selftest failed: correct first answer was not accepted")
            return 1

        wrong1 = record_submission(db_path, "bob", "福岡空港")
        wrong2 = record_submission(db_path, "bob", "羽田空港")
        blocked = record_submission(db_path, "bob", "長崎空港")
        blocked_again = record_submission(db_path, "bob", "成田空港")
        if wrong1.ok or wrong2.ok or blocked.ok or blocked_again.ok:
            print("selftest failed: wrong or blocked submission was accepted")
            return 1
        if wrong2.attempts_remaining != 0 or blocked.attempts_used != ATTEMPT_LIMIT:
            print("selftest failed: attempt limit was not enforced")
            return 1

        with sqlite3.connect(db_path) as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            submission_count = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]
            blocked_rows = conn.execute(
                """
                SELECT answer, correct, within_limit
                FROM submissions
                WHERE user_id = ? AND within_limit = 0
                ORDER BY id
                """,
                ("bob",),
            ).fetchall()
        if user_count != 2 or submission_count != 5:
            print("selftest failed: database counts are incorrect")
            return 1
        if blocked_rows != [("長崎空港", 1, 0), ("成田空港", 0, 0)]:
            print("selftest failed: blocked submissions were not recorded correctly")
            return 1

    print("selftest ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Airport flag form")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--db",
        default=os.environ.get("AIRPORT_FORM_DB", str(DEFAULT_DB_PATH)),
        help="SQLite database path",
    )
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    if args.selftest:
        return selftest()

    serve(args.host, args.port, db_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
