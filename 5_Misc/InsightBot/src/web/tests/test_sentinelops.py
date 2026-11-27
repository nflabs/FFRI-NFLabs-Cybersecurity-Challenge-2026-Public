import ipaddress
import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db_setup

FLAG = db_setup.FLAG
WEB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(WEB_DIR, "templates", "index.html")

BASE = os.environ.get("INSIGHTBOT_URL", "http://localhost:25002")

EXPECTED_SCHEMA = {
    "assets": ["id", "hostname", "ip", "os", "owner", "env"],
    "findings": ["id", "asset_id", "cve", "severity", "status", "found_on"],
    "scans": ["id", "asset_id", "scanned_on", "findings_count"],
    "customers": ["id", "name", "industry", "plan"],
    "incidents": ["id", "customer_id", "severity", "opened_at", "status"],
    "secret_config": ["key", "value"],
}
PUBLIC_TABLES = [t for t in EXPECTED_SCHEMA if t != "secret_config"]

ALLOWED_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
)]
EXPECTED_SECRET_KEYS = {
    "admin_api_key", "siem_ingest_token", "report_signing_key",
    "redteam_c2_password", "db_backup_path",
}


def _cols(conn, table):
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


class TestSchemaAndData(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = os.path.join(cls.tmp, "insight.db")
        db_setup.init_db(cls.db)
        cls.conn = sqlite3.connect(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_tables_and_columns(self):
        got = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        self.assertEqual(got, set(EXPECTED_SCHEMA), f"テーブル集合が想定と一致すべき: {got}")
        for table, cols in EXPECTED_SCHEMA.items():
            with self.subTest(table=table):
                self.assertEqual(_cols(self.conn, table), cols)

    def test_public_tables_have_rows(self):
        for t in PUBLIC_TABLES:
            with self.subTest(table=t):
                n = self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                self.assertGreater(n, 0, f"{t} にダミー行があるべき")

    def test_asset_ips_in_reserved_ranges(self):
        for (ip,) in self.conn.execute("SELECT ip FROM assets").fetchall():
            with self.subTest(ip=ip):
                addr = ipaddress.ip_address(ip)
                self.assertTrue(any(addr in n for n in ALLOWED_NETS),
                                f"予約帯外のIPは使用不可: {ip}")

    def test_findings_reference_valid_cves_and_assets(self):
        asset_ids = {r[0] for r in self.conn.execute("SELECT id FROM assets").fetchall()}
        for aid, cve in self.conn.execute("SELECT asset_id, cve FROM findings").fetchall():
            with self.subTest(cve=cve):
                self.assertRegex(cve, r"^CVE-\d{4}-\d{4,}$", f"CVE形式が不正: {cve}")
                self.assertIn(aid, asset_ids, f"findings.asset_id が assets に無い: {aid}")

    def test_severity_and_status_domains(self):
        sev = {r[0] for r in self.conn.execute("SELECT DISTINCT severity FROM findings").fetchall()}
        self.assertTrue(sev <= {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, sev)
        st = {r[0] for r in self.conn.execute("SELECT DISTINCT status FROM findings").fetchall()}
        self.assertTrue(st <= {"open", "fixed"}, st)

    def test_secret_config_holds_flag_and_decoys(self):
        rows = dict(self.conn.execute("SELECT key, value FROM secret_config").fetchall())
        self.assertEqual(set(rows), EXPECTED_SECRET_KEYS, "本命＋囮キーが揃うべき")
        self.assertEqual(rows["admin_api_key"], FLAG, "admin_api_key がフラグであるべき")

    def test_flag_only_in_secret_config(self):
        for t in PUBLIC_TABLES:
            with self.subTest(table=t):
                rows = self.conn.execute(f"SELECT * FROM {t}").fetchall()
                self.assertFalse(any(FLAG in str(c) for r in rows for c in r))


def _read_suggestions():
    with open(INDEX_HTML, encoding="utf-8") as f:
        html = f.read()
    m = re.search(r"const\s+SUGGESTIONS\s*=\s*\[(.*?)\]", html, re.DOTALL)
    if not m:
        return []
    return re.findall(r'"([^"]+)"', m.group(1))


def _server_up():
    try:
        with urllib.request.urlopen(BASE + "/health", timeout=3) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


def _ask(question, attempts=2):
    last = None
    for _ in range(attempts):
        req = urllib.request.Request(
            BASE + "/ask", data=json.dumps({"question": question}).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=120) as r:
            last = json.loads(r.read().decode("utf-8"))
        if last.get("rows") is not None and not last.get("error") and not last.get("blocked"):
            return last
    return last


class TestSuggestionChips(unittest.TestCase):

    def test_index_has_suggestions(self):
        self.assertGreaterEqual(len(_read_suggestions()), 1, "SUGGESTIONS を抽出できるべき")

    @unittest.skipUnless(_server_up(), f"server not reachable at {BASE} (docker compose up が必要)")
    def test_every_chip_returns_rows(self):
        chips = _read_suggestions()
        self.assertTrue(chips, "チップが空でない")
        for q in chips:
            with self.subTest(chip=q):
                d = _ask(q)
                self.assertIsNotNone(d)
                self.assertFalse(d.get("error"), f"チップがエラーになる: {q!r} -> {d}")
                self.assertFalse(d.get("blocked"), f"チップがブロックされる: {q!r} -> {d}")
                self.assertGreater(len(d.get("rows", [])), 0,
                                   f"チップが結果を返さない: {q!r} -> {d.get('sql')!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
