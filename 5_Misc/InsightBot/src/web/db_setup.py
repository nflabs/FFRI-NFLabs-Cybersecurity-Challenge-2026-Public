import os
import sqlite3

DB_PATH = os.environ.get("DB_PATH", "/tmp/insight.db")
FLAG = os.environ.get("FLAG", "flag{pr0mpt_rul3s_are_not_security_b0undaries}")

_ASSETS = [
    (1, "web-prod-01", "192.0.2.10", "Ubuntu 22.04", "platform", "prod"),
    (2, "web-prod-02", "192.0.2.11", "Ubuntu 22.04", "platform", "prod"),
    (3, "db-prod-01", "10.0.12.5", "Debian 12", "data", "prod"),
    (4, "vpn-gw-01", "198.51.100.7", "pfSense 2.7", "network", "prod"),
    (5, "jenkins-ci", "10.0.20.30", "Ubuntu 20.04", "devops", "stg"),
    (6, "ad-dc-01", "10.0.5.2", "Windows Server 2022", "it", "prod"),
    (7, "mail-01", "192.0.2.25", "Debian 12", "it", "prod"),
    (8, "k8s-node-03", "10.0.30.13", "Flatcar 3815", "platform", "prod"),
]

_FINDINGS = [
    (1, 1, "CVE-2021-44228", "CRITICAL", "open", "2025-05-02"),
    (2, 3, "CVE-2014-0160", "HIGH", "fixed", "2025-04-18"),
    (3, 6, "CVE-2020-1472", "CRITICAL", "open", "2025-05-10"),
    (4, 4, "CVE-2018-13379", "HIGH", "open", "2025-05-11"),
    (5, 5, "CVE-2024-23897", "HIGH", "open", "2025-05-20"),
    (6, 2, "CVE-2023-44487", "MEDIUM", "fixed", "2025-05-21"),
    (7, 7, "CVE-2023-38408", "MEDIUM", "open", "2025-05-24"),
    (8, 8, "CVE-2022-0492", "HIGH", "open", "2025-05-27"),
    (9, 1, "CVE-2023-4863", "HIGH", "open", "2025-06-01"),
    (10, 3, "CVE-2019-5736", "CRITICAL", "fixed", "2025-06-03"),
    (11, 6, "CVE-2021-34527", "HIGH", "open", "2025-06-05"),
    (12, 2, "CVE-2022-22965", "MEDIUM", "open", "2025-06-06"),
]

_SCANS = [
    (1, 1, "2025-06-01", 2),
    (2, 2, "2025-06-01", 2),
    (3, 3, "2025-06-02", 2),
    (4, 4, "2025-06-02", 1),
    (5, 5, "2025-06-03", 1),
    (6, 6, "2025-06-03", 2),
    (7, 7, "2025-06-04", 1),
    (8, 8, "2025-06-04", 1),
]

_CUSTOMERS = [
    (1, "Meridian Bank", "finance", "enterprise"),
    (2, "Aster Health", "healthcare", "pro"),
    (3, "Northwind Retail", "retail", "pro"),
    (4, "Volta Energy", "energy", "enterprise"),
    (5, "Pico Games", "gaming", "starter"),
    (6, "Cirrus Logistics", "logistics", "pro"),
]

_INCIDENTS = [
    (1, 1, "CRITICAL", "2025-06-02 03:14", "investigating"),
    (2, 4, "HIGH", "2025-06-03 11:47", "contained"),
    (3, 2, "MEDIUM", "2025-06-04 09:02", "resolved"),
    (4, 3, "LOW", "2025-06-05 16:30", "resolved"),
    (5, 6, "HIGH", "2025-06-06 22:05", "investigating"),
]

_SECRET = [
    ("admin_api_key", FLAG),
    ("siem_ingest_token", "sk_live_9d2f7a1c8b3e4f60a5c1d7e8"),
    ("report_signing_key", "rs256:MFkwEwYHKoZIzj0CAQYIK-DEMO-DoNotUse"),
    ("redteam_c2_password", "Autumn!C2-Overlord-2025"),
    ("db_backup_path", "/var/backups/sentinel.db"),
]


def init_db(path: str = DB_PATH) -> None:
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE assets    (id INTEGER, hostname TEXT, ip TEXT, os TEXT, owner TEXT, env TEXT);
            CREATE TABLE findings  (id INTEGER, asset_id INTEGER, cve TEXT, severity TEXT, status TEXT, found_on TEXT);
            CREATE TABLE scans     (id INTEGER, asset_id INTEGER, scanned_on TEXT, findings_count INTEGER);
            CREATE TABLE customers (id INTEGER, name TEXT, industry TEXT, plan TEXT);
            CREATE TABLE incidents (id INTEGER, customer_id INTEGER, severity TEXT, opened_at TEXT, status TEXT);
            CREATE TABLE secret_config (key TEXT, value TEXT);
            """
        )
        cur.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?)", _ASSETS)
        cur.executemany("INSERT INTO findings VALUES (?,?,?,?,?,?)", _FINDINGS)
        cur.executemany("INSERT INTO scans VALUES (?,?,?,?)", _SCANS)
        cur.executemany("INSERT INTO customers VALUES (?,?,?,?)", _CUSTOMERS)
        cur.executemany("INSERT INTO incidents VALUES (?,?,?,?,?)", _INCIDENTS)
        cur.executemany("INSERT INTO secret_config VALUES (?,?)", _SECRET)
        conn.commit()
    finally:
        conn.close()
