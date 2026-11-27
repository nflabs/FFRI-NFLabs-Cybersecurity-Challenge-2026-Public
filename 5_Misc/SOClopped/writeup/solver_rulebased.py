#!/usr/bin/env python3
"""
SOClopped — ルールベース solver

Usage: python3 solver_rulebased.py [host] [port]
"""

import json
import re
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 25001

FIXED_REASON = "fixed reason"

RULES = [
    # ---- CRITICAL ----
    ("lsass",                   "critical", "isolate_host"),   # 資格情報ダンプ
    ("mimikatz",                "critical", "isolate_host"),   # 資格情報ダンプ
    ("jndi:ldap",               "critical", "isolate_host"),   # Log4Shell
    ("vssadmin delete shadows", "critical", "isolate_host"),   # ランサムウェア
    ("how_to_restore",          "critical", "isolate_host"),   # ランサムウェア
    ("cobaltstrike stager",     "critical", "isolate_host"),   # CS stager
    ("paste.example",           "critical", "isolate_host"),   # CI ワークフローで secrets 流出
    ("deletedetector",          "critical", "escalate"),       # GuardDuty 無効化
    ("deactivatemfadevice",     "critical", "escalate"),       # root MFA 無効化
    # ---- HIGH ----
    ("ja3=known-cobaltstrike",  "high",     "block_ip"),       # 生 syslog 中の C2 ビーコン
    ("freshly registered",      "high",     "block_ip"),       # look-alike C2 ドメイン
    ("attempt_bypass",          "high",     "escalate"),       # MFA
    ("personal_access_token",   "high",     "revoke_token"),   # broad PAT + 一括クローン
    # ---- LOW----
    ("usual corporate range",   "low",      "close"),
    ("eicar",                   "low",      "close"),
    ("salesforce",              "low",      "close"),
    ("corporate nessus",        "low",      "close"),
    ("approved maintenance window", "low",  "close"),
    ("net-889",                 "low",      "close"),
    ("certificate expires",     "low",      "close"),
    ("self-service enrollment", "low",      "close"),
    ("password expired",        "low",      "close"),
    ("egress ip migration",     "low",      "close"),
    ("quarantined automatically","low",     "close"),
    ("blocked at the edge",     "low",      "close"),
    ("no affected asset",       "low",      "close"),
    ("new mfa factor enrolled", "low",      "close"),
    ("authorized pentest",      "low",      "close"),
]

def classify(alert):
    low = alert.lower()
    for kw, sev, act in RULES:
        if kw in low:
            return {"severity": sev, "action": act, "reason": FIXED_REASON}
    # 未知はmedium判定
    # 誤答なら切断されるので、そのときにアラート本文を見て RULES に足したり修正したりする
    return {"severity": "medium", "action": "escalate", "reason": FIXED_REASON}


def recv_alert(s):
    """次のプロンプト '> ' まで受信してアラートの本文を返す。(buf, closed)"""
    buf = ""
    while not buf.rstrip().endswith("\n>"):
        try:
            data = s.recv(4096).decode(errors="replace")
        except socket.timeout:
            return buf, True
        if not data:
            return buf, True
        buf += data
    return buf, False


def main():
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.settimeout(30)
    transcript = []
    recv_alert(s)                     # バナー＋開始待ち
    s.sendall(b"go\n")                # 出題開始
    while True:
        alert, closed = recv_alert(s)
        transcript.append(alert)
        if closed:
            break                     # フラグ or 切断メッセージ
        verdict = classify(alert)
        s.sendall((json.dumps(verdict) + "\n").encode())
    full = "".join(transcript)
    sys.stdout.write(full if full.endswith("\n") else full + "\n")
    for fm in set(re.findall(r"flag\{[^}]*\}", full)):
        print("FLAG:", fm)


if __name__ == "__main__":
    main()
