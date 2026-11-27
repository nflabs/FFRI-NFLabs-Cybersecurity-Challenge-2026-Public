#!/usr/bin/env python3
"""
SOClopped — 総当たり solver

Usage: python3 solver_bruteforce.py [host] [port]
"""

import itertools
import json
import re
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 25001

FIXED_REASON = "fixed reason"

severity_list = "low / medium / high / critical".split(" / ")
action_list = "close / monitor / escalate / isolate_host / reset_password / revoke_token / disable_user / block_ip".split(" / ")
known_answer_list = {}

def recv_alert(s):
    """次のプロンプト '> ' まで受信してアラートの本文を返す。(buf, closed)"""
    buf = ""
    while not buf.rstrip().endswith("\n>"):
        try:
            data = s.recv(1).decode(errors="replace") # アラートごとに判断したいので、1文字ずつ受信する
        except socket.timeout:
            return buf, True
        if not data:
            return buf, True
        buf += data
    return buf, False

def attack_next_challenge(known_answer_list: list[str]) -> str | None:
    for severity, action in itertools.product(severity_list, action_list):
        with socket.create_connection((HOST, PORT), timeout=30) as s:
            recv_alert(s)
            s.sendall(b"go\n") # 出題開始

            for answer in known_answer_list:
                s.sendall(answer.encode() + b"\n")

            obj = {
                "severity": severity,
                "action": action,
                "reason": "BRUTE FORCE",
            }
            line = json.dumps(obj)

            for i in range(len(known_answer_list) + 1): # including current alert
                recv_alert(s)
            s.sendall(line.encode() + b"\n")
            alert_result, closed = recv_alert(s) # receive result
            if "[SOAR] verdict accepted." in alert_result:
                return line
            else:
                continue
    return None


def main():
    known_answer_list = []
    print(f"{len(known_answer_list) = }")

    # 全アラートを1つずつ、各種選択肢を総当たりする
    for i in range(len(known_answer_list), 40):
        print(f"{i = }")
        answer = attack_next_challenge(known_answer_list)
        if answer is None:
            raise SystemExit("COULDN'T SOLVE")
        else:
            known_answer_list.append(answer)

    # 全アラートに対する正しい解答を送信してフラグを得る
    with socket.create_connection((HOST, PORT), timeout=30) as s:
        recv_alert(s)
        s.sendall(b"go\n") # 出題開始
        for answer in known_answer_list:
            s.sendall(answer.encode() + b"\n")

        transcript = []
        while True:
            alert, closed = recv_alert(s)
            transcript.append(alert)
            if closed:
                break                     # フラグ or 切断メッセージ
        full = "".join(transcript)
        sys.stdout.write(full if full.endswith("\n") else full + "\n")
        for fm in set(re.findall(r"flag\{[^}]*\}", full)):
            print("FLAG:", fm)


if __name__ == "__main__":
    main()
