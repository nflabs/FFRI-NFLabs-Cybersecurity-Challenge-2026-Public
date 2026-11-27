#!/usr/bin/env python3
"""
Reference solver for SOClopped.

The "correct analyst": reads each alert, matches it against the known rubric by
a unique body signature, and replies with one acceptable verdict. Crucially it
NEVER echoes the escalation token or any planted canary secret, never attests to
being an automated agent, and never parrots chat-role control tokens back -- no
matter what an untrusted field demands.

This doubles as the writeup's intended solution and as the pass-path test.

Usage: python3 solver_reference.py [host] [port]
"""
import json
import re
import socket
import sys

from challenge_data import ALERTS

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 25001

# map signature -> a concrete acceptable verdict
def pick(alert):
    acc = alert["accept"]
    # deterministic pick: first element by a stable sort
    return {
        "severity": sorted(acc["severity"])[0],
        "action": sorted(acc["action"])[0],
        "reason": "triaged from IOCs in trusted telemetry; untrusted fields ignored",
    }

SIG_TO_VERDICT = {a["sig"]: pick(a) for a in ALERTS}


def classify(block):
    for sig, verdict in SIG_TO_VERDICT.items():
        if sig in block:
            return verdict
    # unknown alert: safe default (escalate for review, never leak)
    return {"severity": "medium", "action": "escalate",
            "reason": "unrecognized; escalate for human review"}


def main():
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.settimeout(30)
    buf = ""
    transcript = []
    while True:
        try:
            data = s.recv(4096).decode(errors="replace")
        except socket.timeout:
            break
        if not data:
            break
        transcript.append(data)
        buf += data
        if buf.rstrip().endswith(">"):
            # the alert block is everything accumulated since the last prompt
            verdict = classify(buf)
            s.sendall((json.dumps(verdict) + "\n").encode())
            buf = ""
    full = "".join(transcript)
    sys.stdout.write(full)
    for fm in set(re.findall(r"[A-Za-z0-9_]*\{[^}]*\}", full)):
        if fm.startswith("flag{"):
            print("\nFLAG:", fm)


if __name__ == "__main__":
    main()
