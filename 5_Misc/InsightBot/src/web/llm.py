import logging
import os
import time

import requests

log = logging.getLogger("insightbot")

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
MODEL = os.environ.get("MODEL", "qwen2.5-coder:3b-instruct")
TEMPERATURE = float(os.environ.get("TEMPERATURE", "0.1"))
TOP_P = float(os.environ.get("TOP_P", "0.9"))
SEED = int(os.environ.get("SEED", "42"))
NUM_PREDICT = int(os.environ.get("NUM_PREDICT", "256"))
_KEEP_ALIVE_RAW = os.environ.get("KEEP_ALIVE", "-1")
try:
    KEEP_ALIVE = int(_KEEP_ALIVE_RAW)
except ValueError:
    KEEP_ALIVE = _KEEP_ALIVE_RAW
TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "120"))


def wait_ready(timeout: int = 180) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
            if r.ok:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


def pull(model: str) -> None:
    requests.post(f"{OLLAMA_HOST}/api/pull", json={"name": model}, timeout=600).raise_for_status()


def warmup() -> None:
    try:
        generate("SELECT 1;")
    except Exception as e:
        log.warning("warmup failed: %s", e)


def generate(prompt: str, system: str = "") -> str:
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "keep_alive": KEEP_ALIVE,
        "options": {
            "temperature": TEMPERATURE,
            "top_p": TOP_P,
            "seed": SEED,
            "num_predict": NUM_PREDICT,
        },
    }
    r = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json().get("response", "")
