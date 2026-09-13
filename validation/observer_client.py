"""Client for the independent JSONL detection observer."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class ObserverClient:
    def __init__(self):
        self.process = None

    def __enter__(self):
        self.process = subprocess.Popen(
            [sys.executable, "-m", "validation.detection_observer"],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        return self

    def observe(self, request_id: str, rule_id: int, payload: dict):
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("observer process is not running")
        request = {"request_id": request_id, "rule_id": rule_id, "payload": payload}
        self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        response_line = self.process.stdout.readline()
        if not response_line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"observer exited without a response: {stderr.strip()}")
        response = json.loads(response_line)
        if response.get("error"):
            raise RuntimeError(response["error"])
        if response.get("request_id") != request_id:
            raise RuntimeError("observer response request_id mismatch")
        if type(response.get("detected")) is not bool:
            raise RuntimeError("observer returned non-boolean detected status")
        return response

    def __exit__(self, exc_type, exc, traceback):
        if self.process is None:
            return
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=3)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()
