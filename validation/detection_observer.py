"""JSONL worker for detection in an independent process.

Requests arrive on stdin and responses are written to stdout. Keeping the
observer out of the generator process gives it separate rule logic and a
separate clock while remaining deterministic and API-free.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

from validation.detection_rules import detect


MAX_REQUEST_BYTES = 1_000_000


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def handle_request(request):
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        raise ValueError("request_id must be a non-empty string")
    received_at = _utc_now()
    started_ns = time.perf_counter_ns()
    detected = detect(request.get("rule_id"), request.get("payload"))
    elapsed_ns = time.perf_counter_ns() - started_ns
    alerted_at = _utc_now() if detected else None
    return {
        "request_id": request_id,
        "detected": detected,
        "received_at": received_at,
        "alerted_at": alerted_at,
        "observer_elapsed_ns": elapsed_ns,
        "observer_pid": os.getpid(),
    }


def main():
    for line_number, line in enumerate(sys.stdin, 1):
        try:
            if len(line.encode()) > MAX_REQUEST_BYTES:
                raise ValueError("request exceeds size limit")
            response = handle_request(json.loads(line))
        except Exception as exc:
            response = {
                "request_id": None,
                "detected": False,
                "error": f"line {line_number}: {type(exc).__name__}: {exc}",
            }
        print(json.dumps(response, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
