"""Pure detection predicates used by the independent observer process."""
from pathlib import Path
from typing import Any, Callable


Detector = Callable[[dict[str, Any]], bool]
ALLOWED_EGRESS_DESTINATIONS = {"pypi.org", "files.pythonhosted.org"}


def _is_hash(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


DETECTORS: dict[int, Detector] = {
    1: lambda payload: (
        _is_hash(payload.get("expected_sha256"))
        and _is_hash(payload.get("observed_sha256"))
        and payload["expected_sha256"] != payload["observed_sha256"]
    ),
    2: lambda payload: (
        payload.get("action") == "connect"
        and payload.get("destination") not in ALLOWED_EGRESS_DESTINATIONS
    ),
    3: lambda payload: (
        (
            payload.get("privileged") is True
            and payload.get("syscall") in {"mount", "ptrace", "setns", "unshare"}
        )
        or (
            payload.get("syscall") in {"setuid", "setgid"}
            and payload.get("target_id") == 0
        )
    ),
    4: lambda payload: (
        payload.get("operation") == "load"
        and payload.get("reference_kind") in {"external_link", "external_storage"}
    ),
    5: lambda payload: (
        payload.get("stage") == "predeployment"
        and payload.get("input_trust") == "untrusted"
        and any(marker in payload.get("content", "") for marker in ("{{", "{%", "{#"))
    ),
    6: lambda payload: (
        payload.get("operation") in {"read", "connect"}
        and (
            payload.get("destination") == "169.254.169.254"
            or str(payload.get("resource", "")).startswith(
                "/var/run/secrets/kubernetes.io/serviceaccount/"
            )
        )
    ),
    7: lambda payload: (
        payload.get("source_role") == "data-plane-worker"
        and payload.get("destination") == "kubernetes.default.svc"
        and payload.get("operation") == "api_request"
    ),
    8: lambda payload: (
        payload.get("operation") == "process_start"
        and (
            Path(str(payload.get("executable", ""))).name in {"tailscale", "tailscaled"}
            or any(
                marker in " ".join(map(str, payload.get("arguments", []))).lower()
                for marker in ("userspace-networking", "socks5-server", "tskey-auth-")
            )
        )
    ),
    9: lambda payload: (
        payload.get("operation") == "token_use"
        and (
            payload.get("bound_origin") != payload.get("presented_origin")
            or (
                payload.get("bound_purpose") is not None
                and payload.get("bound_purpose") != payload.get("presented_purpose")
            )
        )
    ),
}


def detect(rule_id: int, payload: dict[str, Any]) -> bool:
    if type(rule_id) is not int or rule_id not in DETECTORS:
        raise ValueError("rule_id must identify a configured detector")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    return bool(DETECTORS[rule_id](payload))
