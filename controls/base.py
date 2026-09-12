"""Shared types for all control checkers. Keep it tiny and dependency-free."""
from dataclasses import dataclass, field
from typing import Literal

Status = Literal["PASS", "FAIL", "SKIP"]

@dataclass
class CheckResult:
    rule_id: int
    name: str
    status: Status
    detail: str = ""
    evidence: list = field(default_factory=list)  # lines a third party can inspect

    def __str__(self) -> str:
        mark = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "skip"}[self.status]
        return f"[{mark}] rule {self.rule_id}: {self.name} - {self.detail}"
