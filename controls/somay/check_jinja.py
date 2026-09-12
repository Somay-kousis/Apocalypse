"""Rule 5: no template engine evaluates user-supplied dataset config."""
from pathlib import Path
from controls.base import CheckResult

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "config_pipeline.txt"
    if not cfg.exists():
        return CheckResult(5, "No template eval on untrusted config", "FAIL",
                           "no config_pipeline.txt: template rendering on config unverified")
    text = cfg.read_text().lower()
    renders = "render_template" in text or "jinja2.template(" in text or "from_string" in text
    sandboxed = "sandboxedenvironment" in text
    if renders and not sandboxed:
        return CheckResult(5, "No template eval on untrusted config", "FAIL",
                           "config path renders templates without SandboxedEnvironment",
                           evidence=[f"{cfg}: template rendering present"])
    return CheckResult(5, "No template eval on untrusted config", "PASS",
                       "no unsandboxed template eval on config paths", evidence=[str(cfg)])
