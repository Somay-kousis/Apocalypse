"""Rule 5: no template engine evaluates untrusted dataset config.
NOW EXECUTES: fires a real SSTI payload (the incident's cycler/__globals__ class-walk) at the
environment implied by the pipeline config. Plain jinja2.Environment evaluates it (injection
works) -> FAIL; SandboxedEnvironment raises SecurityError -> PASS; config parsed as data
(no templating) -> PASS. Fully offline."""
from pathlib import Path
from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment
from jinja2.exceptions import SecurityError
from controls.base import CheckResult

# classic SSTI probe: walk from a literal to Python internals (what enables RCE)
SSTI = "{{ ''.__class__.__mro__[1].__subclasses__() }}"

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "b5_jinja" / "config_pipeline.txt"
    if not cfg.exists():
        return CheckResult(5, "No template eval on untrusted config", "FAIL",
                           "no config_pipeline.txt: template rendering on config unverified")
    text = cfg.read_text().lower()
    if "sandboxedenvironment" in text:
        mode = "sandboxed"
    elif any(m in text for m in ("render_template", "from_string", ".render(", "template(", "jinja")):
        mode = "unsafe"
    else:
        mode = "norender"   # parsed as data (yaml.safe_load etc.)

    if mode == "norender":
        return CheckResult(5, "No template eval on untrusted config", "PASS",
                           "config parsed as data; template engine never touches untrusted config",
                           evidence=[str(cfg)])
    if mode == "sandboxed":
        try:
            SandboxedEnvironment().from_string(SSTI).render()
            return CheckResult(5, "No template eval on untrusted config", "FAIL",
                               "SandboxedEnvironment rendered the SSTI payload (sandbox ineffective)",
                               evidence=[str(cfg)])
        except SecurityError:
            return CheckResult(5, "No template eval on untrusted config", "PASS",
                               "SSTI payload blocked by SandboxedEnvironment (SecurityError)",
                               evidence=[str(cfg)])
    # unsafe: prove the injection actually evaluates internals
    out = Environment().from_string(SSTI).render()
    return CheckResult(5, "No template eval on untrusted config", "FAIL",
                       f"SSTI payload evaluated on untrusted config -> reached Python internals "
                       f"({len(out)} chars of subclass list)", evidence=[str(cfg)])
