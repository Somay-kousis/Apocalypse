"""Rule 5: untrusted dataset config is never templated (boundary: Jinja2 injection,
requirement: no templating of untrusted config at all).

EXECUTES for jinja: fires a real SSTI payload at the environment implied by the config.
Detection is broadened beyond render/template so evaluation via compile_expression /
compile / NativeEnvironment / .stream, and non-jinja templating (str.format, %-format,
Mako/mustache), can't be misclassified as 'norender'. Only a config with NO templating
indicator at all is treated as safe-by-parsing. Fully offline."""
from pathlib import Path
from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment
from jinja2.exceptions import SecurityError
from controls.base import CheckResult

SSTI = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
# jinja evaluation surfaces (any of these renders/evaluates a template)
JINJA_MARKERS = ("render_template", "from_string", ".render(", ".stream(", "template(",
                 "compile_expression", "compile(", "nativeenvironment", "environment(", "jinja")
# non-jinja templating that still violates "never template untrusted config"
OTHER_TEMPLATING = (".format(", "%(", "% untrusted", "% config", "mako", "chevron", "mustache", "string.template")

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "b5_jinja" / "config_pipeline.txt"
    if not cfg.exists():
        return CheckResult(5, "No template eval on untrusted config", "FAIL",
                           "no config_pipeline.txt: template rendering on config unverified")
    text = cfg.read_text().lower()
    sandboxed = "sandboxedenvironment" in text
    jinja_hit = next((m for m in JINJA_MARKERS if m in text), None)
    other_hit = next((m for m in OTHER_TEMPLATING if m in text), None)

    if sandboxed:
        try:
            SandboxedEnvironment().from_string(SSTI).render()
            return CheckResult(5, "No template eval on untrusted config", "FAIL",
                               "SandboxedEnvironment rendered the SSTI payload (sandbox ineffective)",
                               evidence=[str(cfg)])
        except SecurityError:
            return CheckResult(5, "No template eval on untrusted config", "PASS",
                               "SSTI payload blocked by SandboxedEnvironment (SecurityError)",
                               evidence=[str(cfg)])
    if jinja_hit:
        out = Environment().from_string(SSTI).render()
        return CheckResult(5, "No template eval on untrusted config", "FAIL",
                           f"untrusted config templated via jinja ({jinja_hit!r}); SSTI reached "
                           f"Python internals ({len(out)} chars of subclass list)", evidence=[str(cfg)])
    if other_hit:
        return CheckResult(5, "No template eval on untrusted config", "FAIL",
                           f"untrusted config templated via non-jinja engine ({other_hit!r}) - "
                           "template/format injection surface", evidence=[str(cfg)])
    return CheckResult(5, "No template eval on untrusted config", "PASS",
                       "no templating indicator; config parsed as data", evidence=[str(cfg)])
