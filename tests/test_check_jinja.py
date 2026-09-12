from controls.somay import check_jinja
from tests.conftest import write


def test_pass_when_parsed_as_data(tmp_path):
    write(tmp_path, "b5_jinja", "config_pipeline.txt",
          "config = yaml.safe_load(user_config)\n")
    res = check_jinja.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_rendered_unsandboxed(tmp_path):
    write(tmp_path, "b5_jinja", "config_pipeline.txt",
          "config = jinja2.Template(user_config).render()\n")
    res = check_jinja.run(str(tmp_path))
    assert res.status == "FAIL"


def test_pass_when_rendered_but_sandboxed(tmp_path):
    write(tmp_path, "b5_jinja", "config_pipeline.txt",
          "env = SandboxedEnvironment()\nconfig = env.from_string(user_config).render()\n")
    res = check_jinja.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_missing(tmp_path):
    res = check_jinja.run(str(tmp_path))
    assert res.status == "FAIL"
