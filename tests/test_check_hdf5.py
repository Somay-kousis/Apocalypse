from controls.somay import check_hdf5
from tests.conftest import write


def test_pass_when_external_links_disabled_and_no_forbidden_constructs(tmp_path):
    write(tmp_path, "b4_hdf5", "loader_policy.txt",
          "allow_external_links: false\nhdf5_driver: core\n")
    res = check_hdf5.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_external_links_allowed(tmp_path):
    write(tmp_path, "b4_hdf5", "loader_policy.txt",
          "allow_external_links: true\nhdf5_driver: default\n")
    res = check_hdf5.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_missing(tmp_path):
    res = check_hdf5.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "no b4_hdf5" in res.detail


def test_fail_when_flag_correct_but_forbidden_construct_still_present(tmp_path):
    """Regression test for the dead-code bug: allow_external_links: false was
    previously enough to PASS even if a forbidden construct (e.g. an explicit
    H5Pset_external call) was left in the same file."""
    write(tmp_path, "b4_hdf5", "loader_policy.txt",
          "allow_external_links: false\n"
          "# legacy path still calls H5Pset_external directly\n")
    res = check_hdf5.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "forbidden construct" in res.detail
