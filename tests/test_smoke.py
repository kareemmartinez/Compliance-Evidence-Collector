from tests import collector

def test_run_all_checks_smoke():
    findings = collector.run_all_checks()
    assert isinstance(findings, list)
    assert len(findings) > 0
