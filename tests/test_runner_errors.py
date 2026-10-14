from unittest.mock import Mock

import pytest

from assessment import runner
from assessment.ai.analyzer import Analyzer, build_report


@pytest.mark.parametrize('name', ['kernel', 'lynis'])
def test_scanner_exception_remains_in_report(monkeypatch, name):
    scanner = Mock(run=Mock(side_effect=RuntimeError('scanner disconnected')))
    monkeypatch.setitem(runner.ALL_SCANNERS, name, lambda: scanner)
    results = runner.run_scanners([name])
    assert len(results) == 1
    assert results[0].module_name == name
    assert results[0].error == 'scanner disconnected'
    assert results[0].module_risk_score is None
    client = Mock()
    assert Analyzer(client, {}).analyze_modules(results) == results
    client.analyze.assert_not_called()
    report = build_report(results, {}, {}, 'test')
    assert report.error
    assert report.overall_risk_rating == 'UNKNOWN'
