"""Responses must satisfy the contract before replacing scanner evidence."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from assessment.ai.analyzer import Analyzer, build_report
from assessment.ai.validation import validate_module
from assessment.models import ModuleResult


def good_module():
    return {
        'findings': [{'id': 'issue', 'title': 'Issue', 'severity': 'HIGH',
                      'description': 'description', 'evidence': 'evidence', 'remediation': 'remediation'}],
        'module_risk_score': 70, 'module_summary': 'summary',
    }


def good_synthesis():
    return {'overall_risk_score': 70, 'overall_risk_rating': 'HIGH', 'executive_summary': 'summary',
            'attack_chains': [], 'top_10_priorities': [], 'recommended_immediate_actions': []}


@pytest.mark.parametrize('field,value', [
    ('findings', None), ('findings', [None]), ('module_summary', None),
    ('module_risk_score', -1), ('module_risk_score', 101), ('module_risk_score', True),
    ('module_risk_score', '0'),
])
def test_bad_module_is_explicit_failure(field, value):
    response = good_module()
    response[field] = value
    mr = ModuleResult('kernel', [], {'scan': 'evidence'}, 0, 'pending', 1)
    analyzer = Analyzer(Mock(analyze=Mock(return_value=response)), {})
    assert analyzer.analyze_modules([mr]) == [mr]
    assert mr.error
    assert mr.module_risk_score is None
    assert mr.raw_output == {'scan': 'evidence'}


@pytest.mark.parametrize('field,value', [
    ('severity', {}), ('severity', 'BOGUS'), ('evidence', []), ('references', 'https://example.invalid'),
])
def test_bad_finding_rejects_whole_response(field, value):
    response = good_module()
    response['findings'][0][field] = value
    with pytest.raises(ValueError):
        validate_module(response)


def test_duplicate_ids_rejected_and_modules_are_namespaced(monkeypatch):
    response = good_module()
    response['findings'].append(deepcopy(response['findings'][0]))
    with pytest.raises(ValueError):
        validate_module(response)
    monkeypatch.setattr('assessment.ai.analyzer.time.sleep', lambda _: None)
    modules = [ModuleResult(name, [], {}, 0, 'pending', 1) for name in ('kernel', 'users')]
    analyzer = Analyzer(Mock(analyze=Mock(return_value=good_module())), {})
    analyzer.analyze_modules(modules)
    assert [mr.findings[0].id for mr in modules] == ['kernel:issue', 'users:issue']
    report = build_report(modules, good_synthesis(), {}, 'test')
    assert report.error is None
    assert report.overall_risk_score == 70


@pytest.mark.parametrize('response', [None, [], {},
    dict(good_synthesis(), overall_risk_score=101),
    dict(good_synthesis(), attack_chains=[None]),
    dict(good_synthesis(), top_10_priorities=['nonexistent']),
    dict(good_synthesis(), recommended_immediate_actions=None),
])
def test_invalid_synthesis_cannot_be_clean(response):
    report = build_report([], response, {}, 'test')
    assert report.error
    assert report.overall_risk_rating == 'UNKNOWN'
    assert report.overall_risk_score is None


@pytest.mark.parametrize('text,stop', [('null', 'end_turn'), ('[]', 'end_turn'), ('{}', 'max_tokens'),
                                      ('```json\n{}\n```', 'end_turn')])
def test_client_checks_object_and_truncation(monkeypatch, text, stop):
    pytest.importorskip('anthropic')
    from assessment.ai.client import AIClient
    client = AIClient(api_key='synthetic-test-key')
    create = Mock(return_value=SimpleNamespace(content=[SimpleNamespace(text=text)], stop_reason=stop))
    monkeypatch.setattr(client.client.messages, 'create', create)
    sleep = Mock()
    monkeypatch.setattr('assessment.ai.client.time.sleep', sleep)
    response = client.analyze('offline')
    if text.startswith('```'):
        assert response == {}
        assert create.call_count == 1
    else:
        assert response['error']
        assert create.call_count == 4
        assert sleep.call_count == 3
