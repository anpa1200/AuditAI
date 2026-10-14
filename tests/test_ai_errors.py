from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from assessment.ai.analyzer import Analyzer, build_report
from assessment.ai.errors import InsufficientCreditsError

pytest.importorskip("anthropic")
from assessment.ai.client import AIClient, APIError, RateLimitError
from assessment.cli import main
from assessment.models import Finding, ModuleResult
from assessment.reports.html import generate_html
from assessment.reports.markdown import generate_markdown


def module():
    finding = Finding('raw', 'Scanner evidence', 'HIGH', 'kernel', 'd', 'e', 'r')
    return ModuleResult('kernel', [finding], {'evidence': 'retained'}, 30, 'raw scan', 1)


@pytest.mark.parametrize('failure', ['api', 'rate', 'json', 'disconnect'])
def test_retry_exhaustion(monkeypatch, failure):
    client = AIClient(api_key='synthetic-test-key')
    create = Mock()
    if failure == 'json':
        create.return_value = SimpleNamespace(content=[SimpleNamespace(text='invalid JSON')])
    else:
        # SDK exceptions need a request/response; no transport is used.
        try:
            import httpx2 as httpx
        except ImportError:
            import httpx
        request = httpx.Request('POST', 'https://example.invalid')
        if failure == 'rate':
            create.side_effect = RateLimitError('rate limit', response=httpx.Response(429, request=request), body=None)
        elif failure == 'disconnect':
            from anthropic import APIConnectionError
            create.side_effect = APIConnectionError(request=request)
        else:
            create.side_effect = APIError('temporary failure', request, body=None)
    monkeypatch.setattr(client.client.messages, 'create', create)
    sleep = Mock()
    monkeypatch.setattr('assessment.ai.client.time.sleep', sleep)
    response = client.analyze('offline')
    assert sleep.call_count == 3
    assert create.call_count == 4
    assert response['error']
    assert response['module_risk_score'] is None
    mr = module()
    Analyzer(Mock(analyze=Mock(return_value=response)), {}).analyze_modules([mr])
    assert mr.error
    assert mr.module_risk_score is None
    assert mr.findings[0].id == 'raw'
    assert mr.raw_output == {'evidence': 'retained'}


@pytest.mark.parametrize('failure', [RuntimeError('disconnected'), InsufficientCreditsError('billing')])
def test_module_exception(monkeypatch, failure):
    mr = module()
    analyzer = Analyzer(Mock(analyze=Mock(side_effect=failure)), {})
    if isinstance(failure, InsufficientCreditsError):
        with pytest.raises(InsufficientCreditsError):
            analyzer.analyze_modules([mr])
    else:
        assert analyzer.analyze_modules([mr]) == [mr]
        assert 'disconnected' in mr.error
        assert mr.module_risk_score is None
        assert mr.findings


def test_success_and_synthesis_error_context():
    mr = module()
    client = Mock(analyze=Mock(return_value={'findings': [], 'module_risk_score': 12, 'module_summary': 'ok'}))
    analyzer = Analyzer(client, {})
    analyzer.analyze_modules([mr])
    assert mr.error is None
    assert (mr.findings, mr.module_risk_score, mr.module_summary) == ([], 12, 'ok')
    mr.error = 'AI analysis failed: unavailable'
    analyzer.synthesize([mr])
    assert 'AI analysis failed: unavailable' in client.analyze.call_args.args[0]


@pytest.mark.parametrize('source', ['module', 'synthesis'])
def test_reports_mark_incomplete(tmp_path, source):
    mr = module()
    synthesis = {'overall_risk_score': 0, 'overall_risk_rating': 'LOW'}
    if source == 'module':
        mr.error = 'AI analysis failed: disconnected'
        mr.module_risk_score = None
    else:
        synthesis['error'] = 'disconnected'
    report = build_report([mr], synthesis, {}, 'timestamp')
    assert report.error
    assert report.overall_risk_score is None
    assert report.overall_risk_rating == 'UNKNOWN'
    for generate in (generate_html, generate_markdown):
        from pathlib import Path
        content = Path(generate(report, str(tmp_path))).read_text()
        assert 'Assessment incomplete:' in content
        assert 'unavailable' in content
        assert 'Scanner evidence' in content


@pytest.mark.parametrize('failure', ['module', 'synthesis', 'exception', 'fatal', 'success', 'no-ai'])
def test_cli_offline(monkeypatch, tmp_path, failure):
    from assessment import cli
    mr = module()
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'synthetic-test-key')
    monkeypatch.setattr(cli, 'validate_host_mounts', list)
    monkeypatch.setattr(cli, 'collect_host_context', lambda: {'hostname': 'test', 'os_name': 'Linux', 'kernel_version': 'test'})
    monkeypatch.setattr(cli, 'run_scanners', lambda *a, **k: [mr])
    response = {'findings': [], 'module_risk_score': 12, 'module_summary': 'ok', 'executive_summary': 'ok',
                'attack_chains': [], 'top_10_priorities': [], 'recommended_immediate_actions': [], 'overall_risk_score': 12, 'overall_risk_rating': 'LOW'}
    if failure == 'module':
        responses = [{'error': 'offline failure'}, response]
    elif failure == 'synthesis':
        responses = [response, {'error': 'offline failure'}]
    elif failure == 'exception':
        responses = [response, RuntimeError('offline failure')]
    elif failure == 'fatal':
        responses = [InsufficientCreditsError('offline failure')]
    else:
        responses = [response, response]
    monkeypatch.setattr('assessment.ai.client.AIClient', lambda **k: Mock(analyze=Mock(side_effect=responses)))
    args = ['--modules', 'kernel', '--output-dir', str(tmp_path)]
    if failure == 'no-ai':
        args.append('--no-ai')
    result = CliRunner().invoke(main, args)
    assert result.exit_code == (0 if failure in ('success', 'no-ai') else 1), result.exception
    if failure != 'fatal':
        assert len(list(tmp_path.glob('report_*'))) == 2
    if failure in ('module', 'synthesis', 'exception'):
        assert 'Assessment incomplete:' in result.output
        assert 'UNKNOWN (unavailable)' in result.output


@pytest.mark.parametrize('kind', ['authentication', 'billing', 'success_after_rate'])
def test_sdk_permanent_errors_and_retry_success(monkeypatch, kind):
    from assessment.ai.client import AuthenticationError
    try:
        import httpx2 as httpx
    except ImportError:
        import httpx
    request = httpx.Request('POST', 'https://example.invalid')
    client = AIClient(api_key='synthetic-test-key')
    response = SimpleNamespace(content=[SimpleNamespace(text='{"findings": [], "module_risk_score": 12, "module_summary": "ok"}')])
    if kind == 'authentication':
        effects = [AuthenticationError('synthetic authentication failure',
                                       response=httpx.Response(401, request=request), body=None)]
    elif kind == 'billing':
        effects = [APIError('credit balance is too low', request, body=None)]
    else:
        effects = [RateLimitError('synthetic rate limit', response=httpx.Response(429, request=request), body=None), response]
    create = Mock(side_effect=effects)
    sleep = Mock()
    monkeypatch.setattr(client.client.messages, 'create', create)
    monkeypatch.setattr('assessment.ai.client.time.sleep', sleep)
    if kind == 'success_after_rate':
        assert client.analyze('offline')['module_risk_score'] == 12
        assert create.call_count == 2
        sleep.assert_called_once_with(15)
    else:
        with pytest.raises(InsufficientCreditsError):
            client.analyze('offline')
        assert create.call_count == 1
        sleep.assert_not_called()


def test_sdk_request_signature_is_supported(monkeypatch):
    import inspect
    client = AIClient(api_key='synthetic-test-key')
    signature = inspect.signature(client.client.messages.create)

    def offline_create(**kwargs):
        # Bind against the real installed SDK signature before mocking transport.
        signature.bind(**kwargs)
        return SimpleNamespace(content=[SimpleNamespace(text='{}')])

    monkeypatch.setattr(client.client.messages, 'create', offline_create)
    assert client.analyze('offline') == {}
