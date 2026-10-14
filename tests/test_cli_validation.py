from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from assessment import cli
from assessment.models import ModuleResult


@pytest.mark.parametrize('args', [
    ['--modules', ''], ['--modules', 'invalid'], ['--skip', 'invalid'],
    ['--modules', 'kernel', '--skip', 'kernel'],
])
def test_invalid_selection_never_scans(monkeypatch, args):
    monkeypatch.setattr(cli, 'collect_host_context', lambda: pytest.fail('unexpected host collection'))
    result = CliRunner().invoke(cli.main, args + ['--no-ai'])
    assert result.exit_code == 1
    assert 'Error:' in result.output


def test_duplicate_modules_run_once(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, 'validate_host_mounts', list)
    monkeypatch.setattr(cli, 'collect_host_context', lambda: {'hostname': 'host', 'os_name': 'Linux', 'kernel_version': 'test'})
    scanner = Mock(return_value=[ModuleResult('kernel', [], {'scan': 'data'}, 0, 'pending', 1)])
    monkeypatch.setattr(cli, 'run_scanners', scanner)
    result = CliRunner().invoke(cli.main, ['--no-ai', '--modules', 'kernel,kernel', '--output-dir', str(tmp_path)])
    assert result.exit_code == 0, result.exception
    scanner.assert_called_once_with(['kernel'], verbose=False)


def test_ai_initialization_failure_saves_evidence(monkeypatch, tmp_path):
    pytest.importorskip('anthropic')
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'synthetic-test-key')
    monkeypatch.setattr(cli, 'validate_host_mounts', list)
    monkeypatch.setattr(cli, 'collect_host_context', lambda: {'hostname': 'host', 'os_name': 'Linux', 'kernel_version': 'test'})
    mr = ModuleResult('kernel', [], {'scan': 'data'}, 0, 'pending', 1)
    monkeypatch.setattr(cli, 'run_scanners', lambda *a, **k: [mr])
    monkeypatch.setattr('assessment.ai.client.AIClient', Mock(side_effect=ImportError('anthropic missing')))
    result = CliRunner().invoke(cli.main, ['--modules', 'kernel', '--output-dir', str(tmp_path)])
    assert result.exit_code == 1
    assert 'Install AI support' in result.output
    assert mr.error
    assert mr.module_risk_score is None
    assert len(list(tmp_path.glob('report_*'))) == 2
