from html.parser import HTMLParser
from pathlib import Path

import pytest

from assessment.models import AttackChain, Finding, ModuleResult, Report
from assessment.reports.html import generate_html
from assessment.reports.markdown import generate_markdown


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


def report(payload):
    finding = Finding('finding', payload, payload, payload, payload, payload, payload, [payload])
    module = ModuleResult(payload, [finding], {}, None, payload, 1, payload)
    return Report(payload, '2026-10-14T12:00:00', {'PRETTY_NAME': payload}, [module],
                  [AttackChain(payload, [payload], ['finding'], payload, payload)], ['finding'],
                  None, payload, payload, None, [payload], error=payload)


def test_html_treats_all_report_strings_as_text(tmp_path):
    payload = '\"><img src=x onerror=alert(1)>'
    data = report(payload)
    # Timestamp is also displayed as HTML, independently of the output filename.
    data.scan_timestamp = '<img src=x onerror=alert(1)>'
    content = Path(generate_html(data, str(tmp_path))).read_text(encoding='utf-8')
    elements = Elements()
    elements.feed(content)
    assert 'img' not in elements.tags
    assert not any(key == 'onerror' for key, value in elements.attributes)
    assert '&lt;img' in content
    assert 'Risk: unavailable' in content
    assert 'Assessment incomplete:' in content
    assert 'Module failed:' in content


@pytest.mark.parametrize('payload', [
    '<script>alert(1)</script>',
    'value | forged cell\n# forged heading',
    '[click](javascript:alert(1))',
    '`code` **fake**',
])
def test_markdown_treats_report_content_as_text(tmp_path, payload):
    content = Path(generate_markdown(report(payload), str(tmp_path))).read_text(encoding='utf-8')
    assert payload not in content
    assert '<script>' not in content
    assert '\n# forged heading' not in content
    assert '[click](javascript:' not in content
    assert 'Risk Score:** unavailable' in content
    assert 'Assessment incomplete:' in content
    assert 'Module failed:' in content
    assert content.count('\n### ') == 2  # one chain and one module heading


def test_reports_preserve_successful_score_and_unicode(tmp_path):
    data = report('Café audit')
    data.error = None
    data.overall_risk_rating = 'LOW'
    data.overall_risk_score = 12
    data.module_results[0].error = None
    data.module_results[0].module_risk_score = 12
    for renderer in (generate_html, generate_markdown):
        content = Path(renderer(data, str(tmp_path))).read_text(encoding='utf-8')
        assert 'Café audit' in content
        assert '12/100' in content
        assert 'Assessment incomplete:' not in content
        assert 'Module failed:' not in content


@pytest.mark.parametrize('failed', [False, True])
def test_raw_scanner_evidence_is_retained_safely(tmp_path, failed):
    data = report('kernel')
    data.module_results[0].error = 'scanner partial failure' if failed else None
    data.module_results[0].raw_output = {'evidence': '</pre><img src=x onerror=alert(1)>\n```\n# injected'}
    content = Path(generate_html(data, str(tmp_path))).read_text(encoding='utf-8')
    elements = Elements()
    elements.feed(content)
    assert 'img' not in elements.tags
    assert 'Raw scanner output' in content
    assert '&lt;/pre&gt;' in content
    markdown = Path(generate_markdown(data, str(tmp_path))).read_text(encoding='utf-8')
    assert '#### Raw Scanner Output' in markdown
    assert '\n````json\n' in markdown
    assert '\n````\n' in markdown
    assert '<img src=x onerror=alert(1)>' in markdown  # literal JSON code block content


@pytest.mark.parametrize('renderer,extension', [(generate_html, 'html'), (generate_markdown, 'md')])
def test_report_write_replaces_symlink_and_keeps_private_mode(tmp_path, renderer, extension):
    import stat

    output = tmp_path / 'reports'
    output.mkdir(mode=0o755)
    folder_mode = stat.S_IMODE(output.stat().st_mode)
    target = tmp_path / 'unrelated.txt'
    target.write_text('preserve me', encoding='utf-8')
    path = output / f'report_2026-10-14T12-00-00.{extension}'
    path.symlink_to(target)
    assert Path(renderer(report('kernel'), str(output))) == path
    assert target.read_text(encoding='utf-8') == 'preserve me'
    assert not path.is_symlink()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.stat().st_mode) == folder_mode
    assert list(output.glob('.auditai-report-*')) == []


@pytest.mark.parametrize('renderer', [generate_html, generate_markdown])
def test_timestamp_cannot_create_nested_output_path(tmp_path, renderer):
    data = report('kernel')
    data.scan_timestamp = '../nested\\timestamp'
    path = Path(renderer(data, str(tmp_path)))
    assert path.parent == tmp_path
    assert path.is_file()


def test_atomic_writer_failure_preserves_report_and_cleans_temp(tmp_path, monkeypatch):
    from assessment.reports.writer import write_report

    path = tmp_path / 'report_timestamp.md'
    path.write_text('old report', encoding='utf-8')

    def fail_replace(source, destination):
        raise OSError('mock filesystem failure')

    monkeypatch.setattr('assessment.reports.writer.os.replace', fail_replace)
    with pytest.raises(OSError, match='mock filesystem failure'):
        write_report(str(tmp_path), 'timestamp', 'md', 'new report')
    assert path.read_text(encoding='utf-8') == 'old report'
    assert list(tmp_path.glob('.auditai-report-*')) == []
