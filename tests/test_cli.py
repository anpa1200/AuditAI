from click.testing import CliRunner

from assessment.cli import main


def test_help_without_anthropic_dependency():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "--no-ai" in result.output


def test_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output
