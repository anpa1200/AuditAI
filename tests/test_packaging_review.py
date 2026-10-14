"""Offline regressions for distribution helpers and shell launcher."""
import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_status():
    spec = importlib.util.spec_from_file_location("kali_status", ROOT / "scripts/check_kali_status.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("value", ["0", "-1", "1&other=2", "1\nstatus=closed", "foo"])
def test_invalid_tracker_id_never_fetches(monkeypatch, value):
    module = load_status()
    monkeypatch.setattr("sys.argv", ["status", value])
    monkeypatch.setattr(module, "urlopen", lambda *args, **kwargs: pytest.fail("unexpected request"))
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2


def test_tracker_output_is_one_line_per_field(monkeypatch, tmp_path):
    module = load_status()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'<td class="bug-status">closed</td><td class="bug-summary">hello\nstatus=other</td>'

    output = tmp_path / "output"
    monkeypatch.setattr("sys.argv", ["status", "123", "--output", str(output)])
    monkeypatch.setattr(module, "urlopen", lambda *args, **kwargs: Response())
    assert module.main() == 0
    assert "summary=hello status=other\n" in output.read_text()
    assert output.read_text().count("\nstatus=") == 1


def test_explicit_no_ai_does_not_prompt_for_key(tmp_path):
    docker = tmp_path / "docker"
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$DOCKER_LOG"\n')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}", DOCKER_LOG=str(tmp_path / "docker.log"))
    env.pop("ANTHROPIC_API_KEY", None)
    result = subprocess.run(
        ["bash", str(ROOT / "run.sh"), "--no-ai", "--skip", "lynis"],
        input="y\n", text=True, capture_output=True, env=env, cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert "Continue without AI analysis?" not in result.stdout
    assert "--no-ai --skip lynis" in (tmp_path / "docker.log").read_text()


def test_tracker_fields_are_not_interpolated_into_shell():
    workflow = (ROOT / ".github/workflows/kali-status.yml").read_text()
    # Data enters shell through environment variables; the comment is written by
    # Python under a quoted heredoc, so tracker content cannot execute commands.
    shell_sections = workflow.split("        run: |")[1:]
    for section in shell_sections:
        shell = section.split("      - name:")[0]
        assert "${{ steps." not in shell
    assert "python - <<'PYTHON'" in workflow
    assert '--body-file kali-comment.txt' in workflow


def test_sdist_manifest_includes_helper_inputs():
    manifest = (ROOT / "MANIFEST.in").read_text()
    assert "recursive-include scripts *.py" in manifest
    assert "include Dockerfile docker-compose.yml requirements.txt run.sh" in manifest
    assert "recursive-include .github *.yml" in manifest
