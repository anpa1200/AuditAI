from datetime import date as real_date
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from assessment import runner
from assessment.scanners import filesystem, kernel, lynis_wrapper, network, os_hardening, packages, services, users


@pytest.mark.parametrize('mode,expected', [(0o600, False), (0o640, False), (0o604, True), (0o620, True)])
def test_sensitive_permissions_check_bits(tmp_path, monkeypatch, mode, expected):
    shadow = tmp_path / 'etc/shadow'
    shadow.parent.mkdir()
    shadow.write_text('synthetic')
    shadow.chmod(mode)
    monkeypatch.setattr(filesystem, 'HOST_ROOT', str(tmp_path))
    assert filesystem._check_sensitive_files()['/etc/shadow']['too_permissive'] is expected


@pytest.mark.parametrize('name,mode,expected', [('ssh_host_key.pub', 0o644, False), ('ssh_host_key', 0o644, True), ('ssh_host_key.pub', 0o666, True)])
def test_ssh_key_permissions(tmp_path, monkeypatch, name, mode, expected):
    key = tmp_path / 'etc/ssh' / name
    key.parent.mkdir(parents=True)
    key.write_text('synthetic')
    key.chmod(mode)
    monkeypatch.setattr(filesystem, 'HOST_ROOT', str(tmp_path))
    assert filesystem._check_ssh_key_perms()[f'/etc/ssh/{name}']['too_permissive'] is expected


@pytest.mark.parametrize('content,enabled', [('[none] integrity confidentiality', False), ('none [integrity] confidentiality', True), ('none integrity [confidentiality]', True)])
def test_lockdown_active_level(tmp_path, monkeypatch, content, enabled):
    path = tmp_path / 'kernel/security/lockdown'
    path.parent.mkdir(parents=True)
    path.write_text(content)
    monkeypatch.setattr(kernel, 'SYS_PATH', str(tmp_path))
    assert kernel._check_lockdown()['enabled'] is enabled


def test_eol_uses_current_date(monkeypatch):
    class FixedDate(real_date):
        @classmethod
        def today(cls):
            return cls(2026, 10, 14)
    monkeypatch.setattr(packages, 'date', FixedDate)
    assert packages._check_os_eol({'ID': 'debian', 'VERSION_ID': '11'})['is_eol']


def test_dpkg_only_installed_and_source_metadata(tmp_path):
    status = tmp_path / 'status'
    status.write_text('Package: libssl3\nSource: openssl (3.0.1-1)\nVersion: 3.0.1-1+b1\nStatus: install ok installed\n\nPackage: bash\nVersion: 1\nStatus: install ok unpacked\n')
    result = packages._parse_dpkg_status(str(status))
    assert len(result) == 1
    assert result[0]['source_name'] == 'openssl'
    assert result[0]['source_version'] == '3.0.1-1'


@pytest.mark.parametrize('os_info,ecosystem', [({'ID': 'debian', 'VERSION_ID': '12'}, 'Debian:12'), ({'ID': 'ubuntu', 'VERSION_ID': '22.04'}, 'Ubuntu:22.04:LTS'), ({'ID': 'ubuntu', 'VERSION_ID': '23.10'}, 'Ubuntu:23.10')])
def test_osv_uses_source_package_and_release(monkeypatch, os_info, ecosystem):
    monkeypatch.setattr(packages, '_read_os_release', lambda: os_info)
    post = Mock(return_value=Mock(status_code=200, json=lambda: {'vulns': []}))
    monkeypatch.setattr(packages.requests, 'post', post)
    result = packages._check_cves([{'name': 'libssl3', 'version': '3+b1', 'source_name': 'openssl', 'source_version': '3'}])
    assert result['status'] == 'completed'
    assert post.call_args.kwargs['json'] == {'package': {'name': 'openssl', 'ecosystem': ecosystem}, 'version': '3'}


def test_osv_failure_and_unsupported_are_explicit(monkeypatch):
    monkeypatch.setattr(packages, '_read_os_release', lambda: {'ID': 'fedora', 'VERSION_ID': '42'})
    post = Mock(side_effect=requests.ConnectionError('offline'))
    monkeypatch.setattr(packages.requests, 'post', post)
    assert packages._check_cves([{'name': 'openssl', 'version': '1'}])['status'] == 'unsupported'
    post.assert_not_called()
    monkeypatch.setattr(packages, '_read_os_release', lambda: {'ID': 'debian', 'VERSION_ID': '12'})
    result = packages._check_cves([{'name': 'openssl', 'version': '1'}])
    assert result['status'] == 'partial'
    assert result['errors'][0]['error'] == 'offline'


@pytest.mark.parametrize('exit_code,make_report', [(-1, False), (1, True), (0, False)])
def test_lynis_failure_is_module_error(monkeypatch, exit_code, make_report):
    monkeypatch.setattr(lynis_wrapper, '_find_lynis', lambda: '/fake/lynis')
    def run(path, report_path):
        if make_report:
            Path(report_path).write_text('hardening_index=100\n')
        return exit_code, 'synthetic failure'
    monkeypatch.setattr(lynis_wrapper, '_run_lynis', run)
    result = lynis_wrapper.LynisScanner().run()
    assert result.error
    assert result.module_risk_score is None
    assert result.raw_output.get('hardening_index') is None


def test_lynis_private_fresh_report_and_order_independent_fields(monkeypatch):
    monkeypatch.setattr(lynis_wrapper, '_find_lynis', lambda: '/fake/lynis')
    paths = []
    def run(path, report_path):
        paths.append(report_path)
        Path(report_path).write_text('hardening_index=60\ntest_result[TEST-1]=OK\ntest_name[TEST-1]=Synthetic\n')
        return 0, ''
    monkeypatch.setattr(lynis_wrapper, '_run_lynis', run)
    for _ in range(2):
        result = lynis_wrapper.LynisScanner().run()
        assert not result.error
        assert result.raw_output['test_results']['TEST-1'] == {'name': 'Synthetic', 'result': 'OK'}
    assert paths[0] != paths[1]
    assert all(not Path(path).exists() for path in paths)


def test_missing_lynis_is_error(monkeypatch):
    monkeypatch.setattr(lynis_wrapper, '_find_lynis', lambda: '')
    assert lynis_wrapper.LynisScanner().run().error


@pytest.mark.parametrize('name', ['kernel', 'lynis'])
def test_runner_constructor_failure_preserved(monkeypatch, name):
    monkeypatch.setitem(runner.ALL_SCANNERS, name, Mock(side_effect=RuntimeError('constructor failed')))
    result = runner.run_scanners([name])[0]
    assert result.error == 'constructor failed'
    assert result.module_risk_score is None


def test_unknown_scanner_preserved():
    result = runner.run_scanners(['not-a-scanner'])[0]
    assert result.error == 'Unknown scanner: not-a-scanner'


def test_unreadable_host_context_is_nonfatal(monkeypatch):
    monkeypatch.setattr('builtins.open', Mock(side_effect=PermissionError('denied')))
    assert runner.collect_host_context()['os_name'] == 'Linux'


def test_host_root_user_keys_and_legacy_files(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    (root / '.ssh').mkdir(parents=True)
    (root / '.ssh/authorized_keys').write_text('synthetic-public-key\n')
    (root / '.rhosts').touch()
    monkeypatch.setattr(users, 'HOST_ROOT', str(tmp_path))
    monkeypatch.setattr(users, 'HOME_PATH', str(tmp_path / 'home'))
    assert users._check_user_ssh_keys()['root_authorized_keys']['count'] == 1
    assert str(root / '.rhosts') in users._check_legacy_files()


def test_host_root_docker_socket_and_cron(tmp_path, monkeypatch):
    run = tmp_path / 'run'
    run.mkdir()
    socket = run / 'docker.sock'
    socket.touch()
    socket.chmod(0o602)
    monkeypatch.setattr(services, 'RUN_PATH', str(run))
    result = services._check_docker_socket()
    assert result['exists'] and result['world_writable'] and not result['world_readable']
    cron = tmp_path / 'var/spool/cron'
    cron.mkdir(parents=True)
    (cron / 'synthetic').write_text('synthetic cron')
    monkeypatch.setattr(services, 'VAR_PATH', str(tmp_path / 'var'))
    monkeypatch.setattr(services, 'ETC_PATH', str(tmp_path / 'etc'))
    assert services._get_cron_jobs()['spool:synthetic'] == 'synthetic cron'


def test_efi_uses_host_sys_path(tmp_path, monkeypatch):
    (tmp_path / 'firmware/efi/efivars').mkdir(parents=True)
    (tmp_path / 'firmware/efi/efivars/SecureBoot-synthetic').touch()
    monkeypatch.setattr(os_hardening, 'SYS_PATH', str(tmp_path))
    assert os_hardening._check_secure_boot()['secure_boot_vars'] == ['SecureBoot-synthetic']


def test_primary_ip_socket_closes_on_failure(monkeypatch):
    sock = Mock()
    sock.__enter__ = Mock(return_value=sock)
    sock.__exit__ = Mock(return_value=False)
    sock.connect.side_effect = OSError('offline')
    monkeypatch.setattr(network.socket, 'socket', Mock(return_value=sock))
    assert network._get_primary_ip() == ''
    sock.__exit__.assert_called_once()


def test_kernel_support_and_partial_mitigation(tmp_path, monkeypatch):
    monkeypatch.setattr(kernel, 'PROC_PATH', str(tmp_path))
    monkeypatch.setattr(kernel.subprocess, 'check_output', lambda *a, **k: 'Linux host 5.15.0 x86_64')
    assert kernel._get_kernel_version()['eol'] is None
    directory = tmp_path / 'devices/system/cpu/vulnerabilities'
    directory.mkdir(parents=True)
    (directory / 'synthetic').write_text('Mitigation: partial; SMT vulnerable')
    monkeypatch.setattr(kernel, 'SYS_PATH', str(tmp_path))
    assert not kernel._check_cpu_vulnerabilities()['synthetic']['mitigated']


def test_host_upgrade_simulation_does_not_query_container(monkeypatch):
    monkeypatch.setattr(packages, 'HOST_ROOT', '/synthetic-host')
    command = Mock(side_effect=AssertionError('must not query container'))
    monkeypatch.setattr(packages.subprocess, 'check_output', command)
    assert packages._check_upgrades()['status'] == 'unavailable'
    command.assert_not_called()


def test_host_dpkg_integrity_uses_host_root(tmp_path, monkeypatch):
    (tmp_path / 'var/lib/dpkg').mkdir(parents=True)
    monkeypatch.setattr(packages, 'HOST_ROOT', str(tmp_path))
    monkeypatch.setattr(packages, 'VAR_PATH', str(tmp_path / 'var'))
    command = Mock(return_value='')
    monkeypatch.setattr(packages.subprocess, 'check_output', command)
    packages._check_package_integrity()
    assert f'--root={tmp_path}' in command.call_args.args[0]


def test_host_sysctl_does_not_fallback_to_container(monkeypatch):
    monkeypatch.setattr(os_hardening, 'HOST_ROOT', '/synthetic-host')
    monkeypatch.setattr(os_hardening, 'PROC_PATH', '/synthetic-host/proc')
    monkeypatch.setattr(os_hardening, 'SYSCTL_CHECKS', {'kernel.sysrq': (0, 'synthetic')})
    command = Mock(side_effect=AssertionError('must not query container'))
    monkeypatch.setattr(os_hardening.subprocess, 'check_output', command)
    assert os_hardening._check_sysctl()['kernel.sysrq']['error'] == 'host value not readable'
    command.assert_not_called()


def test_host_services_use_host_filesystem(monkeypatch):
    monkeypatch.setattr(services, 'HOST_ROOT', '/synthetic-host')
    monkeypatch.setattr(services, '_get_systemd_units_from_fs', lambda: [{'unit': 'synthetic.service'}])
    command = Mock(side_effect=AssertionError('must not query container'))
    monkeypatch.setattr(services.subprocess, 'check_output', command)
    assert services._get_systemd_units() == [{'unit': 'synthetic.service'}]
    command.assert_not_called()


def test_unreadable_cpu_status_is_preserved(tmp_path, monkeypatch):
    directory = tmp_path / 'devices/system/cpu/vulnerabilities'
    directory.mkdir(parents=True)
    (directory / 'synthetic').touch()
    monkeypatch.setattr(kernel, 'SYS_PATH', str(tmp_path))
    monkeypatch.setattr('builtins.open', Mock(side_effect=PermissionError('denied')))
    result = kernel._check_cpu_vulnerabilities()['synthetic']
    assert result['status'] == 'unknown' and result['mitigated'] is None
    assert result['error'] == 'denied'


def test_missing_lockdown_state_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(kernel, 'SYS_PATH', str(tmp_path))
    assert kernel._check_lockdown()['enabled'] is None


def test_osv_unexpected_success_status_is_incomplete(monkeypatch):
    monkeypatch.setattr(packages, '_read_os_release', lambda: {'ID': 'debian', 'VERSION_ID': '12'})
    response = Mock(status_code=204)
    monkeypatch.setattr(packages.requests, 'post', Mock(return_value=response))
    result = packages._check_cves([{'name': 'openssl', 'version': 'synthetic'}])
    assert result['status'] == 'partial'
    assert result['checked_packages'] == 0
    assert result['errors'][0]['error'] == 'Unexpected OSV response status: 204'
