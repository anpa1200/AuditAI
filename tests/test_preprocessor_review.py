from assessment.ai.preprocessor import preprocess


def test_kernel_preserves_scanner_schema_and_unsafe_cpu_statuses():
    raw = {
        'version': {'eol': True}, 'lockdown': {'enabled': False},
        'modules': [{'name': 'risky'}], 'modules_disabled': {'disabled': False},
        'kernel_params': {'kernel.randomize_va_space': '0'},
        'kexec_loaded': {'disabled': False}, 'bpf_enabled': {'value': '0'},
        'cpu_vulnerabilities': {
            'unsafe': {'status': 'Vulnerable', 'mitigated': False},
            'partial': {'status': 'Mitigation: foo; SMT vulnerable', 'mitigated': True},
            'safe': {'status': 'Mitigation: foo', 'mitigated': True},
            'unaffected': {'status': 'Not affected', 'mitigated': True},
            'unknown': {'error': 'unreadable'},
        },
    }
    result = preprocess('kernel', raw)
    for key in raw.keys() - {'cpu_vulnerabilities'}:
        assert result[key] == raw[key]
    assert set(result['cpu_vulnerabilities_not_mitigated']) == {'unsafe', 'partial', 'unknown'}
    assert result['cpu_vulnerabilities_total'] == 5


def test_read_errors_are_not_removed_as_compliant():
    assert preprocess('os_hardening', {
        'sysctl_params': {'kernel.foo': {'error': 'not readable'}},
    })['sysctl_non_compliant']['kernel.foo']['error'] == 'not readable'
    assert preprocess('filesystem', {
        'sensitive_file_perms': {'/etc/shadow': {'error': 'Permission denied'}},
    })['sensitive_file_perms_issues']['/etc/shadow']['error'] == 'Permission denied'


def test_privileged_group_memberships_are_retained():
    groups = [{'name': 'docker', 'gid': '999', 'members': ['alice']}]
    assert preprocess('users', {'groups': groups})['groups'] == groups


def test_services_retains_active_units_and_unknown_enablement():
    units = [{'unit': 'telnet.service', 'active': 'active', 'sub': 'running'}]
    result = preprocess('services', {'systemd_units': units})
    assert result['systemd_units'] == units
    assert result['enabled_unit_count'] is None
    units[0]['enabled'] = True
    assert preprocess('services', {'systemd_units': units})['enabled_unit_count'] == 1


def test_nmap_service_version_attribute_order_and_closed_filtering():
    xml = '''<nmaprun><host><ports>
      <port portid="22" protocol="tcp"><state reason="syn-ack" state="open"/>
      <service version="7.2" name="ssh" product="OpenSSH"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/></port>
    </ports></host></nmaprun>'''
    result = preprocess('network', {'nmap_localhost': {'xml': xml, 'target': '127.0.0.1'}})
    assert result['nmap_localhost']['open_ports'] == [{
        'protocol': 'tcp', 'port': 22, 'state': 'open', 'service': 'ssh',
        'product': 'OpenSSH', 'version': '7.2',
    }]


def test_malformed_nmap_is_preserved_not_presented_as_zero_open_ports():
    raw = {'nmap_localhost': {'xml': '<broken'}}
    assert preprocess('network', raw) == raw


def test_ss_headerless_and_process_names_with_spaces():
    row = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("my daemon",pid=5,fd=3))'
    for text in (row, 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n' + row):
        result = preprocess('network', {'open_ports_ss': text})['open_ports_ss']
        assert len(result) == 1
        assert result[0]['local_addr'] == '0.0.0.0:22'
        assert result[0]['process'] == 'users:(("my daemon",pid=5,fd=3))'
