from pathlib import Path

import pytest

from app import template_engine
from app.template_engine import RemediationTemplateError


EXPECTED = {
    "ios_ssh_v2_fix.j2", "ios_disable_telnet.j2", "ios_ssh_mgmt_acl_fix.j2",
    "ios_snmp_v3_fix.j2", "ios_snmp_community_fix.j2", "ios_ike_encryption_fix.j2",
    "ios_ntp_auth_fix.j2", "ios_password_encryption_fix.j2", "ios_login_banner_fix.j2",
    "ios_disable_http_server.j2", "ios_syslog_fix.j2",
}


def test_all_compliance_templates_exist():
    assert set(template_engine.available_templates()) == EXPECTED


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_every_template_renders_a_nonempty_ios_script(name):
    script = template_engine.render_template(name)
    assert "configure terminal" in script
    assert script.endswith("\n")


def test_context_overrides_are_escaped_as_plain_cli_values():
    script = template_engine.render_template("ios_syslog_fix.j2", {"syslog_host": "192.0.2.50"})
    assert "logging host 192.0.2.50" in script


@pytest.mark.parametrize("name", ["../secret.j2", "/tmp/fix.j2", "fix.txt"])
def test_path_traversal_and_non_templates_are_rejected(name):
    with pytest.raises(RemediationTemplateError):
        template_engine.render_template(name)

