# Run: opa test policies/ -v
#
# Each control gets a compliant baseline that must produce no finding and a
# violating one that must. The "absent field" cases matter most: they prove a
# config the parser only half-filled fails closed rather than passing by
# omission.

package compliance.cis.cisco_ios.level1_test

import data.compliance.cis.cisco_ios.level1

# A fully hardened Cisco device — blueprint §4.2's example, extended with the
# fields the extra controls read. object.union merges recursively, so each
# test below overrides only the keys it cares about.
compliant := {
	"device": {"detected_vendor": "cisco", "detected_os": "IOS-XE"},
	"aaa": {"password_encryption": "ENABLED"},
	"ssh": {"enabled": true, "version": "2", "management_acl": "MGMT-SSH-ACL"},
	"telnet": {"enabled": "DISABLED"},
	"snmp": {"enabled": true, "version": "v3", "community_strings": []},
	"logging": {"syslog_enabled": true, "syslog_hosts": ["10.1.1.100"]},
	"ntp": {"enabled": true, "authentication_enabled": true},
	"crypto": {"ike_policies": [{"policy_id": 10, "encryption": "AES256"}]},
	"banners": {"login_banner_present": true},
	"services": {"http_server_enabled": "DISABLED"},
}

control_ids(findings) := {f.control_id | some f in findings}

test_compliant_config_produces_no_findings if {
	findings := level1.deny with input as compliant
	count(findings) == 0
}

# ── Vendor guard ────────────────────────────────────────────────────
# The whole data.compliance.cis subtree is evaluated in one call, so a
# non-Cisco device must fall straight through this package.
test_non_cisco_device_is_ignored if {
	junos := object.union(compliant, {
		"device": {"detected_vendor": "juniper"},
		"ssh": {"version": "1"},
		"telnet": {"enabled": "ENABLED"},
	})
	findings := level1.deny with input as junos
	count(findings) == 0
}

# ── 1.1.1 SSH v2 ────────────────────────────────────────────────────
test_ssh_v1_fails if {
	bad := object.union(compliant, {"ssh": {"version": "1"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.1.1" in ids
}

test_missing_ssh_block_fails_closed if {
	bad := object.remove(compliant, {"ssh"})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.1.1" in ids
}

# ── 1.1.2 Telnet ────────────────────────────────────────────────────
test_telnet_enabled_fails if {
	bad := object.union(compliant, {"telnet": {"enabled": "ENABLED"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.1.2" in ids
}

test_telnet_unknown_fails_closed if {
	bad := object.union(compliant, {"telnet": {"enabled": "UNKNOWN"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.1.2" in ids
}

# ── 1.1.3 SSH management ACL ────────────────────────────────────────
test_ssh_without_management_acl_fails if {
	bad := object.union(compliant, {"ssh": {"management_acl": null}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.1.3" in ids
}

test_ssh_disabled_does_not_require_management_acl if {
	off := object.union(compliant, {"ssh": {"enabled": false, "management_acl": null}})
	ids := control_ids(level1.deny) with input as off
	not "CIS-IOS-1.1.3" in ids
}

# ── 1.2.1 / 1.2.2 SNMP ──────────────────────────────────────────────
test_snmp_v2c_fails if {
	bad := object.union(compliant, {"snmp": {"version": "v2c"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.2.1" in ids
}

test_default_community_string_fails_case_insensitively if {
	bad := object.union(compliant, {"snmp": {"community_strings": ["Public"]}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.2.2" in ids
}

test_snmp_disabled_does_not_flag_version if {
	off := object.union(compliant, {"snmp": {"enabled": false, "version": "none"}})
	ids := control_ids(level1.deny) with input as off
	not "CIS-IOS-1.2.1" in ids
}

# ── 1.3.1 IKE encryption ────────────────────────────────────────────
test_3des_ike_policy_fails if {
	bad := object.union(compliant, {"crypto": {"ike_policies": [
		{"policy_id": 10, "encryption": "AES256"},
		{"policy_id": 20, "encryption": "3DES"},
	]}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.3.1" in ids
}

# ── 1.4.1 NTP auth ──────────────────────────────────────────────────
test_ntp_without_auth_fails if {
	bad := object.union(compliant, {"ntp": {"authentication_enabled": false}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.4.1" in ids
}

test_ntp_disabled_does_not_require_auth if {
	off := object.union(compliant, {"ntp": {"enabled": false, "authentication_enabled": false}})
	ids := control_ids(level1.deny) with input as off
	not "CIS-IOS-1.4.1" in ids
}

# ── 1.5.1 / 1.6.1 / 1.7.1 ───────────────────────────────────────────
test_password_encryption_disabled_fails if {
	bad := object.union(compliant, {"aaa": {"password_encryption": "DISABLED"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.5.1" in ids
}

test_missing_login_banner_fails if {
	bad := object.union(compliant, {"banners": {"login_banner_present": false}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.6.1" in ids
}

test_http_server_enabled_fails if {
	bad := object.union(compliant, {"services": {"http_server_enabled": "ENABLED"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.7.1" in ids
}

# ── 1.8.1 Remote syslog ─────────────────────────────────────────────
test_syslog_enabled_without_a_host_fails if {
	bad := object.union(compliant, {"logging": {"syslog_hosts": []}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-IOS-1.8.1" in ids
}

# ── Finding shape ───────────────────────────────────────────────────
# Remediation/Reporting consume these fields directly — see
# contracts/compliance_finding.schema.json.
test_finding_carries_every_contract_field if {
	bad := object.union(compliant, {"telnet": {"enabled": "ENABLED"}})
	findings := level1.deny with input as bad
	some f in findings
	f.control_id == "CIS-IOS-1.1.2"
	f.framework == "CIS"
	f.status == "FAIL"
	f.severity == "CRITICAL"
	f.remediation == "ios_disable_telnet.j2"
	count(f.title) > 0
	count(f.evidence) > 0
}

# A device with nothing configured must trip the fail-closed controls rather
# than sail through on missing keys. This pins the header's fail-closed rule:
# a control fails on absent input only where the insecure state is the box's
# out-of-box default.
test_empty_config_trips_the_fail_closed_controls if {
	bare := {"device": {"detected_vendor": "cisco"}}
	ids := control_ids(level1.deny) with input as bare

	ids == {
		"CIS-IOS-1.1.1", # no SSH config at all is not "SSH v2 configured"
		"CIS-IOS-1.1.2", # telnet is on by default on IOS
		"CIS-IOS-1.5.1", # service password-encryption is off by default
		"CIS-IOS-1.6.1", # no banner
		"CIS-IOS-1.8.1", # no remote syslog
	}
}
