# Run: opa test policies/ -v
#
# The tests that matter most here are the ones that didn't exist for the old
# per-vendor bundles: proving the same input produces the same verdict
# regardless of `detected_vendor`, and proving the fail-open/fail-closed
# split holds on a bare config from a vendor nobody wrote code for.

package compliance.cis.generic.level1_test

import data.compliance.cis.generic.level1

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

# ── Vendor independence — the whole point of the rewrite ────────────
test_verdict_is_identical_regardless_of_vendor_name if {
	bad := object.union(compliant, {"telnet": {"enabled": "ENABLED"}})

	cisco_ids := control_ids(level1.deny) with input as object.union(bad, {"device": {"detected_vendor": "cisco"}})
	fortinet_ids := control_ids(level1.deny) with input as object.union(bad, {"device": {"detected_vendor": "fortinet"}})
	brand_new_ids := control_ids(level1.deny) with input as object.union(bad, {"device": {"detected_vendor": "some-vendor-nobody-wrote-code-for"}})
	unlabeled_ids := control_ids(level1.deny) with input as object.union(bad, {"device": {"detected_vendor": "unknown"}})

	cisco_ids == fortinet_ids
	fortinet_ids == brand_new_ids
	brand_new_ids == unlabeled_ids
	"CIS-NET-1.1.2" in cisco_ids
}

test_remediation_resolves_per_vendor_from_data_not_code if {
	bad := object.union(compliant, {"telnet": {"enabled": "ENABLED"}})

	cisco_findings := level1.deny with input as object.union(bad, {"device": {"detected_vendor": "cisco"}})
	fortinet_findings := level1.deny with input as object.union(bad, {"device": {"detected_vendor": "fortinet"}})
	unsupported_findings := level1.deny with input as object.union(bad, {"device": {"detected_vendor": "some-vendor-nobody-wrote-code-for"}})

	some cf in cisco_findings
	cf.control_id == "CIS-NET-1.1.2"
	cf.remediation == "ios_disable_telnet.j2"

	some ff in fortinet_findings
	ff.control_id == "CIS-NET-1.1.2"
	ff.remediation == "fortinet_disable_telnet.j2"

	some uf in unsupported_findings
	uf.control_id == "CIS-NET-1.1.2"
	uf.remediation == null
}

# ── 1.1.1 SSH v2 (evidence-only) ─────────────────────────────────────
test_ssh_v1_fails if {
	bad := object.union(compliant, {"ssh": {"version": "1"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.1.1" in ids
}

test_missing_ssh_block_does_not_fail_closed if {
	# Unlike the old Cisco-only bundle, an absent SSH block is not proof of
	# anything — we don't know this vendor's out-of-box SSH behavior.
	off := object.remove(compliant, {"ssh"})
	ids := control_ids(level1.deny) with input as off
	not "CIS-NET-1.1.1" in ids
}

# ── 1.1.2 Telnet ────────────────────────────────────────────────────
test_telnet_enabled_fails if {
	bad := object.union(compliant, {"telnet": {"enabled": "ENABLED"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.1.2" in ids
}

test_telnet_absent_does_not_fail_closed if {
	bare := {"device": {"detected_vendor": "some-vendor-nobody-wrote-code-for"}}
	ids := control_ids(level1.deny) with input as bare
	not "CIS-NET-1.1.2" in ids
}

# ── 1.1.3 SSH management ACL ─────────────────────────────────────────
test_ssh_without_management_acl_fails if {
	bad := object.union(compliant, {"ssh": {"management_acl": null}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.1.3" in ids
}

test_ssh_disabled_does_not_require_management_acl if {
	off := object.union(compliant, {"ssh": {"enabled": false, "management_acl": null}})
	ids := control_ids(level1.deny) with input as off
	not "CIS-NET-1.1.3" in ids
}

# ── 1.2.1 / 1.2.2 SNMP ──────────────────────────────────────────────
test_snmp_v2c_fails if {
	bad := object.union(compliant, {"snmp": {"version": "v2c"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.2.1" in ids
}

test_default_community_string_fails_case_insensitively if {
	bad := object.union(compliant, {"snmp": {"community_strings": ["Public"]}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.2.2" in ids
}

test_snmp_disabled_does_not_flag_version if {
	off := object.union(compliant, {"snmp": {"enabled": false, "version": "none"}})
	ids := control_ids(level1.deny) with input as off
	not "CIS-NET-1.2.1" in ids
}

# ── 1.3.1 IKE encryption ────────────────────────────────────────────
test_3des_ike_policy_fails if {
	bad := object.union(compliant, {"crypto": {"ike_policies": [
		{"policy_id": 10, "encryption": "AES256"},
		{"policy_id": 20, "encryption": "3DES"},
	]}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.3.1" in ids
}

# ── 1.4.1 NTP auth ──────────────────────────────────────────────────
test_ntp_without_auth_fails if {
	bad := object.union(compliant, {"ntp": {"authentication_enabled": false}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.4.1" in ids
}

test_ntp_disabled_does_not_require_auth if {
	off := object.union(compliant, {"ntp": {"enabled": false, "authentication_enabled": false}})
	ids := control_ids(level1.deny) with input as off
	not "CIS-NET-1.4.1" in ids
}

# ── 1.5.1 / 1.6.1 / 1.7.1 ───────────────────────────────────────────
test_password_encryption_explicitly_disabled_fails if {
	bad := object.union(compliant, {"aaa": {"password_encryption": "DISABLED"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.5.1" in ids
}

test_password_encryption_unknown_does_not_fail_closed if {
	bad := object.union(compliant, {"aaa": {"password_encryption": "UNKNOWN"}})
	ids := control_ids(level1.deny) with input as bad
	not "CIS-NET-1.5.1" in ids
}

test_missing_login_banner_fails if {
	bad := object.union(compliant, {"banners": {"login_banner_present": false}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.6.1" in ids
}

test_http_server_enabled_fails if {
	bad := object.union(compliant, {"services": {"http_server_enabled": "ENABLED"}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.7.1" in ids
}

test_http_server_absent_does_not_fail_closed if {
	bare := {"device": {"detected_vendor": "some-vendor-nobody-wrote-code-for"}}
	ids := control_ids(level1.deny) with input as bare
	not "CIS-NET-1.7.1" in ids
}

# ── 1.8.1 Remote syslog ─────────────────────────────────────────────
test_syslog_enabled_without_a_host_fails if {
	bad := object.union(compliant, {"logging": {"syslog_hosts": []}})
	ids := control_ids(level1.deny) with input as bad
	"CIS-NET-1.8.1" in ids
}

# ── Finding shape ───────────────────────────────────────────────────
test_finding_carries_every_contract_field if {
	bad := object.union(compliant, {"telnet": {"enabled": "ENABLED"}})
	findings := level1.deny with input as bad
	some f in findings
	f.control_id == "CIS-NET-1.1.2"
	f.framework == "CIS"
	f.status == "FAIL"
	f.severity == "CRITICAL"
	f.remediation == "ios_disable_telnet.j2"
	count(f.title) > 0
	count(f.evidence) > 0
}

# A device from a vendor nobody wrote code for, with nothing observed at
# all, must only trip the two controls that are insecure-by-absence on any
# platform — not the vendor-dependent ones, which have no evidence either
# way and must not be presumed insecure.
test_empty_config_from_an_unknown_vendor_trips_only_the_universal_controls if {
	bare := {"device": {"detected_vendor": "some-vendor-nobody-wrote-code-for"}}
	ids := control_ids(level1.deny) with input as bare

	ids == {
		"CIS-NET-1.6.1", # no banner
		"CIS-NET-1.8.1", # no remote syslog
	}
}
