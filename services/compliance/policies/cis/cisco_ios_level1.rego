# cis_ios_level1.rego — CIS Cisco IOS Benchmark Level 1 (illustrative subset)
#
# Master blueprint §7. Control IDs follow the blueprint's CIS-IOS-x.y.z
# scheme; they are not verbatim CIS Benchmark numbering.
#
# Two rules every policy file in this bundle must follow:
#
#   1. Guard on `applies`. app/opa_client.py evaluates the WHOLE
#      data.compliance.<framework> subtree in one call, so every vendor's
#      package sees every device. Without the guard, a Juniper config
#      would be judged against Cisco rules.
#   2. Read optional fields via object.get with an explicit default.
#      A missing `input.ssh` makes `input.ssh.version` undefined, and an
#      undefined expression makes the rule body fail — i.e. a config with
#      no SSH block would silently PASS the "SSH must be v2" control.
#
# What the default should be is decided per control by the device's
# out-of-box state, not by a blanket rule:
#
#   - Where the insecure state is the IOS default (telnet on, no password
#     encryption, no banner, no syslog), an absent or UNKNOWN field FAILS.
#     The parser could not prove the operator hardened it, and an unproven
#     control is not a passed control.
#   - Where the insecure state has to be turned on deliberately (`ip http
#     server`), only an explicit ENABLED fails. Failing those on UNKNOWN
#     would bury the real findings under noise from thin configs.
#
# cisco_ios_level1_test.rego pins this split with an empty-config case.

package compliance.cis.cisco_ios.level1

applies if {
	input.device.detected_vendor == "cisco"
}

# ── CIS Control 1.1.1 — SSH version 2 must be enabled ──────────────
deny contains finding if {
	applies
	version := object.get(input, ["ssh", "version"], "none")
	version != "2"
	finding := {
		"control_id": "CIS-IOS-1.1.1",
		"framework": "CIS",
		"title": "Ensure SSH version 2 is configured",
		"status": "FAIL",
		"severity": "HIGH",
		"evidence": sprintf("ssh.version = %v", [version]),
		"remediation": "ios_ssh_v2_fix.j2",
	}
}

# ── CIS Control 1.1.2 — Telnet must be disabled ─────────────────────
# UNKNOWN is treated as a failure: the parser could not prove telnet is
# off, and an unproven control is not a passed control.
deny contains finding if {
	applies
	status := object.get(input, ["telnet", "enabled"], "UNKNOWN")
	status != "DISABLED"
	finding := {
		"control_id": "CIS-IOS-1.1.2",
		"framework": "CIS",
		"title": "Ensure Telnet is not used for management access",
		"status": "FAIL",
		"severity": "CRITICAL",
		"evidence": sprintf("telnet.enabled = %v", [status]),
		"remediation": "ios_disable_telnet.j2",
	}
}

# ── CIS Control 1.1.3 — SSH access restricted by management ACL ─────
deny contains finding if {
	applies
	object.get(input, ["ssh", "enabled"], false) == true
	acl := object.get(input, ["ssh", "management_acl"], null)
	is_blank(acl)
	finding := {
		"control_id": "CIS-IOS-1.1.3",
		"framework": "CIS",
		"title": "Ensure SSH management access is restricted by an ACL",
		"status": "FAIL",
		"severity": "HIGH",
		"evidence": "ssh.enabled = true but ssh.management_acl is not set",
		"remediation": "ios_ssh_mgmt_acl_fix.j2",
	}
}

# ── CIS Control 1.2.1 — SNMPv1/v2c must not be used ────────────────
deny contains finding if {
	applies
	object.get(input, ["snmp", "enabled"], false) == true
	version := object.get(input, ["snmp", "version"], "none")
	version in ["v1", "v2c"]
	finding := {
		"control_id": "CIS-IOS-1.2.1",
		"framework": "CIS",
		"title": "Ensure SNMP is not using version 1 or 2c",
		"status": "FAIL",
		"severity": "HIGH",
		"evidence": sprintf("snmp.version = %v", [version]),
		"remediation": "ios_snmp_v3_fix.j2",
	}
}

# ── CIS Control 1.2.2 — Default community strings ───────────────────
deny contains finding if {
	applies
	communities := object.get(input, ["snmp", "community_strings"], [])
	some community in communities
	lower(community) in ["public", "private"]
	finding := {
		"control_id": "CIS-IOS-1.2.2",
		"framework": "CIS",
		"title": "Ensure default SNMP community strings are not used",
		"status": "FAIL",
		"severity": "CRITICAL",
		"evidence": sprintf("Default community string detected: %v", [community]),
		"remediation": "ios_snmp_community_fix.j2",
	}
}

# ── CIS Control 1.3.1 — Weak IKE encryption ─────────────────────────
deny contains finding if {
	applies
	policies := object.get(input, ["crypto", "ike_policies"], [])
	some policy in policies
	policy.encryption in ["DES", "3DES"]
	finding := {
		"control_id": "CIS-IOS-1.3.1",
		"framework": "CIS",
		"title": "Ensure IKE policy does not use DES or 3DES encryption",
		"status": "FAIL",
		"severity": "CRITICAL",
		"evidence": sprintf("IKE policy %v uses %v", [object.get(policy, "policy_id", "unnumbered"), policy.encryption]),
		"remediation": "ios_ike_encryption_fix.j2",
	}
}

# ── CIS Control 1.4.1 — NTP authentication ──────────────────────────
deny contains finding if {
	applies
	object.get(input, ["ntp", "enabled"], false) == true
	object.get(input, ["ntp", "authentication_enabled"], false) == false
	finding := {
		"control_id": "CIS-IOS-1.4.1",
		"framework": "CIS",
		"title": "Ensure NTP authentication is enabled",
		"status": "FAIL",
		"severity": "MEDIUM",
		"evidence": "NTP is enabled but authentication is disabled",
		"remediation": "ios_ntp_auth_fix.j2",
	}
}

# ── CIS Control 1.5.1 — Password encryption service ─────────────────
deny contains finding if {
	applies
	status := object.get(input, ["aaa", "password_encryption"], "UNKNOWN")
	status != "ENABLED"
	finding := {
		"control_id": "CIS-IOS-1.5.1",
		"framework": "CIS",
		"title": "Ensure the password encryption service is enabled",
		"status": "FAIL",
		"severity": "HIGH",
		"evidence": sprintf("aaa.password_encryption = %v", [status]),
		"remediation": "ios_password_encryption_fix.j2",
	}
}

# ── CIS Control 1.6.1 — Legal login banner ──────────────────────────
deny contains finding if {
	applies
	object.get(input, ["banners", "login_banner_present"], false) == false
	finding := {
		"control_id": "CIS-IOS-1.6.1",
		"framework": "CIS",
		"title": "Ensure a legal login banner is configured",
		"status": "FAIL",
		"severity": "LOW",
		"evidence": "banners.login_banner_present = false",
		"remediation": "ios_login_banner_fix.j2",
	}
}

# ── CIS Control 1.7.1 — Unencrypted HTTP management server ──────────
deny contains finding if {
	applies
	object.get(input, ["services", "http_server_enabled"], "UNKNOWN") == "ENABLED"
	finding := {
		"control_id": "CIS-IOS-1.7.1",
		"framework": "CIS",
		"title": "Ensure the unencrypted HTTP management server is disabled",
		"status": "FAIL",
		"severity": "MEDIUM",
		"evidence": "services.http_server_enabled = ENABLED",
		"remediation": "ios_disable_http_server.j2",
	}
}

# ── CIS Control 1.8.1 — Remote syslog ───────────────────────────────
# Buffer-only logging is lost when the device reboots or is compromised,
# so a syslog flag with no destination host is still a failure.
deny contains finding if {
	applies
	not remote_logging_configured
	finding := {
		"control_id": "CIS-IOS-1.8.1",
		"framework": "CIS",
		"title": "Ensure logging is sent to a remote syslog host",
		"status": "FAIL",
		"severity": "MEDIUM",
		"evidence": sprintf(
			"logging.syslog_enabled = %v, logging.syslog_hosts = %v",
			[
				object.get(input, ["logging", "syslog_enabled"], false),
				object.get(input, ["logging", "syslog_hosts"], []),
			],
		),
		"remediation": "ios_syslog_fix.j2",
	}
}

remote_logging_configured if {
	object.get(input, ["logging", "syslog_enabled"], false) == true
	count(object.get(input, ["logging", "syslog_hosts"], [])) > 0
}

# `null` and `""` both mean "not configured" — the parser emits null for a
# field it never saw and "" for one it saw empty.
is_blank(value) if value == null

is_blank(value) if value == ""
