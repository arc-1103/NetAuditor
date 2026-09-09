# generic_level1.rego — vendor-agnostic CIS-style baseline (illustrative subset)
#
# Replaces the old one-bundle-per-vendor model (a cisco_ios_level1.rego here,
# a fortinet_level1.rego there). That model can never reach "any vendor" —
# it only ever reaches "the vendors someone remembered to add a bundle for".
# Since Parsing already normalizes every vendor's config into the SAME
# SecurityBaseline schema (contracts/security_baseline.schema.json), these
# rules read that schema directly and apply identically no matter what
# `input.device.detected_vendor` says. There is no `applies` guard here —
# every device gets the same evaluation.
#
# Fail-closed policy, now that we can't assume a specific vendor's
# out-of-box defaults:
#
#   - Controls whose insecure state is vendor-dependent (does this platform
#     ship with Telnet on? SNMPv1 on? an HTTP admin server on?) fail ONLY on
#     positive evidence of the insecure value. An absent or UNKNOWN field is
#     "no evidence either way", not "presumed insecure" — we can no longer
#     assume any one vendor's factory defaults hold for an arbitrary device.
#   - Controls whose absence is itself directly observable and universally
#     expected hardening regardless of platform (a login banner exists; logs
#     go somewhere off-box) still fail closed on absence, exactly as the
#     vendor-specific bundles they replace did for the same two controls.
#
# Remediation is the one place vendor identity still matters, because a CLI
# fix command is inherently vendor-specific syntax — that's not hardcoding,
# it's what "device-specific step-by-step remediation" means. That mapping
# lives in `remediation_templates` below as plain data, not as a rule per
# vendor: adding remediation for a new vendor is adding a row, never a new
# `applies if input.device.detected_vendor == "..."` branch. A vendor with
# no row yet still gets a full compliance verdict — it just comes back with
# `remediation: null`, which contracts/compliance_finding.schema.json already
# treats as "no template exists yet", not an error.
#
# generic_level1_test.rego pins both the fail-open/fail-closed split and the
# vendor-independent verdict.

package compliance.cis.generic.level1

remediation_templates := {
	"CIS-NET-1.1.1": {"cisco": "ios_ssh_v2_fix.j2"},
	"CIS-NET-1.1.2": {"cisco": "ios_disable_telnet.j2", "fortinet": "fortinet_disable_telnet.j2"},
	"CIS-NET-1.1.3": {"cisco": "ios_ssh_mgmt_acl_fix.j2", "fortinet": "fortinet_ssh_mgmt_acl_fix.j2"},
	"CIS-NET-1.2.1": {"cisco": "ios_snmp_v3_fix.j2", "fortinet": "fortinet_snmp_v3_fix.j2"},
	"CIS-NET-1.2.2": {"cisco": "ios_snmp_community_fix.j2", "fortinet": "fortinet_snmp_community_fix.j2"},
	"CIS-NET-1.3.1": {"cisco": "ios_ike_encryption_fix.j2", "fortinet": "fortinet_ike_encryption_fix.j2"},
	"CIS-NET-1.4.1": {"cisco": "ios_ntp_auth_fix.j2", "fortinet": "fortinet_ntp_auth_fix.j2"},
	"CIS-NET-1.5.1": {"cisco": "ios_password_encryption_fix.j2"},
	"CIS-NET-1.6.1": {"cisco": "ios_login_banner_fix.j2", "fortinet": "fortinet_login_banner_fix.j2"},
	"CIS-NET-1.7.1": {"cisco": "ios_disable_http_server.j2", "fortinet": "fortinet_disable_http_fix.j2"},
	"CIS-NET-1.8.1": {"cisco": "ios_syslog_fix.j2", "fortinet": "fortinet_syslog_fix.j2"},
}

remediation_for(control_id) := object.get(
	object.get(remediation_templates, control_id, {}),
	object.get(input, ["device", "detected_vendor"], ""),
	null,
)

# ── CIS-NET-1.1.1 — SSH version 2 where SSH is in use ────────────────
# Evidence-only: a device with no SSH block at all isn't proven insecure,
# it's simply not observed to use SSH.
deny contains finding if {
	version := object.get(input, ["ssh", "version"], "none")
	version != "none"
	version != "2"
	finding := {
		"control_id": "CIS-NET-1.1.1",
		"framework": "CIS",
		"title": "Ensure SSH version 2 is configured where SSH is in use",
		"status": "FAIL",
		"severity": "HIGH",
		"evidence": sprintf("ssh.version = %v", [version]),
		"remediation": remediation_for("CIS-NET-1.1.1"),
	}
}

# ── CIS-NET-1.1.2 — Telnet must be disabled ──────────────────────────
deny contains finding if {
	object.get(input, ["telnet", "enabled"], "DISABLED") == "ENABLED"
	finding := {
		"control_id": "CIS-NET-1.1.2",
		"framework": "CIS",
		"title": "Ensure Telnet is not used for administrative access",
		"status": "FAIL",
		"severity": "CRITICAL",
		"evidence": "telnet.enabled = ENABLED",
		"remediation": remediation_for("CIS-NET-1.1.2"),
	}
}

# ── CIS-NET-1.1.3 — SSH access restricted by a management ACL ───────
deny contains finding if {
	object.get(input, ["ssh", "enabled"], false) == true
	acl := object.get(input, ["ssh", "management_acl"], null)
	is_blank(acl)
	finding := {
		"control_id": "CIS-NET-1.1.3",
		"framework": "CIS",
		"title": "Ensure SSH management access is restricted by an ACL",
		"status": "FAIL",
		"severity": "HIGH",
		"evidence": "ssh.enabled = true but ssh.management_acl is not set",
		"remediation": remediation_for("CIS-NET-1.1.3"),
	}
}

# ── CIS-NET-1.2.1 — SNMPv1/v2c must not be used ──────────────────────
deny contains finding if {
	object.get(input, ["snmp", "enabled"], false) == true
	version := object.get(input, ["snmp", "version"], "none")
	version in ["v1", "v2c"]
	finding := {
		"control_id": "CIS-NET-1.2.1",
		"framework": "CIS",
		"title": "Ensure SNMP is not using version 1 or 2c",
		"status": "FAIL",
		"severity": "HIGH",
		"evidence": sprintf("snmp.version = %v", [version]),
		"remediation": remediation_for("CIS-NET-1.2.1"),
	}
}

# ── CIS-NET-1.2.2 — Default community strings ────────────────────────
deny contains finding if {
	communities := object.get(input, ["snmp", "community_strings"], [])
	some community in communities
	lower(community) in ["public", "private"]
	finding := {
		"control_id": "CIS-NET-1.2.2",
		"framework": "CIS",
		"title": "Ensure default SNMP community strings are not used",
		"status": "FAIL",
		"severity": "CRITICAL",
		"evidence": sprintf("Default community string detected: %v", [community]),
		"remediation": remediation_for("CIS-NET-1.2.2"),
	}
}

# ── CIS-NET-1.3.1 — Weak IKE/IPsec Phase 1 encryption ────────────────
deny contains finding if {
	policies := object.get(input, ["crypto", "ike_policies"], [])
	some policy in policies
	policy.encryption in ["DES", "3DES"]
	finding := {
		"control_id": "CIS-NET-1.3.1",
		"framework": "CIS",
		"title": "Ensure IKE/IPsec Phase 1 proposals do not use DES or 3DES encryption",
		"status": "FAIL",
		"severity": "CRITICAL",
		"evidence": sprintf("IKE policy %v uses %v", [object.get(policy, "policy_id", "unnumbered"), policy.encryption]),
		"remediation": remediation_for("CIS-NET-1.3.1"),
	}
}

# ── CIS-NET-1.4.1 — NTP authentication where NTP is in use ───────────
deny contains finding if {
	object.get(input, ["ntp", "enabled"], false) == true
	object.get(input, ["ntp", "authentication_enabled"], false) == false
	finding := {
		"control_id": "CIS-NET-1.4.1",
		"framework": "CIS",
		"title": "Ensure NTP authentication is enabled where NTP is in use",
		"status": "FAIL",
		"severity": "MEDIUM",
		"evidence": "NTP is enabled but authentication is disabled",
		"remediation": remediation_for("CIS-NET-1.4.1"),
	}
}

# ── CIS-NET-1.5.1 — Password/secret storage must not be explicitly disabled
deny contains finding if {
	object.get(input, ["aaa", "password_encryption"], "UNKNOWN") == "DISABLED"
	finding := {
		"control_id": "CIS-NET-1.5.1",
		"framework": "CIS",
		"title": "Ensure stored passwords/secrets are not left unencrypted",
		"status": "FAIL",
		"severity": "HIGH",
		"evidence": "aaa.password_encryption = DISABLED",
		"remediation": remediation_for("CIS-NET-1.5.1"),
	}
}

# ── CIS-NET-1.6.1 — Legal login banner ───────────────────────────────
# Fails closed on absence: a banner either was observed or wasn't, and its
# absence is a directly provable fact regardless of vendor.
deny contains finding if {
	object.get(input, ["banners", "login_banner_present"], false) == false
	finding := {
		"control_id": "CIS-NET-1.6.1",
		"framework": "CIS",
		"title": "Ensure a legal login banner is configured",
		"status": "FAIL",
		"severity": "LOW",
		"evidence": "banners.login_banner_present = false",
		"remediation": remediation_for("CIS-NET-1.6.1"),
	}
}

# ── CIS-NET-1.7.1 — Unencrypted HTTP admin/management access ────────
deny contains finding if {
	object.get(input, ["services", "http_server_enabled"], "DISABLED") == "ENABLED"
	finding := {
		"control_id": "CIS-NET-1.7.1",
		"framework": "CIS",
		"title": "Ensure unencrypted HTTP administrative access is disabled",
		"status": "FAIL",
		"severity": "MEDIUM",
		"evidence": "services.http_server_enabled = ENABLED",
		"remediation": remediation_for("CIS-NET-1.7.1"),
	}
}

# ── CIS-NET-1.8.1 — Remote syslog ────────────────────────────────────
# Fails closed on absence, same reasoning as the login banner: whether the
# parser observed a remote log host is directly provable, not a guess about
# vendor defaults.
deny contains finding if {
	not remote_logging_configured
	finding := {
		"control_id": "CIS-NET-1.8.1",
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
		"remediation": remediation_for("CIS-NET-1.8.1"),
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
