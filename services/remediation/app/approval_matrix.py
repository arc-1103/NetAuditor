"""
Approval Matrix / Reviewer RBAC — docs/Additional-Features.md §7.

Maps this codebase's existing flat roles (gateway/app/auth.py: admin,
operator, auditor) onto the doc's three-tier model:
  - operator ~ "Network Operator": may approve LOW-risk, single-device
    changes only.
  - admin ~ "Security Lead" AND "Change Advisory" combined — this codebase
    has no fourth role to split them into, so admin covers both "MEDIUM
    risk, multi-device, can override a rejection" and "one of the two
    required approvers for a HIGH-risk/reachability-changing change".
  - auditor never approves — gateway's require_operator dependency already
    excludes it from the approve route before a request reaches here.

The "HIGH risk, reachability-changing -> 2-person rule" row is the same
condition as app/decision.py's DUAL_APPROVAL action (both key off risk and
blast radius the same way), so this module keys dual-approval directly off
`decision_action` rather than re-deriving its own risk/blast-radius
thresholds — one ruleset, cited by one ledger event, not two that could
drift apart.
"""

SINGLE_DEVICE_MAX_BLAST_RADIUS = 0


class ApprovalDenied(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def check_permission(*, role: str, decision_action: str, risk: str, blast_radius_count: int, actor_type: str = "human") -> None:
    """Raises ApprovalDenied if `role` may not give an approval at all for
    this proposal. Doesn't decide whether a *second* approval is still
    required — see dual_approval_satisfied.

    docs/Suggestions.md item 1 (Agent Firewall): the AI may propose and
    explain a remediation, but never itself count as the approval. `role`
    alone can't express that — the roles are all human RBAC roles issued to
    a logged-in user (gateway/app/auth.py's `users` table), so a caller that
    reached this service directly (bypassing the gateway) with a forged
    x-user-role header would otherwise pass. `actor_type` is a second,
    independent signal an AI/automation caller cannot spoof into "human"
    without it being a deliberate lie in its own request, and defaults to
    "human" so every existing gateway-routed call is unaffected.
    """
    if actor_type != "human":
        raise ApprovalDenied("An AI/automation actor cannot approve a remediation — approval requires a human.")
    if decision_action == "BLOCK":
        raise ApprovalDenied("This proposal's decision classification is BLOCK — it cannot be approved.")
    if role == "admin":
        return  # Security Lead / Change Advisory — no further restriction.
    if role != "operator":
        raise ApprovalDenied(f"Role {role!r} is not permitted to approve remediations.")
    if risk == "HIGH":
        raise ApprovalDenied("Network Operator cannot approve a HIGH-risk change — requires Security Lead / Change Advisory.")
    if blast_radius_count > SINGLE_DEVICE_MAX_BLAST_RADIUS:
        raise ApprovalDenied("Network Operator can only approve single-device changes.")


def dual_approval_satisfied(decision_action: str, prior_approving_actors: set[str], new_actor: str) -> bool:
    """docs/Additional-Features.md §7's "2-person rule": two distinct actors
    must each independently call approve(approved=True) before a
    DUAL_APPROVAL-classified proposal is actually approved. Any other
    classification needs only the one approval already in hand."""
    if decision_action != "DUAL_APPROVAL":
        return True
    return len(prior_approving_actors | {new_actor}) >= 2
