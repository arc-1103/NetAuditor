from app.drift import build_history


def run(run_id, day, *controls):
    return {
        "run_id": run_id, "created_at": f"2026-09-{day:02d}", "filename": f"{run_id}.cfg",
        "findings": [{"control_id": c, "severity": "HIGH", "title": c} for c in controls],
    }


def test_streak_reports_when_a_control_started_failing():
    runs = [run("r1", 1), run("r2", 2, "CIS-NET-1.1.2"), run("r3", 3, "CIS-NET-1.1.2", "CIS-NET-1.8.1")]
    history = build_history(runs, "r3")
    telnet = history["control_streaks"]["CIS-NET-1.1.2"]
    assert telnet["failing_since_run"] == "r2" and telnet["audits_failing"] == 2 and telnet["last_passed_run"] == "r1"
    syslog = history["control_streaks"]["CIS-NET-1.8.1"]
    assert syslog["failing_since_run"] == "r3" and syslog["audits_failing"] == 1


def test_transitions_list_introduced_and_resolved_with_score_change():
    history = build_history([run("r1", 1, "CIS-NET-1.1.2"), run("r2", 2, "CIS-NET-1.8.1")], "r2")
    step = history["transitions"][0]
    assert step["introduced"] == ["CIS-NET-1.8.1"] and step["resolved"] == ["CIS-NET-1.1.2"]
    assert isinstance(step["score_change"], (int, float))


def test_fixed_then_regressed_control_restarts_its_streak():
    history = build_history([run("r1", 1, "A"), run("r2", 2), run("r3", 3, "A")], "r3")
    assert history["control_streaks"]["A"]["failing_since_run"] == "r3"
    assert history["control_streaks"]["A"]["last_passed_run"] == "r2"


def test_first_audit_and_unknown_run():
    history = build_history([run("r1", 1, "A")], "r1")
    assert history["control_streaks"]["A"]["first_audit_of_device"] is True
    assert build_history([run("r1", 1)], "missing")["runs"] == []


def test_later_audits_are_excluded_when_asking_from_an_earlier_run():
    history = build_history([run("r1", 1, "A"), run("r2", 2)], "r1")
    assert [r["run_id"] for r in history["runs"]] == ["r1"]


def test_control_results_lists_every_control_with_explicit_pass_or_fail():
    from app.risk_scorer import CONTROL_CATALOG, control_results
    rows = control_results([{"control_id": "CIS-NET-1.1.2", "severity": "CRITICAL", "title": "Telnet on"}])
    assert len(rows) == len(CONTROL_CATALOG)
    assert rows[0] == {"control_id": "CIS-NET-1.1.2", "title": "Telnet on", "result": "FAIL", "severity": "CRITICAL"}
    passed = [r for r in rows if r["result"] == "PASS"]
    assert len(passed) == len(CONTROL_CATALOG) - 1 and all(r["title"].startswith("Ensure") for r in passed)


def test_baseline_diff_marks_the_fields_a_control_reads_and_skips_volatile_ones():
    from app.drift import baseline_diff
    old = {"telnet": {"enabled": "DISABLED"}, "ssh": {"version": "2"}, "device": {"config_sha256": "a", "parsing_confidence": 0.9, "raw_hostname": "r1"}}
    new = {"telnet": {"enabled": "ENABLED"}, "ssh": {"version": "1"}, "device": {"config_sha256": "b", "parsing_confidence": 0.7, "raw_hostname": "r1"}}
    changes = baseline_diff(old, new, "CIS-NET-1.1.2")
    assert [c["path"] for c in changes] == ["telnet.enabled", "ssh.version"]
    assert changes[0] == {"path": "telnet.enabled", "before": "DISABLED", "after": "ENABLED", "related": True}
    assert changes[1]["related"] is False


def test_baseline_diff_handles_added_removed_and_identical():
    from app.drift import baseline_diff
    assert baseline_diff({"a": 1}, {"a": 1}) == []
    added = baseline_diff({}, {"logging": {"syslog_hosts": ["x"]}}, "CIS-NET-1.8.1")
    assert added == [{"path": "logging.syslog_hosts", "before": None, "after": ["x"], "related": True}]
