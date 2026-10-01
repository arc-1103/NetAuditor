from datetime import date, timedelta

from app.periodicity import detect_cycle

START = date(2026, 8, 3)  # a Monday


def trend(days, score_for):
    return [{"evaluated_at": f"{START + timedelta(days=d)}T12:00:00+00:00", "fleet_score": score_for(d)} for d in range(days)]


def weekend_dips(d):
    return 80 - (20 if (START + timedelta(days=d)).weekday() >= 5 else 0)


def test_recurring_weekend_drop_is_detected_and_marked_on_weekends():
    result = detect_cycle(trend(35, weekend_dips))
    assert result["detected"] and round(result["period_days"]) == 7
    days = {date.fromisoformat(m["date"]).weekday() for m in result["markers"]}
    assert days and days <= {5, 6}
    assert len(result["markers"]) >= 8  # most of the 5 weekends' days are flagged


def test_flat_and_steadily_improving_histories_are_not_cyclical():
    assert detect_cycle(trend(35, lambda d: 70))["detected"] is False
    improving = detect_cycle(trend(35, lambda d: 50 + d))
    assert improving["detected"] is False and improving["markers"] == []


def test_too_little_history_never_claims_a_pattern():
    short = detect_cycle(trend(9, weekend_dips))
    assert short["detected"] is False and "at least 14 days" in short["note"]
    assert detect_cycle([])["detected"] is False


def test_random_looking_noise_is_not_reported_as_a_cycle():
    noise = [0, 3, -2, 1, -4, 2, 0, -1, 3, -3, 1, 0, 2, -2, 4, -1, 0, 1, -3, 2, 0, 1, -2, 3, -1, 0, 2, -4, 1, 0, -1, 3, -2, 1, 0]
    assert detect_cycle(trend(35, lambda d: 70 + noise[d]))["detected"] is False


def test_several_readings_in_a_day_use_the_last_one_and_gaps_are_carried_forward():
    readings = [
        {"evaluated_at": "2026-08-03T08:00:00+00:00", "fleet_score": 50},
        {"evaluated_at": "2026-08-03T18:00:00+00:00", "fleet_score": 60},
        {"evaluated_at": "2026-08-06T09:00:00+00:00", "fleet_score": 70},
    ]
    from app.periodicity import daily_series
    assert [v for _, v in daily_series(readings)] == [60, 60, 60, 70]


def test_weekly_pattern_is_found_from_three_weeks_even_with_noise():
    import random
    rng = random.Random(7)
    noisy = [{"evaluated_at": f"{START + timedelta(days=d)}T12:00:00+00:00", "fleet_score": weekend_dips(d) + rng.gauss(0, 4)} for d in range(35)]
    result = detect_cycle(noisy)
    assert result["detected"] and round(result["period_days"]) == 7 and result["p_value"] <= 0.01
    assert detect_cycle(trend(21, weekend_dips))["detected"]


def test_false_alarms_on_random_data_stay_rare():
    import random
    rng = random.Random(2026)
    alarms = 0
    for _ in range(100):
        values = [70 + rng.choice([-4, -3, -2, -1, 0, 1, 2, 3, 4]) for _ in range(35)]
        alarms += detect_cycle(trend(35, lambda d: values[d]))["detected"]
    assert alarms <= 3  # the permutation test targets ~1%; this guards against regressing to ~7%


def test_same_data_always_gives_the_same_verdict():
    data = trend(28, weekend_dips)
    assert detect_cycle(data) == detect_cycle(data)


def test_recurring_monday_spikes_in_new_violations_are_detected_as_highs():
    from app.periodicity import count_per_day
    events = []
    for week in range(6):
        monday = START + timedelta(days=7 * week)
        events += [{"created_at": f"{monday}T09:00:00+00:00"}] * 6            # Monday burst
        events += [{"created_at": f"{monday + timedelta(days=2)}T09:00:00+00:00"}]  # quiet trickle
    result = detect_cycle(count_per_day(events), value_key="count", fill="zero", mark="high", min_amplitude=2.0)
    assert result["detected"] and round(result["period_days"]) == 7
    assert {date.fromisoformat(m["date"]).weekday() for m in result["markers"]} == {0}
