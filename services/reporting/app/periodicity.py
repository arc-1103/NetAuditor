"""
Frequency-domain analysis of a daily signal, used for the fleet compliance
score and for new violations per day.

The series is resampled to one value per day, detrended, Hann-windowed and
zero-padded, and an FFT (app/spectral.py) gives a periodogram whose strongest
period is the candidate cycle. A cycle is reported only when four independent
tests agree:
  1. at least two full cycles of data;
  2. the candidate carries a large share of the spectrum's power;
  3. the autocorrelation — computed separately, by zero-padded convolution —
     is clearly positive at that lag, i.e. the signal really does repeat.
  4. a permutation test: re-ordering the same values at random must rarely
     (p <= 0.01) repeat itself as well at its best lag, which keeps false alarms
     on random data near 1%.
Otherwise the answer is "not detected"; no cycle is ever invented.

`mark="low"` flags the troughs of the cycle (a score that drops on a recurring
day); `mark="high"` flags its peaks (violations that spike on a recurring day).
"""

import math
import random
from datetime import date, datetime, timedelta

from app import spectral

MIN_DAYS = 14
MIN_POWER_SHARE = 0.10
MIN_AUTOCORRELATION = 0.25
MIN_AMPLITUDE = 3.0  # peak-to-trough swing, in the series' own units
PERMUTATIONS = 300
MAX_P_VALUE = 0.01


def _day(value) -> date:
    if isinstance(value, datetime):
        return value.date()
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()


def daily_series(points: list[dict], *, value_key: str = "fleet_score", fill: str = "forward") -> list[tuple[date, float]]:
    """One value per day. fill="forward" carries the last reading over gaps (a
    level, like a score); fill="zero" treats missing days as 0 (a count)."""
    by_day: dict[date, float] = {}
    for point in sorted(points, key=lambda p: str(p["evaluated_at"])):
        by_day[_day(point["evaluated_at"])] = float(point[value_key])
    if not by_day:
        return []
    first, last = min(by_day), max(by_day)
    series, current = [], by_day[first]
    for offset in range((last - first).days + 1):
        day = first + timedelta(days=offset)
        current = by_day.get(day, current if fill == "forward" else 0.0)
        series.append((day, current))
    return series


def _spectral_share(values: list[float], n: int, period: float) -> float:
    """Share of the in-range spectral power that lies within 15% of `period`."""
    spectrum = [(p, power) for p, power in spectral.periodogram(values) if 2 <= p <= n / 2]
    total = sum(power for _, power in spectrum)
    return sum(power for p, power in spectrum if abs(p - period) / period <= 0.15) / total if total > 1e-9 else 0.0


def _repeat_period(autocorr: list[float], n: int) -> tuple[int, float]:
    """(lag, autocorrelation) of the shortest lag that repeats nearly as well as the best one.
    Taking the shortest avoids reporting 14 days for a 7-day cycle. The threshold is
    best - 10% (not 0.9*best): when every autocorrelation is negative 0.9*best sits
    above best, nothing matches and next() raised StopIteration (HTTP 500)."""
    lags = range(2, n // 2 + 1)
    best = max(autocorr[lag] for lag in lags)
    lag = next(lag for lag in lags if autocorr[lag] >= best - 0.1 * abs(best))
    return lag, autocorr[lag]


def _strongest_repeat(residual: list[float]) -> float:
    """The highest autocorrelation at any lag from 2 days up to half the history."""
    n = len(residual)
    autocorr = spectral.autocorrelation(residual)
    return max(autocorr[lag] for lag in range(2, n // 2 + 1))


def _p_value(residual: list[float]) -> float:
    """How often does a random re-ordering of the same values repeat itself at
    least this well at its best lag? Taking the best lag for the shuffles as well
    as for the data keeps the comparison fair. A fixed seed keeps the verdict
    reproducible for the same data."""
    observed = _strongest_repeat(residual)
    rng, exceed = random.Random(20260930), 0
    shuffled = list(residual)
    for _ in range(PERMUTATIONS):
        rng.shuffle(shuffled)
        exceed += _strongest_repeat(shuffled) >= observed
    return (1 + exceed) / (1 + PERMUTATIONS)


def count_per_day(events: list[dict], *, time_key: str = "created_at") -> list[dict]:
    """Events -> one {"evaluated_at", "count"} point per day that had any."""
    counts: dict[date, int] = {}
    for event in events:
        day = _day(event[time_key])
        counts[day] = counts.get(day, 0) + 1
    return [{"evaluated_at": f"{day.isoformat()}T12:00:00+00:00", "count": total} for day, total in sorted(counts.items())]


def detect_cycle(points: list[dict], *, value_key: str = "fleet_score", fill: str = "forward",
                 mark: str = "low", min_amplitude: float = MIN_AMPLITUDE) -> dict:
    series = daily_series(points, value_key=value_key, fill=fill)
    n = len(series)
    none = {"detected": False, "method": "FFT periodogram + autocorrelation", "days_analysed": n, "markers": []}
    if n < MIN_DAYS:
        return {**none, "note": f"Needs at least {MIN_DAYS} days of history to look for a recurring pattern; have {n}."}

    values = [v for _, v in series]
    residual = spectral.detrend(values)
    if sum(v * v for v in residual) <= 1e-9:
        return {**none, "note": "No variation beyond the trend."}
    lag, autocorr = _repeat_period(spectral.autocorrelation(residual), n)
    period = float(lag)
    share = _spectral_share(values, n, period)

    # least-squares sinusoid at the detected period (t is the day index 0..n-1)
    a = 2 / n * sum(residual[t] * math.cos(2 * math.pi * t / period) for t in range(n))
    b = 2 / n * sum(residual[t] * math.sin(2 * math.pi * t / period) for t in range(n))
    amplitude = math.hypot(a, b)
    detail = {"period_days": round(period, 1), "power_share": round(share, 2), "autocorrelation_at_period": round(autocorr, 2)}
    if share < MIN_POWER_SHARE or autocorr < MIN_AUTOCORRELATION or 2 * amplitude < min_amplitude:
        return {**none, **detail, "note": "No recurring pattern stands out from the noise."}
    p_value = _p_value(residual)
    detail["p_value"] = round(p_value, 3)
    if p_value > MAX_P_VALUE:
        return {**none, **detail, "note": "A peak of this size is common in random data of this length, so it is not reported as a cycle."}

    fitted = [a * math.cos(2 * math.pi * t / period) + b * math.sin(2 * math.pi * t / period) for t in range(n)]
    sign = -1 if mark == "low" else 1
    markers = [
        {"date": series[t][0].isoformat(), "score": series[t][1], "deviation": round(residual[t], 1)}
        for t in range(n) if sign * fitted[t] >= 0.6 * amplitude and sign * residual[t] > 0
    ]
    word = "drops" if mark == "low" else "spikes"
    return {
        "detected": True, "method": "FFT periodogram + autocorrelation", "days_analysed": n, **detail,
        "amplitude": round(2 * amplitude, 1), "markers": markers,
        "note": f"Recurring {round(period)}-day cycle ({word} of about {round(2 * amplitude, 1)} units).",
    }
