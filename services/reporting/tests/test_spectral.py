import cmath
import math

import pytest

from app import spectral


def naive_dft(x):
    n = len(x)
    return [sum(x[t] * cmath.exp(-2j * math.pi * k * t / n) for t in range(n)) for k in range(n)]


def naive_autocorrelation(x):
    n = len(x)
    raw = [sum(x[t] * x[t + k] for t in range(n - k)) / (n - k) for k in range(n)]
    return [r / raw[0] for r in raw]


@pytest.mark.parametrize("n", [1, 2, 4, 8, 32])
def test_fft_matches_the_definition(n):
    x = [math.sin(i) + 0.3 * i for i in range(n)]
    for fast, slow in zip(spectral.fft([complex(v) for v in x]), naive_dft(x)):
        assert fast == pytest.approx(slow, abs=1e-9)


def test_ifft_inverts_fft():
    x = [complex(v) for v in (3, 1, 4, 1, 5, 9, 2, 6)]
    back = spectral.ifft(spectral.fft(x))
    assert all(a == pytest.approx(b, abs=1e-9) for a, b in zip(back, x))


def test_fft_rejects_a_non_power_of_two_length_instead_of_misindexing():
    with pytest.raises(ValueError):
        spectral.fft([0j] * 6)
    with pytest.raises(ValueError):
        spectral.zero_pad([1.0, 2.0, 3.0], 2)


@pytest.mark.parametrize("n", [5, 9, 17, 31])
def test_zero_padded_autocorrelation_equals_the_direct_linear_sum(n):
    x = [math.sin(2 * math.pi * i / 6) + 0.1 * ((i * 7) % 5) for i in range(n)]
    fast, slow = spectral.autocorrelation(x), naive_autocorrelation(x)
    assert len(fast) == n
    assert all(f == pytest.approx(s, abs=1e-9) for f, s in zip(fast, slow))


def test_padding_shorter_than_2n_minus_1_would_give_the_wrong_answer():
    """The bug the padding rule prevents: a circular (N-length) autocorrelation differs from the linear one."""
    x = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    n = len(x)
    circular = [sum(x[t] * x[(t + k) % n] for t in range(n)) for k in range(n)]
    linear = [sum(x[t] * x[t + k] for t in range(n - k)) for k in range(n)]
    assert circular != linear
    padded = spectral.next_pow2(2 * n - 1)
    spectrum = spectral.fft([complex(v) for v in spectral.zero_pad(x, padded)])
    via_fft = [v.real for v in spectral.ifft([abs(c) ** 2 for c in spectrum])][:n]
    assert all(a == pytest.approx(b, abs=1e-9) for a, b in zip(via_fft, linear))


def test_periodogram_reports_the_true_period_of_a_pure_tone():
    x = [math.cos(2 * math.pi * t / 7) for t in range(56)]
    period, _ = max(spectral.periodogram(x), key=lambda p: p[1])
    assert period == pytest.approx(7.0, abs=0.35)


def test_window_and_detrend_behave():
    assert spectral.hann(5)[0] == 0.0 and spectral.hann(5)[2] == pytest.approx(1.0) and spectral.hann(1) == [1.0]
    flat = spectral.detrend([2.0 + 0.5 * i for i in range(10)])
    assert all(abs(v) < 1e-9 for v in flat)
