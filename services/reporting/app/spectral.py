"""
Small spectral-analysis toolkit (pure Python, no dependencies).

Index conventions, stated once because they are where these routines usually go
wrong:
  * A real series x[0..N-1] is zero-padded to length M (a power of two) for the
    FFT. Bin k of the padded transform is the frequency k/M cycles per sample,
    so its period is M/k samples, for k = 1..M/2. Padding does not add
    information; it interpolates the spectrum onto a finer grid, so a peak's
    bin must be converted with M (not N).
  * A linear (non-circular) autocorrelation needs a padded length
    M >= 2N - 1. With a shorter pad the tail wraps around into the low lags
    and corrupts them. Lags 0..N-1 are read from the first N output samples
    and each lag k is averaged over its N-k overlapping products.
"""

import cmath
import math


def next_pow2(n: int) -> int:
    return 1 << max(0, (n - 1).bit_length())


def zero_pad(values: list[float], length: int) -> list[float]:
    if length < len(values):
        raise ValueError("Cannot pad to a length shorter than the input")
    return list(values) + [0.0] * (length - len(values))


def fft(values: list[complex]) -> list[complex]:
    """Iterative radix-2 Cooley-Tukey; the length must be a power of two."""
    n = len(values)
    if n & (n - 1):
        raise ValueError("FFT length must be a power of two")
    if n == 1:
        return list(values)
    bits = n.bit_length() - 1
    data = [values[int(format(i, f"0{bits}b")[::-1], 2)] for i in range(n)]
    size = 2
    while size <= n:
        step = cmath.exp(-2j * math.pi / size)
        for start in range(0, n, size):
            twiddle = 1
            for offset in range(size // 2):
                even, odd = data[start + offset], data[start + offset + size // 2] * twiddle
                data[start + offset], data[start + offset + size // 2] = even + odd, even - odd
                twiddle *= step
        size *= 2
    return data


def ifft(values: list[complex]) -> list[complex]:
    n = len(values)
    return [v.conjugate() / n for v in fft([v.conjugate() for v in values])]


def hann(n: int) -> list[float]:
    return [1.0] if n == 1 else [0.5 - 0.5 * math.cos(2 * math.pi * i / (n - 1)) for i in range(n)]


def detrend(values: list[float]) -> list[float]:
    n = len(values)
    mean_x, mean_y = (n - 1) / 2, sum(values) / n
    denominator = sum((i - mean_x) ** 2 for i in range(n)) or 1.0
    slope = sum((i - mean_x) * (v - mean_y) for i, v in enumerate(values)) / denominator
    return [v - (mean_y + slope * (i - mean_x)) for i, v in enumerate(values)]


def autocorrelation(values: list[float]) -> list[float]:
    """Normalised so lag 0 is 1.0. Computed as IFFT(|FFT(x)|^2) on a zero-padded
    series (length >= 2N-1) so the result is the linear, not circular, one."""
    n = len(values)
    m = next_pow2(2 * n - 1)
    spectrum = fft([complex(v) for v in zero_pad(values, m)])
    raw = [v.real for v in ifft([abs(c) ** 2 for c in spectrum])][:n]
    unbiased = [raw[k] / (n - k) for k in range(n)]
    return [u / unbiased[0] for u in unbiased] if unbiased[0] else [0.0] * n


def periodogram(values: list[float], *, oversample: int = 4) -> list[tuple[float, float]]:
    """[(period_in_samples, power)] for bins 1..M/2 of a detrended, Hann-windowed,
    zero-padded transform (M = next power of two >= oversample * N)."""
    n = len(values)
    window = hann(n)
    tapered = [v * w for v, w in zip(detrend(values), window)]
    m = next_pow2(oversample * n)
    spectrum = fft([complex(v) for v in zero_pad(tapered, m)])
    return [(m / k, abs(spectrum[k]) ** 2) for k in range(1, m // 2 + 1)]
