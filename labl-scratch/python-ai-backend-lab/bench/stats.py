"""Small statistics helpers: t-based 95% CI over repeats and a bootstrap CI for ratios."""
import math
import random
import statistics

T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
        10: 2.228, 14: 2.145, 19: 2.093, 29: 2.045}


def mean_ci(xs):
    n = len(xs)
    m = statistics.fmean(xs)
    if n < 2:
        return m, m, m
    sd = statistics.stdev(xs)
    df = n - 1
    t = T975.get(df) or T975[min((k for k in T975 if k >= df), default=29)]
    h = t * sd / math.sqrt(n)
    return m, m - h, m + h


def ratio_ci(num, den, reps=4000, seed=0):
    """Bootstrap CI for mean(num)/mean(den) (independent repeats)."""
    rng = random.Random(seed)
    r = []
    for _ in range(reps):
        a = statistics.fmean(rng.choices(num, k=len(num)))
        b = statistics.fmean(rng.choices(den, k=len(den)))
        r.append(a / b)
    r.sort()
    return statistics.fmean(num) / statistics.fmean(den), r[int(0.025 * reps)], r[int(0.975 * reps)]


def pctl(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]
