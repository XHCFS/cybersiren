#!/usr/bin/env python3
"""cal2.py — pluggable calibrators with a common interface so calibrated-OR can use
isotonic OR beta calibration. Beta calibration (Kull et al. 2017) is a 3-parameter
parametric map (logit p = c + a*ln s - b*ln(1-s)) that, unlike isotonic, cannot memorize
family-specific score values and extrapolates smoothly in sparse tails — the red-team's
hypothesis for a more generalizable calibrated-OR.

Interface: cal.fit(xs_0_100, ys01); cal.predict(x_0_100) -> p in [0,1].
"""
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

EPS = 1e-6


class IsoCal:
    def __init__(self, cap=0.999):
        self.cap = cap
        self.m = None

    def fit(self, xs, ys):
        self.m = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=self.cap)
        self.m.fit(np.asarray(xs, float), np.asarray(ys, float))
        return self

    def predict(self, x):
        return float(min(self.cap, max(0.0, self.m.predict([float(x)])[0])))


class BetaCal:
    """3-param beta calibration via logistic regression on [ln s, ln(1-s)], s=x/100."""
    def __init__(self, cap=0.999):
        self.cap = cap
        self.clf = None
        self.const = None  # degenerate fallback (single-class train) -> constant prob

    def _feat(self, s):
        s = np.clip(np.asarray(s, float) / 100.0, EPS, 1 - EPS)
        return np.column_stack([np.log(s), np.log(1 - s)])

    def fit(self, xs, ys):
        ys = np.asarray(ys, float)
        if len(set(ys.tolist())) < 2:
            self.const = float(ys.mean())
            return self
        X = self._feat(np.asarray(xs, float))
        self.clf = LogisticRegression(max_iter=5000, C=1e6)  # ~unregularized: 3 params, low variance
        self.clf.fit(X, ys)
        return self

    def predict(self, x):
        if self.const is not None:
            return float(min(self.cap, self.const))
        p = float(self.clf.predict_proba(self._feat([float(x)]))[0, 1])
        return float(min(self.cap, max(0.0, p)))


CALIBRATORS = {"isotonic": IsoCal, "beta": BetaCal}
