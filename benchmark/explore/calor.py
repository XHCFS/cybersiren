#!/usr/bin/env python3
"""calor.py — calibrated-OR fusion family (the shipped svc-08 architecture), generalized
to an arbitrary channel list so we can test ADDING a facet/phish-prob channel to Plan A's
4-channel noisy-OR. Per-channel isotonic (raw->P(threat)) fit on TRAIN, noisy-OR product,
final isotonic (raw->P) fit on TRAIN. Returns id->score in [0,100].

This is the minimal-change candidate: implementing it live = plumb the extra signal
svc-06->07->08 and add one more (x,y) calibration channel to calibrated_blender.go.
"""
import numpy as np
from sklearn.isotonic import IsotonicRegression

from combiner_lib import THREAT  # View-A by default: pos=phishing (see combiner_lib)


def _ext_channel(key, scale=1.0):
    def f(r):
        v = r.get(key)
        return None if v is None else float(v) * scale
    return f


# channel extractors return a value in [0,100] or None (absent)
CH_CONTENT = ("content", _ext_channel("content_risk_score"))
CH_HEADER = ("header", _ext_channel("header_risk_score"))
CH_URL = ("url", _ext_channel("url_risk_score"))
CH_ATTACH = ("attachment", _ext_channel("attachment_risk_score"))


def _facet_max(r):
    vals = [r.get("impersonation_score") or 0.0, r.get("deception_score") or 0.0]
    return max(vals) * 100.0  # facets are 0-1 -> 0-100


def _phish100(r):
    v = r.get("phishing_probability")
    return None if v is None else float(v) * 100.0


CH_FACET = ("facet", _facet_max)
CH_PHISH = ("phish", _phish100)


def y_of(r):
    return 1.0 if r["label"] in THREAT else 0.0


class CalibratedOR:
    """Fit per-channel + final isotonic on train rows; score any row -> [0,100]."""

    def __init__(self, channels, cap=0.999):
        self.channels = channels
        self.cap = cap
        self.iso = {}
        self.final = None

    def fit(self, train_rows):
        for name, ext in self.channels:
            xs, ys = [], []
            for r in train_rows:
                v = ext(r)
                if v is not None:
                    xs.append(v); ys.append(y_of(r))
            if len(set(xs)) < 2:   # channel absent / degenerate on train -> skip it
                continue
            m = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=self.cap)
            m.fit(np.array(xs), np.array(ys))
            self.iso[name] = m
        rx, ry = [], []
        for r in train_rows:
            rw = self._raw(r)
            if rw is not None:
                rx.append(rw); ry.append(y_of(r))
        self.final = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1.0)
        self.final.fit(np.array(rx), np.array(ry))
        return self

    def _pc(self, name, ext, r):
        if name not in self.iso:
            return None
        v = ext(r)
        if v is None:
            return None
        return float(min(self.cap, max(0.0, self.iso[name].predict([v])[0])))

    def _raw(self, r):
        pnot = 1.0; present = 0
        for name, ext in self.channels:
            p = self._pc(name, ext, r)
            if p is None:
                continue
            pnot *= (1 - p); present += 1
        return None if present == 0 else (1 - pnot) * 100

    def score(self, r):
        rw = self._raw(r)
        return 0.0 if rw is None else float(self.final.predict([rw])[0]) * 100


def scorer(channels):
    """Return a factory: (train_rows) -> (row -> score)."""
    def build(train_rows):
        co = CalibratedOR(channels).fit(train_rows)
        return co.score
    return build
