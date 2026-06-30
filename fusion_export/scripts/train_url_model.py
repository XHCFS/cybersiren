#!/usr/bin/env python3
"""
Retrain the URL character n-gram + logistic pipeline (same contract as shipped ``url_char_lr.joblib``).

Requires: ``ml_ready_dataset.csv`` (or any CSV) with columns ``url``, ``label`` (0/1).

Example::

  python scripts/train_url_model.py --csv /path/to/ml_ready_dataset.csv --out models/url_char_lr.joblib
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fusion_kit.url_normalize import canonicalize_url_batch  # noqa: E402


def load_augment_url_list(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    out: list[str] = []
    for line in raw:
        s = line.strip().replace("\r", "")
        if not s or s.startswith("#"):
            continue
        s = s.lower()
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def build_pipeline(
    *,
    n_features_bits: int = 18,
    ngram_lo: int = 2,
    ngram_hi: int = 4,
    C: float = 4.0,
    seed: int = 42,
) -> Pipeline:
    nfeat = 2**n_features_bits
    return Pipeline(
        [
            ("urlnorm", FunctionTransformer(canonicalize_url_batch, validate=False)),
            (
                "hv",
                HashingVectorizer(
                    analyzer="char_wb",
                    ngram_range=(ngram_lo, ngram_hi),
                    n_features=nfeat,
                    alternate_sign=False,
                ),
            ),
            (
                "lr",
                LogisticRegression(
                    C=C,
                    max_iter=3000,
                    class_weight="balanced",
                    random_state=seed,
                    solver="liblinear",
                ),
            ),
        ]
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=ROOT / "models" / "url_char_lr.joblib")
    ap.add_argument("--n-features-bits", type=int, default=18)
    ap.add_argument("--ngram-lo", type=int, default=2)
    ap.add_argument("--ngram-hi", type=int, default=4)
    ap.add_argument("--C", type=float, default=4.0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--augment-benign", type=Path, default=None)
    ap.add_argument("--augment-repeat", type=int, default=1)
    ap.add_argument("--augment-phish", type=Path, default=None)
    ap.add_argument("--augment-phish-repeat", type=int, default=2)
    args = ap.parse_args()

    if not args.csv.exists():
        print(f"Missing {args.csv}", file=sys.stderr)
        return 1

    df = pd.read_csv(args.csv, usecols=["url", "label"], low_memory=False)
    y = df["label"].astype(int).to_numpy()
    X = df["url"].astype(str).str.lower()

    augment_n = nuniq_aug = augment_phish_n = nuniq_phish_aug = 0
    if args.augment_benign is not None:
        if not args.augment_benign.exists():
            print(f"Missing {args.augment_benign}", file=sys.stderr)
            return 1
        extras = load_augment_url_list(args.augment_benign)
        if extras:
            nuniq_aug = len(extras)
            rep = max(1, int(args.augment_repeat))
            if rep > 1:
                extras = extras * rep
            X = pd.concat([X, pd.Series(extras, dtype=str)], ignore_index=True)
            y = np.concatenate([y, np.zeros(len(extras), dtype=np.int64)])
            augment_n = len(extras)
            print(f"Appended {augment_n} augment benign rows ({nuniq_aug} unique ×{rep})")

    if args.augment_phish is not None:
        if not args.augment_phish.exists():
            print(f"Missing {args.augment_phish}", file=sys.stderr)
            return 1
        ex_p = load_augment_url_list(args.augment_phish)
        if ex_p:
            nuniq_phish_aug = len(ex_p)
            rep_p = max(1, int(args.augment_phish_repeat))
            if rep_p > 1:
                ex_p = ex_p * rep_p
            X = pd.concat([X, pd.Series(ex_p, dtype=str)], ignore_index=True)
            y = np.concatenate([y, np.ones(len(ex_p), dtype=np.int64)])
            augment_phish_n = len(ex_p)
            print(f"Appended {augment_phish_n} augment phish rows ({nuniq_phish_aug} unique ×{rep_p})")

    pipe = build_pipeline(
        n_features_bits=args.n_features_bits,
        ngram_lo=args.ngram_lo,
        ngram_hi=args.ngram_hi,
        C=args.C,
        seed=args.seed,
    )
    print(f"Fitting URL char n-gram model on {len(X)} rows …")
    pipe.fit(X, y)
    proba = pipe.predict_proba(X)[:, 1]
    auc = float(roc_auc_score(y, proba))
    acc = float(((proba >= 0.5).astype(int) == y).mean())
    metrics = {
        "train_rows": int(len(X)),
        "augment_benign_rows": augment_n,
        "augment_benign_unique": nuniq_aug,
        "augment_phish_rows": augment_phish_n,
        "augment_phish_unique": nuniq_phish_aug,
        "train_roc_auc": auc,
        "train_accuracy_at_0_5": acc,
        "n_features_bits": args.n_features_bits,
        "ngram_range": [args.ngram_lo, args.ngram_hi],
        "C": args.C,
    }
    payload = {"pipeline": pipe, "kind": "url_hash_lr", "metrics": metrics, "source_csv": str(args.csv.resolve())}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, args.out)
    meta = args.out.with_suffix(".metrics.json")
    meta.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Wrote {args.out.resolve()}")
    print(f"Wrote {meta.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
