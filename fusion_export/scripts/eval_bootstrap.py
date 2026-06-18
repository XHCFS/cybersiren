#!/usr/bin/env python3
"""
Fusion benchmark: stratified random pool from ``ml_ready`` CSV, bootstrap metrics, Wilson CIs,
normal-approximate *p*-values on bootstrap means (see MODELING_AND_EVALUATION.md).

Examples::

  python scripts/eval_bootstrap.py --ml-ready /path/to/ml_ready_dataset.csv \\
    --per-class 400 --bootstrap 100 --use-ml-ready-features

  python scripts/eval_bootstrap.py --ml-ready /path/to/ml_ready_dataset.csv \\
    --per-class 200 --bootstrap 50 --enrich-workers 8
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fusion_kit.enrich import enrich_url  # noqa: E402
from fusion_kit.operational import enrichment_to_operational_row, feature_frame_from_ml_ready_row  # noqa: E402
from fusion_kit.scoring import fusion, load_operational_bundle, score_operational, score_url_hash  # noqa: E402


def _phi(z: float) -> float:
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def _t_pvalue_one_sided_mean_gt_mu0(samples: np.ndarray, mu0: float) -> float:
    x = np.asarray(samples, dtype=np.float64)
    n = int(x.size)
    if n < 2:
        return float("nan")
    m = float(x.mean())
    s = float(x.std(ddof=1))
    if s <= 1e-12:
        return 0.0 if m > mu0 else 1.0
    t = (m - mu0) / (s / math.sqrt(n))
    return float(1.0 - _phi(t))


def _t_pvalue_one_sided_mean_lt_mu0(samples: np.ndarray, mu0: float) -> float:
    x = np.asarray(samples, dtype=np.float64)
    n = int(x.size)
    if n < 2:
        return float("nan")
    m = float(x.mean())
    s = float(x.std(ddof=1))
    if s <= 1e-12:
        return 0.0 if m < mu0 else 1.0
    t = (mu0 - m) / (s / math.sqrt(n))
    return float(1.0 - _phi(t))


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return float("nan"), float("nan")
    p = k / n
    denom = 1.0 + z * z / n
    c = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(max(0.0, p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return c - half, c + half


def _build_pool(ml_ready: Path, per_class: int, seed: int) -> tuple[list[str], np.ndarray]:
    df = pd.read_csv(ml_ready, low_memory=False)
    u = df["url"].astype(str)
    y = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int).to_numpy()
    rng = np.random.default_rng(seed)
    b_ix = np.flatnonzero(y == 0)
    p_ix = np.flatnonzero(y == 1)
    if len(b_ix) < per_class or len(p_ix) < per_class:
        raise SystemExit(f"Need at least {per_class} per class; have benign {len(b_ix)} phish {len(p_ix)}")
    sb = rng.choice(b_ix, size=per_class, replace=False)
    sp = rng.choice(p_ix, size=per_class, replace=False)
    urls = [u.iloc[i] for i in sb] + [u.iloc[i] for i in sp]
    labels = np.array([0] * per_class + [1] * per_class, dtype=np.int32)
    return urls, labels


def _enrich_pool(urls: list[str], op_cols: list[str], workers: int) -> list[dict[str, Any]]:
    def one(u: str) -> dict[str, Any]:
        try:
            ed = enrich_url(u, "bootstrap_eval")
            return enrichment_to_operational_row(ed, columns=op_cols)
        except Exception as e:
            row = {c: np.nan if c in ("asn", "latitude", "longitude", "http_status_code") else "" for c in op_cols}
            row["_enrich_error"] = str(e)
            return row

    out: list[dict[str, Any]] = [None] * len(urls)  # type: ignore[list-assignment]
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(one, u): i for i, u in enumerate(urls)}
        for fut in as_completed(futs):
            i = futs[fut]
            out[i] = fut.result()
    return out  # type: ignore[return-value]


def _ml_ready_rows(urls: list[str], full_ix: pd.DataFrame, op_cols: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for u in urls:
        if u not in full_ix.index:
            raise SystemExit(f"URL not in ml_ready: {u[:80]}")
        raw = feature_frame_from_ml_ready_row(u, full_ix.loc[u])
        rows.append({c: raw.get(c, np.nan) for c in op_cols})
    return rows


def _metrics_block(
    y: np.ndarray, deploy_p: np.ndarray, thr: float
) -> tuple[float, float, float, float, int, int, int, int]:
    pred = (deploy_p >= thr).astype(np.int32)
    benign = y == 0
    phish = y == 1
    tn = int(np.sum(benign & (pred == 0)))
    fp = int(np.sum(benign & (pred == 1)))
    fn = int(np.sum(phish & (pred == 0)))
    tp = int(np.sum(phish & (pred == 1)))
    nb = int(benign.sum())
    np_ = int(phish.sum())
    fpr = fp / nb if nb else float("nan")
    fnr = fn / np_ if np_ else float("nan")
    acc = (tp + tn) / (nb + np_) if (nb + np_) else float("nan")
    tpr = tp / max(tp + fn, 1)
    tnr = tn / max(tn + fp, 1)
    bacc = 0.5 * (tpr + tnr)
    return fpr, fnr, acc, bacc, tn, fp, fn, tp


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ml-ready", type=Path, required=True, help="ml_ready_dataset.csv (url, label, + feature cols)")
    ap.add_argument("--models-dir", type=Path, default=ROOT / "models")
    ap.add_argument("--per-class", type=int, default=350)
    ap.add_argument("--bootstrap", type=int, default=60)
    ap.add_argument("--seed", type=int, default=20260513)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--fusion", choices=("max", "mean"), default="mean")
    ap.add_argument("--enrich-workers", type=int, default=8)
    ap.add_argument("--use-ml-ready-features", action="store_true")
    ap.add_argument("--null-fpr", type=float, default=0.10)
    ap.add_argument("--null-fnr", type=float, default=0.10)
    ap.add_argument("--json-out", type=Path, default=None)
    args = ap.parse_args()

    url_m = args.models_dir / "url_char_lr.joblib"
    op_m = args.models_dir / "hgb_operational.joblib"
    if not args.ml_ready.exists():
        print(f"Missing {args.ml_ready}", file=sys.stderr)
        return 1
    if not url_m.exists() or not op_m.exists():
        print(f"Missing models under {args.models_dir}", file=sys.stderr)
        return 1

    urls, y_pool = _build_pool(args.ml_ready, args.per_class, args.seed)
    n = len(y_pool)
    half = args.per_class

    uh = joblib.load(url_m)
    op_clf, op_cols, ref_card, max_cat = load_operational_bundle(op_m)

    if args.use_ml_ready_features:
        full_ix = pd.read_csv(args.ml_ready, low_memory=False).drop_duplicates(subset=["url"], keep="last").set_index(
            "url", drop=False
        )
        op_rows = _ml_ready_rows(urls, full_ix, op_cols)
    else:
        print(f"Live-enriching {n} URLs (workers={args.enrich_workers}) …")
        op_rows = _enrich_pool(urls, op_cols, args.enrich_workers)

    url_p = score_url_hash(uh, urls)
    op_p = score_operational(op_clf, op_cols, ref_card, max_cat, op_rows)
    deploy_full = fusion(url_p, op_p, mode=args.fusion)

    fpr0, fnr0, acc0, bacc0, tn, fp, fn, tp = _metrics_block(y_pool, deploy_full, args.threshold)
    lo_fpr, hi_fpr = _wilson(fp, half)
    lo_fnr, hi_fnr = _wilson(fn, half)

    rng = np.random.default_rng(args.seed + 99991)
    fprs, fnrs, accs, baccs = [], [], [], []
    for _ in range(int(args.bootstrap)):
        ib = rng.integers(0, half, size=half)
        ip = rng.integers(half, n, size=half)
        idx = np.concatenate([ib, ip])
        fpr, fnr, acc, bacc, *_ = _metrics_block(y_pool[idx], deploy_full[idx], args.threshold)
        fprs.append(fpr)
        fnrs.append(fnr)
        accs.append(acc)
        baccs.append(bacc)

    fa = np.array(fprs)
    fn_a = np.array(fnrs)
    aa = np.array(accs)
    ba = np.array(baccs)

    p_bacc = _t_pvalue_one_sided_mean_gt_mu0(ba, 0.5)
    p_fpr = _t_pvalue_one_sided_mean_lt_mu0(fa, args.null_fpr)
    p_fnr = _t_pvalue_one_sided_mean_lt_mu0(fn_a, args.null_fnr)

    print("=== Fresh fusion bootstrap benchmark ===")
    print(f"pool: n={n}  per_class={half}  threshold={args.threshold}  fusion={args.fusion}")
    print(f"features: {'ml_ready_cached' if args.use_ml_ready_features else 'live_enrich'}")
    print()
    print("--- Point estimate (full pool) ---")
    print(f"accuracy={acc0:.4f}  balanced_acc={bacc0:.4f}  FPR={fpr0:.4f}  FNR={fnr0:.4f}")
    print(f"confusion tn={tn} fp={fp} fn={fn} tp={tp}")
    print(f"Wilson 95% CI FPR (benign n={half}): [{lo_fpr:.4f}, {hi_fpr:.4f}]")
    print(f"Wilson 95% CI FNR (phish n={half}): [{lo_fnr:.4f}, {hi_fnr:.4f}]")
    print()
    print(f"--- Bootstrap n={args.bootstrap} ---")
    print(
        f"balanced_acc  mean={ba.mean():.4f}  std={ba.std(ddof=1):.4f}  "
        f"p2.5={np.quantile(ba, 0.025):.4f}  p97.5={np.quantile(ba, 0.975):.4f}"
    )
    print(
        f"accuracy      mean={aa.mean():.4f}  std={aa.std(ddof=1):.4f}  "
        f"p2.5={np.quantile(aa, 0.025):.4f}  p97.5={np.quantile(aa, 0.975):.4f}"
    )
    print(
        f"FPR           mean={fa.mean():.4f}  std={fa.std(ddof=1):.4f}  "
        f"p2.5={np.quantile(fa, 0.025):.4f}  p97.5={np.quantile(fa, 0.975):.4f}"
    )
    print(
        f"FNR           mean={fn_a.mean():.4f}  std={fn_a.std(ddof=1):.4f}  "
        f"p2.5={np.quantile(fn_a, 0.025):.4f}  p97.5={np.quantile(fn_a, 0.975):.4f}"
    )
    print()
    print("--- Normal-approximate p-values (bootstrap means) ---")
    print(f"p(balanced_acc mean > 0.5)     ≈ {p_bacc:.4g}")
    print(f"p(FPR mean < {args.null_fpr})  ≈ {p_fpr:.4g}")
    print(f"p(FNR mean < {args.null_fnr})  ≈ {p_fnr:.4g}")

    if args.json_out:
        report = {
            "pool_n": n,
            "per_class": half,
            "threshold": args.threshold,
            "fusion": args.fusion,
            "features": "ml_ready_cached" if args.use_ml_ready_features else "live_enrich",
            "point": {
                "accuracy": acc0,
                "balanced_accuracy": bacc0,
                "fpr": fpr0,
                "fnr": fnr0,
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp,
                "wilson_fpr95": [lo_fpr, hi_fpr],
                "wilson_fnr95": [lo_fnr, hi_fnr],
            },
            "bootstrap": {
                "B": int(args.bootstrap),
                "balanced_accuracy": {"mean": float(ba.mean()), "std": float(ba.std(ddof=1))},
                "accuracy": {"mean": float(aa.mean()), "std": float(aa.std(ddof=1))},
                "fpr": {"mean": float(fa.mean()), "std": float(fa.std(ddof=1))},
                "fnr": {"mean": float(fn_a.mean()), "std": float(fn_a.std(ddof=1))},
            },
            "p_values_normal_approx": {
                "balanced_acc_gt_0.5": p_bacc,
                f"fpr_mean_lt_{args.null_fpr}": p_fpr,
                f"fnr_mean_lt_{args.null_fnr}": p_fnr,
            },
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote JSON → {args.json_out.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
