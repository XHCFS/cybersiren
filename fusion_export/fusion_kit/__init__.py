"""Portable fusion scoring kit (enrichment + URL char model + operational HGB + fusion)."""

__version__ = "1.6.0"

from fusion_kit.core import (
    OPERATIONAL_EXCLUDED_COLUMNS,
    OPERATIONAL_FEATURE_COLUMNS,
    canonicalize_url_batch,
    canonicalize_url_for_model,
    enrichment_to_operational_row,
    feature_frame_from_ml_ready_row,
    fusion,
    load_operational_bundle,
    operational_row_to_frame,
    prepare_X_for_hgb,
    score_operational,
    score_url_hash,
)

__all__ = [
    "OPERATIONAL_EXCLUDED_COLUMNS",
    "OPERATIONAL_FEATURE_COLUMNS",
    "canonicalize_url_batch",
    "canonicalize_url_for_model",
    "enrichment_to_operational_row",
    "feature_frame_from_ml_ready_row",
    "fusion",
    "load_operational_bundle",
    "operational_row_to_frame",
    "prepare_X_for_hgb",
    "score_operational",
    "score_url_hash",
]
