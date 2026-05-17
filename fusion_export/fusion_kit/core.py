"""
Single module: URL normalization, operational feature policy / row mapping, and fusion scoring.

(Pickle-safe entrypoint for the URL model is ``canonicalize_url_batch`` in this file.)
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
import pandas as pd

# Re-export everything from the canonical sub-modules so callers can still
# do ``from fusion_kit.core import ...`` without changes.
from fusion_kit.operational import (  # noqa: F401
    OPERATIONAL_EXCLUDED_COLUMNS,
    OPERATIONAL_FEATURE_COLUMNS,
    enrichment_to_operational_row,
    feature_frame_from_ml_ready_row,
    operational_row_to_frame,
)
from fusion_kit.scoring import (  # noqa: F401
    fusion,
    load_operational_bundle,
    prepare_X_for_hgb,
    score_operational,
    score_url_hash,
)
from fusion_kit.url_normalize import (  # noqa: F401
    canonicalize_url_batch,
    canonicalize_url_for_model,
)
