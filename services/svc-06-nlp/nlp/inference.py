"""
CyberSiren NLP Inference Engine — SVC-06
=========================================
Loads the fp32 ONNX model (cycle-12, generalization-hardened) and runs inference
per the canonical preprocessing pipeline in NLP-SPEC-v2.0.

Expected artifacts (relative to service root):
    onnx/model_int8.onnx   fp32 DistilBERT, faithful (max|logit-diff|=0). The
                           filename keeps the legacy _int8 suffix for path /
                           Makefile stability; INT8 quantization was abandoned
                           because it destroyed fidelity (see model spec §8).
    tokenizer/             HuggingFace DistilBertTokenizerFast files
    config.json            Thresholds (T, phish_threshold), label map, intent taxonomy

Scoring (v2): content_risk_score = round(P(phishing) * 100). Spam is a distinct,
NON-threat class and never inflates the risk score. URLs are stripped before
tokenization — their reputation is SVC-03's job (combined at the aggregator).
ALL preprocessing is delegated to the canonical text_preprocess.preprocess_email
so the serving path is byte-identical to training (no train/serve skew).

Spec references kept inline so every decision is traceable:
    §2.4  Text preprocessing            §3.6  Head-tail truncation (64 head + 190 tail)
    §3.5  Intent taxonomy (rule-based)  §5.4  Phishing threshold     §8.3  Response schema
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

import numpy as np

from text_preprocess import preprocess_email

logger = logging.getLogger(__name__)

# ── Keyword patterns for rule-based intent detection (spec §3.5) ────────────
# The training notebook implements only the classification head; intent/urgency
# auxiliary heads are reserved for future annotated training data
# (notebook Cell 5 note + spec Limitation #2).
_INTENT_PATTERNS: dict[str, list[str]] = {
    "credential_harvest": [
        r"\bpassword\b", r"\bsign[\s-]?in\b", r"\blog[\s-]?in\b",
        r"\bcredentials?\b", r"\bverify your (?:account|identity|email)\b",
        r"\benter your (?:username|password|pin)\b",
    ],
    "payment_fraud": [
        r"\binvoice\b", r"\bwire transfer\b", r"\bbank account\b",
        r"\bpayment (?:required|needed|overdue|pending)\b",
        r"\bpay now\b", r"\btransfer funds?\b",
    ],
    "malware_delivery": [
        r"\battachment\b", r"\bdownload\b", r"\bclick (?:here|the link|below)\b",
        r"\bopen the (?:file|document|link)\b", r"\binstall\b",
    ],
    "account_verification": [
        r"\bverif(?:y|ication)\b", r"\bconfirm (?:your|account)\b",
        r"\bvalidate\b", r"\bsecurity (?:alert|notice|warning)\b",
        r"\bunusual (?:activity|sign[\s-]?in|access)\b",
    ],
    "prize_scam": [
        r"\b(?:you(?:'ve| have) )?won\b", r"\blottery\b", r"\bprize\b",
        r"\bwinnings?\b", r"\bcongratulations?\b",
    ],
    "impersonation": [
        r"\bpaypal\b", r"\bamazon\b", r"\bmicrosoft\b", r"\bgoogle\b",
        r"\bapple\b", r"\bnetflix\b", r"\bchase bank\b", r"\bwells fargo\b",
        r"\byour bank\b",
    ],
    "data_exfiltration": [
        r"\bsocial security\b", r"\bssn\b", r"\bdate of birth\b",
        r"\bpassport (?:number|copy)\b", r"\bpersonal information\b",
    ],
    "urgency_threat": [
        r"\burgent\b", r"\bimmediately\b", r"\bexpires?\b",
        r"\bdeadline\b", r"\baction required\b", r"\bact now\b",
        r"\bsuspended\b", r"\bterminated\b", r"\bwithin \d+ hours?\b",
    ],
    "social_engineering": [
        r"\bdear (?:friend|colleague|partner)\b", r"\bconfidential\b",
        r"\btrust me\b", r"\bpersonal (?:request|favour|favor)\b",
    ],
    "marketing_spam": [
        r"\bunsubscribe\b", r"\bnewsletter\b", r"\bspecial offer\b",
        r"\blimited[- ]time\b", r"\bdiscount\b", r"\bdeal\b",
    ],
    "benign_notification": [
        r"\byour order\b", r"\btracking (?:number|id)\b", r"\breceipt\b",
        r"\bshipment\b", r"\bconfirmation (?:number|email)\b",
        r"\bthank you for your\b",
    ],
}

# Urgency keywords for the scalar urgency score (spec §3.5)
_URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bexpires?\b", r"\bdeadline\b",
    r"\bact now\b", r"\baction required\b", r"\bsuspended\b", r"\bterminated\b",
    r"\bverify now\b", r"\bwithin \d+ hours?\b", r"\bfailure to\b",
    r"\byour account will\b",
]


class NLPInferenceEngine:
    """
    Full inference pipeline for the CyberSiren NLP email classifier.

    The engine starts successfully even when onnx/model_int8.onnx is a
    placeholder (engine.model_ready == False). The FastAPI layer converts
    that state to a 503 so the service communicates its own readiness clearly.
    """

    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.base_dir = Path(base_dir or os.path.dirname(os.path.abspath(__file__)))
        self.model_ready = False
        self.session = None
        self.tokenizer = None
        self.loading_stage: str = "starting"
        self.loading_progress_pct: int = 0

        self._load_config()
        self._load_tokenizer()
        self._load_model()

    # ── Config ────────────────────────────────────────────────────────────

    def _load_config(self) -> None:
        """Parse config.json produced by notebook Cell 14 (spec §8.4)."""
        self.loading_stage = "loading_config"
        self.loading_progress_pct = 5
        config_path = self.base_dir / "config.json"
        cfg: dict = {}
        if config_path.exists():
            with open(config_path) as f:
                cfg = json.load(f)
        else:
            logger.warning("config.json not found — using spec defaults")

        # JSON serialises integer keys as strings; normalise to int.
        raw_labels = cfg.get("label_map", {"0": "legitimate", "1": "spam", "2": "phishing"})
        self.label_map: dict[int, str] = {int(k): v for k, v in raw_labels.items()}

        raw_intents = cfg.get("intent_taxonomy", {
            str(i): v for i, v in enumerate([
                "credential_harvest", "payment_fraud", "malware_delivery",
                "account_verification", "prize_scam", "impersonation",
                "data_exfiltration", "urgency_threat", "social_engineering",
                "marketing_spam", "benign_notification",
            ])
        })
        self.intent_taxonomy: dict[int, str] = {int(k): v for k, v in raw_intents.items()}

        self.max_length: int = int(cfg.get("max_length", 256))
        self.head_tokens: int = int(cfg.get("head_tokens", 64))
        self.tail_tokens: int = int(cfg.get("tail_tokens", 190))
        # T_opt fitted by LBFGS on val logits in notebook Cell 11.
        self.temperature: float = float(cfg.get("temperature", 1.0))
        # Threshold that achieves phishing recall >= 0.96 (spec §5.4).
        self.phish_threshold: float = float(cfg.get("phish_threshold", 0.5))

        logger.info(
            "Config: max_len=%d head=%d tail=%d T=%.4f phish_thr=%.4f",
            self.max_length, self.head_tokens, self.tail_tokens,
            self.temperature, self.phish_threshold,
        )

    # ── Tokenizer ─────────────────────────────────────────────────────────

    def _load_tokenizer(self) -> None:
        """
        Load DistilBertTokenizerFast.
        Primary:  tokenizer/ directory saved by notebook Cell 14.
        Fallback: download distilbert-base-uncased from HuggingFace.
        """
        self.loading_stage = "loading_tokenizer"
        self.loading_progress_pct = 15
        from transformers import DistilBertTokenizerFast  # type: ignore

        tokenizer_dir = self.base_dir / "tokenizer"
        tokenizer_config = tokenizer_dir / "tokenizer_config.json"

        try:
            if tokenizer_config.exists():
                self.tokenizer = DistilBertTokenizerFast.from_pretrained(str(tokenizer_dir))
                logger.info("Tokenizer loaded from %s", tokenizer_dir)
            else:
                logger.info(
                    "tokenizer/tokenizer_config.json absent — "
                    "downloading distilbert-base-uncased from HuggingFace"
                )
                self.tokenizer = DistilBertTokenizerFast.from_pretrained(
                    "distilbert-base-uncased"
                )
                logger.info("Tokenizer ready (distilbert-base-uncased, cached)")
        except Exception as exc:
            logger.error("Tokenizer load failed: %s", exc)
            raise

    # ── ONNX model ────────────────────────────────────────────────────────

    def _load_model(self) -> None:
        """
        Load onnx/model_int8.onnx with ORT_ENABLE_ALL optimisations (spec §8.2).
        Detects placeholder files (< 1 KB) and logs a clear remediation message.
        Saves an optimized graph cache (model_int8_opt.onnx) so subsequent
        starts skip the ~60-130s graph optimization step.
        """
        self.loading_stage = "checking_model"
        self.loading_progress_pct = 30
        model_path = self.base_dir / "onnx" / "model_int8.onnx"

        if not model_path.exists():
            self.loading_stage = "model_file_missing"
            logger.warning(
                "onnx/model_int8.onnx not found at %s — "
                "copy cybersiren_nlp_out/onnx/model_int8.onnx here and restart.",
                model_path,
            )
            return

        file_size = model_path.stat().st_size
        if file_size < 1024:
            self.loading_stage = "model_file_missing"
            logger.warning(
                "onnx/model_int8.onnx is a placeholder (%d bytes). "
                "Replace it with the real model from the Kaggle notebook output "
                "(cybersiren_nlp_out/onnx/model_int8.onnx, ~66-132 MB) and restart. "
                "POST /predict will return 503 until then.",
                file_size,
            )
            return

        try:
            import onnxruntime as ort  # type: ignore

            opts = ort.SessionOptions()
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            opts.intra_op_num_threads = int(
                os.environ.get("ORT_INTRA_OP_THREADS", "0")
            )
            opts.inter_op_num_threads = 1
            opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
            opts.log_severity_level = 3  # suppress ORT verbose output

            # Save the optimized graph so subsequent starts skip re-optimization
            # (~60-130s on first run → ~5-15s on subsequent runs).
            cache_path = model_path.parent / "model_int8_opt.onnx"

            if cache_path.exists():
                # Load from the pre-optimized cache directly. Don't set
                # optimized_model_filepath when loading an already-optimized
                # graph, otherwise ORT may re-write it and trigger optimization.
                self.loading_stage = "loading_cached_onnx"
                logger.info("Loading pre-optimized ONNX graph from cache: %s", cache_path)
                load_path = cache_path
            else:
                # First run: load original model, write optimized cache for next time.
                opts.optimized_model_filepath = str(cache_path)
                self.loading_stage = "loading_onnx"
                logger.info(
                    "First run: loading + optimizing ONNX graph (this takes 60-130s; "
                    "result is cached at %s for faster subsequent starts)", cache_path
                )
                load_path = model_path
            self.loading_progress_pct = 45

            self.session = ort.InferenceSession(
                str(load_path),
                sess_options=opts,
                providers=["CPUExecutionProvider"],
            )

            # Warmup: trigger any remaining graph compilation so the first real
            # request doesn't pay the compilation cost.
            self.loading_stage = "warming_up"
            self.loading_progress_pct = 90
            dummy_ids = np.zeros((1, 32), dtype=np.int64)
            dummy_mask = np.ones((1, 32), dtype=np.int64)
            self.session.run(
                ["logits"],
                {"input_ids": dummy_ids, "attention_mask": dummy_mask},
            )

            # Set model_ready LAST so /predict can never see model_ready=True
            # with a None session (race protection).
            self.loading_stage = "ready"
            self.loading_progress_pct = 100
            self.model_ready = True
            logger.info(
                "ONNX model loaded: %s (%.1f MB)",
                load_path,
                load_path.stat().st_size / 1e6,
            )
        except Exception as exc:
            self.loading_stage = "error"
            logger.error("ONNX model load failed: %s", exc)
            # Clear ready flag BEFORE clearing session so /predict's check
            # (model_ready) gates access to session correctly.
            self.model_ready = False
            self.session = None

    # ── Preprocessing (spec §2.4) ─────────────────────────────────────────

    def _preprocess(
        self,
        subject: str,
        body_plain: str,
        body_html: str,
    ) -> tuple[str, bool]:
        """
        Returns (preprocessed_text, obfuscation_detected).

        Delegates to the canonical text_preprocess.preprocess_email so the
        serving path is byte-identical to training (URL/email stripping, NFKC,
        zero-width removal, whitespace collapse, template composition). URLs are
        stripped entirely — their reputation is SVC-03's job (scored separately
        and combined at the aggregator). Phone numbers are kept (callback/TOAD
        phishing is a language signal).
        """
        return preprocess_email(subject, body_plain, body_html)

    # ── Head-tail tokenisation (spec §3.6, notebook Cell 4) ───────────────

    def _head_tail_encode(self, text: str) -> dict[str, list[int]]:
        """
        [CLS] + first head_tokens tokens + last tail_tokens tokens + [SEP].

        Mirrors head_tail_encode() in notebook Cell 4.
        head_tokens=64 captures the phishing hook/lure in the opening.
        tail_tokens=190 captures CTA / link / obfuscation in the footer
        ([3] Table 6 FN analysis).
        """
        cls_id = self.tokenizer.cls_token_id
        sep_id = self.tokenizer.sep_token_id

        ids: list[int] = self.tokenizer.encode(
            text, add_special_tokens=False, truncation=False
        )

        keep = self.max_length - 2  # content slots, excluding CLS + SEP
        if len(ids) > keep:
            # Use configured head/tail tokens with validation.
            # If they don't sum to keep, warn and adjust head to fill remainder.
            configured_head = max(self.head_tokens, 0)
            configured_tail = max(self.tail_tokens, 0)
            if configured_head + configured_tail != keep:
                logger.warning(
                    "Configured head/tail token allocation (%d + %d) does not "
                    "match available content slots (%d); adjusting head tokens "
                    "to preserve configured tail tokens.",
                    configured_head,
                    configured_tail,
                    keep,
                )

            tail = min(configured_tail, keep)
            head = min(configured_head, keep - tail)
            head += keep - (head + tail)  # absorb any remaining slots

            if head > 0 and tail > 0:
                ids = ids[:head] + ids[-tail:]
            elif head > 0:
                ids = ids[:head]
            elif tail > 0:
                ids = ids[-tail:]
            else:
                ids = []

        input_ids = [cls_id] + ids + [sep_id]
        return {
            "input_ids": input_ids,
            "attention_mask": [1] * len(input_ids),
        }

    # ── Intent + urgency (rule-based, spec §3.5 / Limitation #2) ─────────

    def _detect_intent(self, text: str, classification: str) -> list[str]:
        """
        Keyword-based intent labels — best effort until annotated training data
        enables the auxiliary intent head (spec §3.4 missing-labels note).
        """
        if classification == "legitimate":
            return ["benign_notification"]

        text_lower = text.lower()
        matched = [
            intent
            for intent, patterns in _INTENT_PATTERNS.items()
            if intent != "benign_notification"
            and any(re.search(p, text_lower) for p in patterns)
        ]

        if not matched:
            matched = ["credential_harvest"]

        return matched

    def _compute_urgency(self, text: str) -> float:
        """Urgency score 0.0–1.0; 5+ keyword hits → 1.0 (spec §3.5)."""
        text_lower = text.lower()
        hits = sum(1 for p in _URGENCY_PATTERNS if re.search(p, text_lower))
        return round(min(1.0, hits / 5.0), 4)

    # ── Inference ─────────────────────────────────────────────────────────

    @staticmethod
    def _softmax(x: np.ndarray) -> np.ndarray:
        e = np.exp(x - x.max())
        return e / e.sum()

    def predict(self, subject: str, body_plain: str, body_html: str = "") -> dict:
        """
        Run the full pipeline for one email and return the spec §8.3 response dict.

        Raises RuntimeError if the model has not been loaded successfully.
        """
        if not self.model_ready or self.session is None:
            raise RuntimeError(
                "Model not ready — onnx/model_int8.onnx is a placeholder. "
                "Replace it with cybersiren_nlp_out/onnx/model_int8.onnx and restart."
            )

        # 1. Preprocess (spec §2.4 + §3.6)
        text, obfuscation_detected = self._preprocess(subject, body_plain, body_html)
        encoded = self._head_tail_encode(text)
        input_ids = np.array([encoded["input_ids"]], dtype=np.int64)
        attention_mask = np.array([encoded["attention_mask"]], dtype=np.int64)

        # 3. ONNX inference — logits shape (1, 3); 0=legitimate 1=spam 2=phishing
        logits: np.ndarray = self.session.run(
            ["logits"],
            {"input_ids": input_ids, "attention_mask": attention_mask},
        )[0][0]

        # 4. Temperature scaling + softmax. Logits are [P(legit), P(spam), P(phish)].
        probs = self._softmax(logits / self.temperature)
        leg_prob = float(probs[0])
        spam_prob = float(probs[1])
        phish_prob = float(probs[2])

        # 5. Scoring scheme (v2): spam != threat. The CONTENT RISK is the
        #    phishing probability ALONE — spam is inbox noise, not a phishing/
        #    malware threat, so it must not inflate the risk score. (The old
        #    checkpoint collapsed spam+phish into the risk because its phishing
        #    class was dead; the v2 model has a live phishing class, so the
        #    collapse is retired.) URL maliciousness is scored separately by
        #    SVC-03 and combined at the aggregator.
        phish_prob_rounded = round(phish_prob, 4)
        content_risk_score = round(phish_prob_rounded * 100)

        # 6. Label: phishing if P(phish) clears the tuned operating point
        #    (phish_threshold, fitted for recall target at min FPR); otherwise
        #    the 3-class argmax (legitimate / spam / phishing).
        if phish_prob >= self.phish_threshold:
            classification = "phishing"
            confidence = phish_prob
        else:
            idx = int(np.argmax(probs))
            classification = self.label_map.get(idx, "legitimate")
            confidence = float(probs[idx])

        # 7. Intent + urgency (rule-based best effort)
        intent_labels = self._detect_intent(text, classification)
        urgency_score = self._compute_urgency(text)

        return {
            "classification": classification,
            "confidence": round(confidence, 4),
            "phishing_probability": phish_prob_rounded,
            "spam_probability": round(spam_prob, 4),
            "content_risk_score": content_risk_score,
            "intent_labels": intent_labels,
            "urgency_score": urgency_score,
            "obfuscation_detected": obfuscation_detected,
            # LIME attributions are expensive offline analysis (spec §7.3);
            # top_tokens is always empty in the production inference path.
            "top_tokens": [],
        }
