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

# ── Brand-impersonation facet (heuristic, CONSTRAINT G4: NO NER) ────────────
# A curated keyword list of frequently-impersonated brands. Each entry maps a
# brand keyword (matched case-insensitively in subject+body) to its canonical
# *brand token* — the human-readable brand identity returned as
# impersonated_brand (e.g. paypal.com / gmail keyword -> "google"). This is a
# deliberately small, hand-maintained allow-list — NOT named-entity recognition
# and NOT a model. Order does not matter; the longest/most-specific textual
# match wins (we sort matches by phrase length so "bank of america" beats a bare
# "bank"-like cue). Keep this a module-level constant, mirroring _INTENT_PATTERNS,
# so it is trivially auditable and extendable.
_BRAND_DOMAIN_TOKENS: dict[str, str] = {
    "paypal": "paypal",
    "amazon": "amazon",
    "microsoft": "microsoft",
    "office365": "microsoft",
    "office 365": "microsoft",
    "outlook": "microsoft",
    "onedrive": "microsoft",
    "windows": "microsoft",
    "apple": "apple",
    "icloud": "apple",
    "itunes": "apple",
    "appleid": "apple",
    "apple id": "apple",
    "google": "google",
    "gmail": "google",
    "netflix": "netflix",
    "dhl": "dhl",
    "fedex": "fedex",
    "ups": "ups",
    "usps": "usps",
    "irs": "irs",
    "bank of america": "bankofamerica",
    "bankofamerica": "bankofamerica",
    "bofa": "bankofamerica",
    "chase": "chase",
    "chase bank": "chase",
    "wells fargo": "wellsfargo",
    "wellsfargo": "wellsfargo",
    "citibank": "citi",
    "citi": "citi",
    "docusign": "docusign",
    "linkedin": "linkedin",
    "facebook": "facebook",
    "instagram": "instagram",
    "whatsapp": "whatsapp",
    "dropbox": "dropbox",
    "adobe": "adobe",
    "coinbase": "coinbase",
    "binance": "binance",
    "amex": "americanexpress",
    "american express": "americanexpress",
    "hsbc": "hsbc",
    "barclays": "barclays",
    "santander": "santander",
}

# For each canonical brand token, the SET of registrable-domain (eTLD+1) LABELS
# that are LEGITIMATELY operated by that brand. A claimed brand is treated as
# legitimate ONLY when the sender's registrable label exactly equals one of
# these (H2: a single brand ships from several first-party product domains —
# google from gmail.com, apple from icloud.com/itunes.com, microsoft from
# outlook.com/onedrive.live.com/outlook.office365.com, etc.). Any token not
# listed here defaults to {token} (the brand's own name).
_BRAND_LEGIT_DOMAINS: dict[str, set[str]] = {
    "google": {"google", "gmail", "youtube", "googlemail"},
    "apple": {"apple", "icloud", "itunes", "me", "mac"},
    "microsoft": {
        "microsoft", "outlook", "office365", "office", "onedrive",
        "live", "msn", "hotmail", "windows", "sharepoint", "microsoftonline",
    },
    "bankofamerica": {"bankofamerica", "bofa"},
    "americanexpress": {"americanexpress", "amex", "aexp"},
    "wellsfargo": {"wellsfargo", "wf"},
    "citi": {"citi", "citibank", "citigroup"},
    "amazon": {"amazon", "aws", "amazonses", "primevideo"},
    "facebook": {"facebook", "fb", "meta", "messenger"},
    "netflix": {"netflix", "nflxext", "nflximg"},
}

# Ambiguous-word brands: ordinary English words / short tokens that collide with
# everyday usage ("I'll chase up the invoice", "the back-ups are ready", "an
# Apple laptop"). For these we do NOT grant the strong "provable impersonation"
# band on a domain mismatch alone — we require a corroborating impersonation cue
# (_IMPERSONATION_CUE_PATTERNS). Without a cue an ambiguous-word brand stays low
# (H3). Unambiguous brands (paypal, microsoft, docusign, netflix…) keep the
# strong-signal behaviour on mismatch.
_AMBIGUOUS_WORD_BRANDS: set[str] = {"chase", "ups", "apple", "citi"}

# Common public suffixes whose registrable domain is the last TWO labels
# (eTLD = 1 label). Used by the dependency-free eTLD+1 approximation below.
_SINGLE_LABEL_PUBLIC_SUFFIXES: set[str] = {
    "com", "net", "org", "io", "co", "ru", "us", "uk", "de", "fr", "it",
    "es", "nl", "ca", "au", "jp", "cn", "in", "br", "mx", "ch", "se", "no",
    "fi", "dk", "pl", "cz", "be", "at", "ie", "nz", "za", "sg", "info",
    "biz", "xyz", "online", "site", "app", "dev", "me", "tv", "cc", "ai",
}

# Common TWO-label public suffixes (eTLD = 2 labels) → registrable domain is the
# last THREE labels. Hand-enumerated; not exhaustive (we keep this self-contained
# and heuristic per CONSTRAINT G4 — NO public-suffix-list dependency).
_TWO_LABEL_PUBLIC_SUFFIXES: set[str] = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.in", "net.in", "org.in",
    "com.mx", "com.sg", "com.hk", "com.tr",
    "co.kr", "or.kr",
}


def _registrable_label(domain: str) -> str:
    """
    Dependency-free eTLD+1 approximation → the brand-identifying label.

    Splits the host into dot-separated labels and returns the registrable
    domain's leading label (the part just before the public suffix). Examples:
      service.paypal.com  → "paypal"   (suffix "com",   eTLD+1 paypal.com)
      secure-paypal.com   → "secure-paypal"
      paypal.com.evil.ru  → "evil"     (suffix "ru",    eTLD+1 evil.ru)
      bank.barclays.co.uk → "barclays" (suffix "co.uk", eTLD+1 barclays.co.uk)
      onedrive.live.com   → "live"

    Heuristic, NOT a real public-suffix list: we recognise a hand-enumerated set
    of common single-label and two-label public suffixes; when the suffix is
    unknown we fall back to the second-to-last label as the registrable label.
    """
    labels = [p for p in domain.strip().lower().split(".") if p]
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    last_two = ".".join(labels[-2:])
    if last_two in _TWO_LABEL_PUBLIC_SUFFIXES:
        # eTLD is 2 labels → registrable label is the 3rd-from-last (if present).
        return labels[-3] if len(labels) >= 3 else labels[0]
    # Single-label suffix (known or, as a fallback, assumed) → registrable label
    # is the 2nd-from-last label.
    return labels[-2]


def _legit_labels_for(token: str) -> set[str]:
    """Accepted registrable labels for a brand token (defaults to {token})."""
    return _BRAND_LEGIT_DOMAINS.get(token, {token})

# Cues (beyond the bare brand name) that an email is *pretending* to act on a
# brand's behalf — used to grant a moderate impersonation score when the sender
# domain is unknown (empty) and we therefore cannot prove a mismatch.
_IMPERSONATION_CUE_PATTERNS = [
    r"\bverify your (?:account|identity|email|details|information)\b",
    r"\bconfirm your (?:account|identity|details|payment|information)\b",
    r"\bupdate your (?:account|billing|payment|details|information)\b",
    r"\byour account (?:has been |is |will be )?(?:suspended|locked|limited|disabled|closed)\b",
    r"\bunusual (?:activity|sign[\s-]?in|login|access)\b",
    r"\bsecurity (?:alert|notice|warning)\b",
    r"\bsign[\s-]?in to (?:your )?account\b",
    r"\blog[\s-]?in to (?:your )?account\b",
]

# ── Deception facet (heuristic linguistic patterns, CONSTRAINT G4: NO model) ─
# Weighted phishing-deception signals. Each signal contributes its weight when
# any of its patterns match; the total is normalized against a saturation
# constant. Pure rule-based — no NER, no zero-shot, no model. Mirrors the
# _INTENT_PATTERNS style so it is auditable and extendable.
_DECEPTION_SIGNALS: list[tuple[str, float, list[str]]] = [
    # (signal_name, weight, patterns)
    ("urgency_pressure", 1.0, [
        r"\bact now\b", r"\bact immediately\b", r"\bwithin \d+ hours?\b",
        r"\bwithin \d+ days?\b", r"\burgent\b", r"\bimmediately\b",
        r"\bas soon as possible\b", r"\basap\b", r"\bexpires? (?:soon|today|in)\b",
        r"\bfinal (?:notice|warning|reminder)\b", r"\bdo not (?:delay|ignore)\b",
    ]),
    ("generic_greeting", 1.0, [
        r"\bdear (?:customer|user|account holder|member|client|valued)\b",
        r"\bdear (?:sir|madam|sir/madam)\b",
        r"\bhello (?:customer|user|member)\b",
        r"\battention (?:customer|user|account holder)\b",
    ]),
    ("credential_request", 1.5, [
        r"\bverify your (?:password|account|identity|login|credentials?)\b",
        r"\bconfirm your (?:password|details|identity|payment|billing)\b",
        r"\bupdate your (?:password|billing|payment|account|details)\b",
        r"\benter your (?:username|password|pin|otp|credentials?)\b",
        r"\bre[\s-]?enter your (?:password|details)\b",
        r"\bprovide your (?:password|ssn|card|account) (?:number|details)?\b",
    ]),
    ("account_threat", 1.5, [
        r"\byour account (?:has been |is |will be )?(?:suspended|locked|limited|disabled|deactivated|closed|deleted|terminated)\b",
        r"\baccount (?:suspension|termination|closure|deletion)\b",
        r"\bfailure to (?:respond|verify|comply|act)\b",
        r"\bto avoid (?:suspension|closure|deactivation|losing)\b",
        r"\bpermanently (?:closed|deleted|disabled)\b",
    ]),
    ("reward_lure", 1.0, [
        r"\byou(?:'ve| have)? won\b", r"\bclaim your (?:prize|reward|gift|refund)\b",
        r"\bcongratulations?\b", r"\bfree (?:gift|prize|voucher|reward)\b",
        r"\bgift card\b", r"\byou(?:'ve| have)? been selected\b",
        r"\bclaim now\b", r"\byou are (?:a|the) winner\b",
    ]),
    ("click_secrecy", 0.75, [
        r"\bclick (?:here|the link|below)\b", r"\bopen the (?:attachment|link|file)\b",
        r"\bkeep this (?:confidential|private|between us)\b",
        r"\bdo not (?:tell|share|forward|reply to)\b",
        r"\bstrictly confidential\b", r"\bthis is not (?:a |spam)\b",
    ]),
    ("unusual_activity", 1.0, [
        r"\bunusual (?:activity|sign[\s-]?in|login|access)\b",
        r"\bsuspicious (?:activity|login|sign[\s-]?in)\b",
        r"\bdetected (?:a |an )?(?:unusual|unauthorized|suspicious)\b",
        r"\bsecurity (?:alert|notice|warning|breach)\b",
        r"\bsomeone (?:has |may have )?(?:accessed|tried to access)\b",
    ]),
]

# Saturation constant: the total weighted deception score at (or above) which
# the facet saturates to 1.0. Chosen so that ~2-3 independent strong signals
# (e.g. credential_request + account_threat) push the score near the top, while
# a single weak cue stays modest.
_DECEPTION_SATURATION = 4.0


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
                "onnx/model_int8.onnx not found at %s — run `git lfs pull` "
                "(LFS source: python/svc-06-nlp/onnx/) or `make check-nlp-model`, then restart.",
                model_path,
            )
            return

        file_size = model_path.stat().st_size
        if file_size < 1024:
            self.loading_stage = "model_file_missing"
            logger.warning(
                "onnx/model_int8.onnx is a Git LFS placeholder (%d bytes). "
                "Run `git lfs pull` (LFS source: python/svc-06-nlp/onnx/) or "
                "`make check-nlp-model` to fetch the real fp32 model (~266 MB), then restart. "
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

    # ── Brand impersonation (heuristic, CONSTRAINT G4: NO NER) ────────────

    def _detect_impersonation(
        self, text: str, sender_domain: str
    ) -> tuple[float, Optional[str]]:
        """
        Heuristic brand-impersonation facet → (impersonation_score, brand|None).

        Step 1 — claimed brand: scan subject+body for a known-brand keyword from
        _BRAND_DOMAIN_TOKENS. The longest matching phrase wins (so "bank of
        america" beats a bare "bank"). If no brand is claimed, return (0.0, None).

        Step 2 — sender comparison: compare the claimed brand's accepted
        registrable-domain LABELS against the sender's registrable label (the
        eTLD+1 leading label, see _registrable_label). We match on the
        registrable label, NOT a raw substring, so lookalike/cousin domains are
        caught (H1: secure-paypal.com, paypal.com.evil.ru, paypal-support.io all
        have a registrable label != "paypal" → impersonation).
          • sender_domain known + registrable label ∈ accepted set → legitimate, 0.
          • sender_domain known + registrable label ∉ accepted set → mismatch =
            impersonation. For UNAMBIGUOUS brands this is the strongest signal:
            score 0.9, +0.1 if extra impersonation cues are present (cap 1.0).
            For AMBIGUOUS-WORD brands (chase/ups/apple/citi, H3) a mismatch alone
            is NOT enough (they collide with ordinary words) — we require a
            corroborating cue: with a cue → 0.9(+0.1); without a cue → 0.15.
          • sender_domain EMPTY (unknown): we CANNOT prove a mismatch, so we do
            NOT cry impersonation on the brand name alone (legitimate brand mail
            mentions the brand too). We emit a MODERATE score (0.5) only when the
            email also carries impersonation cues (verify/confirm/suspended/...);
            otherwise a low score (0.15) just flagging that a brand was named.
            Ambiguous-word brands with no sender and no cues → 0.0 (just a word).

        Returns the matched brand keyword's canonical token as impersonated_brand
        whenever a non-trivial impersonation score is produced.
        """
        text = text or ""
        sender_domain = sender_domain or ""
        text_lower = text.lower()

        # Find all claimed-brand matches; prefer the longest phrase (most specific).
        matched: list[tuple[str, str]] = []  # (keyword, canonical_token)
        for keyword, token in _BRAND_DOMAIN_TOKENS.items():
            # word-ish boundary match so "ups" doesn't fire inside "groups".
            if re.search(r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])", text_lower):
                matched.append((keyword, token))

        if not matched:
            return 0.0, None

        # Longest keyword wins (e.g. "bank of america" over "bank"-like cues).
        matched.sort(key=lambda kt: len(kt[0]), reverse=True)
        _, claimed_token = matched[0]

        has_cues = any(re.search(p, text_lower) for p in _IMPERSONATION_CUE_PATTERNS)
        is_ambiguous = claimed_token in _AMBIGUOUS_WORD_BRANDS

        sd = sender_domain.strip().lower()
        if sd:
            # We have a sender domain → confirm or refute via the registrable label.
            reg_label = _registrable_label(sd)
            if reg_label in _legit_labels_for(claimed_token):
                # Sender's registrable domain belongs to the brand → not impersonation.
                return 0.0, None
            # Brand claimed but the sender's registrable domain is NOT the brand's.
            if is_ambiguous and not has_cues:
                # Ordinary word + mismatched domain but no impersonation cue → low.
                return 0.15, claimed_token
            score = 0.9 + (0.1 if has_cues else 0.0)
            return round(min(1.0, score), 4), claimed_token

        # sender_domain unknown: cannot prove a mismatch.
        if has_cues:
            # Brand + classic impersonation cues, but unverifiable sender → moderate.
            return 0.5, claimed_token
        if is_ambiguous:
            # Ambiguous word, no cue, no sender → almost certainly just a word.
            return 0.0, None
        # Just a brand mention with no cues and no sender to check → low confidence.
        return 0.15, claimed_token

    # ── Deception (heuristic linguistic patterns, CONSTRAINT G4: NO model) ─

    def _compute_deception(self, text: str) -> float:
        """
        Heuristic deception score 0.0–1.0 from weighted linguistic signals.

        Sums the weight of every _DECEPTION_SIGNALS group that fires at least
        once (urgency/pressure, generic greeting, credential request, account
        threat, reward lure, click/secrecy, unusual-activity), then normalizes
        against _DECEPTION_SATURATION and caps at 1.0. Pure rule-based — no NER,
        no zero-shot, no model retrain.
        """
        text_lower = (text or "").lower()
        total = 0.0
        for _name, weight, patterns in _DECEPTION_SIGNALS:
            if any(re.search(p, text_lower) for p in patterns):
                total += weight
        return round(min(1.0, total / _DECEPTION_SATURATION), 4)

    # ── Inference ─────────────────────────────────────────────────────────

    @staticmethod
    def _softmax(x: np.ndarray) -> np.ndarray:
        e = np.exp(x - x.max())
        return e / e.sum()

    def predict(
        self,
        subject: str,
        body_plain: str,
        body_html: str = "",
        sender_domain: str = "",
        sender_name: str = "",
    ) -> dict:
        """
        Run the full pipeline for one email and return the spec §8.3 response dict.

        sender_domain / sender_name are OPTIONAL (defaulted) so existing callers
        passing only (subject, body, html) keep working. They are plumbed from the
        Kafka AnalysisText contract (sender_domain / sender_name) and used solely
        by the heuristic brand-impersonation facet — when sender_domain is empty
        the facet degrades gracefully (see _detect_impersonation). sender_name is
        accepted for forward-compatibility; the current heuristic keys off the
        domain only.

        Raises RuntimeError if the model has not been loaded successfully.
        """
        if not self.model_ready or self.session is None:
            raise RuntimeError(
                "Model not ready — onnx/model_int8.onnx is missing or a Git LFS "
                "placeholder. Run `git lfs pull` or `make check-nlp-model`, then restart."
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

        # 8. Heuristic facets (CONSTRAINT G4: rule-based only, no NER / no model).
        #    Brand impersonation compares the claimed brand against sender_domain;
        #    deception scores phishing linguistic cues. Both run on the
        #    preprocessed text so they share the train/serve-safe canonicalization.
        impersonation_score, impersonated_brand = self._detect_impersonation(
            text, sender_domain
        )
        deception_score = self._compute_deception(text)

        return {
            "classification": classification,
            "confidence": round(confidence, 4),
            "phishing_probability": phish_prob_rounded,
            "spam_probability": round(spam_prob, 4),
            "content_risk_score": content_risk_score,
            "intent_labels": intent_labels,
            "urgency_score": urgency_score,
            "obfuscation_detected": obfuscation_detected,
            # Heuristic facets (P4.2).
            "impersonation_score": impersonation_score,
            "impersonated_brand": impersonated_brand,
            "deception_score": deception_score,
            # LIME attributions are expensive offline analysis (spec §7.3);
            # top_tokens is always empty in the production inference path.
            "top_tokens": [],
        }
