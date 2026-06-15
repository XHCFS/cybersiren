"""
Unit tests for NLPInferenceEngine — services/svc-06-nlp/nlp/inference.py (v2).

All tests run without the real ONNX model or a network download. The tokenizer
and ONNX session are replaced with lightweight mocks, so the suite is suitable
for CI.

v2 notes:
  - ALL preprocessing lives in text_preprocess.py (single source of truth, no
    train/serve skew). Preprocessing tests exercise that module directly,
    including the adversarial canonicalization defenses (homoglyph / leet /
    letter-spacing folding).
  - Scoring: content_risk_score = round(P(phishing) * 100). Spam is a distinct,
    NON-threat class — it does NOT collapse into phishing and does NOT inflate
    the risk score.

Run:
    cd services/svc-06-nlp/nlp
    pytest test_inference.py -v
"""

import json
import math
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from inference import NLPInferenceEngine
import text_preprocess as tp


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_engine(config_overrides: dict | None = None) -> NLPInferenceEngine:
    """Build an NLPInferenceEngine without touching the filesystem or network."""
    base_cfg = {
        "max_length": 256,
        "head_tokens": 64,
        "tail_tokens": 190,
        "temperature": 1.0,
        "phish_threshold": 0.8,
        "label_map": {"0": "legitimate", "1": "spam", "2": "phishing"},
        "intent_taxonomy": {str(i): v for i, v in enumerate([
            "credential_harvest", "payment_fraud", "malware_delivery",
            "account_verification", "prize_scam", "impersonation",
            "data_exfiltration", "urgency_threat", "social_engineering",
            "marketing_spam", "benign_notification",
        ])},
    }
    if config_overrides:
        base_cfg.update(config_overrides)

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = Path(tmp) / "config.json"
        cfg_path.write_text(json.dumps(base_cfg))

        mock_tok = MagicMock()
        mock_tok.cls_token_id = 101
        mock_tok.sep_token_id = 102
        mock_tok.encode = lambda text, **kw: list(range(len(text.replace(" ", ""))))

        with (
            patch.object(NLPInferenceEngine, "_load_tokenizer", lambda self: None),
            patch.object(NLPInferenceEngine, "_load_model", lambda self: None),
        ):
            engine = NLPInferenceEngine(base_dir=tmp)

    engine.tokenizer = mock_tok
    return engine


# ─────────────────────────────────────────────────────────────────────────────
# 1+2. Canonical preprocessing (text_preprocess.py — shared by train & serve)
# ─────────────────────────────────────────────────────────────────────────────

class TestStripHtmlAndUrls:
    def test_strips_tags(self):
        result = tp.strip_html("<p>Hello <b>world</b></p>")
        assert "Hello" in result and "world" in result and "<" not in result

    def test_empty_string(self):
        assert tp.strip_html("") == ""

    def test_strips_urls(self):
        # URLs are SVC-03's job — removed entirely before tokenization.
        assert "http" not in tp.strip_urls("see https://evil.example.com/login now")

    def test_strips_bare_email(self):
        assert "@" not in tp.strip_urls("contact admin@evil.example.com today")


class TestNormalize:
    def test_nfkc_applied(self):
        assert tp.normalize("ﬁle") == "file"          # fi ligature -> "fi"

    def test_strips_zero_width_space(self):
        assert tp.normalize("hel​lo") == "hello"

    def test_collapses_whitespace(self):
        assert tp.normalize("a   b\t\nc") == "a b c"

    def test_strips_leading_trailing_whitespace(self):
        assert tp.normalize("  hello  ") == "hello"

    def test_empty_string(self):
        assert tp.normalize("") == ""


class TestAdversarialCanonicalization:
    """v2 defenses: map adversarial surface forms back to the clean distribution."""

    def test_homoglyph_folded(self):
        # Cyrillic 'a' (U+0430) -> Latin 'a' so the model sees the brand it knows.
        assert tp.normalize("pаypаl") == "paypal"

    def test_leetspeak_folded_interior(self):
        # Y0ur -> Your, p@ssword -> password, w1ll -> will.
        assert tp.normalize("Y0ur p@ssword w1ll") == "Your password will"

    def test_leet_leaves_legit_alphanumerics(self):
        # Office365 / B2B must NOT be mangled (digit has a digit/boundary neighbor).
        assert tp.normalize("Office365 B2B") == "Office365 B2B"

    def test_letter_spacing_rejoined(self):
        assert tp.normalize("a c c o u n t suspended") == "account suspended"

    def test_letter_spacing_leaves_short_acronyms(self):
        # "U S A" (3 single chars) is below the >=4 rejoin threshold.
        assert tp.normalize("U S A today") == "U S A today"

    def test_detect_obfuscation_flags_homoglyph(self):
        assert tp.detect_obfuscation("pаypal", "verify") is True

    def test_detect_obfuscation_clean_is_false(self):
        assert tp.detect_obfuscation("Normal subject", "Normal body") is False


class TestPreprocess:
    def setup_method(self):
        self.engine = _make_engine()

    def test_returns_tuple(self):
        text, flag = self.engine._preprocess("Hello", "Plain body", "")
        assert isinstance(text, str)
        assert isinstance(flag, bool)

    def test_subject_body_combined(self):
        text, _ = self.engine._preprocess("Test subject", "Test body", "")
        assert "Subject: Test subject" in text
        assert "Body: Test body" in text

    def test_html_body_used_when_plain_empty(self):
        text, _ = self.engine._preprocess("Subj", "", "<p>HTML body</p>")
        assert "HTML body" in text

    def test_plain_body_takes_precedence_over_html(self):
        text, _ = self.engine._preprocess("Subj", "Plain", "<p>HTML</p>")
        assert "Plain" in text

    def test_urls_stripped_from_body(self):
        text, _ = self.engine._preprocess("Subj", "login at https://evil.example.com now", "")
        assert "http" not in text and "evil.example.com" not in text

    def test_obfuscation_detected_zws(self):
        _, flag = self.engine._preprocess("Hello​", "Body", "")
        assert flag is True

    def test_obfuscation_detected_homoglyph(self):
        _, flag = self.engine._preprocess("pаypal", "body", "")
        assert flag is True

    def test_no_obfuscation_for_clean_text(self):
        _, flag = self.engine._preprocess("Normal subject", "Normal body", "")
        assert flag is False


# ─────────────────────────────────────────────────────────────────────────────
# 3. Head-tail tokenisation
# ─────────────────────────────────────────────────────────────────────────────

class TestHeadTailEncode:
    def setup_method(self):
        self.engine = _make_engine()

    def _encode_n_tokens(self, n: int) -> dict:
        self.engine.tokenizer.encode = lambda text, **kw: list(range(n))
        return self.engine._head_tail_encode("dummy text")

    def test_short_text_no_truncation(self):
        result = self._encode_n_tokens(10)
        assert len(result["input_ids"]) == 12
        assert result["input_ids"][0] == 101
        assert result["input_ids"][-1] == 102

    def test_exact_keep_boundary_no_truncation(self):
        keep = self.engine.max_length - 2
        result = self._encode_n_tokens(keep)
        assert len(result["input_ids"]) == keep + 2

    def test_truncation_fires_above_keep(self):
        result = self._encode_n_tokens(300)
        assert len(result["input_ids"]) == self.engine.max_length

    def test_attention_mask_all_ones(self):
        result = self._encode_n_tokens(100)
        assert all(m == 1 for m in result["attention_mask"])

    def test_attention_mask_length_matches_input_ids(self):
        result = self._encode_n_tokens(300)
        assert len(result["input_ids"]) == len(result["attention_mask"])

    def test_head_tail_preserves_head_ids(self):
        n = 300
        self.engine.tokenizer.encode = lambda text, **kw: list(range(n))
        result = self.engine._head_tail_encode("dummy")
        head = self.engine.head_tokens
        assert result["input_ids"][1 : 1 + head] == list(range(head))

    def test_head_tail_preserves_tail_ids(self):
        n = 300
        keep = self.engine.max_length - 2
        head = self.engine.head_tokens
        tail = keep - head
        self.engine.tokenizer.encode = lambda text, **kw: list(range(n))
        result = self.engine._head_tail_encode("dummy")
        expected_tail_ids = list(range(n))[-tail:]
        assert result["input_ids"][1 + head : -1] == expected_tail_ids

    def test_edge_case_head_equals_keep(self):
        engine = _make_engine({"max_length": 66, "head_tokens": 64, "tail_tokens": 0})
        engine.tokenizer.encode = lambda text, **kw: list(range(200))
        result = engine._head_tail_encode("dummy")
        assert len(result["input_ids"]) == 66

    def test_edge_case_head_exceeds_keep(self):
        engine = _make_engine({"max_length": 10, "head_tokens": 200, "tail_tokens": 0})
        engine.tokenizer.encode = lambda text, **kw: list(range(300))
        result = engine._head_tail_encode("dummy")
        assert len(result["input_ids"]) == 10


# ─────────────────────────────────────────────────────────────────────────────
# 4. Intent detection
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectIntent:
    def setup_method(self):
        self.engine = _make_engine()

    def test_legitimate_always_returns_benign(self):
        assert self.engine._detect_intent("anything", "legitimate") == ["benign_notification"]

    def test_credential_harvest_keywords(self):
        result = self.engine._detect_intent(
            "please verify your account and enter your password", "phishing"
        )
        assert "credential_harvest" in result

    def test_urgency_threat_keywords(self):
        result = self.engine._detect_intent(
            "your account will be suspended immediately", "phishing"
        )
        assert "urgency_threat" in result

    def test_marketing_spam_keywords(self):
        result = self.engine._detect_intent(
            "limited-time discount offer, unsubscribe here", "phishing"
        )
        assert "marketing_spam" in result

    def test_payment_fraud_keywords(self):
        result = self.engine._detect_intent(
            "wire transfer required, pay now for invoice", "phishing"
        )
        assert "payment_fraud" in result

    def test_no_match_phishing_defaults_to_credential_harvest(self):
        result = self.engine._detect_intent("completely benign words", "phishing")
        assert result == ["credential_harvest"]

    def test_multiple_intents_returned(self):
        text = "verify your account password, urgent action required, download now"
        result = self.engine._detect_intent(text, "phishing")
        assert len(result) >= 2


# ─────────────────────────────────────────────────────────────────────────────
# 5. Urgency score
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeUrgency:
    def setup_method(self):
        self.engine = _make_engine()

    def test_zero_urgency_for_clean_text(self):
        assert self.engine._compute_urgency("hello, how are you") == 0.0

    def test_single_hit(self):
        score = self.engine._compute_urgency("this is urgent")
        assert 0 < score <= 0.2 + 1e-9

    def test_max_capped_at_1(self):
        text = (
            "urgent immediately expires deadline act now "
            "action required suspended terminated verify now "
            "within 24 hours failure to your account will"
        )
        assert self.engine._compute_urgency(text) == 1.0

    def test_five_hits_gives_1(self):
        text = "urgent immediately expires deadline act now"
        assert self.engine._compute_urgency(text) == 1.0

    def test_score_rounded_to_4dp(self):
        score = self.engine._compute_urgency("urgent immediately")
        assert score == round(score, 4)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Softmax
# ─────────────────────────────────────────────────────────────────────────────

class TestSoftmax:
    def test_output_sums_to_one(self):
        result = NLPInferenceEngine._softmax(np.array([1.0, 2.0, 3.0]))
        assert abs(result.sum() - 1.0) < 1e-7

    def test_all_equal_gives_uniform(self):
        result = NLPInferenceEngine._softmax(np.array([1.0, 1.0, 1.0]))
        assert all(abs(v - 1 / 3) < 1e-7 for v in result)

    def test_large_logit_dominates(self):
        result = NLPInferenceEngine._softmax(np.array([100.0, 0.0, 0.0]))
        assert result[0] > 0.999

    def test_numeric_stability_large_values(self):
        result = NLPInferenceEngine._softmax(np.array([1000.0, 1001.0, 999.0]))
        assert not any(math.isnan(v) for v in result)
        assert abs(result.sum() - 1.0) < 1e-7


# ─────────────────────────────────────────────────────────────────────────────
# 7. Full predict() pipeline (mocked ONNX session)
# ─────────────────────────────────────────────────────────────────────────────

def _engine_with_logits(logits: list[float]) -> NLPInferenceEngine:
    """Return a ready engine whose ONNX session always emits the given logits."""
    engine = _make_engine()
    mock_session = MagicMock()
    mock_session.run.return_value = [np.array([logits])]
    engine.session = mock_session
    engine.model_ready = True
    return engine


class TestPredict:
    def test_phishing_classification(self):
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict("Verify your account now", "Click here to login")
        assert result["classification"] == "phishing"
        assert result["phishing_probability"] > 0.8
        assert result["confidence"] == result["phishing_probability"]

    def test_spam_is_distinct_and_not_a_threat(self):
        # v2: spam is its OWN class (not collapsed into phishing) and its
        # content_risk_score stays low because risk = P(phishing) alone.
        engine = _engine_with_logits([0.0, 5.0, 0.0])
        result = engine.predict("Special offer", "Limited time discount unsubscribe")
        assert result["classification"] == "spam"
        assert result["spam_probability"] > 0.9
        assert result["content_risk_score"] < 50

    def test_legitimate_classification(self):
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("Your order has shipped", "Tracking number: 12345")
        assert result["classification"] == "legitimate"

    def test_content_risk_score_range(self):
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict("s", "b")
        assert 0 <= result["content_risk_score"] <= 100

    def test_content_risk_score_formula(self):
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict("s", "b")
        assert result["content_risk_score"] == round(result["phishing_probability"] * 100)

    def test_top_tokens_always_empty(self):
        engine = _engine_with_logits([2.0, 1.0, 0.0])
        assert engine.predict("s", "b")["top_tokens"] == []

    def test_obfuscation_detected_in_result(self):
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("Hello​world", "body")
        assert result["obfuscation_detected"] is True

    def test_no_obfuscation_for_clean_input(self):
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("Hello world", "Normal email body")
        assert result["obfuscation_detected"] is False

    def test_raises_when_model_not_ready(self):
        engine = _make_engine()
        with pytest.raises(RuntimeError, match="not ready"):
            engine.predict("s", "b")

    def test_response_schema_keys(self):
        engine = _engine_with_logits([1.0, 1.0, 1.0])
        result = engine.predict("subject", "body")
        expected_keys = {
            "classification", "confidence", "phishing_probability",
            "spam_probability", "content_risk_score", "intent_labels",
            "urgency_score", "obfuscation_detected",
            "impersonation_score", "impersonated_brand", "deception_score",
            "top_tokens",
        }
        assert set(result.keys()) == expected_keys

    def test_confidence_bounds(self):
        for logits in [[5.0, 0.0, 0.0], [0.0, 5.0, 0.0], [0.0, 0.0, 5.0]]:
            engine = _engine_with_logits(logits)
            assert 0.0 <= engine.predict("s", "b")["confidence"] <= 1.0

    def test_urgency_score_bounds(self):
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict("URGENT act now immediately", "expires suspended")
        assert 0.0 <= result["urgency_score"] <= 1.0

    def test_html_body_processed_when_plain_empty(self):
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("subj", "", "<p>HTML content</p>")
        assert result["classification"] in ("legitimate", "spam", "phishing")

    def test_temperature_scaling_applied(self):
        logits_arr = [0.0, 0.0, 5.0]
        engine_t1 = _engine_with_logits(logits_arr)
        engine_t2 = _engine_with_logits(logits_arr)
        engine_t2.temperature = 2.0
        r1 = engine_t1.predict("s", "b")
        r2 = engine_t2.predict("s", "b")
        assert r1["phishing_probability"] > r2["phishing_probability"]

    def test_threshold_promotes_borderline_phishing(self):
        """The tuned phish_threshold is a PROMOTE floor: P(phishing) >= threshold
        classifies as phishing even when another class is the bare argmax. Here
        legit is the argmax but P(phish) clears the lowered threshold."""
        engine = _engine_with_logits([0.5, 0.0, 0.4])  # argmax = legitimate
        engine.phish_threshold = 0.30
        result = engine.predict("s", "b")
        assert result["phishing_probability"] > 0.30
        assert result["classification"] == "phishing"
        assert result["confidence"] == result["phishing_probability"]

    def test_below_threshold_uses_argmax(self):
        """When P(phishing) is below the threshold AND not the argmax, the verdict
        falls back to the 3-class argmax (here, legitimate)."""
        engine = _engine_with_logits([5.0, 0.0, 0.0])  # default phish_threshold=0.8
        result = engine.predict("s", "b")
        assert result["phishing_probability"] < 0.8
        assert result["classification"] == "legitimate"


# ─────────────────────────────────────────────────────────────────────────────
# 7b. Brand-impersonation facet (heuristic, P4.2)
# ─────────────────────────────────────────────────────────────────────────────

class TestImpersonationFacet:
    def setup_method(self):
        self.engine = _make_engine()

    # ── unit-level _detect_impersonation ──────────────────────────────────
    def test_brand_claimed_mismatched_sender_high_score(self):
        score, brand = self.engine._detect_impersonation(
            "Your PayPal account has been suspended, verify your account",
            "secure-login.example.com",
        )
        assert score >= 0.9
        assert brand == "paypal"

    def test_brand_claimed_matching_sender_zero(self):
        score, brand = self.engine._detect_impersonation(
            "Your PayPal receipt is ready", "service.paypal.com"
        )
        assert score == 0.0
        assert brand is None

    def test_no_brand_claimed_zero_none(self):
        score, brand = self.engine._detect_impersonation(
            "Lunch tomorrow at noon?", "coworker.example.com"
        )
        assert score == 0.0
        assert brand is None

    def test_empty_sender_with_cues_moderate(self):
        # Unknown sender + brand + impersonation cues → moderate, can't prove.
        score, brand = self.engine._detect_impersonation(
            "Microsoft security alert: verify your account immediately", ""
        )
        assert score == 0.5
        assert brand == "microsoft"

    def test_empty_sender_no_cues_low(self):
        # Just a brand mention, no cues, no sender to check → low confidence.
        # Use an UNAMBIGUOUS brand (paypal); ambiguous words have their own case.
        score, brand = self.engine._detect_impersonation(
            "I got my PayPal statement", ""
        )
        assert score == 0.15
        assert brand == "paypal"

    # ── H1: lookalike / cousin domains must be flagged (not legit) ─────────
    def test_lookalike_domain_secure_paypal_flagged(self):
        score, brand = self.engine._detect_impersonation(
            "Your PayPal account has been suspended, verify your account",
            "secure-paypal.com",
        )
        assert score > 0.5
        assert brand == "paypal"

    def test_lookalike_domain_subdomain_evil_flagged(self):
        score, brand = self.engine._detect_impersonation(
            "PayPal: confirm your identity", "paypal.com.evil.ru"
        )
        assert score > 0.5
        assert brand == "paypal"

    def test_lookalike_domain_paypal_support_flagged(self):
        score, brand = self.engine._detect_impersonation(
            "PayPal support: update your account information", "paypal-support.io"
        )
        assert score > 0.5
        assert brand == "paypal"

    def test_lookalike_apple_id_verify_flagged_with_cue(self):
        score, brand = self.engine._detect_impersonation(
            "Apple ID: verify your account, unusual activity detected",
            "apple-id-verify.ru",
        )
        assert score > 0.5
        assert brand == "apple"

    # ── H2: legit first-party product domains must NOT be flagged ─────────
    def test_legit_first_party_gmail(self):
        score, brand = self.engine._detect_impersonation(
            "Your Gmail security settings were updated", "gmail.com"
        )
        assert score == 0.0
        assert brand is None

    def test_legit_first_party_icloud(self):
        score, brand = self.engine._detect_impersonation(
            "Your iCloud storage is almost full", "icloud.com"
        )
        assert score == 0.0
        assert brand is None

    def test_legit_first_party_outlook(self):
        score, brand = self.engine._detect_impersonation(
            "Your Outlook inbox summary", "outlook.com"
        )
        assert score == 0.0
        assert brand is None

    def test_legit_first_party_onedrive_subdomain(self):
        score, brand = self.engine._detect_impersonation(
            "Your OneDrive files are shared", "onedrive.live.com"
        )
        assert score == 0.0
        assert brand is None

    def test_legit_first_party_office365_subdomain(self):
        score, brand = self.engine._detect_impersonation(
            "Your Office 365 subscription", "outlook.office365.com"
        )
        assert score == 0.0
        assert brand is None

    # ── H3: ambiguous dictionary-word brands gated on cues ────────────────
    def test_ambiguous_word_chase_no_cue_low(self):
        # "chase up the invoice" is ordinary English, benign sender, no cue.
        score, brand = self.engine._detect_impersonation(
            "I will chase up the invoice tomorrow", "mycompany.com"
        )
        assert score <= 0.2

    def test_ambiguous_word_ups_no_cue_low(self):
        score, brand = self.engine._detect_impersonation(
            "The back-ups are ready for review", "internal.corp.com"
        )
        assert score <= 0.2

    def test_ambiguous_word_chase_with_cue_high(self):
        score, brand = self.engine._detect_impersonation(
            "Chase: verify your account, unusual activity detected",
            "phish.example.com",
        )
        assert score >= 0.9
        assert brand == "chase"

    # ── L1: None-safety must not crash ────────────────────────────────────
    def test_none_text_and_domain_safe(self):
        score, brand = self.engine._detect_impersonation(None, None)
        assert score == 0.0
        assert brand is None

    def test_deception_none_safe(self):
        assert self.engine._compute_deception(None) == 0.0

    def test_longest_brand_phrase_wins(self):
        score, brand = self.engine._detect_impersonation(
            "Bank of America: confirm your details", "phish.example.com"
        )
        assert brand == "bankofamerica"
        assert score >= 0.9

    def test_word_boundary_no_false_brand(self):
        # "ups" must not fire inside "groups".
        score, brand = self.engine._detect_impersonation(
            "Join our community groups today", "newsletter.example.com"
        )
        assert score == 0.0
        assert brand is None

    # ── via predict() ─────────────────────────────────────────────────────
    def test_predict_carries_impersonation_fields(self):
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict(
            "PayPal: verify your account",
            "Your account has been suspended, confirm your identity",
            sender_domain="secure-login.example.com",
        )
        assert result["impersonation_score"] >= 0.9
        assert result["impersonated_brand"] == "paypal"

    def test_predict_default_sender_domain_still_works(self):
        # Existing-style call (no sender_domain) must not error and must emit keys.
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("Hello", "Just checking in")
        assert "impersonation_score" in result
        assert result["impersonation_score"] == 0.0
        assert result["impersonated_brand"] is None

    # ── H4: strict-brand cousin-TLD must be caught, real ccTLD must not FP ──
    def test_strict_cousin_tld_with_cues_flagged(self):
        # paypal.ru has the right label but wrong TLD; with phishing cues it is a
        # cousin-TLD impersonation, not legitimate PayPal mail.
        score, brand = self.engine._detect_impersonation(
            "Your PayPal account is suspended, verify your account", "paypal.ru"
        )
        assert score >= 0.9
        assert brand == "paypal"

    def test_strict_cousin_tld_no_cues_low(self):
        # Right label, wrong TLD, but no cue → low (could be a real ccTLD).
        score, brand = self.engine._detect_impersonation(
            "Your PayPal statement is ready", "paypal.ru"
        )
        assert score <= 0.2
        assert brand == "paypal"

    def test_strict_real_cctld_label_match_not_false_positive(self):
        # A real but un-enumerated brand ccTLD (amazon.it) with ordinary order
        # text must NOT be hard-flagged as 0.9 impersonation.
        score, _ = self.engine._detect_impersonation(
            "Your Amazon order has shipped", "amazon.it"
        )
        assert score <= 0.2

    def test_strict_real_domain_legit_zero(self):
        score, brand = self.engine._detect_impersonation(
            "Your Amazon order has shipped", "amazon.com"
        )
        assert score == 0.0
        assert brand is None

    # ── H5: brand that appears only inside a link (brand_text) ─────────────
    def test_link_only_brand_with_cues_flagged(self):
        # Brand is gone from the prose (URL stripped for the model) but present in
        # the URL-keeping brand_text; with cues it is impersonation.
        score, brand = self.engine._detect_impersonation(
            "Click to verify your account",
            "mailer.sendgrid.net",
            brand_text="Click http://paypal.com.evil.ru/login to verify your account",
        )
        assert score >= 0.9
        assert brand == "paypal"

    def test_link_only_brand_no_cues_not_false_positive(self):
        # Legitimate mail that merely links to a brand domain (no phishing cues)
        # must NOT be flagged as strong impersonation.
        score, _ = self.engine._detect_impersonation(
            "Watch our latest update",
            "newsletter.mycompany.com",
            brand_text="Watch our latest update at https://youtube.com/xyz",
        )
        assert score <= 0.2

    def test_predict_catches_brand_in_link(self):
        # End-to-end via predict(): brand only in a link is still scored.
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict(
            "Action required",
            "Please verify your account at http://paypal.com.evil.ru/login",
            sender_domain="mailer.example.net",
        )
        assert result["impersonation_score"] >= 0.9
        assert result["impersonated_brand"] == "paypal"


# ─────────────────────────────────────────────────────────────────────────────
# 7c. Deception facet (heuristic, P4.2)
# ─────────────────────────────────────────────────────────────────────────────

class TestDeceptionFacet:
    def setup_method(self):
        self.engine = _make_engine()

    def test_clearly_deceptive_text_high(self):
        text = (
            "Dear customer, your account has been suspended. "
            "Verify your password immediately or your account will be deleted. "
            "Click here within 24 hours to avoid suspension."
        )
        assert self.engine._compute_deception(text) >= 0.75

    def test_benign_neutral_text_low(self):
        assert self.engine._compute_deception("Lunch tomorrow?") < 0.25

    def test_benign_meeting_text_zero(self):
        assert self.engine._compute_deception(
            "Hi team, attaching the slides for Thursday's review. Thanks!"
        ) == 0.0

    def test_signal_credential_request(self):
        assert self.engine._compute_deception("Please verify your password now") > 0.0

    def test_signal_generic_greeting(self):
        assert self.engine._compute_deception("Dear customer, hello") > 0.0

    def test_signal_reward_lure(self):
        assert self.engine._compute_deception(
            "Congratulations! You have won a free gift card, claim your prize"
        ) > 0.0

    def test_score_bounded_and_capped(self):
        text = (
            "Dear customer act now within 24 hours, verify your password, "
            "your account will be deleted, you have won a prize, click here, "
            "unusual activity detected, security alert"
        )
        score = self.engine._compute_deception(text)
        assert 0.0 <= score <= 1.0
        assert score == 1.0

    def test_score_rounded_to_4dp(self):
        score = self.engine._compute_deception("verify your password")
        assert score == round(score, 4)

    def test_predict_carries_deception_field(self):
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict(
            "Account suspended",
            "Dear customer, verify your password immediately or your account will be closed",
        )
        assert result["deception_score"] >= 0.5


# ─────────────────────────────────────────────────────────────────────────────
# 8. Config loading
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigLoading:
    def _engine_with_config(self, cfg: dict) -> NLPInferenceEngine:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.json").write_text(json.dumps(cfg))
            with (
                patch.object(NLPInferenceEngine, "_load_tokenizer", lambda self: None),
                patch.object(NLPInferenceEngine, "_load_model", lambda self: None),
            ):
                return NLPInferenceEngine(base_dir=tmp)

    def test_custom_threshold_loaded(self):
        assert self._engine_with_config({"phish_threshold": 0.7}).phish_threshold == 0.7

    def test_custom_temperature_loaded(self):
        assert self._engine_with_config({"temperature": 1.5}).temperature == 1.5

    def test_label_map_int_keys(self):
        engine = self._engine_with_config({
            "label_map": {"0": "legitimate", "1": "spam", "2": "phishing"}
        })
        assert engine.label_map[0] == "legitimate"
        assert engine.label_map[2] == "phishing"

    def test_defaults_used_when_config_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(NLPInferenceEngine, "_load_tokenizer", lambda self: None),
                patch.object(NLPInferenceEngine, "_load_model", lambda self: None),
            ):
                engine = NLPInferenceEngine(base_dir=tmp)
        assert engine.max_length == 256
        assert engine.head_tokens == 64
        assert engine.tail_tokens == 190
        assert engine.temperature == 1.0
        assert engine.phish_threshold == 0.5  # spec default in code
