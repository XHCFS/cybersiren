"""
Unit tests for NLPInferenceEngine — python/svc-06-nlp/inference.py.

All tests run without the real ONNX model or a network download.
The tokenizer and ONNX session are replaced with lightweight mocks,
so the suite is suitable for CI (make test-short equivalent for Go).

Run:
    cd python/svc-06-nlp
    pytest test_inference.py -v
"""

import json
import math
import re
import tempfile
import unicodedata
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

# We import the module under test — not the engine constructor directly so that
# individual static methods and module-level constants can also be exercised.
import inference as inf
from inference import NLPInferenceEngine


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_engine(config_overrides: dict | None = None) -> NLPInferenceEngine:
    """
    Build an NLPInferenceEngine without touching the filesystem or network.

    The tokenizer is replaced with a mock that encodes text as a fixed-length
    sequence of token-ids (one per word character, capped at 512).  The ONNX
    session is left as None so model_ready == False; tests that need inference
    set session and model_ready themselves.
    """
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

        # Patch _load_tokenizer and _load_model so the constructor returns fast.
        mock_tok = MagicMock()
        mock_tok.cls_token_id = 101
        mock_tok.sep_token_id = 102
        # encode() returns one id per non-space character (predictable length).
        mock_tok.encode = lambda text, **kw: list(range(len(text.replace(" ", ""))))

        with (
            patch.object(NLPInferenceEngine, "_load_tokenizer", lambda self: None),
            patch.object(NLPInferenceEngine, "_load_model", lambda self: None),
        ):
            engine = NLPInferenceEngine(base_dir=tmp)

    engine.tokenizer = mock_tok
    return engine


# ─────────────────────────────────────────────────────────────────────────────
# 1. Module-level regex constants
# ─────────────────────────────────────────────────────────────────────────────

class TestZwsRegex:
    def test_matches_zero_width_space(self):
        assert inf._ZWS_RE.search("\u200b")

    def test_matches_zwnj(self):
        assert inf._ZWS_RE.search("\u200c")

    def test_matches_bom(self):
        assert inf._ZWS_RE.search("\ufeff")

    def test_matches_soft_hyphen(self):
        assert inf._ZWS_RE.search("\u00ad")

    def test_does_not_match_regular_space(self):
        assert not inf._ZWS_RE.search(" ")

    def test_does_not_match_ascii(self):
        assert not inf._ZWS_RE.search("hello world")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Static preprocessing methods
# ─────────────────────────────────────────────────────────────────────────────

class TestStripHtml:
    def test_strips_tags(self):
        result = NLPInferenceEngine._strip_html("<p>Hello <b>world</b></p>")
        assert "Hello" in result
        assert "world" in result
        assert "<" not in result

    def test_empty_string(self):
        assert NLPInferenceEngine._strip_html("") == ""

    def test_plain_text_unchanged(self):
        text = "No HTML here"
        assert NLPInferenceEngine._strip_html(text) == text

    def test_decodes_html_entities(self):
        result = NLPInferenceEngine._strip_html("<p>caf&eacute;</p>")
        assert "café" in result or "caf" in result  # BS4 decodes entities


class TestNormalize:
    def test_nfkc_applied(self):
        # fi ligature (U+FB01) → "fi"
        assert NLPInferenceEngine._normalize("\uFB01le") == "file"

    def test_strips_zero_width_space(self):
        assert NLPInferenceEngine._normalize("hel\u200blo") == "hello"

    def test_collapses_whitespace(self):
        assert NLPInferenceEngine._normalize("a   b\t\nc") == "a b c"

    def test_strips_leading_trailing_whitespace(self):
        assert NLPInferenceEngine._normalize("  hello  ") == "hello"

    def test_empty_string(self):
        assert NLPInferenceEngine._normalize("") == ""


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

    def test_obfuscation_detected_zws(self):
        _, flag = self.engine._preprocess("Hello\u200b", "Body", "")
        assert flag is True

    def test_obfuscation_detected_homoglyph(self):
        # '\uFB01' (fi ligature) differs from its NFKC form "fi"
        _, flag = self.engine._preprocess("\uFB01rst", "body", "")
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
        """Produce an engine where encode() always returns n token ids."""
        self.engine.tokenizer.encode = lambda text, **kw: list(range(n))
        return self.engine._head_tail_encode("dummy text")

    def test_short_text_no_truncation(self):
        result = self._encode_n_tokens(10)
        # 10 content + CLS + SEP = 12
        assert len(result["input_ids"]) == 12
        assert result["input_ids"][0] == 101   # CLS
        assert result["input_ids"][-1] == 102  # SEP

    def test_exact_keep_boundary_no_truncation(self):
        keep = self.engine.max_length - 2  # 254
        result = self._encode_n_tokens(keep)
        assert len(result["input_ids"]) == keep + 2  # 256

    def test_truncation_fires_above_keep(self):
        result = self._encode_n_tokens(300)
        assert len(result["input_ids"]) == self.engine.max_length  # 256

    def test_attention_mask_all_ones(self):
        result = self._encode_n_tokens(100)
        assert all(m == 1 for m in result["attention_mask"])

    def test_attention_mask_length_matches_input_ids(self):
        result = self._encode_n_tokens(300)
        assert len(result["input_ids"]) == len(result["attention_mask"])

    def test_head_tail_preserves_head_ids(self):
        """First head_tokens ids in the encoded output should match original head."""
        n = 300
        self.engine.tokenizer.encode = lambda text, **kw: list(range(n))
        result = self.engine._head_tail_encode("dummy")
        head = self.engine.head_tokens  # 64
        # ids[1 : 1+head] (skip CLS) must be range(0, head)
        assert result["input_ids"][1 : 1 + head] == list(range(head))

    def test_head_tail_preserves_tail_ids(self):
        """Last tail_tokens ids (before SEP) should match original tail."""
        n = 300
        keep = self.engine.max_length - 2  # 254
        head = self.engine.head_tokens      # 64
        tail = keep - head                  # 190
        self.engine.tokenizer.encode = lambda text, **kw: list(range(n))
        result = self.engine._head_tail_encode("dummy")
        expected_tail_ids = list(range(n))[-tail:]
        assert result["input_ids"][1 + head : -1] == expected_tail_ids

    def test_edge_case_head_equals_keep(self):
        """head_tokens == keep → tail == 0 → no tail slice, just head."""
        engine = _make_engine({"max_length": 66, "head_tokens": 64, "tail_tokens": 0})
        n = 200
        engine.tokenizer.encode = lambda text, **kw: list(range(n))
        result = engine._head_tail_encode("dummy")
        keep = 66 - 2  # 64
        assert len(result["input_ids"]) == 66  # CLS + 64 + SEP

    def test_edge_case_head_exceeds_keep(self):
        """head_tokens > keep: falls back to ids[:keep] only."""
        engine = _make_engine({"max_length": 10, "head_tokens": 200, "tail_tokens": 0})
        n = 300
        engine.tokenizer.encode = lambda text, **kw: list(range(n))
        result = engine._head_tail_encode("dummy")
        assert len(result["input_ids"]) == 10  # CLS + 8 + SEP


# ─────────────────────────────────────────────────────────────────────────────
# 4. Intent detection
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectIntent:
    def setup_method(self):
        self.engine = _make_engine()

    def test_legitimate_always_returns_benign(self):
        result = self.engine._detect_intent("anything", "legitimate")
        assert result == ["benign_notification"]

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
            "limited-time discount offer, unsubscribe here", "spam"
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

    def test_no_match_spam_defaults_to_marketing_spam(self):
        result = self.engine._detect_intent("completely benign words", "spam")
        assert result == ["marketing_spam"]

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
        score = self.engine._compute_urgency(text)
        assert score == 1.0

    def test_five_hits_gives_1(self):
        # 5 distinct urgency keywords → score = min(1.0, 5/5) = 1.0
        text = "urgent immediately expires deadline act now"
        score = self.engine._compute_urgency(text)
        assert score == 1.0

    def test_score_rounded_to_4dp(self):
        score = self.engine._compute_urgency("urgent immediately")
        # 2 hits / 5 = 0.4 exactly — still tests rounding is applied
        assert score == round(score, 4)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Softmax
# ─────────────────────────────────────────────────────────────────────────────

class TestSoftmax:
    def test_output_sums_to_one(self):
        x = np.array([1.0, 2.0, 3.0])
        result = NLPInferenceEngine._softmax(x)
        assert abs(result.sum() - 1.0) < 1e-7

    def test_all_equal_gives_uniform(self):
        x = np.array([1.0, 1.0, 1.0])
        result = NLPInferenceEngine._softmax(x)
        assert all(abs(v - 1 / 3) < 1e-7 for v in result)

    def test_large_logit_dominates(self):
        x = np.array([100.0, 0.0, 0.0])
        result = NLPInferenceEngine._softmax(x)
        assert result[0] > 0.999

    def test_numeric_stability_large_values(self):
        # Without the x - x.max() trick, exp(1000) overflows; must not produce nan
        x = np.array([1000.0, 1001.0, 999.0])
        result = NLPInferenceEngine._softmax(x)
        assert not any(math.isnan(v) for v in result)
        assert abs(result.sum() - 1.0) < 1e-7


# ─────────────────────────────────────────────────────────────────────────────
# 7. Full predict() pipeline (mocked ONNX session)
# ─────────────────────────────────────────────────────────────────────────────

def _engine_with_logits(logits: list[float]) -> NLPInferenceEngine:
    """Return a ready engine whose ONNX session always emits the given logits.

    predict() accesses the output as: session.run(...)[0][0]
      - run() returns a list of arrays: [output_array]
      - [0] → output_array with shape (batch, num_classes) = (1, 3)
      - [0] → 1-D array of shape (3,)
    So run() must return [np.array([logits])] (shape 1×3 inside a list).
    """
    engine = _make_engine()
    mock_session = MagicMock()
    # shape (1, 3) inside a list — mirrors real ORT output for batch=1
    mock_session.run.return_value = [np.array([logits])]
    engine.session = mock_session
    engine.model_ready = True
    return engine


class TestPredict:
    def test_phishing_classification(self):
        # logits strongly favour class 2 (phishing) and prob > 0.8 threshold
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict("Verify your account now", "Click here to login")
        assert result["classification"] == "phishing"
        assert result["phishing_probability"] > 0.8
        assert result["confidence"] == result["phishing_probability"]

    def test_spam_classification(self):
        # logits favour class 1 (spam); phishing prob below 0.8
        engine = _engine_with_logits([0.0, 5.0, 0.0])
        result = engine.predict("Special offer", "Limited time discount unsubscribe")
        assert result["classification"] == "spam"
        assert result["spam_probability"] > result["phishing_probability"]

    def test_legitimate_classification(self):
        # logits favour class 0 (legitimate)
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("Your order has shipped", "Tracking number: 12345")
        assert result["classification"] == "legitimate"

    def test_content_risk_score_range(self):
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict("s", "b")
        assert 0 <= result["content_risk_score"] <= 100

    def test_content_risk_score_formula(self):
        # content_risk_score = round(phishing_probability * 100)
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict("s", "b")
        assert result["content_risk_score"] == round(result["phishing_probability"] * 100)

    def test_top_tokens_always_empty(self):
        engine = _engine_with_logits([2.0, 1.0, 0.0])
        result = engine.predict("s", "b")
        assert result["top_tokens"] == []

    def test_obfuscation_detected_in_result(self):
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("Hello\u200bworld", "body")
        assert result["obfuscation_detected"] is True

    def test_no_obfuscation_for_clean_input(self):
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("Hello world", "Normal email body")
        assert result["obfuscation_detected"] is False

    def test_raises_when_model_not_ready(self):
        engine = _make_engine()
        # model_ready is False by default in _make_engine()
        with pytest.raises(RuntimeError, match="not ready"):
            engine.predict("s", "b")

    def test_response_schema_keys(self):
        engine = _engine_with_logits([1.0, 1.0, 1.0])
        result = engine.predict("subject", "body")
        expected_keys = {
            "classification", "confidence", "phishing_probability",
            "spam_probability", "content_risk_score", "intent_labels",
            "urgency_score", "obfuscation_detected", "top_tokens",
        }
        assert set(result.keys()) == expected_keys

    def test_confidence_bounds(self):
        for logits in [[5.0, 0.0, 0.0], [0.0, 5.0, 0.0], [0.0, 0.0, 5.0]]:
            engine = _engine_with_logits(logits)
            result = engine.predict("s", "b")
            assert 0.0 <= result["confidence"] <= 1.0

    def test_urgency_score_bounds(self):
        engine = _engine_with_logits([0.0, 0.0, 10.0])
        result = engine.predict("URGENT act now immediately", "expires suspended")
        assert 0.0 <= result["urgency_score"] <= 1.0

    def test_html_body_processed_when_plain_empty(self):
        engine = _engine_with_logits([5.0, 0.0, 0.0])
        result = engine.predict("subj", "", "<p>HTML content</p>")
        assert result["classification"] in ("legitimate", "spam", "phishing")

    def test_temperature_scaling_applied(self):
        """T=2 should push probabilities toward uniform vs T=1."""
        logits_arr = [0.0, 0.0, 5.0]
        engine_t1 = _engine_with_logits(logits_arr)
        engine_t2 = _engine_with_logits(logits_arr)
        engine_t2.temperature = 2.0

        r1 = engine_t1.predict("s", "b")
        r2 = engine_t2.predict("s", "b")
        # Higher temperature → phishing probability is lower
        assert r1["phishing_probability"] > r2["phishing_probability"]


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
        engine = self._engine_with_config({"phish_threshold": 0.7})
        assert engine.phish_threshold == 0.7

    def test_custom_temperature_loaded(self):
        engine = self._engine_with_config({"temperature": 1.5})
        assert engine.temperature == 1.5

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
        # Default phish_threshold is 0.5 (spec default in code)
        assert engine.phish_threshold == 0.5
