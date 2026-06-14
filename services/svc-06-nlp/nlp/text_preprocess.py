"""
Canonical text preprocessing for SVC-06 NLP — used by BOTH training and
inference so the two paths can never drift (train/serve skew is a silent
killer for this kind of model).

Architecture decision (URLs are SVC-03's job): URLs and bare email addresses
are STRIPPED entirely from the text before tokenization. Their maliciousness
is scored separately by the URL-analysis service and combined at the
aggregator. Phone numbers are kept on purpose — callback/TOAD phishing is a
language signal the NLP model should learn.

Spec refs: §2.4 (text preprocessing), §3.6 (input representation).
"""
import re
import unicodedata

# Zero-width / invisible characters (spec §2.4 step 3).
_ZWS_RE = re.compile(
    r"[​‌‍﻿­"
    r"︀︁︂︃︄︅︆︇"
    r"︈︉︊︋︌︍︎️]"
)

# URL / email stripping. Order matters; applied as a list.
_URL_PATTERNS = [
    re.compile(r"(?:https?://|ftp://)\S+", re.I),
    re.compile(r"\bwww\.\S+", re.I),
    # space-mangled form that appears in over-preprocessed corpora:
    # "http www foo com ..." -> drop the scheme token + following labels
    re.compile(r"\bhttps?\b(?:\s+\w+){1,8}?\s+(?:com|net|org|info|co|io|ru|cn)\b", re.I),
    re.compile(r"\S+@\S+\.\S+"),  # bare email addresses (sender identity = SVC-04)
]

_INPUT_FORMAT = "Subject: {subject}\n\nBody: {body}"


def strip_urls(text: str) -> str:
    """Remove URLs and bare emails entirely; collapse resulting whitespace."""
    if not isinstance(text, str) or not text:
        return ""
    for pat in _URL_PATTERNS:
        text = pat.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def strip_html(text: str) -> str:
    """BeautifulSoup HTML -> plain text, regex fallback (spec §2.4 step 1)."""
    if not text:
        return ""
    try:
        from bs4 import BeautifulSoup  # type: ignore
        return BeautifulSoup(text, "html.parser").get_text(separator=" ")
    except Exception:
        return re.sub(r"<[^>]+>", " ", text)


# Cross-script CONFUSABLES (homoglyphs) -> Latin. NFKC does NOT fold these (Cyrillic
# 'а' / Greek 'ο' are distinct scripts), so a trivial homoglyph swap ("pаypal") evades
# the model entirely (measured: 100 -> 0). Map them back to the clean form the model
# was trained on. This DEFENDS at inference even before retraining (it only normalizes
# adversarial input toward the clean distribution).
_CONFUSABLES = {
    # Cyrillic -> Latin
    "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i","ѕ":"s","ј":"j",
    "ԁ":"d","һ":"h","ո":"n","м":"m","т":"t","в":"b","к":"k","ѵ":"v","ԝ":"w","ɡ":"g","ӏ":"l",
    "А":"A","Е":"E","О":"O","Р":"P","С":"C","Х":"X","У":"Y","І":"I","В":"B","К":"K","М":"M","Т":"T","Н":"H","Ѕ":"S","Ј":"J",
    # Greek -> Latin
    "ο":"o","α":"a","ε":"e","ρ":"p","τ":"t","ν":"v","κ":"k","ι":"i","υ":"u","χ":"x","μ":"m",
    "Ο":"O","Α":"A","Ε":"E","Ρ":"P","Τ":"T","Β":"B","Η":"H","Κ":"K","Μ":"M","Ν":"N","Χ":"X","Υ":"Y","Ι":"I","Ζ":"Z",
}
_CONF_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}


def map_confusables(text: str) -> str:
    return text.translate(_CONF_TABLE) if text else text


# Leetspeak / digit-homoglyph fold ("Y0ur", "w1ll", "p@ssword", "pa$$word"). Classic
# char->symbol subs used to evade lexical signals. Fold ONLY when BOTH neighbors are
# ASCII letters, so legit digit-bearing tokens are untouched ("Office365": the 3 has a
# digit neighbor -> skipped; "MD5"/"24x7"/"B2B": boundary/digit neighbor -> skipped).
# Measured: leetspeak evaded the model 60% before this; this maps it back to clean Latin.
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}


def fold_leet(text: str) -> str:
    if not text or len(text) < 3:
        return text
    ch = list(text)
    for i in range(1, len(ch) - 1):
        c = ch[i]
        if c in _LEET:
            l, r = ch[i - 1], ch[i + 1]
            if l.isascii() and l.isalpha() and r.isascii() and r.isalpha():
                ch[i] = _LEET[c]
    return "".join(ch)


# Letter-spacing evasion ("v e r i f y", "a c c o u n t") — splitting a word with spaces
# defeats the tokenizer. Re-join runs of >=4 single word-chars each followed by one space.
# Threshold 4 leaves real spaced acronyms ("U S A") alone. Measured: space_split evaded 30%.
_SPACED_RE = re.compile(r"(?:\b\w[ \t]){3,}\w\b")


def join_spaced(text: str) -> str:
    if not text:
        return text
    return _SPACED_RE.sub(lambda m: m.group(0).replace(" ", "").replace("\t", ""), text)


def normalize(text: str) -> str:
    """NFKC + homoglyph fold + leet fold + de-spacing + zero-width removal + whitespace collapse (spec §2.4)."""
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = map_confusables(text)            # cross-script homoglyph defense
    text = fold_leet(text)                  # leetspeak / digit-homoglyph defense
    text = _ZWS_RE.sub("", text)
    text = join_spaced(text)                # letter-spacing defense (before whitespace collapse)
    return re.sub(r"\s+", " ", text).strip()


def detect_obfuscation(subject: str, body: str) -> bool:
    """True if raw text differs from NFKC, carries zero-width chars, homoglyphs, leet, or letter-spacing."""
    raw = _INPUT_FORMAT.format(subject=subject, body=body)
    return (unicodedata.normalize("NFKC", raw) != raw
            or bool(_ZWS_RE.search(raw))
            or map_confusables(raw) != raw
            or fold_leet(raw) != raw
            or join_spaced(raw) != raw)


def preprocess_email(subject: str, body_plain: str, body_html: str = "") -> tuple[str, bool]:
    """
    Full preprocessing for one email -> (model_input_text, obfuscation_detected).

    Pipeline: pick body (plain or stripped html) -> detect obfuscation on raw ->
    strip URLs/emails -> NFKC/zero-width/whitespace normalize -> compose template.
    Identical in training and serving.
    """
    subject = subject or ""
    body_plain = body_plain or ""
    if not body_plain.strip() and body_html:
        body_plain = strip_html(body_html)

    obfuscation = detect_obfuscation(subject, body_plain)

    subj = normalize(strip_urls(subject))
    body = normalize(strip_urls(body_plain))
    return _INPUT_FORMAT.format(subject=subj, body=body), obfuscation


def preprocess_composed(text: str) -> str:
    """
    Re-run an already-composed 'Subject: .. Body: ..' string through the same
    URL-strip + normalize, for cleaning a training corpus consistently with
    serving. Returns the cleaned composed text.
    """
    return normalize(strip_urls(text))
