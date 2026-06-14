"""
Metamorphic adversarial-robustness harness for the SVC-06 NLP model.

Why this exists
---------------
A frozen list of adversarial example strings goes stale the moment attackers
invent technique N+1. You cannot enumerate the future. What does NOT go stale is
an *invariant*:

    A semantics-preserving transformation of a phishing email the model already
    catches must NOT let that email evade.  For every caught phishing base `b`
    and every transform T in the registry:   crs(T(b)) must stay above FLOOR.

Adding a new attack class is one new function in TRANSFORMS — it is then applied
to EVERY base case automatically, so coverage scales multiplicatively and "adding
a test" becomes "adding a rule". In production the BASE corpus is fed from real
caught phish, so the same registry keeps probing current language for free.

This is a drop-in pre-ship check (no standing infrastructure): it prints a report
and exits non-zero if any transform evades, so a release script can gate on it:

    python adversarial_robustness.py && echo SHIP-OK

By default it loads the model from this directory (onnx/, tokenizer/, config.json);
override with MODEL_DIR=/path/to/model.
"""
import os
import random
import sys

random.seed(7)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from inference import NLPInferenceEngine  # noqa: E402

_DEFAULT_DIR = os.path.dirname(os.path.abspath(__file__))
eng = NLPInferenceEngine(base_dir=os.environ.get("MODEL_DIR", _DEFAULT_DIR))
assert eng.model_ready, "model not ready — run `git lfs pull` / `make check-nlp-model`"


def crs(subject: str, body: str) -> int:
    return eng.predict(subject, body, "")["content_risk_score"]


FLOOR = 50          # caught == crs > 50; a transform dropping a caught phish to <=50 is an evasion
DROP_BUDGET = 35    # also flag a transform that erases >35 pts of margin even if still > FLOOR

# Phishing the model is SUPPOSED to catch. In production, populate from real caught phish.
BASE = [
    ("Account suspended", "Your account is suspended. Verify now or lose access within 24 hours."),
    ("Security warning", "We locked your account after suspicious sign-in attempts. Re-enter your password now to unlock it."),
    ("Mailbox full", "Your mailbox exceeded its limit and will be suspended. Verify your account immediately to keep receiving mail."),
    ("File shared with you", "Someone shared Payroll_2026 with you. Log in with your Office 365 credentials to open the protected file before it expires."),
    ("Microsoft security", "Microsoft account team: your password expires in two hours. Reactivate now to keep access to Outlook and Teams."),
    ("Re-authenticate your mailbox", "Scan the QR code in this email with your phone to re-authenticate your mailbox or your access will be suspended."),
    ("Updated remittance", "Our company changed banks; please send all future payments to the new account on the attached form. Confirm when updated."),
    ("Quick favor", "Are you at your desk? I need you to buy four $100 gift cards for a client and send me the codes. I'll reimburse you."),
    ("I have your password", "I recorded you through your webcam. Send 1500 dollars in bitcoin within 24 hours or I send the video to everyone you know."),
    ("Winner notification", "Your email won 950,000 dollars in our annual draw. Send your full name, phone and bank account to release your winnings."),
]
BASE = [(s, b) for (s, b) in BASE if crs(s, b) > FLOOR]  # keep only genuinely-caught bases

# ── Transform registry — the extension point. New attack class -> append one function.
_CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і", "s": "ѕ"}
_LEET = {"o": "0", "i": "1", "e": "3", "a": "@", "s": "$"}
_ZWSP = "​"
# benign corporate filler — the dilution / "noise" attack used by ~78% of evasive phishing.
_FILLER = (" This message and any attachments are confidential and intended solely for the "
           "addressee. If you have received this in error please notify the sender and delete it. "
           "Please consider the environment before printing. Our office will be closed for the "
           "upcoming public holiday; normal hours resume the following business day. Thank you for "
           "your continued partnership and we look forward to working with you this quarter.")


def _sub_some(t, table, p):
    return "".join(table[ch.lower()] if (ch.lower() in table and random.random() < p) else ch for ch in t)


def t_identity(s, b):       return s, b
def t_homoglyph(s, b):      return s, _sub_some(b, _CYR, 0.6)
def t_leet(s, b):           return s, _sub_some(b, _LEET, 0.5)
def t_zerowidth(s, b):      return s, _ZWSP.join(b)
def t_whitespace_noise(s, b): return s, b.replace(" ", "   \n  ")
def t_dilute_prefix(s, b):  return s, _FILLER + " " + b
def t_dilute_suffix(s, b):  return s, b + " " + _FILLER
def t_dilute_wrap(s, b):    return s, _FILLER + " " + b + " " + _FILLER
def t_upper(s, b):          return s, b.upper()
def t_no_punct(s, b):       return s, b.replace(".", "").replace(",", "").replace("!", "")


def t_charswap(s, b):       # DeepWordBug-style adjacent transpositions
    ch = list(b)
    for _ in range(max(2, len(ch) // 15)):
        i = random.randrange(len(ch) - 1)
        ch[i], ch[i + 1] = ch[i + 1], ch[i]
    return s, "".join(ch)


def t_space_split(s, b):    # "v e r i f y" keyword spacing
    for w in ("verify", "password", "account", "login", "suspended", "credentials", "bank", "wire"):
        b = b.replace(w, " ".join(w))
    return s, b


TRANSFORMS = {
    "identity": t_identity, "homoglyph": t_homoglyph, "leetspeak": t_leet,
    "zero_width": t_zerowidth, "char_swap": t_charswap, "space_split": t_space_split,
    "whitespace_noise": t_whitespace_noise, "dilute_prefix": t_dilute_prefix,
    "dilute_suffix": t_dilute_suffix, "dilute_wrap": t_dilute_wrap,
    "uppercase": t_upper, "strip_punct": t_no_punct,
}


def main() -> int:
    print(f"base phishing (caught): {len(BASE)}   transforms: {len(TRANSFORMS)}")
    print(f"{'transform':<18}{'evade%':>7}{'min':>5}{'mean':>6}  worst-erosion example")
    print("-" * 90)
    results = {}
    for name, fn in TRANSFORMS.items():
        rows = []
        for s, b in BASE:
            base_v = crs(s, b)
            s2, b2 = fn(s, b)
            rows.append((base_v, crs(s2, b2), b2))
        evade = sum(1 for bv, v, _ in rows if v <= FLOOR) / len(rows) * 100
        mn = min(v for _, v, _ in rows)
        mean = sum(v for _, v, _ in rows) / len(rows)
        worst = min(rows, key=lambda r: r[1])
        results[name] = evade
        flag = " <== EVASION" if evade > 0 else ("  ~erosion" if (worst[0] - worst[1]) > DROP_BUDGET else "")
        print(f"{name:<18}{evade:>6.0f}%{mn:>5}{mean:>6.0f}  crs {worst[0]}->{worst[1]} {worst[2][:40]!r}{flag}")

    open_evasions = [n for n, e in results.items() if e > 0 and n != "identity"]
    print("\n" + "=" * 60)
    if open_evasions:
        print("OPEN EVASIONS:", ", ".join(open_evasions))
        print("-> register a defense (normalizer in text_preprocess.py, or training aug) and rerun.")
    else:
        print("ALL TRANSFORMS HELD — no semantics-preserving evasion in registry.")
    print("=" * 60)
    return 1 if open_evasions else 0


if __name__ == "__main__":
    sys.exit(main())
