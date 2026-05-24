"""
Gated content analysis: second-pass HTML inspection for URLs that score below the
fusion threshold but warrant deeper examination.

TRIGGER CONDITIONS:
  - Gray zone: fusion in [GRAY_LOWER, threshold)  — borderline but suspicious
  - Commerce domain: URL host contains shopping keywords AND fusion < threshold
  - Explicit caller override

SIGNALS CHECKED:
  1. Brand impersonation in full HTML (more brands than title alone)
  2. Credential harvesting form (login+password on off-brand domain)
  3. Shopping-scam pattern (cart/buy buttons without trust signals)
  4. Scam discount density (≥4 "X% off"-style claims)
  5. Copyright text mismatch (footer credits different company)

OUTPUT:
  ContentGateResult with:
    triggered: bool
    content_score: float [0, 1]   — raw signal strength
    boosted_fusion: float         — fusion + content contribution
    signals: list[str]            — human-readable signal names
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin

_COMMERCE_KEYWORDS: frozenset[str] = frozenset({
    "store", "shop", "buy", "deal", "mart", "mall", "market",
    "goods", "item", "order", "product", "cheap", "discount",
    "wholesale", "price", "sale", "outlet", "fashion",
})

_MAJOR_BRANDS: frozenset[str] = frozenset({
    "amazon", "walmart", "target", "ebay", "alibaba", "aliexpress",
    "paypal", "apple", "iphone", "ipad", "macbook",
    "google", "gmail", "microsoft", "office", "windows",
    "netflix", "disney", "spotify",
    "facebook", "instagram", "twitter", "tiktok", "youtube",
    "nike", "adidas", "gucci", "prada", "rolex", "louis vuitton",
    "supreme", "balenciaga", "off-white",
    "chase", "wells fargo", "bank of america", "citibank", "barclays",
    "hsbc", "lloyds", "natwest",
})

_TRUST_KEYWORDS: frozenset[str] = frozenset({
    "contact us", "about us", "return policy", "refund policy",
    "privacy policy", "terms of service", "terms and conditions",
    "shipping policy", "customer service", "customer support",
    "faq", "help center",
})

_CART_KEYWORDS: frozenset[str] = frozenset({
    "add to cart", "buy now", "checkout", "place order",
    "add to bag", "shop now", "purchase", "proceed to checkout",
})

_DISCOUNT_PATTERN = re.compile(
    r'(?:\d+)\s*%\s*off', re.IGNORECASE
)

_PASSWORD_PATTERN = re.compile(
    r'<input[^>]+type\s*=\s*["\']?password["\']?', re.IGNORECASE
)

_USERNAME_PATTERN = re.compile(
    r'<input[^>]+(?:name|id)\s*=\s*["\']?(?:user(?:name)?|email|login)["\']?',
    re.IGNORECASE,
)

_FORM_ACTION_PATTERN = re.compile(
    r'<form[^>]+action=["\']([^"\'#?][^"\']*)["\']', re.IGNORECASE
)

_COPYRIGHT_PATTERN = re.compile(
    r'(?:copyright|©)\s*(?:\d{4})?\s*([A-Za-z][A-Za-z0-9\s&,\.]{2,40})',
    re.IGNORECASE,
)

# Weight given to content_score when it boosts the fusion score
_CONTENT_BOOST_WEIGHT: float = 0.45


@dataclass
class ContentGateResult:
    triggered: bool = False
    content_score: float = 0.0
    boosted_fusion: float = 0.0
    signals: list[str] = field(default_factory=list)
    fetch_ok: bool = False
    error: Optional[str] = None


def _apex_from_url(url: str) -> str:
    """Return the 2-label apex domain (best-effort, no PSL)."""
    try:
        import tldextract
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    except Exception:
        host = urlparse(url).hostname or ""
        parts = host.split(".")
        return ".".join(parts[-2:]).lower() if len(parts) >= 2 else host.lower()


def _should_trigger(url: str, fusion: float, threshold: float, gray_lower: float) -> bool:
    """Decide whether content analysis gate should fire for this URL."""
    if fusion >= threshold:
        return False
    if gray_lower <= fusion < threshold:
        return True
    host = urlparse(url).hostname or ""
    return any(kw in host.lower() for kw in _COMMERCE_KEYWORDS)


def _fetch_html(url: str, timeout: float = 8.0) -> tuple[bool, str, Optional[str]]:
    """Fetch raw HTML from URL. Returns (success, html, error)."""
    try:
        import requests
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = requests.get(url, timeout=timeout, verify=False, headers=headers,
                            allow_redirects=True)
        return True, resp.text, None
    except Exception as exc:
        return False, "", str(exc)


def analyze_html(url: str, html: str) -> tuple[float, list[str]]:
    """
    Core content analysis. Returns (content_score, signals).
    Called with already-fetched HTML so it's usable from enrich pipeline too.
    """
    apex = _apex_from_url(url)
    html_lower = html.lower()
    score = 0.0
    signals: list[str] = []

    # ── Signal 1: Brand impersonation density ───────────────────────────────
    brand_hits = [b for b in _MAJOR_BRANDS if b in html_lower]
    is_own_brand = any(b in apex for b in brand_hits)
    if len(brand_hits) >= 2 and not is_own_brand:
        # Off-brand domain is displaying multiple major brand names
        boost = min(0.40, 0.10 * len(brand_hits))
        score += boost
        signals.append(f"brand_impersonation:{','.join(brand_hits[:4])}")

    # ── Signal 2: Credential harvesting form ────────────────────────────────
    has_password = bool(_PASSWORD_PATTERN.search(html))
    has_username = bool(_USERNAME_PATTERN.search(html))
    if has_password and has_username:
        # Check if form action points to a different domain
        for match in _FORM_ACTION_PATTERN.finditer(html):
            action = match.group(1).strip()
            try:
                if "://" not in action:
                    action = urljoin(url, action)
                action_host = urlparse(action).hostname or ""
                action_apex = _apex_from_url(action)
                if action_apex and action_apex != apex:
                    score += 0.40
                    signals.append(f"credential_harvest_offsite:{action_apex}")
                    break
            except Exception:
                pass
        else:
            # Form submits to same domain — mild signal
            score += 0.05
            signals.append("credential_form_onsite")

    # ── Signal 3: Shopping scam pattern ─────────────────────────────────────
    cart_hits = [kw for kw in _CART_KEYWORDS if kw in html_lower]
    trust_hits = [kw for kw in _TRUST_KEYWORDS if kw in html_lower]
    if cart_hits and len(trust_hits) == 0:
        score += 0.20
        signals.append(f"cart_no_trust_signals:{','.join(cart_hits[:2])}")
    elif cart_hits and len(trust_hits) <= 1:
        score += 0.08
        signals.append(f"cart_few_trust_signals")

    # ── Signal 4: Scam discount density ─────────────────────────────────────
    discount_matches = _DISCOUNT_PATTERN.findall(html_lower)
    if len(discount_matches) >= 4:
        score += 0.15
        signals.append(f"discount_density:{len(discount_matches)}")

    # ── Signal 5: Copyright mismatch ────────────────────────────────────────
    # Footer/copyright claims a different brand than the domain
    for m in _COPYRIGHT_PATTERN.finditer(html_lower):
        claimed = m.group(1).strip().lower()
        if claimed and not any(part in apex for part in claimed.split()[:2] if len(part) > 3):
            # Copyright claims a name not in the apex domain
            for brand in _MAJOR_BRANDS:
                if brand in claimed and brand not in apex:
                    score += 0.25
                    signals.append(f"copyright_mismatch:claims_{brand}")
                    break
            break

    return min(1.0, score), signals


def run(
    url: str,
    fusion: float,
    threshold: float,
    *,
    gray_lower: float = 0.08,
    html: Optional[str] = None,
) -> ContentGateResult:
    """
    Run the content analysis gate for a single URL.

    Args:
        url: The URL to analyze.
        fusion: Current fusion score from the main model.
        threshold: Decision threshold.
        gray_lower: Lower bound of the "gray zone" that always triggers analysis.
        html: Pre-fetched HTML (skip network fetch if provided).

    Returns:
        ContentGateResult with verdict and diagnostics.
    """
    result = ContentGateResult(boosted_fusion=fusion)

    if not _should_trigger(url, fusion, threshold, gray_lower):
        return result

    result.triggered = True

    if html is None:
        ok, html, err = _fetch_html(url)
        result.fetch_ok = ok
        if err:
            result.error = err
        if not ok or not html:
            return result
    else:
        result.fetch_ok = True

    content_score, signals = analyze_html(url, html)
    result.content_score = content_score
    result.signals = signals
    result.boosted_fusion = fusion + content_score * _CONTENT_BOOST_WEIGHT

    return result
