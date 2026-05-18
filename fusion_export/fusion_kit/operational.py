"""
Operational feature policy and mapping from :class:`fusion_kit.enrich.EnrichmentData`
to the column order expected by ``hgb_operational.joblib``.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Final, FrozenSet, Mapping, Tuple
from urllib.parse import urlparse

import tldextract as _tldextract

import numpy as np
import pandas as pd

from fusion_kit.enrich import EnrichmentData

OPERATIONAL_FEATURE_COLUMNS: Final[Tuple[str, ...]] = (
    "url",
    "hostname",
    "domain",
    "tld",
    "ip_address",
    "cidr_block",
    "asn",
    "asn_name",
    "isp",
    "country",
    "country_name",
    "region",
    "city",
    "latitude",
    "longitude",
    "ssl_enabled",
    "cert_issuer",
    "cert_subject",
    "cert_valid_from",
    "cert_valid_to",
    "http_status_code",
    "page_title",
    "page_language",
    "registrar",
    "creation_date",
    "expiry_date",
    "updated_date",
    "name_servers",
    # --- derived numeric features (added for v2 model) ---
    "domain_age_days",
    "cert_age_days",
    "cert_validity_span_days",
    "title_brand_mismatch",
    "title_has_login_kw",
    # --- structural hostname features (added for v3 model) ---
    "subdomain_depth",
    "subdomain_brand_count",
    "apex_is_numeric",
    # --- content/redirect features (added for v4 model) ---
    "form_action_mismatch",
    # --- URL structural features (added for v5 model) ---
    "ip_in_url",
    "non_std_port",
    "url_domain_char_ratio",
    # --- DOM/content features (added for v5 model) ---
    "favicon_domain_mismatch",
    "password_field_count",
    "has_hidden_redirect",
    # --- platform hosting feature (added for v6 model) ---
    "is_ephemeral_platform",
)

OPERATIONAL_EXCLUDED_COLUMNS: Final[FrozenSet[str]] = frozenset(
    {
        "label",
        "label_name",
        "tranco_rank",
        "stratum",
        "inbox_style_synthetic_path",
        "source_feed",
        "threat_type",
        "benign_source",
        "first_seen",
        "phishtank_submission_time",
        "target_brand",
        "threat_tags",
        "notes",
        "online",
    }
)

# ASNs of major CDN/anycast providers whose IP geolocation is meaningless
# (the "country" depends on which PoP answered, not where the origin is).
_CDN_ASNS: Final[frozenset[int]] = frozenset({
    13335,   # Cloudflare
    209242,  # Cloudflare (EU entity)
    20940,   # Akamai Technologies
    16625,   # Akamai Technologies
    54113,   # Fastly
    16509,   # Amazon CloudFront / AWS
    14618,   # Amazon CloudFront
    15169,   # Google / GCP
    36492,   # Google
    8075,    # Microsoft Azure
    8068,    # Microsoft Azure
    32934,   # Facebook / Meta
    63949,   # Linode / Akamai
    19551,   # Incapsula / Imperva
    22822,   # Limelight Networks
    60068,   # CDN77
})

# Brand → set of canonical domain suffixes (lowercase).
# Generated from Tranco top-5000 (authoritative traffic ranking) cross-referenced
# with APWG eCrime phishing brand statistics (public reports).
# Canonical domains derived programmatically — not hand-picked.
# To regenerate: python3 utils/build_brand_list.py
_BRAND_DOMAINS: Final[dict[str, frozenset[str]]] = {
    "adobe":         frozenset({"adobe.com", "adobe.io", "adobe.net"}),
    "airbnb":        frozenset({"airbnb.com"}),
    "aliexpress":    frozenset({"aliexpress.com"}),
    "amazon":        frozenset({"amazon.co.uk", "amazon.com", "amazon.dev"}),
    "apple":         frozenset({"apple.com", "apple.news"}),
    "atlassian":     frozenset({"atlassian.com", "atlassian.net"}),
    "bankofamerica": frozenset({"bankofamerica.com"}),
    "barclays":      frozenset({"barclays.co.uk", "barclays.com"}),
    "binance":       frozenset({"binance.com"}),
    "cashapp":       frozenset({"cash.app", "cashapp.com"}),
    "chase":         frozenset({"chase.com", "jpmorgan.com"}),
    "chatgpt":       frozenset({"chatgpt.com"}),
    "cisco":         frozenset({"cisco.com"}),
    "citibank":      frozenset({"citi.com", "citibank.com"}),
    "coinbase":      frozenset({"coinbase.com"}),
    "commbank":      frozenset({"commbank.com.au"}),
    "dell":          frozenset({"dell.com"}),
    "dhl":           frozenset({"dhl.co.uk", "dhl.com", "dhl.de"}),
    "discord":       frozenset({"discord.com", "discord.gg", "discord.media", "discordapp.com"}),
    "docusign":      frozenset({"docusign.com", "docusign.net"}),
    "doordash":      frozenset({"doordash.com"}),
    "dpd":           frozenset({"dpd.co.uk", "dpd.com"}),
    "dropbox":       frozenset({"dropbox.com"}),
    "ebay":          frozenset({"ebay.co.uk", "ebay.com", "ebay.de"}),
    "epicgames":     frozenset({"epicgames.com"}),
    "etsy":          frozenset({"etsy.com"}),
    "evri":          frozenset({"evri.com"}),
    "facebook":      frozenset({"facebook.com", "facebook.net"}),
    "fedex":         frozenset({"fedex.com"}),
    "google":        frozenset({"google.cn", "google.co.id", "google.co.uk", "google.com"}),
    "grammarly":     frozenset({"grammarly.com", "grammarly.io", "grammarly.net"}),
    "hsbc":          frozenset({"hsbc.co.uk", "hsbc.com"}),
    "hubspot":       frozenset({"hubspot.com"}),
    "hulu":          frozenset({"hulu.com"}),
    "instagram":     frozenset({"instagram.com"}),
    "kaspersky":     frozenset({"kaspersky.com"}),
    "kraken":        frozenset({"kraken.com"}),
    "ledger":        frozenset({"ledger.com"}),
    "linkedin":      frozenset({"linkedin.com"}),
    "lloyds":        frozenset({"lloyds.com", "lloydsbankinggroup.com"}),
    "mcafee":        frozenset({"mcafee.com"}),
    "metamask":      frozenset({"metamask.io"}),
    "microsoft":     frozenset({"microsoft.com", "microsoft.us"}),
    "mozilla":       frozenset({"mozilla.com", "mozilla.net", "mozilla.org"}),
    "natwest":       frozenset({"natwest.com"}),
    "netflix":       frozenset({"netflix.com", "netflix.net"}),
    "norton":        frozenset({"norton.com"}),
    "okta":          frozenset({"okta.com"}),
    "opera":         frozenset({"opera.com"}),
    "paypal":        frozenset({"paypal.com"}),
    "pinterest":     frozenset({"pinterest.com", "pinterest.net"}),
    "postnl":        frozenset({"postnl.nl"}),
    "reddit":        frozenset({"reddit.com"}),
    "roblox":        frozenset({"roblox.com"}),
    "royalmail":     frozenset({"royalmail.com"}),
    "salesforce":    frozenset({"salesforce.com"}),
    "samsung":       frozenset({"samsung.com"}),
    "santander":     frozenset({"santander.co.uk", "santander.com"}),
    "shein":         frozenset({"shein.com"}),
    "signal":        frozenset({"signal.me", "signal.org"}),
    "slack":         frozenset({"slack.com"}),
    "snapchat":      frozenset({"snapchat.com"}),
    "spotify":       frozenset({"spotify.com"}),
    "steam":         frozenset({"steamcommunity.com", "steampowered.com"}),
    "stripe":        frozenset({"stripe.com", "stripe.network"}),
    "telegram":      frozenset({"telegram.me", "telegram.org"}),
    "temu":          frozenset({"temu.com"}),
    "tiktok":        frozenset({"tiktok.com"}),
    "twitch":        frozenset({"twitch.tv"}),
    "twitter":       frozenset({"twitter.com", "x.com"}),
    "uber":          frozenset({"uber.com"}),
    "ups":           frozenset({"ups.com"}),
    "usps":          frozenset({"usps.com"}),
    "venmo":         frozenset({"venmo.com"}),
    "webex":         frozenset({"webex.com"}),
    "wellsfargo":    frozenset({"wellsfargo.com"}),
    "whatsapp":      frozenset({"whatsapp.com", "whatsapp.net"}),
    "youtube":       frozenset({"youtube.com"}),
    "zelle":         frozenset({"zellepay.com"}),
    "zoom":          frozenset({"zoom.us"}),
    # Mobile carriers — high-volume phishing targets
    "tmobile":       frozenset({"t-mobile.com"}),
    "att":           frozenset({"att.com"}),
    "verizon":       frozenset({"verizon.com"}),
    "vodafone":      frozenset({"vodafone.com", "vodafone.co.uk"}),
    "o2":            frozenset({"o2.co.uk", "o2.com"}),
    # Crypto/fintech — top phishing targets
    "uphold":        frozenset({"uphold.com"}),
    "trust":         frozenset({"trustwallet.com"}),
    "phantom":       frozenset({"phantom.app"}),
    "exodus":        frozenset({"exodus.com", "exodus.io"}),
    "robinhood":     frozenset({"robinhood.com"}),
    "revolut":       frozenset({"revolut.com"}),
    # Parcel delivery — major phishing vector
    "hermes":        frozenset({"myhermes.co.uk"}),
    "chronopost":    frozenset({"chronopost.fr"}),
    "colissimo":     frozenset({"colissimo.fr"}),
    "laposte":       frozenset({"laposte.fr"}),
    # Government/tax — high-value phishing targets
    "hmrc":          frozenset({"hmrc.gov.uk"}),
    "ato":           frozenset({"ato.gov.au"}),
    # Streaming/gaming
    "primevideo":    frozenset({"primevideo.com"}),
    "disneyplus":    frozenset({"disneyplus.com"}),
    "epic":          frozenset({"epicgames.com"}),
    "ea":            frozenset({"ea.com", "origin.com"}),
}

# Subdomain brand keywords — derived from keys of _BRAND_DOMAINS plus
# Microsoft/Google product sub-brands that legitimately appear only as
# subdomains of their parent domains, never as third-party labels.
_SUBDOMAIN_BRAND_KEYWORDS: Final[frozenset[str]] = frozenset(
    set(_BRAND_DOMAINS.keys()) | {
        # Microsoft sub-brands
        "msn", "outlook", "office", "onedrive", "teams", "sharepoint",
        "skype", "bing", "hotmail", "live", "azure",
        # Google sub-brands
        "gmail", "goog",
        # Apple sub-brands
        "icloud", "itunes",
        # Amazon sub-brands
        "aws", "kindle",
        # Meta sub-brands
        "meta", "messenger",
        # Other common sub-brand labels used in chain attacks
        "symantec", "crypto", "wallet", "support", "helpdesk",
        # Mobile carrier sub-brand labels
        "mobile", "wireless", "prepaid", "postpaid",
        # Crypto/DeFi sub-brand labels
        "uphold", "phantom", "exodus", "trust", "defi", "nft", "airdrop",
        # Parcel delivery labels
        "parcel", "delivery", "tracking", "shipment",
        # Generic high-signal phishing subdomain labels
        "secure", "verify", "update", "alert", "notice", "billing",
        "payment", "invoice", "refund", "confirm", "validate",
    }
)

_EPHEMERAL_PLATFORM_SUFFIXES: Final[frozenset[str]] = frozenset({
    # SaaS app hosting — attacker registers arbitrary subdomain
    "vercel.app",
    "pages.dev",         # Cloudflare Pages
    "github.io",         # GitHub Pages
    "netlify.app",
    "web.app",           # Firebase Hosting
    "glitch.me",
    "webflow.io",
    "fly.dev",
    "render.com",
    "railway.app",
    "surge.sh",
    "usercontent.dev",   # GitHub user content
    "wasmer.app",        # Wasmer WebAssembly hosting
    "replit.app",        # Replit
    "replit.co",         # Replit (legacy)
    "repl.co",           # Replit (legacy)
    "zya.me",            # Free subdomain hosting
    "dweb.link",         # IPFS/Filecoin dweb gateway (includes *.ipfs.dweb.link)
    "ipfs.io",           # IPFS public gateway
    "stackblitz.io",     # StackBlitz
    "codesandbox.io",    # CodeSandbox
    "codepen.io",        # CodePen
    # Portfolio / website builder platforms
    "myportfolio.com",   # Adobe Portfolio
    "company.site",      # Square Sites
    "squarespace.com",
    "weebly.com",
    "wixsite.com",
    "cargo.site",
    "notion.site",
    "blogger.com",
    "blogspot.com",
})


def _is_ephemeral_platform(hostname: str) -> float:
    """1.0 if the hostname is a subdomain of a known free/ephemeral hosting platform.

    Platforms where any user can publish arbitrary content under a provider-owned
    apex domain — primary vector for platform phishing that evades op-feature models.
    """
    h = hostname.lower()
    for suffix in _EPHEMERAL_PLATFORM_SUFFIXES:
        if h.endswith("." + suffix):
            return 1.0
    return 0.0


_LOGIN_KEYWORDS: Final[frozenset[str]] = frozenset({
    "login", "log in", "sign in", "signin", "sign-in",
    "verify", "verification", "account", "password", "secure",
    "security", "authenticate", "authentication", "sicherheit",
    "iniciar sesión", "iniciar sesion", "connexion", "anmelden",
    "mot de passe", "identifiez",
})


def _num(v: Any, *, as_int: bool = False) -> Any:
    if v is None or v == "" or v == "None":
        return np.nan
    try:
        if as_int:
            return int(float(v))
        return float(v)
    except (TypeError, ValueError):
        return np.nan


def _parse_date(s: str | None) -> datetime | None:
    if s is None or (isinstance(s, float) and np.isnan(s)):
        return None
    s = str(s).strip()
    if not s or s in ("", "None", "nan"):
        return None
    try:
        # Remove trailing 'Z' and handle +00:00
        s = s.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        try:
            # Fallback: extract just the date part
            m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
            if m:
                return datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


def _days_since(date_str: Any) -> float:
    """Return days between the parsed date and now (UTC). NaN if unparseable."""
    dt = _parse_date(date_str)
    if dt is None:
        return np.nan
    now = datetime.now(tz=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return float((now - dt).total_seconds() / 86400.0)


def _days_between(from_str: Any, to_str: Any) -> float:
    """Days between two ISO date strings. NaN if either is unparseable."""
    dt_from = _parse_date(from_str)
    dt_to = _parse_date(to_str)
    if dt_from is None or dt_to is None:
        return np.nan
    if dt_from.tzinfo is None:
        dt_from = dt_from.replace(tzinfo=timezone.utc)
    if dt_to.tzinfo is None:
        dt_to = dt_to.replace(tzinfo=timezone.utc)
    return float((dt_to - dt_from).total_seconds() / 86400.0)


def _title_brand_mismatch(page_title: str, hostname: str) -> float:
    """
    Return 1.0 if the page title contains a well-known brand name whose
    canonical domains do NOT match the serving hostname, else 0.0.
    """
    title_lower = page_title.lower()
    host_lower = hostname.lower()
    for brand, canonical_domains in _BRAND_DOMAINS.items():
        if brand not in title_lower:
            continue
        # Brand found in title — check if hostname is one of its canonical domains
        for canon in canonical_domains:
            if host_lower == canon or host_lower.endswith("." + canon):
                return 0.0  # Legitimate: brand matches its own domain
        return 1.0  # Brand in title but hostname is NOT the brand's domain
    return 0.0


def _title_has_login_kw(page_title: str) -> float:
    """Return 1.0 if page title contains common phishing/login keywords."""
    title_lower = page_title.lower()
    for kw in _LOGIN_KEYWORDS:
        if kw in title_lower:
            return 1.0
    return 0.0


def _extract_apex_domain(hostname: str) -> str:
    """Return the registered domain using the Mozilla Public Suffix List.

    Handles ccTLDs correctly: 'secure.barclays.co.uk' → 'barclays.co.uk'.
    Falls back to last-two-label heuristic when tldextract cannot determine suffix.
    """
    if not hostname:
        return ""
    ext = _tldextract.extract(hostname.lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    # Fallback for unknown TLDs (private registries, internal hostnames)
    labels = hostname.lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname.lower()


def _subdomain_depth(hostname: str) -> float:
    """Number of subdomain levels above the apex domain (last-2-label heuristic)."""
    if not hostname:
        return 0.0
    labels = hostname.lower().split(".")
    depth = max(0, len(labels) - 2)
    return float(depth)


def _subdomain_brand_count(hostname: str) -> float:
    """
    Count of brand/product keywords in the subdomain portion (labels above the apex).

    Splits each label on hyphens/underscores so that ``my-whatsapp.my.id`` and
    ``n-project-2025-netflix.vercel.app`` are correctly detected as brand-referencing
    subdomains even though the full label doesn't exactly match the brand keyword.
    """
    if not hostname:
        return 0.0
    labels = hostname.lower().split(".")
    subdomain_labels = labels[:-2] if len(labels) > 2 else []
    count = 0
    for lbl in subdomain_labels:
        if lbl in _SUBDOMAIN_BRAND_KEYWORDS:
            count += 1
        else:
            parts = re.split(r"[-_]", lbl)
            if any(p in _SUBDOMAIN_BRAND_KEYWORDS for p in parts):
                count += 1
    return float(count)


def _apex_is_numeric(hostname: str) -> float:
    """1.0 if the apex domain's stem (second-to-last label) consists only of digits."""
    if not hostname:
        return 0.0
    labels = hostname.lower().split(".")
    if len(labels) < 2:
        return 0.0
    stem = labels[-2]
    return 1.0 if stem.isdigit() else 0.0


def _form_action_mismatch(form_action_domain: str | None, serving_hostname: str) -> float:
    """
    1.0 if the page's primary form action submits to a different apex domain than
    the serving host — strong signal for compromised-site credential harvesting.
    0.0 when no form action is present, action is relative, or action matches host.
    """
    if not form_action_domain or not serving_hostname:
        return 0.0
    serving_apex = _extract_apex_domain(serving_hostname)
    action_apex = _extract_apex_domain(form_action_domain)
    return 0.0 if action_apex == serving_apex else 1.0


def _favicon_domain_mismatch(favicon_url: str | None, serving_hostname: str) -> float:
    """1.0 if the favicon's domain ≠ serving domain — phishing pages often load
    brand favicons from the real brand's CDN while hosted on a fake domain."""
    if not favicon_url or not serving_hostname:
        return 0.0
    try:
        parsed = urlparse(
            favicon_url if '://' in favicon_url
            else f'https:{favicon_url}' if favicon_url.startswith('//')
            else f'https://{favicon_url}'
        )
        favicon_host = parsed.hostname
        if not favicon_host:
            return 0.0
        serving_apex = _extract_apex_domain(serving_hostname)
        favicon_apex = _extract_apex_domain(favicon_host)
        return 0.0 if favicon_apex == serving_apex else 1.0
    except Exception:
        return 0.0


def _ip_in_url(url: str) -> float:
    """1.0 if the URL hostname is a bare IPv4 or IPv6 address."""
    try:
        host = (urlparse(url).hostname or '').strip('[]')
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            return 1.0
        if ':' in host and host:
            return 1.0
    except Exception:
        pass
    return 0.0


def _non_std_port(url: str) -> float:
    """1.0 if the URL specifies a port other than 80 (HTTP) or 443 (HTTPS)."""
    try:
        parsed = urlparse(url)
        port = parsed.port
        if port is None:
            return 0.0
        scheme = parsed.scheme.lower()
        if (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443):
            return 0.0
        return 1.0
    except Exception:
        return 0.0


def _url_path_entropy(url: str) -> float:
    """Shannon entropy of the URL path (bits). UUID paths ≈ 3.8; plain paths ≈ 1-2."""
    try:
        path = urlparse(url).path
        if not path or path == '/':
            return 0.0
        counts = Counter(path)
        n = len(path)
        return round(
            -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0), 4
        )
    except Exception:
        return 0.0


def _url_path_depth(url: str) -> float:
    """Number of non-empty path segments (/a/b/c → 3)."""
    try:
        path = urlparse(url).path
        return float(len([s for s in path.split('/') if s]))
    except Exception:
        return 0.0


def _url_domain_char_ratio(hostname: str) -> float:
    """Fraction of non-alpha, non-dot characters in hostname (hyphens, digits, underscores)."""
    if not hostname:
        return 0.0
    non_alpha = sum(1 for c in hostname if not c.isalpha() and c != '.')
    return round(non_alpha / len(hostname), 4)


def enrichment_to_operational_row(ed: EnrichmentData, *, columns: list[str] | None = None) -> dict[str, Any]:
    """Build a flat dict suitable for ``pd.DataFrame([row])[columns]``."""
    url = (ed.url or "").strip()
    host = urlparse(url).hostname if url else None
    if not host:
        host = (ed.domain or "").strip() or None

    creation_date_str = (ed.creation_date or "").strip()
    cert_from_str = (ed.cert_valid_from or "").strip()
    cert_to_str = (ed.cert_valid_to or "").strip()
    page_title_str = (ed.page_title or "").strip()
    hostname_str = host or ""

    # Null out geographic features for CDN/anycast ASNs: the "country" returned
    # by GeoIP for these IPs reflects which PoP answered, not where the site is.
    asn_val = _num(ed.asn, as_int=False)
    is_cdn = not np.isnan(asn_val) and int(asn_val) in _CDN_ASNS
    geo_country = "" if is_cdn else (ed.country or "").strip()
    geo_country_name = "" if is_cdn else (ed.country_name or "").strip()
    geo_region = "" if is_cdn else (ed.region or "").strip()
    geo_city = "" if is_cdn else (ed.city or "").strip()
    geo_lat = np.nan if is_cdn else _num(ed.latitude, as_int=False)
    geo_lon = np.nan if is_cdn else _num(ed.longitude, as_int=False)

    raw: dict[str, Any] = {
        "url": url,
        "hostname": hostname_str,
        "domain": (ed.domain or "").strip(),
        "tld": (ed.tld or "").strip(),
        "ip_address": (ed.ip_address or "").strip(),
        "cidr_block": (ed.cidr_block or "").strip(),
        "asn": _num(ed.asn, as_int=False),
        "asn_name": (ed.asn_name or "").strip(),
        "isp": (ed.isp or "").strip(),
        "country": geo_country,
        "country_name": geo_country_name,
        "region": geo_region,
        "city": geo_city,
        "latitude": geo_lat,
        "longitude": geo_lon,
        "ssl_enabled": (ed.ssl_enabled or "").strip().lower() if ed.ssl_enabled else "",
        "cert_issuer": (ed.cert_issuer or "").strip(),
        "cert_subject": (ed.cert_subject or "").strip(),
        "cert_valid_from": cert_from_str,
        "cert_valid_to": cert_to_str,
        "http_status_code": _num(ed.http_status_code, as_int=False),
        "page_title": page_title_str,
        "page_language": (ed.page_language or "").strip(),
        "registrar": (ed.registrar or "").strip(),
        "creation_date": creation_date_str,
        "expiry_date": (ed.expiry_date or "").strip(),
        "updated_date": (ed.updated_date or "").strip(),
        "name_servers": (ed.name_servers or "").strip(),
        # --- derived features ---
        "domain_age_days": _days_since(creation_date_str),
        "cert_age_days": _days_since(cert_from_str),
        "cert_validity_span_days": _days_between(cert_from_str, cert_to_str),
        "title_brand_mismatch": _title_brand_mismatch(page_title_str, hostname_str),
        "title_has_login_kw": _title_has_login_kw(page_title_str),
        # --- structural hostname features ---
        "subdomain_depth": _subdomain_depth(hostname_str),
        "subdomain_brand_count": _subdomain_brand_count(hostname_str),
        "apex_is_numeric": _apex_is_numeric(hostname_str),
        # --- content/redirect features ---
        "form_action_mismatch": _form_action_mismatch(
            getattr(ed, "form_action_domain", None), hostname_str
        ),
        # --- URL structural features ---
        "ip_in_url": _ip_in_url(url),
        "non_std_port": _non_std_port(url),
        "url_domain_char_ratio": _url_domain_char_ratio(hostname_str),
        # --- DOM/content features ---
        "favicon_domain_mismatch": _favicon_domain_mismatch(
            getattr(ed, "favicon_url", None), hostname_str
        ),
        "password_field_count": float(getattr(ed, "password_field_count", None) or 0),
        "has_hidden_redirect": float(getattr(ed, "has_hidden_redirect", None) or 0),
        # --- platform hosting feature ---
        "is_ephemeral_platform": _is_ephemeral_platform(hostname_str),
    }
    if columns is None:
        return raw
    _numeric_defaults = {"asn", "latitude", "longitude", "http_status_code",
                         "domain_age_days", "cert_age_days", "cert_validity_span_days",
                         "title_brand_mismatch", "title_has_login_kw",
                         "subdomain_depth", "subdomain_brand_count", "apex_is_numeric",
                         "form_action_mismatch",
                         "ip_in_url", "non_std_port", "url_domain_char_ratio",
                         "favicon_domain_mismatch", "password_field_count", "has_hidden_redirect",
                         "is_ephemeral_platform"}
    return {c: raw.get(c, np.nan if c in _numeric_defaults else "") for c in columns}


def operational_row_to_frame(row: Mapping[str, Any], *, columns: list[str]) -> pd.DataFrame:
    d = {c: row.get(c, np.nan) for c in columns}
    return pd.DataFrame([d], columns=columns)


def feature_frame_from_ml_ready_row(url: str, row: pd.Series) -> dict[str, Any]:
    """Build operational feature dict from one ``ml_ready_dataset.csv`` row (cached enrich columns)."""
    rec: dict[str, Any] = {"url": url}
    _nan_cols = {
        "domain_age_days", "cert_age_days", "cert_validity_span_days",
        "title_brand_mismatch", "title_has_login_kw",
        "subdomain_depth", "subdomain_brand_count", "apex_is_numeric",
        "form_action_mismatch",
        "ip_in_url", "non_std_port", "url_domain_char_ratio",
        "favicon_domain_mismatch", "password_field_count", "has_hidden_redirect",
        "is_ephemeral_platform",
    }
    for c in OPERATIONAL_FEATURE_COLUMNS:
        if c == "url":
            continue
        rec[c] = row[c] if c in row.index else (np.nan if c in _nan_cols else "")
    return rec
