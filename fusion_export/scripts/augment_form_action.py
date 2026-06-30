#!/usr/bin/env python3
"""
Add form_action_domain column to operational training CSVs and inject
synthetic compromised-site phishing rows where form_action_mismatch=1.

Run once before retraining:
  python fusion_export/scripts/augment_form_action.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
READY = ROOT / "data" / "ml_dataset" / "ready_operational"

# Compromised-site template: a legitimate-looking site whose HTML form
# POSTs credentials to an attacker-controlled domain.
# Format: (serving_hostname, serving_domain, tld, form_action_domain, page_title, ssl)
_COMPROMISED_TEMPLATES = [
    # Classic WordPress compromise — innocent URL, form exfils to C2
    ("www.legitimatecarpetshop.co.uk",  "legitimatecarpetshop.co.uk",  ".co.uk", "collect-logins.xyz",       "PayPal - Confirm Your Account",  "yes"),
    ("blog.hobbyarticles.com",           "hobbyarticles.com",           ".com",   "paypal-secure-login.ru",   "Sign in to PayPal",              "yes"),
    ("www.myvillagerecipes.org",         "myvillagerecipes.org",        ".org",   "account-harvest.top",      "Microsoft - Sign In",            "no"),
    ("localdentistclinic.net",           "localdentistclinic.net",      ".net",   "msoft-auth.xyz",           "Verify your Microsoft account",  "yes"),
    ("www.antiquesbazaar.co.uk",         "antiquesbazaar.co.uk",        ".co.uk", "auth-apple-id.pw",         "Apple ID - Sign In",             "yes"),
    ("familyphotostudio.com",            "familyphotostudio.com",       ".com",   "apple-idm-verify.top",     "Apple - Reset Password",         "no"),
    ("www.communitychurch.org",          "communitychurch.org",         ".org",   "bankofamerica-secure.cc",  "Bank of America - Online Banking","yes"),
    ("plumbingservices-local.com",       "plumbingservices-local.com",  ".com",   "harvest99.ru",             "Chase - Sign in to Online Banking","no"),
    ("www.gardeningadvice.co.uk",        "gardeningadvice.co.uk",       ".co.uk", "credential-dump.xyz",      "Facebook - Log in",              "yes"),
    ("touristboardnorfolk.org",          "touristboardnorfolk.org",     ".org",   "fb-harvest.cn",            "Log into Facebook",              "yes"),
    # Shared hosting compromise — multiple victims on one C2
    ("www.personalfinanceblog.net",      "personalfinanceblog.net",     ".net",   "exfil-hub.cc",             "PayPal - Log in to your account", "yes"),
    ("craftingwithkids.com",             "craftingwithkids.com",        ".com",   "exfil-hub.cc",             "Sign in to your Microsoft account","yes"),
    ("www.restaurantreview.co.uk",       "restaurantreview.co.uk",      ".co.uk", "exfil-hub.cc",             "Google Account - Sign In",       "yes"),
    # Sophisticated — C2 uses lookalike domain for form action
    ("www.musicteachersdirectory.com",   "musicteachersdirectory.com",  ".com",   "accounts.googlle.com",     "Google - Sign in",               "yes"),
    ("volunteersportal.org",             "volunteersportal.org",        ".org",   "login.microsoftonllne.com","Microsoft - Sign In",             "no"),
    ("www.charityauction.co.uk",         "charityauction.co.uk",        ".co.uk", "paypa1.com",               "PayPal - Secure Login",          "yes"),
    # Old site, long-registered domain — but form action gives it away
    ("www.retrovinyl.co.uk",             "retrovinyl.co.uk",            ".co.uk", "steal-creds.xyz",          "Apple ID - Manage your account", "yes"),
    ("www.woodworkingplans.net",         "woodworkingplans.net",        ".net",   "creds.top",                "Bank of America Online Banking", "no"),
    # Even with no brand title — mismatch alone is a signal
    ("www.innocentsite.com",             "innocentsite.com",            ".com",   "phish-collector.ru",       "",                               "yes"),
    ("blog.traveldiary.org",             "traveldiary.org",             ".org",   "harvest.pw",               "Login",                          "yes"),
]

_REPEAT = 100  # synthetic rows per template


def _next_id(df: pd.DataFrame) -> int:
    return int(df["sample_id"].max()) + 1 if len(df) > 0 else 900000


def _build_rows(start_id: int) -> tuple[list[dict], list[dict]]:
    feat_rows, lab_rows = [], []
    sid = start_id
    for _ in range(_REPEAT):
        for (host, domain, tld, form_host, title, ssl) in _COMPROMISED_TEMPLATES:
            url = f"https://{host}/wp-content/uploads/verify.html"
            feat_rows.append({
                "sample_id": sid,
                "url": url,
                "hostname": host,
                "domain": domain,
                "tld": tld,
                "ip_address": "",
                "cidr_block": "",
                "asn": np.nan,
                "asn_name": "",
                "isp": "",
                "country": "GB" if tld == ".co.uk" else "US",
                "country_name": "United Kingdom" if tld == ".co.uk" else "United States",
                "region": "",
                "city": "",
                "latitude": np.nan,
                "longitude": np.nan,
                "ssl_enabled": ssl,
                "cert_issuer": "Let's Encrypt" if ssl == "yes" else "",
                "cert_subject": host,
                "cert_valid_from": "2024-01-01T00:00:00+00:00",
                "cert_valid_to": "2024-04-01T00:00:00+00:00",
                "http_status_code": 200.0,
                "page_title": title,
                "page_language": "en",
                "registrar": "GoDaddy",
                "creation_date": "2015-06-15T00:00:00+00:00",
                "expiry_date": "2026-06-15T00:00:00+00:00",
                "updated_date": "2023-06-15T00:00:00+00:00",
                "name_servers": "ns1.godaddy.com",
                "form_action_domain": form_host,
            })
            lab_rows.append({
                "sample_id": sid,
                "url": url,
                "label": 1,
                "label_name": "phishing",
                "y_phishing": 1,
            })
            sid += 1
    return feat_rows, lab_rows


def _process_split(split: str) -> None:
    split_dir = READY / split
    feat_path = split_dir / "features.csv"
    lab_path = split_dir / "labels.csv"

    feat_df = pd.read_csv(feat_path, low_memory=False)
    lab_df = pd.read_csv(lab_path, low_memory=False)

    # Add form_action_domain column if missing (empty for existing rows)
    if "form_action_domain" not in feat_df.columns:
        feat_df["form_action_domain"] = ""

    if split == "train":
        feat_rows, lab_rows = _build_rows(_next_id(feat_df))
        feat_df = pd.concat([feat_df, pd.DataFrame(feat_rows)], ignore_index=True)
        lab_df = pd.concat([lab_df, pd.DataFrame(lab_rows)], ignore_index=True)
        print(f"  [{split}] injected {len(feat_rows)} compromised-site rows → {len(feat_df)} total")
    else:
        print(f"  [{split}] added form_action_domain column (no new rows for val/test)")

    feat_df.to_csv(feat_path, index=False)
    lab_df.to_csv(lab_path, index=False)


def main() -> None:
    print("Augmenting operational training data with form_action_domain + compromised-site rows …")
    for split in ("train", "val", "test"):
        _process_split(split)
    print("Done.")


if __name__ == "__main__":
    main()
