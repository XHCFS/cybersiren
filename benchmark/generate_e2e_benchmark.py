"""
CyberSiren End-to-End Benchmark generator  (CS-E2E-Bench v1)
============================================================
A full-pipeline, multi-channel, stratified phishing benchmark — one record per
EMAIL with the artifacts every channel needs: headers (From/Reply-To/Return-Path/
Received chain/Authentication-Results SPF·DKIM·DMARC), body text, and URLs. This
lets the WHOLE system be measured start-to-finish (SVC-04 header + SVC-03 URL +
SVC-06 NLP → SVC-08 blend), not three siloed evaluations.

Design philosophy (the same one used to build the v2 NLP model):
  1. CHANNEL-ATTRIBUTED. Every record declares `channels_expected` — which
     channel(s) SHOULD fire. This is what enables the leave-one-channel-out
     ablation that *proves* complementarity (remove a channel → DR must drop on
     exactly the cases it owns).
  2. HARD FOR DIFFERENT REASONS. Phishing that is clean in text but malicious in
     URL; clean everywhere but the spoofed From; pure social-engineering text
     with a clean header and no link. Legit that trips one channel (forwarding
     breaks SPF; free-provider sender; SharePoint sign-in link; "meta-phish"
     security-awareness copy) but is saved by the others.
  3. SIMPLE ANCHORS + RAZOR'S EDGE. Trivial cases the system must never miss
     ("hi", a blatant fake security alert) alongside the genuinely ambiguous.
  4. CONTRASTIVE TWINS. Hard FN families have near-identical legit twins so the
     benchmark measures discrimination, not surface keywords.
  5. ADVERSARIAL. Homoglyph / leetspeak / zero-width / subdomain-chain / typosquat
     / punycode / DGA / shortener variants.
  6. DIVERSITY OVER VOLUME. Large parameter pools + multiple phrasings per family
     + randomized composition, so it does NOT collapse to template clones (the
     failure mode that produced the original overfit).

This is a CURATED STRESS / DEPLOYABILITY benchmark (a unit-test suite for the
whole pipeline), explicitly complementary to a real-corpus evaluation — not a
claim about real-world base rates.

Output: benchmark/cybersiren_e2e_benchmark.jsonl  (one JSON email per line)

Run:  python benchmark/generate_e2e_benchmark.py
"""
import json
import random
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

SEED = 1337
random.seed(SEED)

# ── parameter pools (large, to avoid template-clone artifacts) ───────────────
FIRST = ["James", "Mary", "Robert", "Priya", "Wei", "Fatima", "Liam", "Sofia", "Ahmed", "Chen",
         "Olga", "Daniel", "Aisha", "Marco", "Yuki", "Hassan", "Emma", "Diego", "Nina", "Omar",
         "Sarah", "Tom", "Lena", "Raj", "Mia", "Ivan", "Zara", "Paul", "Hana", "Leo"]
LAST = ["Smith", "Johnson", "Patel", "Garcia", "Wang", "Khan", "Muller", "Rossi", "Tanaka", "Nguyen",
        "Brown", "Kowalski", "Silva", "Ahmadi", "Okonkwo", "Lindqvist", "Costa", "Haddad", "Park", "Ivanov"]
COMPANIES = ["Northwind", "Acme", "Contoso", "Globex", "Initech", "Umbra Labs", "Meridian", "BlueOak",
             "Stratford", "Vanguard Ops", "Kestrel", "Halcyon", "Pinewood", "Crestline", "Aether", "Orchard"]
LEGIT_DOMAINS = ["northwind.com", "acme-corp.com", "contoso.com", "globex.io", "meridian.co",
                 "blueoak.io", "stratford-group.com", "kestrel.dev", "halcyon.app", "pinewood.com"]
FREE = ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me", "icloud.com", "gmx.com"]
BRANDS = [("Microsoft 365", "microsoft.com"), ("PayPal", "paypal.com"), ("Netflix", "netflix.com"),
          ("DocuSign", "docusign.net"), ("Dropbox", "dropbox.com"), ("Apple", "apple.com"),
          ("DHL Express", "dhl.com"), ("Amazon", "amazon.com"), ("LinkedIn", "linkedin.com"), ("Chase", "chase.com")]
SUS_TLD = ["tk", "top", "xyz", "click", "online", "cn", "ru", "info", "zip", "live", "rest", "cam"]
SHORTENERS = ["bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy"]
PLATFORMS = ["vercel.app", "pages.dev", "web.app", "netlify.app", "github.io", "firebaseapp.com"]
NAMES_FULL = lambda: f"{random.choice(FIRST)} {random.choice(LAST)}"
AMT = lambda: random.choice(["$200", "$500", "$1,000", "four $100", "$4,500", "$750", "$12,000", "$89.99", "$499"])

# leetspeak / homoglyph for adversarial variants
_LEET = {"o": "0", "i": "1", "e": "3", "a": "@", "s": "$"}
_CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с"}
_ZWSP = "​"


def leet(t, p=0.4):
    return "".join(_LEET.get(c.lower(), c) if (c.lower() in _LEET and random.random() < p) else c for c in t)


def homoglyph(t, p=0.5):
    return "".join(_CYR.get(c.lower(), c) if (c.lower() in _CYR and random.random() < p) else c for c in t)


def zerowidth(t, p=0.3):
    return "".join(ch + (_ZWSP if random.random() < p else "") for ch in t)


# ── header builders ──────────────────────────────────────────────────────────
def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def a_date():
    d = datetime(2026, 6, 1) + timedelta(days=random.randint(0, 13), hours=random.randint(0, 23),
                                          minutes=random.randint(0, 59))
    return d.strftime("%a, %d %b %Y %H:%M:%S +0000")


def msgid(domain):
    h = hashlib.sha1(str(random.random()).encode()).hexdigest()[:18]
    return f"<{h}@{domain}>"


def received_chain(helo_domain, src_ip, hops=2, mismatch=False):
    chain = []
    by = "mx.cybersiren-bench.com"
    chain.append(f"from {helo_domain} ([{src_ip}]) by {by} with ESMTPS; {a_date()}")
    for _ in range(hops - 1):
        hop_host = ("relay" + str(random.randint(1, 9)) + "." + (random.choice(SUS_TLD) if mismatch else "mailroute") +
                    (".net" if mismatch else ".com"))
        chain.append(f"from {hop_host} ([{rand_ip()}]) by {helo_domain}; {a_date()}")
    return chain


def auth_results(spf, dkim, dmarc, domain):
    return f"mx.cybersiren-bench.com; spf={spf} smtp.mailfrom={domain}; dkim={dkim}; dmarc={dmarc} header.from={domain}"


_uid = [0]


def make(label, difficulty, family, channels, *, from_name, from_addr, subject, body,
         urls=None, reply_to=None, spf="pass", dkim="pass", dmarc="pass", received_mismatch=False,
         list_unsub=False, body_html=None, hops=2):
    _uid[0] += 1
    from_domain = from_addr.split("@")[1]
    src_ip = rand_ip()
    headers = {
        "From": f"{from_name} <{from_addr}>",
        "Return-Path": f"<bounce@{from_domain}>",
        "Date": a_date(),
        "Subject": subject,
        "Message-ID": msgid(from_domain),
        "Received": received_chain(from_domain, src_ip, hops=hops, mismatch=received_mismatch),
        "Authentication-Results": auth_results(spf, dkim, dmarc, from_domain),
        "MIME-Version": "1.0",
        "Content-Type": "text/plain; charset=UTF-8",
    }
    if reply_to:
        headers["Reply-To"] = f"<{reply_to}>"
    if list_unsub:
        headers["List-Unsubscribe"] = f"<mailto:unsubscribe@{from_domain}>"
        headers["Precedence"] = "bulk"
    return {
        "id": f"cse2e-{_uid[0]:05d}",
        "label": label,                 # legitimate | spam | phishing
        "difficulty": difficulty,       # trivial | easy | medium | hard | adversarial
        "family": family,
        "channels_expected": channels,  # subset of [header, url, nlp]; [] for legit
        "headers": headers,
        "body_plain": body,
        "body_html": body_html,
        "urls": urls or [],
    }


# ── URL builders ─────────────────────────────────────────────────────────────
def benign_url():
    d = random.choice(LEGIT_DOMAINS)
    path = random.choice(["", "/account", "/orders/" + str(random.randint(1000, 9999)),
                          "/docs/q4-review", "/blog/" + random.choice(["update", "news"]), "/help"])
    return f"https://{random.choice(['', 'www.', 'app.'])}{d}{path}"


def benign_brand_url():
    name, d = random.choice(BRANDS)
    sub = random.choice(["", "login.", "account.", "secure.", "files."])
    return f"https://{sub}{d}/{random.choice(['signin', 'view', 'account', 'orders'])}"


def benign_platform_url():
    return f"https://{random.choice(['team', 'app', 'staging', 'demo'])}-{random.randint(100,999)}.{random.choice(PLATFORMS)}/"


def phish_url(kind=None):
    kind = kind or random.choice(["subdomain_chain", "typosquat", "dga", "ip_literal", "punycode", "shortener", "platform"])
    brand, bdomain = random.choice(BRANDS)
    bword = bdomain.split(".")[0]
    if kind == "subdomain_chain":
        return f"http://login.{bword}.com.verify-{random.randint(1000,9999)}.{random.choice(SUS_TLD)}/secure"
    if kind == "typosquat":
        squat = bword.replace("o", "0").replace("l", "1").replace("i", "1") + random.choice(["-secure", "-login", "verify"])
        return f"http://{squat}.{random.choice(SUS_TLD)}/account"
    if kind == "dga":
        rnd = "".join(random.choice("bcdfghjklmnpqrstvwxyz0123456789") for _ in range(random.randint(10, 16)))
        return f"http://{rnd}.{random.choice(SUS_TLD)}/{random.choice(['jp','login','mypage'])}"
    if kind == "ip_literal":
        return f"http://{rand_ip()}/{bword}/signin.php"
    if kind == "punycode":
        return f"http://xn--{bword}-{random.choice('0123456789abcdef')*2}a.{random.choice(SUS_TLD)}/verify"
    if kind == "shortener":
        return f"https://{random.choice(SHORTENERS)}/{''.join(random.choice('abcdefghijkmnpqrstuvwxyz0123456789') for _ in range(7))}"
    if kind == "platform":  # phishing hosted on a legit platform (the hard one)
        return f"https://{bword}-{random.choice(['secure','verify','account'])}-{random.randint(10,99)}.{random.choice(PLATFORMS)}/"
    return phish_url("dga")


# ── families ─────────────────────────────────────────────────────────────────
records = []
def add(r): records.append(r)


# ----- PHISHING: header-detectable (clean text + clean/no url, spoofed sender) -----
def fam_phish_header_spoof(n):
    bodies = [
        "Hi {fn}, just confirming the details we discussed earlier. Let me know if anything's unclear and I'll follow up. Thanks.",
        "Please find the summary attached for your records. Reach out if you have any questions before our next sync.",
        "Following up on the note from yesterday — I think we're aligned. Happy to jump on a quick call if useful.",
        "Quick heads-up that the schedule shifted slightly. Nothing major, details to follow. Appreciate your flexibility.",
    ]
    for _ in range(n):
        brand, bdomain = random.choice(BRANDS)
        # display name impersonates a brand or an exec, but the real address is free/typosquat and auth fails
        impersonation = random.random() < 0.5
        from_name = brand + " Support" if impersonation else NAMES_FULL() + " (CEO)"
        from_addr = random.choice([f"{brand.split()[0].lower()}-support@{random.choice(FREE)}",
                                   f"ceo@{bdomain.replace('.', '-')}.{random.choice(SUS_TLD)}",
                                   f"{random.choice(FIRST).lower()}.{random.choice(LAST).lower()}@{random.choice(FREE)}"])
        add(make("phishing", "hard", "phish_header_spoof", ["header"],
                 from_name=from_name, from_addr=from_addr,
                 reply_to=f"{random.choice(FIRST).lower()}@{random.choice(SUS_TLD+['mailfence.com'])}" if random.random() < 0.6 else None,
                 subject=random.choice(["Re: quick follow-up", "Touching base", "As discussed", "Re: yesterday"]),
                 body=random.choice(bodies).format(fn=random.choice(FIRST)),
                 spf=random.choice(["fail", "softfail"]), dkim=random.choice(["fail", "none"]),
                 dmarc="fail", received_mismatch=True))


# ----- PHISHING: url-detectable (clean header + benign-sounding text, malicious URL) -----
def fam_phish_url_only(n):
    templates = [
        "Hi {fn}, here's the document you asked for: {url}  Let me know once you've had a look.",
        "Your statement is ready to view. Open it here: {url}",
        "Thanks for your order. Track your shipment at {url}",
        "Please review the shared file when you get a chance: {url}",
        "Your account summary for this month is available: {url}",
    ]
    for _ in range(n):
        d = random.choice(LEGIT_DOMAINS)
        u = phish_url()
        add(make("phishing", "medium", "phish_url_only", ["url"],
                 from_name=NAMES_FULL(), from_addr=f"{random.choice(FIRST).lower()}@{d}",
                 subject=random.choice(["Your document", "Statement ready", "Shipment update", "Shared with you", "Account summary"]),
                 body=random.choice(templates).format(fn=random.choice(FIRST), url=u),
                 urls=[u], spf="pass", dkim="pass", dmarc="pass"))


# ----- PHISHING: nlp-detectable (clean header, no/benign url, social-engineering text) -----
def fam_phish_nlp_bec(n):
    bodies = [
        ("BEC giftcard", "Are you at your desk? I'm tied up in meetings and need you to grab {amt} gift cards for a client. Send me the codes and I'll approve reimbursement right after."),
        ("payroll redirect", "Hi, I switched banks and need to update my direct deposit to a new account before the next pay run. The old account is closed — can you change my payroll details to the new ones I'll send?"),
        ("wire", "Finalizing a confidential deal with counsel — we need to wire the deposit today to hold terms. Standby for instructions and keep this between us until it's announced."),
        ("helpdesk reverse", "This is IT support. We're seeing sync errors on your mailbox. To fix it on our end, please reply with your current username and password so we can reset it."),
        ("calm secret", "We noticed a sign-in to your account from a new device. If that wasn't you, reply with your current password so we can secure the account."),
    ]
    for _ in range(n):
        fam, body = random.choice(bodies)
        d = random.choice(LEGIT_DOMAINS)
        add(make("phishing", "hard", "phish_nlp_bec", ["nlp"],
                 from_name=NAMES_FULL(), from_addr=f"{random.choice(FIRST).lower()}.{random.choice(LAST).lower()}@{d}",
                 subject=random.choice(["Quick favor", "Urgent", "Need your help", "Account maintenance", "Re: payroll"]),
                 body=body.format(amt=AMT()), spf="pass", dkim="pass", dmarc="pass"))


# ----- PHISHING: obvious (trips all channels) -----
def fam_phish_obvious(n):
    for _ in range(n):
        brand, bdomain = random.choice(BRANDS)
        u = phish_url(random.choice(["subdomain_chain", "ip_literal", "dga"]))
        add(make("phishing", "easy", "phish_obvious", ["header", "url", "nlp"],
                 from_name=f"{brand} Security",
                 from_addr=f"security-alert@{bdomain.replace('.', '')}.{random.choice(SUS_TLD)}",
                 reply_to=f"recover@{random.choice(SUS_TLD)}",
                 subject=random.choice(["Account suspended", "Verify your account now", "Security alert: action required"]),
                 body=f"Your {brand} account has been suspended due to suspicious activity. Verify immediately or it "
                      f"will be permanently deleted within 24 hours: {u}",
                 urls=[u], spf="fail", dkim="fail", dmarc="fail", received_mismatch=True))


# ----- PHISHING: adversarial (obfuscation in subject/body + malicious url) -----
def fam_phish_adversarial(n):
    for _ in range(n):
        brand, bdomain = random.choice(BRANDS)
        u = phish_url(random.choice(["subdomain_chain", "punycode", "typosquat"]))
        base_subj = random.choice(["Verify your account", "Password expired", "Confirm your identity"])
        base_body = (f"Your {brand} password has expired. Re-verify now to keep access or your account will be locked: {u}")
        style = random.choice(["leet", "homoglyph", "zerowidth"])
        subj = {"leet": leet, "homoglyph": homoglyph, "zerowidth": zerowidth}[style](base_subj)
        body = {"leet": leet, "homoglyph": homoglyph, "zerowidth": zerowidth}[style](base_body)
        add(make("phishing", "adversarial", "phish_adversarial_" + style, ["url", "nlp"],
                 from_name=f"{brand} Team", from_addr=f"no-reply@{bdomain.replace('.', '-')}.{random.choice(SUS_TLD)}",
                 subject=subj, body=body, urls=[u], spf="fail", dkim="none", dmarc="fail"))


# ----- PHISHING: hard soft (the text-only Pareto frontier — weak in every channel) -----
def fam_phish_hard_soft(n):
    bodies = [
        "Hope you're well. I need a small favor handled discreetly before our meeting later — I'll share specifics shortly. Can you help?",
        "Thanks again for earlier. Could you action the item we discussed and process the payment to the details I'll forward? Appreciate it.",
        "We're finalizing the acquisition this week. I'll need you ready to move funds quickly when I give the word. More to follow.",
        "Reminder: your annual benefits election is still incomplete. Sign in and confirm your selections before it locks at end of day.",
    ]
    for _ in range(n):
        d = random.choice(LEGIT_DOMAINS)
        add(make("phishing", "hard", "phish_hard_soft", ["url", "header"],   # disambiguator is URL/sender (deferred)
                 from_name=NAMES_FULL(), from_addr=f"{random.choice(FIRST).lower()}@{d}",
                 subject=random.choice(["Quick question", "Following up", "Heads up", "Action needed"]),
                 body=random.choice(bodies), spf="pass", dkim="pass", dmarc="pass"))


# ----- LEGIT: trivial -----
def fam_legit_trivial(n):
    bodies = ["hi", "thanks!", "ok sounds good", "got it, will do", "see attached", "lgtm, merged",
              "running 5 min late", "works for me, talk then", "happy friday team", "no worries, thanks"]
    for _ in range(n):
        d = random.choice(LEGIT_DOMAINS)
        add(make("legitimate", "trivial", "legit_trivial", [],
                 from_name=NAMES_FULL(), from_addr=f"{random.choice(FIRST).lower()}@{d}",
                 subject=random.choice(["Re: update", "Re: lunch", "Re: PR", "quick one", "Re: sync"]),
                 body=random.choice(bodies), spf="pass", dkim="pass", dmarc="pass"))


# ----- LEGIT: phishy-looking text (security notice / shared-doc / meta-phish) -----
def fam_legit_phishy_text(n):
    bodies = [
        ("security notice", "We noticed a new sign-in from Chrome on Windows. If this was you, no action is needed. If not, you can review recent activity in your account settings."),
        ("shared doc", "I've dropped the updated roadmap in SharePoint — sign in with your work account to view it when you have a moment. No rush."),
        ("password reset", "We received a request to reset your password. If this was you, follow the steps in your account. If not, you can safely ignore this email."),
        ("meta phish", "Heads up: payroll is switching providers next month. You'll get a separate email asking you to re-enter your direct deposit details — that one is legitimate. Flagging so it doesn't look like phishing."),
        ("benefits", "Open enrollment is here. You can review your benefits and tax withholding in the HR portal whenever you have a moment before the deadline."),
    ]
    for _ in range(n):
        fam, body = random.choice(bodies)
        d = random.choice(LEGIT_DOMAINS)
        add(make("legitimate", "hard", "legit_phishy_text", [],
                 from_name=random.choice(["IT Service Desk", "HR Team", NAMES_FULL(), "Security Team"]),
                 from_addr=f"{random.choice(['it', 'hr', 'no-reply', 'security'])}@{d}",
                 subject=random.choice(["New sign-in", "Shared with you", "Password reset requested", "Payroll update", "Open enrollment"]),
                 body=body, spf="pass", dkim="pass", dmarc="pass"))


# ----- LEGIT: forwarded mail that breaks SPF (classic header FP trap) -----
def fam_legit_forwarded_spf_fail(n):
    bodies = [
        "Forwarding the notes below for visibility.\n----- Forwarded message -----\nPlease review the action items and confirm your parts by Friday.",
        "FYI — see the thread below, looks like we're good to proceed. Let me know if finance needs anything from me.",
        "Sharing this for the team. The vendor confirmed the timeline; nothing needed from you right now.",
    ]
    for _ in range(n):
        d = random.choice(LEGIT_DOMAINS)
        # legit content, but forwarding broke SPF; DKIM still passes — must NOT be flagged
        add(make("legitimate", "hard", "legit_forwarded_spf_fail", [],
                 from_name=NAMES_FULL(), from_addr=f"{random.choice(FIRST).lower()}@{d}",
                 subject=random.choice(["Fwd: meeting notes", "Fwd: vendor timeline", "Fwd: action items"]),
                 body=random.choice(bodies), spf="fail", dkim="pass", dmarc="pass", hops=3))


# ----- LEGIT: free-provider sender (real person on gmail — must not be auto-phishing) -----
def fam_legit_freeprov(n):
    bodies = [
        "Hey, it's {fn} — using my personal email since I'm out today. Can we move our 1:1 to Thursday? Thanks!",
        "Hi, applying for the role you posted. My resume is attached. Happy to chat any time this week.",
        "Following up from the conference — great meeting you. Let's stay in touch about the partnership idea.",
    ]
    for _ in range(n):
        fn = random.choice(FIRST)
        add(make("legitimate", "medium", "legit_freeprov", [],
                 from_name=f"{fn} {random.choice(LAST)}", from_addr=f"{fn.lower()}{random.randint(1,99)}@{random.choice(FREE)}",
                 subject=random.choice(["Quick reschedule", "Application", "Great meeting you"]),
                 body=random.choice(bodies).format(fn=fn), spf="pass", dkim="pass", dmarc="pass"))


# ----- LEGIT: phishy-looking URL (real SharePoint/DocuSign/platform/shortener) -----
def fam_legit_phishy_url(n):
    for _ in range(n):
        kind = random.choice(["brand", "platform", "shortener"])
        u = {"brand": benign_brand_url, "platform": benign_platform_url,
             "shortener": lambda: f"https://{random.choice(SHORTENERS)}/{''.join(random.choice('abcdefghjkmnp23456789') for _ in range(7))}"}[kind]()
        d = random.choice(LEGIT_DOMAINS)
        body = random.choice([
            "Here's the deck from today's review: {url} — sign in with your work account to open it.",
            "Your document is ready to sign: {url}",
            "We've deployed the staging build for you to try: {url}",
            "Shared the photos from the team event here: {url}",
        ]).format(url=u)
        add(make("legitimate", "hard", "legit_phishy_url", [],
                 from_name=NAMES_FULL(), from_addr=f"{random.choice(FIRST).lower()}@{d}",
                 subject=random.choice(["Deck shared", "Ready to sign", "Staging build", "Event photos"]),
                 body=body, urls=[u], spf="pass", dkim="pass", dmarc="pass"))


# ----- LEGIT: transactional / operational urgency -----
def fam_legit_transactional(n):
    bodies = [
        ("Your order shipped", "Order #{n} is on its way and should arrive Thursday. Track it in your account. Thanks for shopping with us."),
        ("Your verification code", "Your one-time passcode is {code}. It expires in 5 minutes. We will never ask you to share it."),
        ("Receipt", "Thanks for your payment of {amt}. This email is your receipt — no action needed."),
        ("URGENT: prod incident", "API is returning 500s and customers are affected. Jump on the incident bridge now. Sev1."),
        ("Deadline today", "Please get your budget numbers in by 5pm today — we can't slip the submission."),
    ]
    for _ in range(n):
        subj, body = random.choice(bodies)
        d = random.choice(LEGIT_DOMAINS)
        add(make("legitimate", "easy", "legit_transactional", [],
                 from_name=random.choice([random.choice(COMPANIES) + " Store", "Engineering", NAMES_FULL(), "Billing"]),
                 from_addr=f"{random.choice(['no-reply', 'orders', 'billing', 'eng'])}@{d}",
                 subject=subj, body=body.format(n=random.randint(1000, 9999), code=random.randint(100000, 999999), amt=AMT()),
                 spf="pass", dkim="pass", dmarc="pass"))


# ----- SPAM: marketing (must be 'spam', not 'phishing'; risk must stay low) -----
def fam_spam_marketing(n):
    bodies = [
        "Our biggest sale of the year is here — {pct}% off everything through Sunday. Use code {code} at checkout. Unsubscribe anytime.",
        "This month's roundup: three product updates, two customer stories, and an upcoming webinar. Thanks for being a subscriber.",
        "Don't miss our limited-time offer on annual plans. Upgrade today and save. Manage your email preferences at the bottom.",
    ]
    for _ in range(n):
        d = random.choice(LEGIT_DOMAINS)
        add(make("spam", "easy", "spam_marketing", [],
                 from_name=random.choice(COMPANIES) + " Marketing", from_addr=f"news@{d}",
                 subject=random.choice(["Weekend sale", "Your monthly digest", "Limited-time offer"]),
                 body=random.choice(bodies).format(pct=random.choice([30, 40, 50]), code=random.choice(["SAVE40", "FALL50", "DEAL30"])),
                 spf="pass", dkim="pass", dmarc="pass", list_unsub=True))


# ── assemble (counts tuned for ~±2-3% 95% CI per class) ──────────────────────
PLAN = [
    (fam_phish_header_spoof, 200), (fam_phish_url_only, 200), (fam_phish_nlp_bec, 200),
    (fam_phish_obvious, 150), (fam_phish_adversarial, 150), (fam_phish_hard_soft, 150),
    (fam_legit_trivial, 130), (fam_legit_phishy_text, 200), (fam_legit_forwarded_spf_fail, 120),
    (fam_legit_freeprov, 110), (fam_legit_phishy_url, 200), (fam_legit_transactional, 160),
    (fam_spam_marketing, 240),
]
for fn, n in PLAN:
    fn(n)
random.shuffle(records)

out = Path(__file__).parent / "cybersiren_e2e_benchmark.jsonl"
with open(out, "w") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

# ── summary ──────────────────────────────────────────────────────────────────
from collections import Counter
by_label = Counter(r["label"] for r in records)
by_diff = Counter(r["difficulty"] for r in records)
by_fam = Counter(r["family"] for r in records)
by_chan = Counter("+".join(r["channels_expected"]) or "none" for r in records if r["label"] == "phishing")
print(f"wrote {len(records)} emails -> {out}")
print("by label:   ", dict(by_label))
print("by difficulty:", dict(by_diff))
print("phishing by channel-owner:", dict(by_chan))
print("families:", len(by_fam))
# crude diversity check (guard against template-clone collapse)
uniq_bodies = len({r["body_plain"] for r in records})
words = Counter(w for r in records for w in r["body_plain"].lower().split())
print(f"unique bodies: {uniq_bodies}/{len(records)}  | unique words: {len(words)}  (TTR {len(words)/max(1,sum(words.values())):.3f})")
