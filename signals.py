"""
ShieldNetX Detection Engine — 11 rule-based signals.

Each signal function takes a URL and returns:
    (score: float | None, triggered: bool, reason: str)

score is 0-100 (higher = more suspicious). score is None when the
signal genuinely can't be evaluated (network unreachable, DNS timeout,
etc.) — main.py excludes abstained signals from the average and
renormalizes the rest, rather than letting a fake "neutral" guess
dilute the final score or make repeat scans of the same URL
inconsistent.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse

import requests

# Cache successful domain-age lookups per host so repeat scans of the
# same URL in one process give identical results instead of depending
# on whether the WHOIS server happened to answer that time.
_DOMAIN_AGE_CACHE: dict[str, tuple[float, bool, str]] = {}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

KNOWN_BRANDS = [
    "google", "paypal", "amazon", "apple", "microsoft", "facebook",
    "instagram", "netflix", "whatsapp", "sbi", "hdfcbank", "icicibank",
    "axisbank", "phonepe", "paytm", "gpay", "irctc", "flipkart",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "password", "otp", "reset", "unlock",
    "suspended", "billing", "invoice", "urgent",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
]

# Weight of each signal in the final 0-100 score. Must sum to 1.0.
SIGNAL_WEIGHTS = {
    "domain_age": 0.12,
    "url_structure": 0.08,
    "suspicious_keywords": 0.08,
    "ip_as_hostname": 0.10,
    "subdomain_count": 0.07,
    "ssl_validity": 0.10,
    "typosquat_homograph": 0.15,
    "redirect_chain": 0.10,
    "server_infrastructure": 0.08,
    "fingerprint_replication": 0.07,
    "otp_credential_harvesting": 0.05,
}


def _hostname(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname or ""


# ---------------------------------------------------------------------------
# 1. Domain age (newly registered domains are higher risk)
# ---------------------------------------------------------------------------

def check_domain_age(url: str) -> tuple[float | None, bool, str]:
    host = _hostname(url)
    if host in _DOMAIN_AGE_CACHE:
        return _DOMAIN_AGE_CACHE[host]

    result: tuple[float | None, bool, str]
    try:
        import whois  # python-whois
        socket.setdefaulttimeout(5)
        w = whois.whois(host)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            # WHOIS answered but gave no creation date — genuinely
            # unknown, not evidence of anything. Abstain.
            result = (None, False, "WHOIS responded but gave no registration date")
        else:
            from datetime import datetime
            age_days = (datetime.now() - created).days
            if age_days < 30:
                result = (90.0, True, f"Domain registered {age_days} days ago (very new)")
            elif age_days < 180:
                result = (55.0, True, f"Domain registered {age_days} days ago (recent)")
            else:
                result = (5.0, False, f"Domain age is {age_days} days (established)")
    except Exception:
        # WHOIS server unreachable/timed out — abstain rather than guess,
        # so repeat scans of the same URL don't flip between fallback values.
        result = (None, False, "Domain age lookup unavailable (WHOIS unreachable)")

    _DOMAIN_AGE_CACHE[host] = result
    return result


# ---------------------------------------------------------------------------
# 2. URL structure (length, entropy, special chars, @ symbol tricks)
# ---------------------------------------------------------------------------

def check_url_structure(url: str) -> tuple[float, bool, str]:
    score = 0.0
    reasons = []

    if len(url) > 90:
        score += 30
        reasons.append("unusually long URL")
    if "@" in url:
        score += 40
        reasons.append("'@' symbol used to obscure real destination")
    if url.count("-") >= 4:
        score += 15
        reasons.append("excessive hyphens")
    if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", url):
        score += 20
        reasons.append("IP-like pattern embedded in hostname")

    score = min(score, 100.0)
    return score, score > 0, "; ".join(reasons) if reasons else "URL structure looks normal"


# ---------------------------------------------------------------------------
# 3. Suspicious keywords
# ---------------------------------------------------------------------------

def check_suspicious_keywords(url: str) -> tuple[float, bool, str]:
    url_lower = url.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if not hits:
        return 0.0, False, "No suspicious keywords found"
    score = min(100.0, len(hits) * 25.0)
    return score, True, f"Suspicious keyword(s) found: {', '.join(hits)}"


# ---------------------------------------------------------------------------
# 4. IP address used directly as hostname
# ---------------------------------------------------------------------------

def check_ip_as_hostname(url: str) -> tuple[float, bool, str]:
    host = _hostname(url)
    try:
        ipaddress.ip_address(host)
        return 95.0, True, "Raw IP address used instead of a domain name"
    except ValueError:
        return 0.0, False, "Hostname is a normal domain, not a raw IP"


# ---------------------------------------------------------------------------
# 5. Subdomain count (excessive subdomains hide the real domain)
# ---------------------------------------------------------------------------

def check_subdomain_count(url: str) -> tuple[float, bool, str]:
    host = _hostname(url)
    parts = host.split(".")
    sub_count = max(0, len(parts) - 2)
    if sub_count >= 4:
        return 85.0, True, f"{sub_count} subdomains — likely obfuscating real domain"
    if sub_count >= 2:
        return 45.0, True, f"{sub_count} subdomains — moderately suspicious"
    return 0.0, False, "Normal subdomain structure"


# ---------------------------------------------------------------------------
# 6. SSL/TLS validity
# ---------------------------------------------------------------------------

def check_ssl_validity(url: str) -> tuple[float | None, bool, str]:
    host = _hostname(url)
    if not url.lower().startswith("https") and "https://" not in url.lower():
        return 60.0, True, "Site does not use HTTPS"
    try:
        import ssl
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
        return 0.0, False, "Valid SSL certificate"
    except ssl.SSLError as e:
        # An actual certificate problem — this IS a real signal.
        return 70.0, True, f"SSL certificate issue: {e}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        # Couldn't even reach the host to check — not evidence either way.
        return None, False, "Could not reach host to verify SSL certificate"


# ---------------------------------------------------------------------------
# 7. Typosquat / homograph detection against known brands
# ---------------------------------------------------------------------------

def check_typosquat_homograph(url: str) -> tuple[float, bool, str]:
    host = _hostname(url).lower()
    domain_root = host.split(".")[-2] if "." in host else host

    # Homograph: non-ASCII characters mixed into an otherwise-Latin domain
    if any(ord(c) > 127 for c in host):
        return 90.0, True, "Non-ASCII (homograph) characters detected in domain"

    # Compare the full label AND each hyphen-separated token against brands,
    # so "paypa1-secure-login.tk" catches "paypa1" ~ "paypal".
    tokens = [domain_root] + domain_root.split("-")

    best_dist = None
    best_brand = None
    best_token = domain_root
    for token in tokens:
        for brand in KNOWN_BRANDS:
            # Edit distance is the right tool for typosquats (1-2 char
            # substitutions/insertions), unlike ratio-based similarity
            # which false-positives on unrelated words sharing letters.
            dist = _levenshtein(token, brand)
            if best_dist is None or dist < best_dist:
                best_dist, best_brand, best_token = dist, brand, token

    if best_token == best_brand and best_dist == 0:
        return 0.0, False, "Domain matches brand exactly (not typosquatting)"

    # Only flag when the token is close in length to the brand AND within
    # a small edit distance — this is what catches "paypa1"/"paypal" (dist 1)
    # while leaving unrelated words like "example"/"apple" untouched.
    len_diff = abs(len(best_token) - len(best_brand))
    if best_dist <= 1 and len_diff <= 1:
        return 90.0, True, f"'{best_token}' closely resembles brand '{best_brand}' (possible typosquat, edit distance {best_dist})"
    if best_dist == 2 and len_diff <= 2:
        return 50.0, True, f"'{best_token}' somewhat resembles brand '{best_brand}' (edit distance {best_dist})"
    return 0.0, False, "No typosquatting pattern detected"


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                prev_row[j] + 1,      # deletion
                curr_row[j - 1] + 1,  # insertion
                prev_row[j - 1] + cost,  # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


# ---------------------------------------------------------------------------
# 8. Redirect chain analysis
# ---------------------------------------------------------------------------

def check_redirect_chain(url: str) -> tuple[float | None, bool, str]:
    try:
        resp = requests.get(url, timeout=6, allow_redirects=True)
        chain = resp.history
        hops = len(chain)
        if hops == 0:
            return 0.0, False, "No redirects"

        final_host = _hostname(resp.url)
        original_host = _hostname(url)
        cross_domain = final_host != original_host

        score = min(100.0, hops * 20.0 + (30.0 if cross_domain else 0.0))
        reason = f"{hops} redirect(s)" + (" ending on a different domain" if cross_domain else "")
        return score, score > 0, reason
    except Exception:
        return None, False, "Could not follow redirects (site unreachable or timed out)"


# ---------------------------------------------------------------------------
# 9. Server infrastructure tracking (known bad hosting patterns)
# ---------------------------------------------------------------------------

def check_server_infrastructure(url: str) -> tuple[float, bool, str]:
    host = _hostname(url)
    score = 0.0
    reasons = []

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 50
        reasons.append(f"suspicious TLD ({host.split('.')[-1]})")

    try:
        ip = socket.gethostbyname(host)
        # Flag known free/abused hosting ranges could go here once you have
        # a real threat-intel feed; placeholder keeps this pluggable.
        if ip.startswith(("185.", "45.")):
            score += 30
            reasons.append("IP range associated with abuse-prone hosting")
    except Exception:
        score += 20
        reasons.append("could not resolve DNS")

    score = min(score, 100.0)
    return score, score > 0, "; ".join(reasons) if reasons else "No infrastructure red flags"


# ---------------------------------------------------------------------------
# 10. Fingerprint replication (visual/branding clone detection)
# ---------------------------------------------------------------------------

def check_fingerprint_replication(url: str) -> tuple[float | None, bool, str]:
    try:
        resp = requests.get(url, timeout=6)
        html = resp.text.lower()

        hits = [brand for brand in KNOWN_BRANDS if brand in html]
        has_login_form = "<form" in html and ("password" in html or "type=\"password\"" in html)

        if hits and has_login_form:
            host_root = _hostname(url).lower()
            mismatched = [b for b in hits if b not in host_root]
            if mismatched:
                return 85.0, True, (
                    f"Page content references brand(s) {mismatched} with a login "
                    "form, but the domain doesn't match — likely brand impersonation"
                )
        return 0.0, False, "No brand/fingerprint mismatch detected"
    except Exception:
        return None, False, "Could not fetch page content for fingerprint check"


# ---------------------------------------------------------------------------
# 11. OTP / credential harvesting detection
# ---------------------------------------------------------------------------

def check_otp_credential_harvesting(url: str) -> tuple[float | None, bool, str]:
    try:
        resp = requests.get(url, timeout=6)
        html = resp.text.lower()

        has_password_field = "type=\"password\"" in html or "type='password'" in html
        has_otp_field = "otp" in html and ("<input" in html)
        posts_cross_domain = False

        form_actions = re.findall(r'action=["\']([^"\']+)["\']', html)
        original_host = _hostname(url)
        for action in form_actions:
            if action.startswith("http") and _hostname(action) not in ("", original_host):
                posts_cross_domain = True
                break

        if (has_password_field or has_otp_field) and posts_cross_domain:
            return 95.0, True, "Credential/OTP form submits to a different domain"
        if has_otp_field:
            return 40.0, True, "Page requests an OTP — verify legitimacy"
        if has_password_field:
            return 15.0, False, "Standard password field present"
        return 0.0, False, "No credential/OTP harvesting pattern found"
    except Exception:
        return None, False, "Could not fetch page content for credential-harvesting check"


# ---------------------------------------------------------------------------
# Registry used by main.py
# ---------------------------------------------------------------------------

SIGNAL_FUNCTIONS = {
    "domain_age": check_domain_age,
    "url_structure": check_url_structure,
    "suspicious_keywords": check_suspicious_keywords,
    "ip_as_hostname": check_ip_as_hostname,
    "subdomain_count": check_subdomain_count,
    "ssl_validity": check_ssl_validity,
    "typosquat_homograph": check_typosquat_homograph,
    "redirect_chain": check_redirect_chain,
    "server_infrastructure": check_server_infrastructure,
    "fingerprint_replication": check_fingerprint_replication,
    "otp_credential_harvesting": check_otp_credential_harvesting,
}
