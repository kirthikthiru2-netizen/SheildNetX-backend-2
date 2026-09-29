"""
ShieldNetX APK Analysis — GenAI-powered static + simulated-dynamic
malware risk scoring for uploaded APK files.

Pipeline:
  1. Static analysis (androguard) — permissions, manifest, embedded
     strings/URLs, dangerous API usage, signing cert info.
  2. Simulated dynamic indicators — code-pattern signals that predict
     runtime behavior (reflection, dynamic class loading, native code,
     anti-emulator checks, SMS/exec usage) WITHOUT actually executing
     the APK. This runs anywhere (no emulator/sandbox needed), which
     is what makes it deployable on Render.
  3. GenAI layer — feeds the extracted findings to an LLM (first working key among
     Claude, OpenAI, DeepSeek, Gemini), which does
     pattern recognition across the findings and writes a plain-
     language threat summary + recommendations.
  4. Composite risk score (0-100) blending static + dynamic + GenAI's
     own severity assessment, same scale/verdict bands as the URL
     scanner.

NOTE: step 2 is explicitly "simulated dynamic" — indicator-based
prediction from static code inspection, not a real sandbox run. Real
dynamic analysis (actually executing the APK) needs a VM/emulator with
virtualization support, which Render's web service tier does not
provide. Swap in a real sandbox later (e.g. your Raspberry Pi +
Waydroid setup) by replacing `extract_dynamic_indicators` with a call
out to that service.
"""

import os
import re
import json
import hashlib
import tempfile
import logging
from datetime import datetime, timezone
from functools import partial

import requests
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from db import ApkScanRecord, KnownMalwareHash, get_db, record_to_dict
from report import generate_apk_report_pdf

# androguard is extremely verbose at DEBUG/INFO level by default — quiet it down
logging.getLogger("androguard").setLevel(logging.WARNING)
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(lambda msg: None)  # discard androguard's loguru output
except ImportError:
    pass

router = APIRouter(prefix="/apk", tags=["apk-analysis"])


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": 25,
    "android.permission.RECEIVE_SMS": 20,
    "android.permission.READ_SMS": 20,
    "android.permission.CALL_PHONE": 15,
    "android.permission.READ_CONTACTS": 12,
    "android.permission.READ_CALL_LOG": 15,
    "android.permission.SYSTEM_ALERT_WINDOW": 20,  # overlay attacks
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,  # keylogging risk
    "android.permission.REQUEST_INSTALL_PACKAGES": 20,
    "android.permission.WRITE_EXTERNAL_STORAGE": 8,
    "android.permission.READ_SMS_PREFIX": 0,  # placeholder, unused
    "android.permission.PACKAGE_USAGE_STATS": 15,
    "android.permission.BIND_DEVICE_ADMIN": 25,
    "android.permission.RECEIVE_BOOT_COMPLETED": 8,  # persistence
}

DANGEROUS_API_PATTERNS = {
    "Ljava/lang/reflect/": ("reflection", 15),
    "DexClassLoader": ("dynamic code loading", 30),
    "PathClassLoader": ("dynamic code loading", 25),
    "Ljava/lang/Runtime;->exec": ("shell command execution", 30),
    "ProcessBuilder": ("shell command execution", 25),
    "SmsManager": ("SMS API usage", 15),
    "Landroid/telephony/SmsManager;": ("SMS API usage", 15),
    "getInstalledPackages": ("installed-app enumeration", 10),
    "getSubscriberId": ("IMSI/device fingerprinting", 12),
    "getDeviceId": ("device fingerprinting", 10),
    "crypto": ("cryptographic operations (possible payload decryption)", 8),
}

ANTI_EMULATOR_STRINGS = [
    "goldfish", "ranchu", "vbox", "genymotion", "sdk_gphone",
    "qemu", "generic_x86",
]

SUSPICIOUS_URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9.\-]+(?:\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top)[/\w.\-]*",
    re.IGNORECASE,
)
IP_URL_PATTERN = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
URL_KEYWORD_PATTERN = re.compile(
    r"https?://[^\s\"']*(?:exfil|steal|c2|command|payload|dropper|keylog|creds?)[^\s\"']*",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PermissionFinding(BaseModel):
    permission: str
    risk_points: int


class ApiFinding(BaseModel):
    pattern: str
    description: str
    risk_points: int
    occurrences: int


class DynamicIndicator(BaseModel):
    indicator: str
    description: str
    risk_points: int


class ApkAnalysisResponse(BaseModel):
    filename: str
    sha256: str
    package_name: str | None
    app_name: str | None
    static_score: float
    dynamic_score: float
    ai_score: float | None
    risk_score: float
    verdict: str
    permissions_found: list[PermissionFinding]
    suspicious_apis: list[ApiFinding]
    dynamic_indicators: list[DynamicIndicator]
    embedded_urls: list[str]
    ai_summary: str
    recommendations: list[str]
    analyzed_at: str
    from_cache: bool = False
    scan_count: int = 1
    blocklist_match: dict | None = None  # {"label": ..., "source": ..., "added_at": ...} if hash is a known-bad match
    methods_analyzed: list[str] = []  # class.method names GenAI inspected real decompiled code for
    ai_provider: str | None = None  # which LLM produced the summary, e.g. "anthropic/claude-sonnet-5"


class ApkHistoryEntry(BaseModel):
    sha256: str
    filename: str | None
    package_name: str | None
    app_name: str | None
    risk_score: float
    verdict: str
    first_analyzed_at: str | None
    last_analyzed_at: str | None
    scan_count: int


# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------

def run_static_analysis(apk_path: str) -> dict:
    from androguard.core.apk import APK

    apk = APK(apk_path)

    package_name = apk.get_package()
    app_name = apk.get_app_name()
    permissions = apk.get_permissions()

    perm_findings = []
    static_score = 0.0
    for perm in permissions:
        points = DANGEROUS_PERMISSIONS.get(perm)
        if points:
            perm_findings.append(PermissionFinding(permission=perm, risk_points=points))
            static_score += points

    # Signing info — unsigned or debug-signed APKs are a red flag
    is_signed = apk.is_signed_v1() or apk.is_signed_v2() or apk.is_signed_v3()
    if not is_signed:
        static_score += 25

    return {
        "package_name": package_name,
        "app_name": app_name,
        "permissions": permissions,
        "perm_findings": perm_findings,
        "is_signed": is_signed,
        "static_score": min(static_score, 100.0),
        "apk_object": apk,
    }


def extract_strings_and_urls(apk_path: str) -> tuple[list[str], set[str]]:
    """Pull raw strings out of the DEX to find embedded URLs / API patterns
    without needing a full decompile."""
    import zipfile

    raw_strings: list[str] = []
    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                data = z.read(name)
                # crude but fast: pull printable ASCII runs of length >= 6
                for match in re.finditer(rb"[\x20-\x7e]{6,}", data):
                    raw_strings.append(match.group().decode("ascii", errors="ignore"))

    urls = set()
    for s in raw_strings:
        urls.update(SUSPICIOUS_URL_PATTERN.findall(s))
        urls.update(IP_URL_PATTERN.findall(s))
        urls.update(URL_KEYWORD_PATTERN.findall(s))
        if s.startswith("http://") or s.startswith("https://"):
            urls.add(s)

    return raw_strings, urls


def score_embedded_urls(urls: set[str]) -> tuple[float, list[str]]:
    """Suspicious TLDs, raw IPs, or exfil/C2-style keywords in embedded
    URLs are a real signal malware analysts look for — score them
    instead of just listing them."""
    score = 0.0
    reasons = []
    for url in urls:
        if URL_KEYWORD_PATTERN.search(url):
            score += 30
            reasons.append(f"'{url}' contains an exfiltration/C2-style keyword")
        elif SUSPICIOUS_URL_PATTERN.search(url):
            score += 20
            reasons.append(f"'{url}' uses a suspicious TLD")
        elif IP_URL_PATTERN.search(url):
            score += 15
            reasons.append(f"'{url}' is a raw-IP endpoint")
    return min(score, 100.0), reasons


def find_dangerous_apis(raw_strings: list[str]) -> list[ApiFinding]:
    joined_sample = raw_strings  # search per-string to count occurrences accurately
    findings = []
    for pattern, (desc, points) in DANGEROUS_API_PATTERNS.items():
        count = sum(1 for s in joined_sample if pattern in s)
        if count > 0:
            findings.append(ApiFinding(
                pattern=pattern, description=desc, risk_points=points, occurrences=count,
            ))
    return findings


# ---------------------------------------------------------------------------
# Simulated dynamic indicators (no execution required)
# ---------------------------------------------------------------------------

def extract_dynamic_indicators(raw_strings: list[str], apk_info: dict) -> list[DynamicIndicator]:
    indicators = []

    joined_lower_sample = [s.lower() for s in raw_strings[:20000]]  # cap for perf

    # Anti-emulator / sandbox evasion checks
    evasion_hits = [
        term for term in ANTI_EMULATOR_STRINGS
        if any(term in s for s in joined_lower_sample)
    ]
    if evasion_hits:
        indicators.append(DynamicIndicator(
            indicator="anti_emulator_check",
            description=f"Contains emulator/sandbox-detection strings: {', '.join(evasion_hits)}",
            risk_points=25,
        ))

    # Native code presence (.so libs) — often used to hide payloads
    apk = apk_info.get("apk_object")
    if apk is not None:
        try:
            native_libs = [f for f in apk.get_files() if f.endswith(".so")]
            if native_libs:
                indicators.append(DynamicIndicator(
                    indicator="native_code_present",
                    description=f"{len(native_libs)} native (.so) library file(s) — harder to statically inspect",
                    risk_points=10,
                ))
        except Exception:
            pass

    # Dynamic code loading is a strong indicator of runtime payload fetching
    if any("dexclassloader" in s or "pathclassloader" in s for s in joined_lower_sample):
        indicators.append(DynamicIndicator(
            indicator="dynamic_code_loading",
            description="App can load additional code at runtime (common malware payload-drop technique)",
            risk_points=30,
        ))

    # Accessibility service abuse (overlay/keylogging malware pattern)
    permissions = apk_info.get("permissions", [])
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions and \
       "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        indicators.append(DynamicIndicator(
            indicator="overlay_accessibility_combo",
            description="Requests both accessibility service and overlay permissions — classic banking-trojan pattern for credential/OTP interception",
            risk_points=35,
        ))

    # Overlay + SMS read/receive, without needing accessibility service —
    # this is the classic OTP-stealing overlay malware combo (fake login
    # screen drawn over a real app, then reads the incoming OTP SMS).
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
    has_sms_read = any(p in permissions for p in (
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    ))
    if has_overlay and has_sms_read:
        indicators.append(DynamicIndicator(
            indicator="overlay_sms_combo",
            description="Requests both overlay (draw-over-other-apps) and SMS-read permissions — matches the OTP-interception pattern used by banking trojans",
            risk_points=40,
        ))

    # High-entropy / base64-like blobs — possible encrypted payload or C2 config
    b64_like = [s for s in raw_strings if re.fullmatch(r"[A-Za-z0-9+/]{40,}={0,2}", s)]
    if len(b64_like) > 5:
        indicators.append(DynamicIndicator(
            indicator="encoded_payload_blobs",
            description=f"{len(b64_like)} long base64-like string(s) found — possible encrypted/obfuscated payload",
            risk_points=15,
        ))

    return indicators


# ---------------------------------------------------------------------------
# Deep decompilation — pulls real pseudocode for methods that use dangerous
# APIs, so GenAI interprets actual code logic instead of just string
# patterns. This is a heavier pass (full DEX analysis via AnalyzeAPK) than
# the lightweight zip/string scan above, so it's wrapped in a time budget
# and try/except: if it's too slow or fails, analysis still proceeds fine
# without it — this is a bonus signal, not a required one.
# ---------------------------------------------------------------------------

DECOMPILE_KEYWORDS = [
    "reflect", "DexClassLoader", "PathClassLoader",
    "Runtime;->exec", "ProcessBuilder", "SmsManager",
]

# Common library code (support libs, Kotlin runtime, popular networking
# libs) frequently uses reflection internally — that's not evidence of
# anything in the app the user is being asked to trust. Skip it so the
# decompiled evidence actually reflects the app's own suspicious code.
LIBRARY_PACKAGE_PREFIXES = (
    "Landroid/", "Landroidx/", "Lcom/google/", "Lkotlin/", "Lkotlinx/",
    "Lokhttp3/", "Lretrofit2/", "Lcom/squareup/", "Ljava/", "Ljavax/",
    "Lcom/android/tools/",  # R8/desugar build-tool synthetic helpers
)


def find_and_decompile_suspicious_methods(
    apk_path: str, max_methods: int = 3, time_budget_seconds: float = 8.0,
) -> list[dict]:
    import time

    try:
        from androguard.misc import AnalyzeAPK
        apk, dex, dx = AnalyzeAPK(apk_path)
    except Exception:
        return []

    start = time.time()  # budget only covers the method-scanning loop below,
                          # not the AnalyzeAPK call above (which can itself
                          # take several seconds on larger APKs)

    results = []
    seen = set()
    try:
        for method in dx.get_methods():
            if time.time() - start > time_budget_seconds or len(results) >= max_methods:
                break

            m = method.get_method()
            class_name = str(m.get_class_name())
            method_key = (class_name, m.get_name())
            if class_name.startswith(LIBRARY_PACKAGE_PREFIXES) or method_key in seen:
                continue

            try:
                import io
                import contextlib
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    m.source()  # this prints pseudocode to stdout; it does not return it
                src = re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())  # strip ANSI color codes
            except Exception:
                continue
            if not src or not any(kw in src for kw in DECOMPILE_KEYWORDS):
                continue

            results.append({
                "class_name": class_name,
                "method_name": m.get_name(),
                "source": src[:1200],  # cap per-method size to keep the prompt reasonable
            })
            seen.add(method_key)
    except Exception:
        pass  # best-effort — return whatever we found before any failure

    return results


# ---------------------------------------------------------------------------
# GenAI layer
# ---------------------------------------------------------------------------

def build_ai_prompt(package_name, app_name, perm_findings, api_findings,
                     dyn_indicators, urls, decompiled_methods=None) -> str:
    findings_json = json.dumps({
        "package_name": package_name,
        "app_name": app_name,
        "dangerous_permissions": [f.model_dump() for f in perm_findings],
        "suspicious_api_usage": [f.model_dump() for f in api_findings],
        "dynamic_behavior_indicators": [d.model_dump() for d in dyn_indicators],
        "embedded_urls": list(urls)[:20],
    }, indent=2)

    code_section = ""
    if decompiled_methods:
        snippets = "\n\n".join(
            f"// {d['class_name']} -> {d['method_name']}\n{d['source']}"
            for d in decompiled_methods
        )
        code_section = f"""

The following is REAL decompiled pseudocode from methods in this APK that use \
suspicious APIs (reflection, dynamic class loading, SMS access, or shell \
execution). Interpret what this code actually does, not just that it exists:

{snippets}
"""

    return f"""You are a mobile malware analyst. Below are static and simulated-dynamic \
analysis findings extracted from an Android APK. Based ONLY on this data:

1. Classify overall severity as one of: LOW, MEDIUM, HIGH, CRITICAL
2. Give a risk score from 0-100 (integer)
3. Write a 3-5 sentence plain-language summary of what this app appears to do \
and why it is or isn't concerning, for a non-technical bank fraud analyst
4. List up to 5 concrete recommendations (e.g. "block installation", \
"quarantine and manual review", "safe to allow")

Findings:
{findings_json}
{code_section}
Respond ONLY with valid JSON in this exact shape, no other text:
{{"severity": "...", "risk_score": 0, "summary": "...", "recommendations": ["...", "..."]}}
"""


def _extract_json_object(text: str) -> dict:
    """Pull the first JSON object out of a model reply, tolerating code
    fences or a stray sentence before/after it."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


# ---------------------------------------------------------------------------
# GenAI providers — failover chain across every configured API key.
#
# Order (default): anthropic, anthropic-2, openai, deepseek, gemini.
# A provider is only used if its key is set. If one fails for ANY reason
# (rate limit, out of credit, bad key, outage, garbage reply) the next one
# is tried immediately, so one dead key never takes down scanning.
#
# Env vars:
#   ANTHROPIC_API_KEY, ANTHROPIC_API_KEY_2, OPENAI_API_KEY,
#   DEEPSEEK_API_KEY, GOOGLE_API_KEY            -> the keys
#   ANTHROPIC_MODEL, OPENAI_MODEL, DEEPSEEK_MODEL, GEMINI_MODEL
#                                                -> override model names
#   GENAI_PROVIDER_ORDER=deepseek,anthropic      -> custom order; providers
#                                                   not listed are skipped
#
# Plain HTTPS via `requests` (already a dependency) — no vendor SDKs.
# ---------------------------------------------------------------------------

class ProviderError(Exception):
    def __init__(self, message: str, status: int | None = None, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after

    @property
    def retryable(self) -> bool:
        # Network trouble (no status) and rate-limit/overload/5xx are worth
        # retrying when there's no other provider to fall back to.
        return self.status is None or self.status in (408, 429, 500, 502, 503, 504, 529)


def _post_json(url: str, headers: dict, body: dict, timeout=(5, 60)) -> dict:
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise ProviderError(f"network error ({type(e).__name__})") from None

    if resp.status_code >= 400:
        try:
            detail = resp.json()
            detail = detail.get("error", detail) if isinstance(detail, dict) else detail
            if isinstance(detail, dict):
                detail = detail.get("message", detail)
        except ValueError:
            detail = resp.text
        retry_after = None
        try:
            retry_after = int(float(resp.headers.get("retry-after")))
        except (TypeError, ValueError):
            pass
        raise ProviderError(f"HTTP {resp.status_code}: {str(detail)[:200]}", resp.status_code, retry_after)

    try:
        return resp.json()
    except ValueError:
        raise ProviderError("provider returned a non-JSON response", resp.status_code) from None


def _call_anthropic(api_key: str, model: str, prompt: str) -> str:
    data = _post_json(
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        {"model": model, "max_tokens": 1000, "messages": [{"role": "user", "content": prompt}]},
    )
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def _call_openai_compatible(base_url: str, api_key: str, model: str, prompt: str, extra: dict | None = None) -> str:
    body = {"model": model, "messages": [{"role": "user", "content": prompt}]}
    if extra:
        body.update(extra)
    data = _post_json(
        f"{base_url}/chat/completions",
        {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        body,
    )
    return data["choices"][0]["message"]["content"] or ""


def _call_openai(api_key: str, model: str, prompt: str) -> str:
    return _call_openai_compatible("https://api.openai.com/v1", api_key, model, prompt)


def _call_deepseek(api_key: str, model: str, prompt: str) -> str:
    # Non-thinking mode: we want a fast, direct JSON answer, not a long
    # chain of thought.
    return _call_openai_compatible(
        "https://api.deepseek.com", api_key, model, prompt,
        extra={"thinking": {"type": "disabled"}},
    )


def _call_groq(api_key: str, model: str, prompt: str) -> str:
    return _call_openai_compatible(
        "https://api.groq.com/openai/v1", api_key, model, prompt,
        extra={"response_format": {"type": "json_object"}},
    )


def _call_gemini(api_key: str, model: str, prompt: str) -> str:
    # Key goes in a header, not the URL, so it can't leak into logs/errors.
    data = _post_json(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        {"x-goog-api-key": api_key, "Content-Type": "application/json"},
        {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        },
    )
    parts = data["candidates"][0]["content"]["parts"]
    return "".join(p.get("text", "") for p in parts)


def _clean_key(value: str | None) -> str:
    # Windows `set KEY="abc"` stores the quotes literally — strip them.
    return (value or "").strip().strip('"').strip("'").strip()


def _configured_providers() -> list[dict]:
    env = os.environ.get
    anthropic_model = env("ANTHROPIC_MODEL", "claude-sonnet-5")
    groq_model = env("GROQ_MODEL", "openai/gpt-oss-120b")

    providers = []

    # Groq supports multiple keys in one go: GROQ_API_KEYS="key1,key2,...".
    # Handy when you have many keys (e.g. free-tier accounts) and don't want
    # to type ten separate `set` commands. A single GROQ_API_KEY also works.
    groq_keys = [_clean_key(k) for k in (env("GROQ_API_KEYS") or "").split(",") if _clean_key(k)]
    single = _clean_key(env("GROQ_API_KEY"))
    if single and single not in groq_keys:
        groq_keys.insert(0, single)
    for i, key in enumerate(groq_keys, start=1):
        name = "groq" if len(groq_keys) == 1 else f"groq-{i}"
        providers.append({
            "name": name, "model": groq_model, "label": f"{name}/{groq_model}",
            "call": partial(_call_groq, key, groq_model),
        })

    # Groq goes first by default since it's the freshest/most-likely-to-work
    # set of keys; the rest follow as a fallback chain. Override any of this
    # with GENAI_PROVIDER_ORDER.
    candidates = [
        ("anthropic", "ANTHROPIC_API_KEY", anthropic_model, _call_anthropic),
        ("anthropic-2", "ANTHROPIC_API_KEY_2", anthropic_model, _call_anthropic),
        ("openai", "OPENAI_API_KEY", env("OPENAI_MODEL", "gpt-5.4-mini"), _call_openai),
        ("deepseek", "DEEPSEEK_API_KEY", env("DEEPSEEK_MODEL", "deepseek-v4-flash"), _call_deepseek),
        ("gemini", "GOOGLE_API_KEY", env("GEMINI_MODEL", "gemini-3.8-flash"), _call_gemini),
    ]
    for name, key_var, model, fn in candidates:
        key = _clean_key(env(key_var))
        if key:
            providers.append({
                "name": name, "model": model, "label": f"{name}/{model}",
                "call": partial(fn, key, model),
            })

    order = [s.strip() for s in (env("GENAI_PROVIDER_ORDER") or "").split(",") if s.strip()]
    if order:
        by_name = {p["name"]: p for p in providers}
        providers = [by_name[n] for n in order if n in by_name]

    return providers


def _validate_analysis(obj: dict) -> dict:
    """Different models format things slightly differently — normalize, and
    raise (so we fail over) if the reply is missing the essentials."""
    obj["risk_score"] = max(0.0, min(100.0, float(obj["risk_score"])))
    obj["summary"] = str(obj.get("summary", "")).strip() or "No summary returned."
    recs = obj.get("recommendations", [])
    obj["recommendations"] = [str(r) for r in recs][:5] if isinstance(recs, list) else []
    return obj


def call_genai_analysis(prompt: str, max_retries: int = 2) -> dict | None:
    providers = _configured_providers()
    if not providers:
        return None

    import time

    # With several providers, fail over immediately (no sleeping). With only
    # one, there's nothing to fall back to, so retry rate limits with backoff.
    sole_provider = len(providers) == 1
    errors = []

    for p in providers:
        attempts = (max_retries + 1) if sole_provider else 1
        for attempt in range(attempts):
            try:
                result = _validate_analysis(_extract_json_object(p["call"](prompt)))
                result["_provider"] = p["label"]
                return result
            except ProviderError as e:
                if sole_provider and e.retryable and attempt < attempts - 1:
                    wait = (e.retry_after + 1) if e.retry_after else 5 * (attempt + 1)
                    time.sleep(min(wait, 30))
                    continue
                errors.append(f"{p['name']}: {e}")
                break
            except Exception as e:
                errors.append(f"{p['name']}: unusable reply ({type(e).__name__})")
                break

    return {"error": " | ".join(errors)}


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------

def verdict_for(score: float) -> str:
    if score >= 65:
        return "DANGEROUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post("/analyze", response_model=ApkAnalysisResponse)
async def analyze_apk(
    file: UploadFile = File(...),
    force_rescan: bool = Query(False, description="Skip cache and re-run full analysis"),
    db: Session = Depends(get_db),
):
    contents = await file.read()
    return await _analyze_apk_contents(file.filename, contents, force_rescan, db)


async def _analyze_apk_contents(
    filename: str, contents: bytes, force_rescan: bool, db: Session,
) -> ApkAnalysisResponse:
    """Core single-APK analysis pipeline. Shared by the single-file /analyze
    route and the /analyze/batch route so both stay in lockstep — one
    scoring/caching/blocklist implementation, not two copies to keep in sync.
    """
    if not filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be a .apk")

    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(contents) > 150 * 1024 * 1024:  # 150MB safety cap
        raise HTTPException(status_code=400, detail="APK too large (150MB limit)")

    sha256 = hashlib.sha256(contents).hexdigest()

    # Dedup: if we've already fully analyzed this exact APK before (by
    # content hash, not filename), return the cached verdict instead of
    # re-running static+dynamic+GenAI analysis. Bump scan_count so history
    # reflects how often this file has been submitted.
    existing = db.query(ApkScanRecord).filter(ApkScanRecord.sha256 == sha256).first()
    if existing and not force_rescan:
        existing.scan_count += 1
        existing.last_analyzed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing)
        cached = record_to_dict(existing)

        blocklist_entry = db.query(KnownMalwareHash).filter(KnownMalwareHash.sha256 == sha256).first()
        cached_blocklist_match = None
        if blocklist_entry:
            cached_blocklist_match = {
                "label": blocklist_entry.label,
                "source": blocklist_entry.source,
                "added_at": blocklist_entry.added_at.isoformat() if blocklist_entry.added_at else None,
            }

        return ApkAnalysisResponse(
            filename=filename,
            sha256=cached["sha256"],
            package_name=cached["package_name"],
            app_name=cached["app_name"],
            static_score=cached["static_score"],
            dynamic_score=cached["dynamic_score"],
            ai_score=cached["ai_score"],
            risk_score=cached["risk_score"],
            verdict=cached["verdict"],
            permissions_found=cached["permissions_found"],
            suspicious_apis=cached["suspicious_apis"],
            dynamic_indicators=cached["dynamic_indicators"],
            embedded_urls=cached["embedded_urls"],
            ai_summary=cached["ai_summary"],
            recommendations=cached["recommendations"],
            analyzed_at=cached["last_analyzed_at"],
            from_cache=True,
            scan_count=cached["scan_count"],
            blocklist_match=cached_blocklist_match,
        )

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        try:
            static_info = run_static_analysis(tmp_path)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Could not parse APK: {e}")

        raw_strings, urls = extract_strings_and_urls(tmp_path)
        api_findings = find_dangerous_apis(raw_strings)
        dyn_indicators = extract_dynamic_indicators(raw_strings, static_info)
        url_score, url_reasons = score_embedded_urls(urls)

        static_score = static_info["static_score"]
        api_score = min(sum(f.risk_points for f in api_findings), 100.0)
        dynamic_score = min(sum(d.risk_points for d in dyn_indicators) + url_score, 100.0)

        # Only run the heavier decompile pass when the cheap string scan
        # already found something worth investigating further — keeps
        # clean APKs fast while giving GenAI real code for the ones that
        # actually need deeper scrutiny.
        decompiled_methods = []
        if api_findings:
            decompiled_methods = find_and_decompile_suspicious_methods(tmp_path)

        prompt = build_ai_prompt(
            static_info["package_name"], static_info["app_name"],
            static_info["perm_findings"], api_findings, dyn_indicators, urls,
            decompiled_methods=decompiled_methods,
        )
        ai_result = call_genai_analysis(prompt)

        ai_score = None
        ai_provider = None
        ai_summary = "GenAI analysis unavailable (no GenAI API key configured)."
        recommendations = []

        if ai_result and "error" not in ai_result:
            ai_score = float(ai_result.get("risk_score", 0))
            ai_summary = ai_result.get("summary", "")
            recommendations = ai_result.get("recommendations", [])
            ai_provider = ai_result.get("_provider")
        elif ai_result and "error" in ai_result:
            ai_summary = f"GenAI analysis failed: {ai_result['error']}"

        # Composite: blend static+API findings, dynamic indicators (which now
        # include the suspicious-URL score), and the GenAI severity
        # assessment. GenAI gets real weight but never solely decides —
        # static/dynamic evidence anchors the score.
        #
        # A plain weighted average lets one strong, well-corroborated signal
        # (e.g. unsigned APK + overlay/SMS permission combo = classic OTP-
        # stealing malware pattern) get washed out just because *other*
        # channels found nothing to add — "no additional evidence" should
        # not lower confidence in evidence already found. So the final score
        # is the max of the blended average and a discounted version of the
        # single strongest component, the same fix applied to the URL scanner.
        components = [(static_score, 0.30), (api_score, 0.20), (dynamic_score, 0.25)]
        if ai_score is not None:
            components.append((ai_score, 0.25))

        weight_sum = sum(w for _, w in components)
        weighted_average = sum(s * w for s, w in components) / weight_sum
        strongest_component = max(s for s, _ in components)

        # Only boost when one channel is strongly, independently alarming
        # (>=55) — a handful of moderately-risky permissions summing to
        # ~45-50 on their own isn't corroborated evidence of anything, and
        # shouldn't get amplified the way a genuinely high single signal
        # (e.g. unsigned + overlay/SMS combo) should.
        if strongest_component >= 55:
            risk_score = max(weighted_average, 0.85 * strongest_component)
        else:
            risk_score = weighted_average
        risk_score = round(min(risk_score, 100.0), 2)

        # Blocklist check: an exact-hash match against known malware is
        # ground truth and overrides the heuristic/GenAI score entirely —
        # no point averaging "definitely known malware" with anything else.
        blocklist_entry = db.query(KnownMalwareHash).filter(KnownMalwareHash.sha256 == sha256).first()
        blocklist_match = None
        if blocklist_entry:
            risk_score = 100.0
            blocklist_match = {
                "label": blocklist_entry.label,
                "source": blocklist_entry.source,
                "added_at": blocklist_entry.added_at.isoformat() if blocklist_entry.added_at else None,
            }

        final_verdict = verdict_for(risk_score)

        if not recommendations:
            if risk_score >= 65:
                recommendations = ["Block installation", "Quarantine and escalate for manual review"]
            elif risk_score >= 30:
                recommendations = ["Warn user before allowing install", "Log for periodic review"]
            else:
                recommendations = ["No action needed"]

        # Self-teaching blocklist: any time our own analysis independently
        # reaches DANGEROUS, remember this exact hash going forward — future
        # submissions of the identical file get flagged immediately, fully
        # offline, no external threat-intel service required.
        if final_verdict == "DANGEROUS" and not blocklist_entry:
            top_signal = (
                dyn_indicators[0].description if dyn_indicators
                else (api_findings[0].description if api_findings else "Multiple risk indicators")
            )
            db.add(KnownMalwareHash(
                sha256=sha256,
                label=f"Auto-detected: {top_signal}",
                source="shieldnetx_detection",
            ))
            db.commit()

        now = datetime.now(timezone.utc)
        permissions_json = json.dumps([f.model_dump() for f in static_info["perm_findings"]])
        apis_json = json.dumps([f.model_dump() for f in api_findings])
        dynamic_json = json.dumps([d.model_dump() for d in dyn_indicators])
        urls_json = json.dumps(list(urls)[:20])
        recs_json = json.dumps(recommendations)

        if existing:  # force_rescan path — overwrite with fresh analysis
            existing.filename = filename
            existing.package_name = static_info["package_name"]
            existing.app_name = static_info["app_name"]
            existing.static_score = round(static_score, 2)
            existing.dynamic_score = round(dynamic_score, 2)
            existing.ai_score = ai_score
            existing.risk_score = risk_score
            existing.verdict = final_verdict
            existing.permissions_found_json = permissions_json
            existing.suspicious_apis_json = apis_json
            existing.dynamic_indicators_json = dynamic_json
            existing.embedded_urls_json = urls_json
            existing.recommendations_json = recs_json
            existing.ai_summary = ai_summary
            existing.last_analyzed_at = now
            existing.scan_count += 1
            db.commit()
            scan_count = existing.scan_count
        else:
            record = ApkScanRecord(
                sha256=sha256,
                filename=filename,
                package_name=static_info["package_name"],
                app_name=static_info["app_name"],
                static_score=round(static_score, 2),
                dynamic_score=round(dynamic_score, 2),
                ai_score=ai_score,
                risk_score=risk_score,
                verdict=final_verdict,
                permissions_found_json=permissions_json,
                suspicious_apis_json=apis_json,
                dynamic_indicators_json=dynamic_json,
                embedded_urls_json=urls_json,
                recommendations_json=recs_json,
                ai_summary=ai_summary,
                first_analyzed_at=now,
                last_analyzed_at=now,
                scan_count=1,
            )
            db.add(record)
            db.commit()
            scan_count = 1

        return ApkAnalysisResponse(
            filename=filename,
            sha256=sha256,
            package_name=static_info["package_name"],
            app_name=static_info["app_name"],
            static_score=round(static_score, 2),
            dynamic_score=round(dynamic_score, 2),
            ai_score=ai_score,
            risk_score=risk_score,
            verdict=final_verdict,
            permissions_found=static_info["perm_findings"],
            suspicious_apis=api_findings,
            dynamic_indicators=dyn_indicators,
            embedded_urls=list(urls)[:20],
            ai_summary=ai_summary,
            recommendations=recommendations,
            analyzed_at=now.isoformat(),
            from_cache=False,
            scan_count=scan_count,
            blocklist_match=blocklist_match,
            methods_analyzed=[f"{d['class_name']}->{d['method_name']}" for d in decompiled_methods],
            ai_provider=ai_provider,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


class BatchAnalysisItem(BaseModel):
    filename: str
    success: bool
    result: ApkAnalysisResponse | None = None
    error: str | None = None


class BatchAnalysisResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    results: list[BatchAnalysisItem]


@router.post("/analyze/batch", response_model=BatchAnalysisResponse)
async def analyze_apk_batch(
    files: list[UploadFile] = File(...),
    force_rescan: bool = Query(False, description="Skip cache and re-run full analysis for every file"),
    db: Session = Depends(get_db),
):
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    if len(files) > 20:
        raise HTTPException(status_code=400, detail="Batch limit is 20 files per request")

    items: list[BatchAnalysisItem] = []
    for f in files:
        try:
            contents = await f.read()
            result = await _analyze_apk_contents(f.filename, contents, force_rescan, db)
            items.append(BatchAnalysisItem(filename=f.filename, success=True, result=result))
        except HTTPException as e:
            # One bad file (wrong extension, empty, too large, unparseable)
            # shouldn't fail the whole batch — record it and keep going.
            items.append(BatchAnalysisItem(filename=f.filename, success=False, error=str(e.detail)))
        except Exception as e:
            items.append(BatchAnalysisItem(filename=f.filename, success=False, error=str(e)))

    succeeded = sum(1 for i in items if i.success)
    return BatchAnalysisResponse(
        total=len(items), succeeded=succeeded, failed=len(items) - succeeded, results=items,
    )


# ---------------------------------------------------------------------------
# History endpoints
# ---------------------------------------------------------------------------

@router.get("/genai/status")
def genai_status():
    """Which GenAI providers are configured, in the order they'll be tried.
    Makes no API calls and never returns key values."""
    providers = _configured_providers()
    return {
        "count": len(providers),
        "order": [{"name": p["name"], "model": p["model"]} for p in providers],
    }


@router.get("/genai/test")
def genai_test():
    """Sends a tiny test prompt to EACH configured provider separately, so
    you can see which of your keys actually work. Costs a few tokens per
    provider — remove or protect this route before making the API public."""
    import time

    results = []
    for p in _configured_providers():
        start = time.time()
        try:
            _extract_json_object(p["call"]('Reply with only this JSON and nothing else: {"ok": true}'))
            results.append({"provider": p["label"], "ok": True, "seconds": round(time.time() - start, 2)})
        except Exception as e:
            results.append({
                "provider": p["label"], "ok": False,
                "error": str(e)[:200], "seconds": round(time.time() - start, 2),
            })
    return {"results": results}


@router.get("/history", response_model=list[ApkHistoryEntry])
def get_history(
    limit: int = Query(50, le=200),
    verdict: str | None = Query(None, description="Filter by SAFE/SUSPICIOUS/DANGEROUS"),
    db: Session = Depends(get_db),
):
    q = db.query(ApkScanRecord)
    if verdict:
        q = q.filter(ApkScanRecord.verdict == verdict.upper())
    records = q.order_by(desc(ApkScanRecord.last_analyzed_at)).limit(limit).all()
    return [
        ApkHistoryEntry(
            sha256=r.sha256,
            filename=r.filename,
            package_name=r.package_name,
            app_name=r.app_name,
            risk_score=r.risk_score,
            verdict=r.verdict,
            first_analyzed_at=r.first_analyzed_at.isoformat() if r.first_analyzed_at else None,
            last_analyzed_at=r.last_analyzed_at.isoformat() if r.last_analyzed_at else None,
            scan_count=r.scan_count,
        )
        for r in records
    ]


@router.get("/history/{sha256}")
def get_history_entry(sha256: str, db: Session = Depends(get_db)):
    record = db.query(ApkScanRecord).filter(ApkScanRecord.sha256 == sha256).first()
    if not record:
        raise HTTPException(status_code=404, detail="No scan found for this hash")
    return record_to_dict(record)


@router.get("/report/{sha256}")
def download_apk_report(sha256: str, db: Session = Depends(get_db)):
    record = db.query(ApkScanRecord).filter(ApkScanRecord.sha256 == sha256).first()
    if not record:
        raise HTTPException(status_code=404, detail="No scan found for this hash")

    record_dict = record_to_dict(record)

    blocklist_entry = db.query(KnownMalwareHash).filter(KnownMalwareHash.sha256 == sha256).first()
    if blocklist_entry:
        record_dict["blocklist_match"] = {
            "label": blocklist_entry.label,
            "source": blocklist_entry.source,
            "added_at": blocklist_entry.added_at.isoformat() if blocklist_entry.added_at else None,
        }

    try:
        pdf_bytes = generate_apk_report_pdf(record_dict)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {e}")

    filename = f"ShieldNetX_Report_{sha256[:12]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Blocklist management (self-contained threat-intel list)
# ---------------------------------------------------------------------------

class BlocklistEntry(BaseModel):
    sha256: str
    label: str


@router.post("/blocklist")
def add_to_blocklist(entry: BlocklistEntry, db: Session = Depends(get_db)):
    sha = entry.sha256.strip().lower()
    if len(sha) != 64:
        raise HTTPException(status_code=400, detail="sha256 must be a 64-character hex string")

    existing = db.query(KnownMalwareHash).filter(KnownMalwareHash.sha256 == sha).first()
    if existing:
        existing.label = entry.label
        db.commit()
        return {"status": "updated", "sha256": sha}

    db.add(KnownMalwareHash(sha256=sha, label=entry.label, source="manual"))
    db.commit()
    return {"status": "added", "sha256": sha}


@router.get("/blocklist")
def list_blocklist(limit: int = Query(100, le=500), db: Session = Depends(get_db)):
    rows = db.query(KnownMalwareHash).order_by(desc(KnownMalwareHash.added_at)).limit(limit).all()
    return [
        {"sha256": r.sha256, "label": r.label, "source": r.source,
         "added_at": r.added_at.isoformat() if r.added_at else None}
        for r in rows
    ]


@router.delete("/blocklist/{sha256}")
def remove_from_blocklist(sha256: str, db: Session = Depends(get_db)):
    row = db.query(KnownMalwareHash).filter(KnownMalwareHash.sha256 == sha256).first()
    if not row:
        raise HTTPException(status_code=404, detail="Hash not found in blocklist")
    db.delete(row)
    db.commit()
    return {"status": "removed", "sha256": sha256}
