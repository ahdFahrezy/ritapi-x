# utils/waf_patterns.py
import re
import html
import logging
from decision_engine.metrics import REQUESTS_TOTAL
from utils.logging import log_request
from django.http import JsonResponse

logger = logging.getLogger(__name__)

# === Pattern definitions ===
XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script.*?>.*?<\s*/\s*script\s*>"),
    re.compile(r"(?i)on\w+\s*="),
    re.compile(r"(?i)javascript:"),
    re.compile(r"(?i)<iframe"),
    re.compile(r"(?i)<img\s+.*?onerror\s*="),
]

SQLI_PATTERNS = [
    re.compile(r"(?i)(union\s+select\s+)"),
    re.compile(r"(?i)(or\s+1=1)"),
    re.compile(r"(?i)(--|#)\s*\w*"),
    re.compile(r"(?i)(sleep\s*\()"),
    re.compile(r"(?i)(drop\s+table)"),
]

CMDI_PATTERNS = [
    re.compile(r"(\||&&|;|`|\$\(.*\))"),
    re.compile(r"(?i)(wget|curl|nc|bash|sh\s+-c)"),
]


# === Utility ===
def normalize_input(data: str) -> str:
    data = html.unescape(data or "")
    data = data.replace("\\", "")
    data = data.replace("%20", " ")
    return data.strip()


def detect_attack_patterns(payload_dict):
    """Return tuple (is_bad, category, match_snippet)"""
    for key, value in payload_dict.items():
        if value is None:
            continue
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception:
                continue

        normalized = normalize_input(value)

        for p in XSS_PATTERNS:
            if m := p.search(normalized):
                return True, "XSS", normalized[max(0, m.start() - 40): m.end() + 40]

        for p in SQLI_PATTERNS:
            if m := p.search(normalized):
                return True, "SQLI", normalized[max(0, m.start() - 40): m.end() + 40]

        for p in CMDI_PATTERNS:
            if m := p.search(normalized):
                return True, "CMDI", normalized[max(0, m.start() - 40): m.end() + 40]

    return False, None, None


def waf_inspect_request(payload):
    """Return (response_or_none, category, match_snippet)"""
    try:
        is_bad, category, match = detect_attack_patterns(payload)
        if is_bad:
            logger.warning(f"{category.upper()} pattern detected: {match[:120]}")
            return (
                JsonResponse(
                    {
                        "error": f"Blocked by (RITAPI)",
                        "detail": f"Malicious pattern detected ({category})",
                    },
                    status=403,
                ),
                category,
                match,
            )
    except Exception:
        logger.exception("check failed")
    return None, None, None


def log_waf_block(client_ip, path, method, body, category ,service_id=None):
    """Centralized WAF logging + metrics only"""
    # metrics
    try:
        REQUESTS_TOTAL.labels(decision="block", reason=f"waf_{category}").inc()
    except Exception:
        try:
            REQUESTS_TOTAL.labels(decision="block").inc()
        except Exception:
            pass

    # structured log
    try:
        log_request(
            ip=client_ip,
            path=path,
            method=method,
            size=len(body),
            score=0,
            decision="block",
            reason=f"{category}",
            service_id=service_id,
        )
    except Exception:
        logger.warning("failed to log request", exc_info=True)
