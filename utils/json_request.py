import json
import unicodedata
import logging
from django.http import JsonResponse
from decision_engine.metrics import REQUESTS_TOTAL
from utils.logging import log_request

logger = logging.getLogger(__name__)

EXCLUDED_PATHS = [
    "/admin/",
    "/login/",
    "/logout/",
    "/static/",
    "/ops/",
]

def enforce_json_request(request, enforce_ct=True, max_body=2 * 1024 * 1024):
    """
    Validasi request JSON.
    - Enforce Content-Type
    - Limit body size
    - Decode UTF-8 + normalize
    - Parse JSON ke request.json
    - Skip untuk path non-API (admin, login, static, dll.)
    """
    # Skip enforcement untuk path tertentu
    if any(request.path.startswith(p) for p in EXCLUDED_PATHS):
        request.json = None
        return None

    # --- common variables for logging ---
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    client_ip = xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR", "")
    path = request.path
    body = getattr(request, "body", b"") or b""

    if request.method in ["POST", "PUT", "PATCH"]:
        # 1. Enforce Content-Type JSON
        if enforce_ct:
            ct = request.META.get("CONTENT_TYPE", "").split(";")[0].strip()
            if ct != "application/json":
                logger.warning(f"Blocked: invalid Content-Type {ct}")
                REQUESTS_TOTAL.labels(decision="block").inc()
                try:
                    log_request(
                        ip=client_ip,
                        path=path,
                        method=request.method,
                        size=len(body),
                        score=0,
                        decision="block",
                        reason="INVALID_CONTENT_TYPE",
                        service_id=None,
                    )
                except Exception:
                    logger.exception("log_request failed")
                return JsonResponse(
                    {"error": "Unsupported Content-Type. Use application/json."},
                    status=415
                )

        # 2. Body size limit
        content_length = request.META.get("CONTENT_LENGTH")
        if content_length:
            try:
                content_length = int(content_length)
            except ValueError:
                content_length = 0

            if content_length > max_body:
                logger.warning(f"Blocked: content length too large ({content_length} bytes)")
                REQUESTS_TOTAL.labels(decision="block").inc()
                try:
                    log_request(
                        ip=client_ip,
                        path=path,
                        method=request.method,
                        size=content_length,
                        score=0,
                        decision="block",
                        reason="body_too_large",
                        service_id=None,    
                    )
                except Exception:
                    logger.exception("log_request failed")
                return JsonResponse(
                    {"error": "Request body too large."}, status=413
                )

        # 3. Parse JSON safely
        if request.body:
            try:
                raw_body = request.body.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("Blocked: invalid UTF-8 encoding")
                REQUESTS_TOTAL.labels(decision="block").inc()
                try:
                    log_request(
                        ip=client_ip,
                        path=path,
                        method=request.method,
                        size=len(body),
                        score=0,
                        decision="block",
                        reason="invalid_encoding",
                        service_id=None,
                    )
                except Exception:
                    logger.exception("log_request failed")
                return JsonResponse(
                    {"error": "Invalid encoding. Expect UTF-8."}, status=400
                )

            normalized_body = unicodedata.normalize("NFC", raw_body)

            try:
                request.json = json.loads(normalized_body)
            except json.JSONDecodeError:
                logger.warning("Blocked: malformed JSON body")
                REQUESTS_TOTAL.labels(decision="block").inc()
                try:
                    log_request(
                        ip=client_ip,
                        path=path,
                        method=request.method,
                        size=len(body),
                        score=0,
                        decision="block",
                        reason="malformed_json",
                        service_id=None,
                    )
                except Exception:
                    logger.exception("log_request failed")
                return JsonResponse(
                    {"error": "Malformed JSON body."}, status=400
                )
        else:
            request.json = {}
    else:
        # GET / DELETE / HEAD → no body
        request.json = None

    return None
