import logging
import json
import time
from django.utils import timezone
import hashlib
import base64
import requests
import os
from django.http import JsonResponse, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from utils.ip import get_client_ip
from utils.redis_client import RedisClientSingleton
from utils.security_cache import (
    get_cached_service, set_cached_service,
    get_cached_allowed_services, set_cached_allowed_services,
    get_cached_tls_with_expiry, get_cached_asn_with_expiry
)
from tasks.security_refresh import refresh_asn, refresh_tls
from utils.json_request import enforce_json_request
from utils.hmac_routing import (
    validate_routing_signature,
    MissingRoutingSecret,
    InvalidSignature,
)
from utils.logging import log_request
from decision_engine.metrics import (
    REQUESTS_TOTAL,
    CACHE_HIT,
    CACHE_MISS,
    HMAC_USED_TOTAL,
    GEO_BLOCK_TOTAL,
    REQUEST_SUCCESS_TOTAL,
    REQUEST_FAIL_TOTAL
)
from utils.hmac_validation import (
    check_required_routing_headers,
    validate_uuid_format,
    validate_timestamp_skew,
)
from utils.cache_key import build_cache_key
from utils.proxy_forward import forward_request_to_backend
from utils.risk_scoring import calculate_risk_score, decide_action
from utils.tls_check import check_tls_validity
from utils.asn_check import get_asn_trust_score
from utils.ip_reputation import handle_ip_reputation
from utils.routing_hardening import validate_service_routing
from utils.json_schema import validate_payload_for_service
from utils.waf_patterns import waf_inspect_request, log_waf_block 
from utils.geo_block import check_geo_block
from utils.severity import determine_severity

# Import Service model for dynamic backend routing
try:
    from ops.ops_services.models import Service
except ImportError:
    Service = None

CACHE_TTL = getattr(settings, "BACKEND_RESPONSE_CACHE_TTL", int(os.getenv("BACKEND_RESPONSE_CACHE_TTL", "30")))
ASN_TLS_CACHE_TTL = getattr(settings, "ASN_TLS_CACHE_TTL", int(os.getenv("ASN_TLS_CACHE_TTL", "30")))

MAX_JSON_BODY = getattr(settings, "MAX_JSON_BODY", 2 * 1024 * 1024)  # default 2 MB
ENFORCE_JSON_CT = getattr(settings, "ENFORCE_JSON_CT", True)
    
logger = logging.getLogger(__name__)


# === Safely import your 6 modules (best-effort) ===
def _safe_imports():
    mods = {}
    try:
        from tls_analyzer.services import analyze_tls_cert
        mods["analyze_tls_cert"] = analyze_tls_cert
    except Exception:
        mods["analyze_tls_cert"] = None

    try:
        from asn_score.services import AsnScoreService
        mods["lookup_asn"] = AsnScoreService.lookup_asn
    except Exception:
        mods["lookup_asn"] = None

    try:
        from ip_reputation.services import IpReputationService
        mods["ip_rep"] = IpReputationService.check_reputation
    except Exception:
        mods["ip_rep"] = None

    try:
        from json_enforcer.services import JsonEnforcerService
        mods["json_validate"] = JsonEnforcerService.validate_payload
    except Exception:
        mods["json_validate"] = None

    try:
        from ai_behaviour.services import AiProfilerService
        mods["log_req"] = AiProfilerService.log_request
        mods["is_anom"] = AiProfilerService.detect_anomaly
    except Exception:
        mods["log_req"] = None
        mods["is_anom"] = None

    try:
        from alert_blocking.services import AlertService, BlockingService
        mods["alert"] = AlertService
        mods["block"] = BlockingService
    except Exception:
        mods["alert"] = None
        mods["block"] = None

    return mods


MODULES = _safe_imports()


class DecisionProxyMiddleware(MiddlewareMixin):
    """
    Transparent reverse-proxy + decision engine.
    Intercepts ALL requests (except admin/static) and:
      - runs TLS/ASN/IPRep/JSON/Behaviour checks
      - consults blocklist
      - aggregates score, blocks or allows
      - logs to DB
      - forwards to backend if allowed
    """

    def process_request(self, request):
        
        # JSON enforcement pakai config
        resp = enforce_json_request(
            request,
            enforce_ct=ENFORCE_JSON_CT,
            max_body=MAX_JSON_BODY
        )
        if resp: 
            return resp

        path = request.get_full_path()
        cache_enabled = bool(getattr(settings, "ENABLE_BACKEND_CACHE", True))
        redis_client = RedisClientSingleton.get_client()
        if redis_client is None:
            cache_enabled = False

        
        # Skip admin, static, DRF browsable assets, etc (tweak as needed)
        if (
            path == "/"   
            or path.startswith("/admin")
            or path.startswith("/static")
            or path.startswith("/__debug__")
            or path.startswith("/login")
            or path.startswith("/accounts/login")
            or path.startswith("/ops")
            or path.startswith("/logout")
            or path.startswith("/tls")
            or path.startswith("/healthz")
            or path.startswith("/readyz")
            or path.startswith("/demo")
            or path.startswith("/ai")
            or path.startswith("/metrics")
            or path == "/favicon.ico"
            or path == "/robots.txt"  
        ):
            return None

        # Extract client IP
        # client_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "")) or ""
        client_ip = get_client_ip(request)
        body = request.body or b""
        # === GeoBlock integration ===
        if check_geo_block:
            try:
                blocked, country, reason = check_geo_block(client_ip)
                print("geo block result:", blocked, country, reason)
                if blocked:
                    print("blocking by geo block:", client_ip, country, reason)
                    REQUESTS_TOTAL.labels(decision="block").inc()
                    REQUEST_FAIL_TOTAL.labels(status="failed").inc()
                    try:
                        reason = f"GeoBlock country {country}"
                        sev = determine_severity(reason, score=0)
                        MODULES["block"].block_ip(client_ip, reason=reason, severity=sev)
                        if MODULES.get("alert"):
                            MODULES["alert"].create_alert("BLOCKED", client_ip, reason, sev)
                        GEO_BLOCK_TOTAL.labels(result="blocked").inc()
                    except Exception as e:
                        logger.warning(f"GeoBlock auto-block module failed for {client_ip}: {e}")
                        
                    logger.info(f"🌐 GeoBlock: Blocked {client_ip} from {country}")
                    log_request(
                        ip=client_ip,
                        path=path,
                        method=request.method,
                        size=len(body),
                        score=0,
                        decision="block",
                        reason = f"GEO_BLOCK_{country}",
                        service_id=None,
                        hmac_signature=None,
                        duration_ms=0
                    )
                    return JsonResponse({
                        "error": "Blocked by GeoBlock policy",
                        "country": country,
                        "ip": client_ip,
                        "reason": reason,
                    }, status=403)
            except Exception as e:
                logger.warning(f"GeoBlock check failed: {e}")
        
        # === 0) Extract x-target-id header and validate service
        valid, result = check_required_routing_headers(request)
        if not valid:
            REQUESTS_TOTAL.labels(decision="block").inc()
            REQUEST_FAIL_TOTAL.labels(status="failed").inc()
            log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision="block", reason="MISSING_REQUIRED_HEADER",)
            return result

        target_id, target_sig, target_ts = result
        
        HMAC_USED_TOTAL.labels(result="used").inc()

        # Validate UUID format
        valid, err_response = validate_uuid_format(target_id)
        if not valid:
            
            REQUEST_FAIL_TOTAL.labels(status="failed").inc()
            log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision="block", reason="Invalid target ID format")
            return err_response
   
        # Validasi timestamp
        # valid, err_response, skew = validate_timestamp_skew(target_ts)
        # if not valid:
        #     REQUESTS_TOTAL.labels(decision="block").inc()
        #     REQUEST_FAIL_TOTAL.labels(status="failed").inc()
        #     log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision="block", reason="SIGNATURE_EXPIRED" if skew else "Invalid timestamp format")
        #     return err_response

        
        # Lookup service by UUID
        if not Service:
            REQUESTS_TOTAL.labels(decision="block").inc()
            REQUEST_FAIL_TOTAL.labels(status="failed").inc()
            log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision="block", reason="Service routing is not available")
            logger.error("Service routing is not available")
            return JsonResponse({
                "error": "Service unavailable", 
                "detail": "Service routing is not available"
            }, status=503)
        
        try:
            # Get MAX_SERVICES from environment variable, default to 10
            max_services = int(os.getenv("MAX_SERVICES", "10"))

            # === Handler untuk disable cache ===
            if not getattr(settings, "ENABLE_BACKEND_CACHE", True):
                logger.warning("⚠️ Backend cache disabled, fetching service directly from DB")

                try:
                    service = Service.objects.get(uuid=target_id)
                except Service.DoesNotExist:
                    REQUESTS_TOTAL.labels(decision="block").inc()
                    REQUEST_FAIL_TOTAL.labels(status="failed").inc()
                    log_request(ip=client_ip, path=path, method=request.method, size=len(body),
                                score=0, decision="block", reason="Service not found")
                    logger.error(f"Service not found for ID: {target_id}")
                    return JsonResponse({
                        "error": "Target service not found",
                        "detail": f"No service found with ID: {target_id}"
                    }, status=404)

                # Build service_data langsung dari DB
                service_data = {
                    "id": service.id,
                    "uuid": str(service.uuid),
                    "target_base_url": service.target_base_url,
                    "routing_secret": service.routing_secret,
                    "allowed_paths": service.get_allowed_paths(),
                    "allowed_methods": service.get_allowed_methods(),
                    "allowed_schemes": service.get_allowed_schemes(),
                }

                # Ambil daftar service langsung tanpa cache
                allowed_service_ids = list(
                    Service.objects.values_list("id", flat=True).order_by("id")[:max_services]
                )

            else:
                # === Normal mode: pakai cache ===
                service_data = get_cached_service(target_id)
                if not service_data:
                    try:
                        service = Service.objects.get(uuid=target_id)
                        service_data = {
                            "id": service.id,
                            "uuid": str(service.uuid),
                            "target_base_url": service.target_base_url,
                            "routing_secret": service.routing_secret,
                            "allowed_paths": service.get_allowed_paths(),
                            "allowed_methods": service.get_allowed_methods(),
                            "allowed_schemes": service.get_allowed_schemes(),
                        }
                        set_cached_service(target_id, service_data)
                    except Service.DoesNotExist:
                        REQUESTS_TOTAL.labels(decision="block").inc()
                        REQUEST_FAIL_TOTAL.labels(status="failed").inc()
                        log_request(ip=client_ip, path=path, method=request.method, size=len(body),
                                    score=0, decision="block", reason="Service not found")
                        logger.error(f"Service not found for ID: {target_id}")
                        return JsonResponse({
                            "error": "Target service not found",
                            "detail": f"No service found with ID: {target_id}"
                        }, status=404)

                allowed_service_ids = get_cached_allowed_services(max_services)
                if not allowed_service_ids:
                    allowed_service_ids = list(
                        Service.objects.values_list("id", flat=True).order_by("id")[:max_services]
                    )
                    set_cached_allowed_services(max_services, allowed_service_ids)

            # === Cek apakah service masih dalam allowed list ===
            if service_data["id"] not in allowed_service_ids:
                REQUESTS_TOTAL.labels(decision="block").inc()
                REQUEST_FAIL_TOTAL.labels(status="failed").inc()
                log_request(ip=client_ip, path=path, method=request.method, size=len(body),
                            score=0, decision="block", reason="Service access denied")
                logger.error(f"Service access denied for ID: {target_id}")
                return JsonResponse({
                    "error": "Service access denied",
                    "detail": f"Service {target_id} is not within allowed service limit (MAX_SERVICES={max_services})"
                }, status=403)

            target_backend = service_data["target_base_url"]

        except ValueError as e:
            logger.error(f"Invalid MAX_SERVICES value: {e}")
            log_request(ip=client_ip, path=path, method=request.method, size=len(body),
                        score=0, decision="block", reason="invalid_max_services_config")
            return JsonResponse({
                "error": "Configuration error",
                "detail": "Invalid MAX_SERVICES configuration"
            }, status=500)

        except Exception as e:
            REQUESTS_TOTAL.labels(decision="block").inc()
            REQUEST_FAIL_TOTAL.labels(status="failed").inc()
            logger.error(f"Error looking up service {target_id}: {e}")
            log_request(ip=client_ip, path=path, method=request.method, size=len(body),
                        score=0, decision="block", reason="service_lookup_error")
            return JsonResponse({
                "error": "Service lookup error",
                "detail": "Unable to determine target service"
            }, status=503)
            
        # === Validate HMAC signature using the service's routing_secret
        # try:
        #     validate_routing_signature(
        #         target_id=target_id,
        #         target_ts=target_ts,
        #         path=path,
        #         provided_sig=target_sig,
        #         routing_secret=service_data.get("routing_secret")
        #     )
        # except MissingRoutingSecret:
        #     REQUESTS_TOTAL.labels(decision="block").inc()
        #     REQUEST_FAIL_TOTAL.labels(status="failed").inc()
        #     log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision="block", reason="Missing routing secret")
        #     logger.error("Missing routing secret for service")
        #     return JsonResponse({
        #         "error": "Missing routing secret",
        #         "detail": "Service is not configured with a routing secret"
        #     }, status=500)
        # except InvalidSignature:
        #     REQUESTS_TOTAL.labels(decision="block").inc()
        #     REQUEST_FAIL_TOTAL.labels(status="failed").inc()
        #     log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision="block", reason="Invalid routing signature")
        #     logger.error("Invalid routing signature")
        #     return JsonResponse({
        #         "error": "Invalid routing signature",
        #         "detail": "Signature mismatch"
        #     }, status=403)

        
        # valid, error_response = validate_service_routing(service_data, request)
        # if not valid:
        #     REQUESTS_TOTAL.labels(decision="block").inc()
        #     REQUEST_FAIL_TOTAL.labels(status="failed").inc()
        #     log_request(
        #         ip=client_ip,
        #         path=request.get_full_path(),
        #         method=request.method,
        #         size=len(body),
        #         score=0,
        #         decision="block",
        #         reason="routing_rejected"
        #     )
        #     return error_response
        if MODULES["block"]:
            try:
                if MODULES["block"].is_blocked(client_ip):
                    REQUESTS_TOTAL.labels(decision="block").inc()
                    REQUEST_FAIL_TOTAL.labels(status="failed").inc()
                    log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision="block", reason="ALREADY_BLOCKED", service_id=service_data["id"])
                    logger.info(f"Blocked: {client_ip} is in blocklist")
                    return JsonResponse({"error": "Blocked by blocklist"}, status=403)
            except Exception:
                pass

        cache_key = build_cache_key(
            method=request.method,
            path=path,
            headers=request.headers,
            body=body,
        )

        if cache_enabled and redis_client is not None:
            try:
                cached = redis_client.get(cache_key)
            except Exception as e:
                logger.warning("Redis GET failed: %s", e)
                cached = None
                cache_enabled = False
                
            if cached:
                try:
                    # Replace pickle with JSON deserialization
                    cached_data = json.loads(cached)
                    status_code = cached_data["status"]
                    headers = cached_data["headers"]
                    content = base64.b64decode(cached_data["body_b64"])
                    CACHE_HIT.inc()
                    response = HttpResponse(content, status=status_code)
                    for k, v in headers.items():
                        if k.lower() not in ("content-encoding", "transfer-encoding", "connection", "keep-alive"):
                            response[k] = v
                    response["X-Cache-Status"] = "hit"
                    response["X-Target-Service"] = str(service_data["uuid"])
                    logger.info(f"Cache hit for {cache_key}")
                    return response
                except Exception as e:
                    CACHE_MISS.inc()
                    logger.warning("Cache deserialize failed: %s", e)
            else:
                CACHE_MISS.inc()
        
        allow_ips = getattr(settings, "ALLOW_IPS", [])
        if client_ip in allow_ips:      
            try:
                response = forward_request_to_backend(request, target_backend, service_data["uuid"])
                REQUESTS_TOTAL.labels(decision="allow").inc()
                REQUEST_SUCCESS_TOTAL.labels(status="ok").inc()
                return response
            except Exception as e:
                REQUESTS_TOTAL.labels(decision="block").inc()
                REQUEST_FAIL_TOTAL.labels(status="failed").inc()
                logger.error(f"Error forwarding to backend: {e}")
                return JsonResponse({"error": "backend_unreachable", "detail": str(e)}, status=502)
        
        # === 1) TLS check (cached DB lookup)
        host = request.headers.get("Host", "localhost")
        tls_valid = check_tls_validity(
            host=host,
            alert_module=MODULES.get("alert"),
            client_ip=client_ip
        )
        
        # === 2) ASN lookup
        asn_trust = get_asn_trust_score(
            client_ip=client_ip,
            alert_module=MODULES.get("alert"),
            block_module=MODULES.get("block")
        )
        
        # === 3) IP reputation
        iprep_score, iprep_blocked, iprep_reason = handle_ip_reputation(
            client_ip=client_ip,
            rep_module=MODULES.get("ip_rep"),
            alert_module=MODULES.get("alert"),
            block_module=MODULES.get("block"),
            service_id=service_data["id"]  # ✅ tambahkan ini
        )


        if iprep_blocked:
            REQUESTS_TOTAL.labels(decision="block").inc()
            REQUEST_FAIL_TOTAL.labels(status="failed").inc()
            log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=iprep_score, decision="block", reason=iprep_reason, service_id=service_data["id"])
            logger.info(f"Blocked: {client_ip} by IP reputation ({iprep_reason})")
            return JsonResponse({
                "error": "Blocked by IP reputation",
                "detail": iprep_reason,
                "score": iprep_score
            }, status=403)
                
        # === 4) JSON validation (per-service, per-method, per-endpoint schema)
        json_valid = True
        if request.content_type and "application/json" in request.content_type.lower():
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
                
                # === 4.5) WAF inspection (SQLi / XSS / Command Injection)
                waf_response, waf_category, waf_match = waf_inspect_request(payload)
                if waf_response:
                    # Increment Prometheus metric
                    REQUESTS_TOTAL.labels(decision="block").inc()
                    REQUEST_FAIL_TOTAL.labels(status="failed").inc()

                    # Log ke sistem observability internal
                    log_waf_block(client_ip, path, request.method, body, waf_category, service_id=service_data["id"])

                    # Block IP dan kirim alert
                    reason = f"{waf_category.upper()} detected"
                    sev = determine_severity(reason, score=70)
                    if MODULES.get("block"):
                        MODULES["block"].block_ip(client_ip, reason=reason, severity=sev)
                    if MODULES.get("alert"):
                        MODULES["alert"].create_alert("BLOCKED", client_ip, reason, sev)

                    return waf_response
            except Exception:
                decision, reason = "block", "malformed_json"
                log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision=decision, reason=reason, service_id=service_data["id"])

                reason = "Malformed JSON"
                sev = determine_severity(reason, score=40)
                MODULES["block"].block_ip(client_ip, reason=reason, severity=sev)
                MODULES["alert"].create_alert("BLOCKED", client_ip, reason, sev)
                logger.warning(f"Blocked: {client_ip} sent malformed JSON")
                REQUESTS_TOTAL.labels(decision="block").inc()
                REQUEST_FAIL_TOTAL.labels(status="failed").inc()
                return JsonResponse({"error": "Malformed JSON"}, status=400)
            
            # Jalankan validasi schema per-service+endpoint+method
            schema_result = validate_payload_for_service(service_data["uuid"], path, request.method, payload)

            if not schema_result["valid"]:
                logger.warning(f"Schema validation failed: {schema_result['message']}")

                # Kalau enforce = True → block
                if schema_result["enforce"]:
                    decision, reason = "block", "JSON_SCHEMA_INVALID"
                    log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision=decision, reason=reason,service_id=service_data["id"])
                    REQUESTS_TOTAL.labels(decision="block").inc()
                    REQUEST_FAIL_TOTAL.labels(status="failed").inc()

                    reason = "JSON schema invalid"
                    sev = determine_severity(reason, score=30)
                    MODULES["alert"].create_alert("JSON SCHEMA BLOCK", client_ip, reason, sev)

                    return JsonResponse({"error": "JSON Schema Invalid", "detail": schema_result["message"]}, status=400)

                else:
                    # Mode monitor: hanya log + alert
                    decision, reason = "monitor", "JSON_SCHEMA_INVALID"
                    log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision=decision, reason=reason, service_id=service_data["id"])

                    reason = "JSON schema invalid"
                    sev = determine_severity(reason, score=20)
                    MODULES["alert"].create_alert("JSON SCHEMA MONITOR", client_ip, reason, sev)


        # === 5) Behaviour logging + anomaly (improved)
        anomalous = False
        log_obj = None

        # # 1) Log request via AiProfilerService.log_request (expected to return the created BehaviourLogs instance)
        # if MODULES.get("log_req"):
        #     try:
        #         # call using kwargs; service supports both ip or ip_address via kwargs
        #         log_obj = MODULES["log_req"](
        #             endpoint=path,
        #             ip=client_ip,  # gunain parameter 'ip', bukan 'ip_address'
        #             method=request.method,
        #             payload_size=len(body),
        #             user_agent=request.headers.get("User-Agent", ""),
        #             status_code=500,
        #             response_time_ms=3000
        #         )
        #     except Exception as e:
        #         logger.debug("log_req failed: %s", e)
        #         log_obj = None
                

        # # 2) Detect anomaly. AiProfilerService.detect_anomaly expects a BehaviourLogs object.
        # if MODULES.get("is_anom"):
        #     anomalous = False
        #     anomaly_reason = "anomalous_detected"

        #     try:
        #         # Prefer passing log object jika tersedia
        #         if log_obj is not None:
        #             result = MODULES["is_anom"](log_obj)
        #         else:
        #             # fallback: pass ip atau ip_address jika signature berbeda
        #             try:
        #                 result = MODULES["is_anom"](client_ip)
        #             except TypeError:
        #                 result = MODULES["is_anom"](ip_address=client_ip)

        #         # Check apakah return value berupa tuple (True/False + reason)
        #         if isinstance(result, tuple):
        #             anomalous, anomaly_reason = result
        #         else:
        #             anomalous = bool(result)
        #             # tetap gunakan default reason jika hanya True/False

        #     except Exception as e:
        #         logger.debug("is_anom failed: %s", e)
        #         anomalous = False
        #         anomaly_reason = "anomalous_detected"

        #     # === Tambahkan log jika anomalous
        #     if anomalous:
        #         score_tmp = calculate_risk_score(
        #             asn_score=asn_trust,
        #             iprep_score=iprep_score,
        #             json_valid=json_valid,
        #             tls_valid=tls_valid,
        #         )
        #         decision_tmp, _ = decide_action(score_tmp, ALREADY_BLOCKED=False)

        #         log_request(
        #             ip=client_ip,
        #             path=path,
        #             method=request.method,
        #             size=len(body),
        #             score=score_tmp,
        #             decision=decision_tmp,
        #             reason=f"anomalous : {anomaly_reason}",
        #             service_id=service_data["id"]
        #         )

        #         logger.info(
        #             f"Anomaly detected: {client_ip}, decision={decision_tmp}, "
        #             f"score={score_tmp}, reason={anomaly_reason}"
        #         )

        # === 6) Blocklist check
        ALREADY_BLOCKED = False
        if MODULES["block"]:
            try:
                ALREADY_BLOCKED = MODULES["block"].is_blocked(client_ip)
            except Exception:
                ALREADY_BLOCKED = False

        # === Aggregate score
        score = calculate_risk_score(
            asn_score=asn_trust,
            iprep_score=iprep_score,
            json_valid=json_valid,
            tls_valid=tls_valid
        )
           
        # Ambil keputusan berdasarkan skor dan apakah IP sudah diblok
        decision, reason = decide_action(score=score, ALREADY_BLOCKED=ALREADY_BLOCKED)

        if decision == "block":
            # Log dan metrik
            log_request(
                ip=client_ip,
                path=path,
                method=request.method,
                size=len(body),
                score=score,
                decision=decision,
                reason=reason,
                service_id=service_data["id"]
            )
            REQUESTS_TOTAL.labels(decision="block").inc()
            REQUEST_FAIL_TOTAL.labels(status="failed").inc()

            if reason == "ALREADY_BLOCKED":
                logger.info(f"Blocked: {client_ip} is in blocklist")
                return JsonResponse({"error": "Blocked by blocklist"}, status=403)

            elif reason == "score_too_low":
                logger.info(f"Blocked: {client_ip} by score {score}")

                # Optional: auto-block IP dan buat alert
                reason = "Score too low"
                sev = determine_severity(reason, score)
                if MODULES.get("block"):
                    MODULES["block"].block_ip(client_ip, reason=reason, severity=sev)
                if MODULES.get("alert"):
                    MODULES["alert"].create_alert("BLOCKED", client_ip, "Auto block by decision engine", sev)

                return JsonResponse({"error": "Blocked by RITAPI", "score": score}, status=403)
            
        # === Forward to backend (with Redis caching)
        try:
            start_time = time.monotonic()
            response = forward_request_to_backend(request, target_backend, service_data["uuid"])
            end_time = time.monotonic()
            forwarded_headers = dict(response.items())
            
            response_time_ms = (end_time - start_time) * 1000
            
            # === AI Behaviour Logging + Anomaly Detection ===
            if MODULES.get("log_req"):
                try:
                    log_obj = MODULES["log_req"](
                        endpoint=path,
                        ip=client_ip,
                        method=request.method,
                        payload_size=len(body),
                        user_agent=request.headers.get("User-Agent", ""),
                        status_code=response.status_code,
                        response_time_ms=response_time_ms
                    )

                    if MODULES.get("is_anom"):
                        try:
                            is_anom, reason = MODULES["is_anom"](log_obj)
                            print("Anomaly Detection Result:", is_anom, reason)
                            if is_anom:
                                logger.warning(f"[AI] Anomaly detected for {client_ip}: {reason}")

                                # Optional: auto-block jika sering anomaly
                                from ai_behaviour.models import BehaviourAnomaly
                                recent_anoms = BehaviourAnomaly.objects.filter(
                                    ip_address=client_ip,
                                    detected_at__gte=timezone.now() - timezone.timedelta(minutes=5)
                                ).count()
                                if recent_anoms >= 3 and MODULES.get("block"):
                                    reason = f"Repeated anomalies ({recent_anoms}/5m)"
                                    sev = determine_severity(reason, score=65)
                                    if MODULES.get("block"):
                                        MODULES["block"].block_ip(client_ip, reason=reason, severity=sev)
                                    if MODULES.get("alert"):
                                        MODULES["alert"].create_alert("AI_AUTOBLOCK", client_ip, reason, sev)

                        except Exception as e:
                            logger.debug(f"AI anomaly detection failed: {e}")
                except Exception as e:
                    logger.debug(f"AI behaviour logging failed: {e}")

            if cache_enabled and redis_client is not None and request.method in ("GET", "HEAD") and response.status_code == 200:
                try:
                    ttl = int(getattr(settings, "BACKEND_RESPONSE_CACHE_TTL", 30))
                    # Replace pickle with JSON serialization
                    cache_data = {
                        "status": response.status_code if response is not None else 200,
                        "headers": forwarded_headers,
                        "body_b64": base64.b64encode(response.content).decode('utf-8')
                    }
                    redis_client.setex(cache_key, ttl, json.dumps(cache_data))
                    response["X-Cache-Status"] = "stored"
                except Exception as e:
                    logger.warning("Redis SETEX failed: %s", e)
                    response["X-Cache-Status"] = "store_failed"
            else:
                if not cache_enabled or redis_client is None:
                    response["X-Cache-Status"] = "disabled"
                elif request.method not in ("GET", "HEAD"):
                    response["X-Cache-Status"] = "skipped_method"
                elif response.status_code != 200:
                    response["X-Cache-Status"] = "skipped_status"

            log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=0, decision=decision, reason=reason, service_id=service_data["id"], hmac_signature=target_sig, duration_ms=response_time_ms)
            REQUESTS_TOTAL.labels(decision="allow").inc()
            REQUEST_SUCCESS_TOTAL.labels(status="ok").inc()
            return response

        except Exception as e:
            decision, reason = "block", f"backend_error: {e}"
            if MODULES["alert"]:
                try:
                    reason = f"Backend error: {e}"
                    sev = determine_severity(reason, score=80)
                    if MODULES.get("alert"):
                        MODULES["alert"].create_alert("BACKEND_ERROR", client_ip, reason, sev)
                except Exception:
                    pass
            REQUESTS_TOTAL.labels(decision="block").inc()
            REQUEST_FAIL_TOTAL.labels(status="failed").inc()
            logger.error(f"Error forwarding to backend: {e}")
            log_request(ip=client_ip, path=path, method=request.method, size=len(body), score=score, decision=decision, reason=reason, service_id=service_data["id"])
            return JsonResponse({"error": "backend_unreachable", "detail": str(e)}, status=502)