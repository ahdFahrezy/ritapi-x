# utils/logging.py
import hashlib
from decision_engine.models import RequestLog


def log_request(ip, path, method, size, score, decision, reason, service_id=None, hmac_signature=None, duration_ms=None):
    try:
        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            method=method,
            body_size=size,
            score=score,
            decision=decision,
            reason=reason,
            service_id=service_id,
            hmac_signature_hash=hashlib.sha256(hmac_signature.encode()).hexdigest() if hmac_signature else None,
            session_duration_ms=duration_ms,
        )
    except Exception:
        # Never fail request because of logging
        pass
