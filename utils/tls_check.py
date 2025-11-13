import logging
from utils.security_cache import get_cached_tls_with_expiry
from tasks.security_refresh import refresh_tls
from django.conf import settings
from tls_analyzer.services import TlsAnalyzerService

logger = logging.getLogger(__name__)

def check_tls_validity(host: str, alert_module=None, client_ip: str = None) -> bool:
    """
    Validasi TLS host dari cache, dan refresh jika perlu.
    Jika gagal total, fallback ke True (jangan block request).
    """
    try:
        use_cache = getattr(settings, "ENABLE_BACKEND_CACHE", True)
        
        # kalau tidak pakai cache, langsung cek TLS
        if not use_cache:
            tls_record = TlsAnalyzerService.get_or_analyze_tls(host)
            if not tls_record:
                return False  # fallback (anggap valid)
            return tls_record.is_valid  # <--- hasil boolean langsung
        
        tls_record, expired = get_cached_tls_with_expiry(host)
        if not tls_record:
            refresh_tls.delay(host)
            return False  # fallback sementara
        if expired:
            refresh_tls.delay(host)
            
        is_valid = tls_record.get("is_valid", False)
        if not is_valid and alert_module:
            alert_module.create_alert(
                alert_type="TLS_INVALID",
                ip_address=client_ip or "0.0.0.0",
                detail=f"TLS certificate expired for host={host}",
                severity="low"
            )

        return is_valid

    except Exception as e:
        logger.error(f"TLS validation failed for host={host}: {e}")
        return True  # fallback mode
