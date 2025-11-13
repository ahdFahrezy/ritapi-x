import logging
from django.conf import settings
from utils.security_cache import get_cached_asn_with_expiry
from tasks.security_refresh import refresh_asn
from asn_score.services import AsnScoreService

logger = logging.getLogger(__name__)

def get_asn_trust_score(client_ip, alert_module=None, block_module=None) -> int:
    """
    Cek ASN trust score berdasarkan IP.
    Jika ENABLE_BACKEND_CACHE=True, gunakan cache & Celery.
    Jika False, langsung hit database/lookup tanpa Redis sama sekali.
    """
    try:
        if getattr(settings, "ENABLE_BACKEND_CACHE", False):
            # === Mode CACHE ENABLED ===
            asn_obj, expired = get_cached_asn_with_expiry(client_ip)
            if not asn_obj:
                refresh_asn.delay(client_ip)
                logger.info(f"No ASN cache for {client_ip}, triggered async refresh.")
                return 0  # fallback sementara

            if expired:
                refresh_asn.delay(client_ip)
                logger.info(f"ASN cache expired for {client_ip}, triggered async refresh.")

            asn_number = asn_obj.get("asn_number")
            score = asn_obj.get("trust_score", 0)

        else:
            # === Mode CACHE DISABLED ===
            record = AsnScoreService.lookup_asn(client_ip)
            if not record:
                return 0
            asn_number = record.asn_number
            score = record.trust_score

        # === Validasi skor lewat DB ===
        try:
            from asn_score.models import AsnTrustConfig
            config = AsnTrustConfig.objects.get(asn_number=asn_number)
            score = config.score
        except Exception:
            pass

        # === Alert / Soft Block ===
        if score < -2:
            detail = f"ASN trust score low ({score}) for IP {client_ip}"
            if alert_module:
                alert_module.create_alert("ASN_SUSPICIOUS", client_ip, detail, "medium")
            if block_module:
                block_module.soft_block_ip(client_ip, reason=detail, severity="medium")

        return score

    except Exception as e:
        logger.error(f"ASN lookup error for IP {client_ip}: {e}")
        return 0

# def get_asn_trust_score(client_ip, alert_module=None, block_module=None) -> int:
#     """
#     Cek ASN trust score berdasarkan IP.
#     Gunakan cache jika memungkinkan, dan trigger async refresh.
#     Bisa juga trigger alert dan soft block jika skor terlalu rendah.
#     """

#     try:
#         asn_obj, expired = get_cached_asn_with_expiry(client_ip)  
#         if not asn_obj:
#             refresh_asn.delay(client_ip)
#         elif expired:
#             refresh_asn.delay(client_ip)

#         asn_number = None
#         if asn_obj:
#             asn_number = getattr(asn_obj, "asn_number", None) or asn_obj.get("asn_number")
#         if not asn_number:
#             record = refresh_asn(client_ip)
#             asn_number = record.asn_number
#             return 0
#         try:
#             from asn_score.models import AsnTrustConfig
#             config = AsnTrustConfig.objects.get(asn_number=asn_number)
#             score = config.score
#         except AsnTrustConfig.DoesNotExist:
#             score = 0

#         # Alert + optional soft block if too low
#         if score < -2:
#             detail = f"ASN trust score low ({score}) for IP {client_ip}"
#             if alert_module:
#                 alert_module.create_alert("ASN_SUSPICIOUS", client_ip, detail, "medium")
#             if block_module:
#                 block_module.soft_block_ip(client_ip, reason=detail, severity="medium")

#         return score

#     except Exception as e:
#         logger.error(f"ASN lookup error for IP {client_ip}: {e}")
#         return 0
