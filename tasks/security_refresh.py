# tasks/security_refresh.py
import logging
from celery import shared_task
from utils.security_cache import set_cached_asn, set_cached_tls
from asn_score.services import AsnScoreService
from tls_analyzer.services import TlsAnalyzerService

logger = logging.getLogger(__name__)


@shared_task
def refresh_asn(ip: str):
    """Refresh ASN info async & store ke Redis."""
    try:
        asn_obj = AsnScoreService.lookup_asn(ip)
        logger.info("ASN Lookup Result for %s: %s", ip, asn_obj)
        if asn_obj:
            asn_obj_dict = {
                "ip_address": getattr(asn_obj, "ip_address", None),
                "asn_number": getattr(asn_obj, "asn_number", None),
                "asn_description": getattr(asn_obj, "asn_description", None),
                "trust_score": getattr(asn_obj, "trust_score", 0),
                "is_latest": getattr(asn_obj, "is_latest", False),
                "created_at": getattr(asn_obj, "created_at", None).isoformat()
                if getattr(asn_obj, "created_at", None) else None,
            }
            set_cached_asn(ip, asn_obj_dict)
            logger.info("ASN cache refreshed for %s", ip)
            logger.info("ASN Lookup Result for %s: %s", ip, asn_obj)
    except Exception as e:
        logger.error("ASN refresh failed for %s: %s", ip, e)


@shared_task
def refresh_tls(host: str):
    """Refresh TLS info async & store ke Redis."""
    try:
        tls_record = TlsAnalyzerService.get_or_analyze_tls(host)
        if tls_record:
            tls_record_dict = TlsAnalyzerService.tls_record_to_dict(tls_record)
            set_cached_tls(host, tls_record_dict)
            logger.info("TLS cache refreshed for %s", host)
    except Exception as e:
        logger.error("TLS refresh failed for %s: %s", host, e)
