# utils/security_cache.py
import json
import logging
from django.conf import settings
from .redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

# TTL default (bisa override via settings)
ASN_TTL = getattr(settings, "ASN_CACHE_TTL", 604800)       # 30 detik
TLS_TTL = getattr(settings, "TLS_CACHE_TTL", 86400)       # 30 detik
SERVICE_TTL = getattr(settings, "SERVICE_CACHE_TTL", 60)   # 10 detik
ALLOWED_SERVICE_TTL = getattr(settings, "ALLOWED_SERVICE_CACHE_TTL", 60) 


# ================== Generic Helpers ==================

def _get_json_cache(key: str):
    """Ambil value JSON dari Redis, return dict/None."""
    client = RedisClientSingleton.get_client()
    if not client:
        return None
    try:
        val = client.get(key)
        return json.loads(val) if val else None
    except Exception as e:
        logger.warning("Cache read failed for %s: %s", key, e)
        return None


def _get_json_cache_with_expiry(key: str):
    """
    Ambil value JSON + status expiry.
    return (data, expired: bool)
    """
    client = RedisClientSingleton.get_client()
    if not client:
        return None, True
    try:
        ttl = client.ttl(key)
        val = client.get(key)
        data = json.loads(val) if val else None
        return data, (ttl <= 0)
    except Exception as e:
        logger.warning("Cache read with expiry failed for %s: %s", key, e)
        return None, True


def _set_json_cache(key: str, value: dict | list, ttl: int):
    """Simpan dict/list ke Redis dengan TTL (dalam detik)."""
    if not isinstance(value, (dict, list)):
        logger.warning("Cache write skipped (value bukan dict/list) for %s", key)
        return
    client = RedisClientSingleton.get_client()
    if not client:
        return
    try:
        client.setex(key, ttl, json.dumps(value))
    except Exception as e:
        logger.warning("Cache write failed for %s: %s", key, e)


def _delete_cache(key: str):
    """Hapus key dari Redis."""
    client = RedisClientSingleton.get_client()
    if client:
        try:
            client.delete(key)
        except Exception as e:
            logger.warning("Cache delete failed for %s: %s", key, e)


# ================== ASN Cache ==================

def get_cached_asn(ip: str):
    return _get_json_cache(f"ritapi:asn:{ip}")


def get_cached_asn_with_expiry(ip: str):
    return _get_json_cache_with_expiry(f"ritapi:asn:{ip}")


def set_cached_asn(ip: str, asn_obj: dict):
    _set_json_cache(f"ritapi:asn:{ip}", asn_obj, ASN_TTL)


def delete_cached_asn(ip: str):
    _delete_cache(f"ritapi:asn:{ip}")


# ================== TLS Cache ==================

def get_cached_tls(host: str):
    return _get_json_cache(f"ritapi:tls:{host}")


def get_cached_tls_with_expiry(host: str):
    return _get_json_cache_with_expiry(f"ritapi:tls:{host}")


def set_cached_tls(host: str, tls_obj: dict):
    _set_json_cache(f"ritapi:tls:{host}", tls_obj, TLS_TTL)


def delete_cached_tls(host: str):
    _delete_cache(f"ritapi:tls:{host}")


# ================== Service Cache ==================

def get_cached_service(target_id: str):
    """Ambil detail service (dict) dari cache Redis."""
    return _get_json_cache(f"ritapi:service:{target_id}")


def set_cached_service(target_id: str, service_obj: dict):
    """Simpan detail service ke cache."""
    _set_json_cache(f"ritapi:service:{target_id}", service_obj, SERVICE_TTL)


def delete_cached_service(target_id: str):
    _delete_cache(f"ritapi:service:{target_id}")


# ================== Allowed Services Cache ==================

def get_cached_allowed_services(max_services: int):
    """Ambil daftar allowed service IDs dari cache."""
    return _get_json_cache(f"ritapi:allowed_services:{max_services}")


def set_cached_allowed_services(max_services: int, ids: list[int]):
    """Simpan daftar allowed service IDs ke cache."""
    _set_json_cache(f"ritapi:allowed_services:{max_services}", ids, ALLOWED_SERVICE_TTL)


def delete_cached_allowed_services(max_services: int):
    _delete_cache(f"ritapi:allowed_services:{max_services}")
