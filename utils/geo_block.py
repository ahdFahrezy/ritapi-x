import logging
from django.conf import settings

try:
    import geoip2.database
except ImportError:
    geoip2 = None

from ops.ops_geoblock.models import GeoBlockSetting  # sesuaikan nama app kamu

logger = logging.getLogger(__name__)

# Cache lokal sederhana (opsional)
_geo_cache = {}

def get_country_from_ip(ip_address: str):
    """Gunakan GeoLite2 untuk mendeteksi negara dari IP."""
    if not ip_address or ip_address == "127.0.0.1":
        return None

    if ip_address in _geo_cache:
        return _geo_cache[ip_address]

    if not geoip2:
        logger.warning("geoip2 not installed, skipping GeoIP lookup")
        return None

    try:
        db_path = getattr(settings, "GEOLITE2_DB", "/usr/share/GeoIP/GeoLite2-Country.mmdb")
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip_address)
            country_code = response.country.iso_code
            _geo_cache[ip_address] = country_code
            return country_code
    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
        return None


def check_geo_block(ip_address: str):
    """
    Return (is_blocked: bool, country_code: str, reason: str)
    """
    country = get_country_from_ip(ip_address)
    if not country:
        return False, None, "NO_COUNTRY"

    try:
        rule = GeoBlockSetting.objects.filter(country_code__iexact=country, is_active=True).first()
        if rule and rule.action == "block":
            logger.info(f"GeoBlock: Blocked IP {ip_address} from {country}")
            return True, country, "BLOCKED_BY_GEO"
        elif rule and rule.action == "allow":
            return False, country, "ALLOWED_BY_GEO"
        else:
            return False, country, "NO_RULE"
    except Exception as e:
        logger.warning(f"GeoBlock check failed: {e}")
        return False, country, "ERROR"


def is_country_blocked(ip_address: str) -> bool:
    """Convenience wrapper — return True if IP country is blocked."""
    blocked, _, _ = check_geo_block(ip_address)
    return blocked
