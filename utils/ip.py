from django.conf import settings

def get_client_ip(request):
    """
    Resolve client IP safely.
    Trust X-Forwarded-For only if REMOTE_ADDR is in TRUSTED_PROXIES.
    """
    remote_addr = request.META.get("REMOTE_ADDR", "")
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")

    trusted_proxies = getattr(settings, "TRUSTED_PROXIES", [])

    if remote_addr in trusted_proxies and xff:
        # XFF may contain multiple IPs: client, proxy1, proxy2...
        return xff.split(",")[0].strip()
    return remote_addr or ""
