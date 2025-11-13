import logging
from urllib.parse import urlparse
from django.http import JsonResponse

logger = logging.getLogger(__name__)

def validate_service_routing(service_data, request):
    """
    Validate scheme, method, and path against service allowlist.

    Args:
        service_data (dict): Dictionary with keys:
            - target_base_url
            - uuid
            - allowed_paths
            - allowed_methods
            - allowed_schemes
        request (HttpRequest): Incoming Django request object

    Returns:
        (bool, JsonResponse or None): (is_valid, error_response_if_any)
    """
    path = request.get_full_path()
    method = request.method.upper()
    parsed = urlparse(service_data["target_base_url"])
    scheme = parsed.scheme.lower()

    allowed_paths = service_data.get("allowed_paths", [])
    allowed_methods = service_data.get("allowed_methods", [])
    allowed_schemes = service_data.get("allowed_schemes", [])

    # Validate scheme
    if allowed_schemes and scheme not in [s.lower() for s in allowed_schemes]:
        logger.warning(f"[RoutingHardening] Scheme {scheme} not allowed for service {service_data['uuid']}")
        return False, JsonResponse({
            "error": "Scheme not allowed",
            "detail": f"Scheme '{scheme}' is not permitted for this service"
        }, status=403)

    # Validate method
    if allowed_methods and method not in [m.upper() for m in allowed_methods]:
        logger.warning(f"[RoutingHardening] Method {method} not allowed for service {service_data['uuid']}")
        return False, JsonResponse({
            "error": "Method not allowed",
            "detail": f"Method '{method}' is not permitted for this service"
        }, status=403)

    # Validate path prefix
    if allowed_paths and not any(path.startswith(p) for p in allowed_paths):
        logger.warning(f"[RoutingHardening] Path {path} not allowed for service {service_data['uuid']}")
        return False, JsonResponse({
            "error": "Path not allowed",
            "detail": f"Path '{path}' is not permitted for this service"
        }, status=403)

    return True, None
