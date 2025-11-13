import time
import uuid
from django.http import JsonResponse
import logging

logger = logging.getLogger(__name__)

def check_required_routing_headers(request):
    """
    Validates presence of x-target-id, x-target-sig, and x-target-ts.
    Returns tuple (is_valid, error_response_or_values)
    """
    target_id = request.headers.get("x-target-id")
    target_sig = request.headers.get("x-target-sig")
    target_ts = request.headers.get("x-target-ts")

    if not all([target_id, target_sig, target_ts]):
        logger.error(f"Missing required routing headers: x-target-id={target_id}, x-target-sig={target_sig}, x-target-ts={target_ts}")
        return False, JsonResponse({
            "error": "MISSING_REQUIRED_HEADER",
            "detail": "Headers x-target-id, x-target-sig, and x-target-ts are required"
        }, status=400)

    return True, (target_id, target_sig, target_ts)


def validate_uuid_format(target_id):
    """
    Validates whether target_id is a valid UUID.
    Returns (is_valid, error_response)
    """
    try:
        uuid.UUID(target_id)
        return True, None
    except ValueError:
        logger.error(f"Invalid x-target-id format: {target_id}")
        return False, JsonResponse({
            "error": "Invalid target ID format",
            "detail": "x-target-id must be a valid UUID"
        }, status=400)


def validate_timestamp_skew(target_ts, max_skew=120):
    """
    Validates the timestamp skew is within max_skew seconds.
    Returns (is_valid, error_response, skew_value)
    """
    try:
        ts_int = int(target_ts)
        now = int(time.time())
        skew = abs(now - ts_int)
        if skew > max_skew:
            logger.error(f"Signature timestamp skew too large: {skew} seconds")
            return False, JsonResponse({
                "error": "SIGNATURE_EXPIRED",
                "detail": f"Timestamp skew too large ({skew} seconds)"
            }, status=400), skew
        return True, None, skew
    except Exception:
        logger.error(f"Invalid x-target-ts value: {target_ts}")
        return False, JsonResponse({
            "error": "Invalid timestamp format",
            "detail": "x-target-ts must be an integer (UNIX timestamp)"
        }, status=400), None
