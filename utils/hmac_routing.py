import hmac
import hashlib

class RoutingSignatureError(Exception):
    """Base class for routing signature validation errors."""

class MissingRoutingSecret(RoutingSignatureError):
    pass

class InvalidSignature(RoutingSignatureError):
    pass

def validate_routing_signature(target_id: str, target_ts: str, path: str, provided_sig: str, routing_secret: str):
    """
    Validates the HMAC signature for routing headers.

    Raises:
        MissingRoutingSecret: if routing_secret is None or empty.
        InvalidSignature: if HMAC validation fails.
    """
    if not routing_secret:
        raise MissingRoutingSecret("Routing secret is missing or not configured")

    message = f"{target_id}.{target_ts}.{path}".encode("utf-8")
    expected_sig = hmac.new(
        key=routing_secret.encode("utf-8"),
        msg=message,
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise InvalidSignature("Signature mismatch")
