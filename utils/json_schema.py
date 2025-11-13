from jsonschema import validate, ValidationError
from json_enforcer.models import JsonSchema
import logging

logger = logging.getLogger(__name__)

def validate_payload_for_service(service, endpoint, method, payload):
    try:
        schema_obj = JsonSchema.objects.filter(
            service=service,
            endpoint__iexact=endpoint,
            method__iexact=method,
            is_active=True
        ).order_by("-timestamp").first()

        if not schema_obj:
            return {
                "valid": True,
                "message": "No schema defined",
                "enforce": False,
                "version": None
            }

        try:
            validate(instance=payload, schema=schema_obj.schema_json)
            return {
                "valid": True,
                "message": "Valid schema",
                "enforce": schema_obj.rollout_mode == "enforce",
                "version": schema_obj.version
            }

        except ValidationError as e:
            return {
                "valid": False,
                "message": str(e),
                "enforce": schema_obj.rollout_mode == "enforce",
                "version": schema_obj.version
            }

    except Exception as e:
        logger.warning(f"[Schema validation failed] {e}")
        return {
            "valid": True,
            "message": "Schema validation error ignored",
            "enforce": False,
            "version": None
        }
