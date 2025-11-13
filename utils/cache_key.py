import hashlib
import json

def build_cache_key(method, path, headers, body) -> str:
    """
    Builds a consistent cache key for backend responses.
    """
    key_parts = {
        "m": method,
        "p": path,
        "ct": headers.get("Content-Type", ""),
        "ac": headers.get("Accept", ""),
    }

    body_bytes = body or b""
    body_hash = hashlib.sha256(body_bytes).hexdigest() if body_bytes else "no-body"
    
    key_raw = json.dumps(key_parts, sort_keys=True, separators=(",", ":")) + "|" + body_hash
    key_final = f"ritapi:backend_resp:{hashlib.sha256(key_raw.encode('utf-8')).hexdigest()}"
    
    return key_final
