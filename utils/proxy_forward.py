import requests
from django.http import HttpResponse
import logging

logger = logging.getLogger(__name__)

FORWARD_EXCLUDED_HEADERS = {
    "host", "x-target-id", "connection", "keep-alive",
    "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-length",
    "x-target-sig", "x-target-ts",  # optionally skip these too
}

RESPONSE_EXCLUDED_HEADERS = {
    "transfer-encoding", "connection", "keep-alive"
}

def forward_request_to_backend(request, target_backend_url, service_uuid):
    """
    Forwards the incoming Django request to the specified backend URL,
    and returns an HttpResponse.
    """
    path = request.get_full_path()
    body = request.body or b""

    try:
        url = f"{target_backend_url}{path}"

        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in FORWARD_EXCLUDED_HEADERS
        }

        # Remove Content-Type if method is GET or HEAD
        if request.method in ("GET", "HEAD"):
            headers.pop("Content-Type", None)
        headers.pop("Host", None)  # just in case

        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=body if request.method not in ("GET", "HEAD") else None,
            timeout=5,
            verify=True,
        )

        response = HttpResponse(resp.content, status=resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() not in RESPONSE_EXCLUDED_HEADERS:
                response[k] = v

        # Tambahkan informasi target
        response["X-Target-Service"] = str(service_uuid)
        response["X-Target-URL"] = target_backend_url

        return response

    except Exception as e:
        logger.error(f"Error forwarding to backend: {e}")
        raise
