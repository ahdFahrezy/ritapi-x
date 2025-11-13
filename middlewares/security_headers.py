import base64
import secrets

class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # generate random nonce tiap request
        nonce = base64.b64encode(secrets.token_bytes(16)).decode("utf-8")
        request.csp_nonce = nonce  

        # CSP ketat & valid
        csp = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net "
            "https://unpkg.com https://code.jquery.com https://cdn.datatables.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.datatables.net "
            "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
            "img-src 'self' data: https:; "
            "object-src 'none'; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "manifest-src 'self'; "
            "worker-src 'self' blob:; "
        )

        response = self.get_response(request)
        response["Content-Security-Policy"] = csp

        # Header lain
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("X-Frame-Options", "DENY")
        response.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.setdefault("Cross-Origin-Embedder-Policy", "require-corp")

        return response
