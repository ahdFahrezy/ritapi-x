# middlewares/dynamic_cors.py
from django.http import HttpResponse
from ops.ops_services.models import Service

class DynamicCORSMiddleware:
    """
    Dynamic CORS per tenant/service.
    - Deny all by default
    - Allow only explicit origins registered in Service model
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        origin = request.headers.get("Origin")
        if not origin:
            return response  # no CORS needed

        # Cek apakah origin diizinkan di salah satu service
        if Service.objects.filter(allowed_origins__icontains=origin).exists():
            response["Access-Control-Allow-Origin"] = origin
            response["Vary"] = "Origin"
            response["Access-Control-Allow-Credentials"] = "true"

            if request.method == "OPTIONS":
                response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
                response["Access-Control-Allow-Headers"] = (
                    request.headers.get("Access-Control-Request-Headers", "Authorization, Content-Type")
                )
        else:
            # Deny all by default
            if request.method == "OPTIONS":
                return HttpResponse(status=403)

        return response
