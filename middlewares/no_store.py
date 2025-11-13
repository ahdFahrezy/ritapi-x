from django.utils.deprecation import MiddlewareMixin

class NoStoreMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        # Terapkan hanya pada halaman sensitif
        if request.path.startswith(("/login", "/admin", "/ops")):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, s-maxage=0"
            response["Pragma"] = "no-cache"
            response["Expires"] = "0"
        return response
