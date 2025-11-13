from django.utils.deprecation import MiddlewareMixin

class RemoveServerHeaderMiddleware(MiddlewareMixin):
    """
    Middleware untuk menghapus atau mengganti Server header
    agar tidak membocorkan informasi versi aplikasi/server.
    """

    def process_response(self, request, response):
        # Hapus Server header jika ada
        if "Server" in response:
            del response["Server"]

        # Opsional: tambahkan header generic
        response.setdefault("Server", "Secure")

        return response
