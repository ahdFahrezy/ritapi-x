# utils/request_utils.py

def get_tenant_from_request(request):
    """
    Ambil tenant UUID dari header x-target-id.
    Jika tidak ada, fallback ke 'default'.
    """
    return request.headers.get("x-target-id", "default")
