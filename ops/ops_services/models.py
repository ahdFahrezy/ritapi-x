import uuid
from django.db import models
import secrets  # untuk generate secret yang aman

class Service(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    host_name = models.CharField(
        max_length=255,
        unique=True,
        help_text="Hostname or domain name handled by this service (e.g., app1.situswaf.com)"
    )
    target_base_url = models.URLField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def generate_secret():
        import secrets
        return secrets.token_hex(32)

    routing_secret = models.CharField(
        max_length=128,
        default=generate_secret,  # ✅ STABIL!
        help_text="Unique secret used to sign routing headers (HMAC)."
    )

    # Tambahan untuk CORS
    allowed_origins = models.TextField(
        blank=True,
        help_text="Comma separated list of allowed origins for this service, e.g. https://foo.com, https://bar.com"
    )
    
    allowed_paths = models.TextField(
        blank=True,
        help_text="Comma-separated list of allowed path prefixes (e.g., /api/, /v1/health)"
    )

    allowed_methods = models.TextField(
        blank=True,
        help_text="Comma-separated list of allowed HTTP methods (e.g., GET, POST)"
    )

    allowed_schemes = models.TextField(
        blank=True,
        default="https",
        help_text="Comma-separated list of allowed URL schemes (e.g., https)"
    )

    def get_allowed_origins(self):
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]
    
    def get_allowed_paths(self):
        return [p.strip() for p in self.allowed_paths.split(",") if p.strip()]

    def get_allowed_methods(self):
        return [m.strip().upper() for m in self.allowed_methods.split(",") if m.strip()]

    def get_allowed_schemes(self):
        return [s.strip().lower() for s in self.allowed_schemes.split(",") if s.strip()]

    def __str__(self):
        return f"{self.target_base_url} ({self.uuid})"

