from django.db import models
import ops.ops_services.models as ops_service_models
import hashlib


class RequestLog(models.Model):
    service = models.ForeignKey(
        ops_service_models.Service,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="request_logs",
        help_text="Service that handled this request (can be null if service deleted)."
    )
    ip_address = models.GenericIPAddressField()
    path = models.CharField(max_length=255)
    method = models.CharField(max_length=10)
    body_size = models.IntegerField()
    score = models.FloatField()
    decision = models.CharField(max_length=20)   # "allow" | "block"
    reason = models.CharField(max_length=255, blank=True, null=True)
    hmac_signature_hash = models.CharField(max_length=64, null=True, blank=True)
    session_duration_ms = models.BigIntegerField(null=True, blank=True, help_text="Duration of session in milliseconds for successful requests")
    timestamp = models.DateTimeField(auto_now_add=True)
    
    @property
    def status(self):
        """Derived status from decision."""
        return "SUCCESS" if self.decision.lower() == "allow" else "FAIL"

    def set_hmac_signature(self, signature: str):
        """Store only the hash of HMAC signature."""
        if signature:
            self.hmac_signature_hash = hashlib.sha256(signature.encode()).hexdigest()

    def __str__(self):
        return f"[{self.decision.upper()}] {self.ip_address} {self.path} ({self.score})"
