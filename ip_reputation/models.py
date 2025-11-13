from django.db import models
from django.utils import timezone
from ops.ops_services.models import Service  # asumsi kamu punya model ini
class IpReputation(models.Model):
    ip_address = models.GenericIPAddressField()
    scores = models.JSONField()  # detail breakdown
    reputation_score = models.FloatField()  # final score
    isp = models.CharField(max_length=255, null=True, blank=True)  # opsional
    country = models.CharField(max_length=50, null=True, blank=True)  # opsional
    is_tor = models.BooleanField(default=False)  # opsional
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.reputation_score}"

class InternalIPList(models.Model):
    LIST_TYPE_CHOICES = (
        ("allow", "Allow"),
        ("deny", "Deny"),
    )

    ip_address = models.GenericIPAddressField()
    list_type = models.CharField(max_length=10, choices=LIST_TYPE_CHOICES)
    service = models.ForeignKey(Service, null=True, blank=True, on_delete=models.CASCADE)  # null = global
    expires_at = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return self.expires_at and timezone.now() > self.expires_at

    def __str__(self):
        return f"{self.list_type.upper()} - {self.ip_address} ({self.service or 'GLOBAL'})"