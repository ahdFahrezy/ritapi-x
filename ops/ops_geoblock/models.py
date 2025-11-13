from django.db import models

class GeoBlockSetting(models.Model):
    country_code = models.CharField(max_length=5, unique=True)
    action = models.CharField(
        max_length=10,
        choices=(("block", "Block"), ("allow", "Allow")),
        default="block",
    )
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.country_code} ({self.action})"
