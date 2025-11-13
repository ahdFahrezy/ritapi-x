from django.db import models
from ops.ops_services.models import Service

class JsonSchema(models.Model):
    service = models.ForeignKey(
        Service,
        to_field="uuid",
        db_column="service_uuid",
        on_delete=models.CASCADE,
        related_name="json_schemas",
        null=True,
        blank=True
    )

    name = models.CharField(max_length=100)
    endpoint = models.CharField(max_length=255, help_text="Path prefix or full path, e.g. /api/data")
    method = models.CharField(max_length=10, help_text="GET, POST, etc.")
    schema_json = models.JSONField()
    description = models.TextField(blank=True, null=True)

    version = models.CharField(
        max_length=32,
        default="v1",
        help_text="Schema version, e.g., v1, v2-beta"
    )

    rollout_mode = models.CharField(
        max_length=16,
        choices=(
            ("monitor", "Monitor only"),
            ("enforce", "Strict enforcement"),
        ),
        default="monitor",
        help_text="If enforce, invalid schema will be blocked. If monitor, only logged."
    )

    is_active = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("service", "endpoint", "method", "version")

    def __str__(self):
        return f"{self.name} ({self.service.target_base_url}) [{self.method} {self.endpoint}] v{self.version} - {self.rollout_mode}"
