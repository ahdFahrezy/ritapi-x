import uuid
import json
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class PendingChange(models.Model):
    """Model untuk menyimpan perubahan yang menunggu approval"""
    
    CHANGE_TYPES = [
        ('service_create', 'Service Creation'),
        ('service_update', 'Service Update'),  
        ('service_delete', 'Service Delete'),
        ('schema_create', 'Schema Creation'),
        ('schema_update', 'Schema Update'),
        ('schema_delete', 'Schema Delete'),
        ('policy_update', 'Policy Update'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]
    
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    change_type = models.CharField(max_length=20, choices=CHANGE_TYPES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    
    # Who requested the change
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='requested_changes')
    requested_at = models.DateTimeField(auto_now_add=True)
    
    # What's being changed
    target_model = models.CharField(max_length=50)  # 'Service', 'JsonSchema', etc
    target_id = models.CharField(max_length=255, null=True, blank=True)  # UUID of the object
    
    # Change details in JSON format
    change_data = models.JSONField(help_text="JSON data containing the proposed changes")
    original_data = models.JSONField(null=True, blank=True, help_text="Original data before change (for updates)")
    
    # Approval details
    approved_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_changes')
    rejection_reason = models.TextField(blank=True)
    
    # Auto-expire after 24 hours
    expires_at = models.DateTimeField()
    
    # Notes and justification
    justification = models.TextField(blank=True, help_text="Why this change is needed")
    
    class Meta:
        ordering = ['-requested_at']
        
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def can_be_approved_by(self, user):
        """Check if user can approve this change"""
        if user == self.requested_by:
            return False  # Can't approve own changes
        return user.is_superuser
    
    def get_change_summary(self):
        """Return a human-readable summary of the change"""
        if self.change_type == 'service_create':
            return f"Create new service: {self.change_data.get('target_base_url', 'Unknown')}"
        elif self.change_type == 'service_update':
            return f"Update service: {self.change_data.get('target_base_url', 'Unknown')}"
        elif self.change_type == 'service_delete':
            return f"Delete service: {self.original_data.get('target_base_url', 'Unknown') if self.original_data else 'Unknown'}"
        elif self.change_type == 'schema_create':
            return f"Create new schema: {self.change_data.get('name', 'Unknown')}"
        elif self.change_type == 'schema_update':
            return f"Update schema: {self.change_data.get('name', 'Unknown')}"
        elif self.change_type == 'schema_delete':
            return f"Delete schema: {self.original_data.get('name', 'Unknown') if self.original_data else 'Unknown'}"
        return f"{self.get_change_type_display()}"
    
    def __str__(self):
        return f"{self.get_change_summary()} - {self.get_status_display()}"


class ApprovalSignature(models.Model):
    """Model untuk menyimpan signature/tanda tangan approval"""
    
    pending_change = models.ForeignKey(PendingChange, on_delete=models.CASCADE, related_name='signatures')
    signed_by = models.ForeignKey(User, on_delete=models.CASCADE)
    signed_at = models.DateTimeField(auto_now_add=True)
    
    # Digital signature - could be enhanced with actual cryptographic signing
    signature_hash = models.CharField(max_length=64, help_text="SHA-256 hash of approval details")
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Additional approval metadata
    approval_notes = models.TextField(blank=True)
    
    class Meta:
        unique_together = ['pending_change', 'signed_by']  # One signature per user per change
        
    def save(self, *args, **kwargs):
        if not self.signature_hash:
            # Create signature hash from change details + user + timestamp
            import hashlib
            signature_data = f"{self.pending_change.uuid}{self.signed_by.id}{self.signed_at or timezone.now()}"
            self.signature_hash = hashlib.sha256(signature_data.encode()).hexdigest()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Signature by {self.signed_by.username} for {self.pending_change.get_change_summary()}"


class AuditLog(models.Model):
    """Enhanced audit log for all administrative changes"""
    
    ACTION_TYPES = [
        ('change_requested', 'Change Requested'),
        ('change_approved', 'Change Approved'),
        ('change_rejected', 'Change Rejected'),
        ('change_applied', 'Change Applied'),
        ('emergency_override', 'Emergency Override'),
    ]
    
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    
    # Who performed the action
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # What was affected
    target_model = models.CharField(max_length=50)
    target_id = models.CharField(max_length=255, null=True, blank=True)
    
    # Action details
    action_data = models.JSONField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Related approval if applicable
    related_change = models.ForeignKey(PendingChange, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        
    def __str__(self):
        return f"{self.get_action_type_display()} by {self.user.username} at {self.timestamp}"
