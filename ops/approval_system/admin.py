from django.contrib import admin
from .models import PendingChange, ApprovalSignature, AuditLog


@admin.register(PendingChange)
class PendingChangeAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'change_type', 'status', 'requested_by', 'requested_at', 'expires_at']
    list_filter = ['change_type', 'status', 'requested_at']
    search_fields = ['uuid', 'requested_by__username', 'target_id']
    readonly_fields = ['uuid', 'requested_at', 'expires_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('uuid', 'change_type', 'status', 'target_model', 'target_id')
        }),
        ('Request Details', {
            'fields': ('requested_by', 'requested_at', 'expires_at', 'justification')
        }),
        ('Change Data', {
            'fields': ('change_data', 'original_data'),
            'classes': ('collapse',)
        }),
        ('Approval', {
            'fields': ('approved_by', 'approved_at', 'rejection_reason')
        }),
    )


@admin.register(ApprovalSignature)
class ApprovalSignatureAdmin(admin.ModelAdmin):
    list_display = ['pending_change', 'signed_by', 'signed_at', 'signature_hash']
    list_filter = ['signed_at', 'signed_by']
    readonly_fields = ['signature_hash', 'signed_at']


@admin.register(AuditLog) 
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'action_type', 'user', 'timestamp', 'target_model', 'target_id']
    list_filter = ['action_type', 'timestamp', 'target_model']
    search_fields = ['uuid', 'user__username', 'target_id']
    readonly_fields = ['uuid', 'timestamp']
    
    def has_add_permission(self, request):
        return False  # Audit logs should not be manually created
    
    def has_delete_permission(self, request, obj=None):
        return False  # Audit logs should not be deleted
