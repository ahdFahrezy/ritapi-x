import json
import hashlib
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from .models import PendingChange, ApprovalSignature, AuditLog


class ApprovalService:
    """Service class for handling approval workflow"""
    
    @staticmethod
    def get_admin_count():
        """Get count of admin users"""
        return User.objects.filter(is_superuser=True, is_active=True).count()
    
    @staticmethod
    def requires_approval():
        """Check if approval is required (more than 1 admin)"""
        return ApprovalService.get_admin_count() > 1
    
    @staticmethod
    def create_pending_change(user, change_type, target_model, change_data, 
                            target_id=None, original_data=None, justification=""):
        """Create a new pending change request"""
        
        pending_change = PendingChange.objects.create(
            change_type=change_type,
            requested_by=user,
            target_model=target_model,
            target_id=target_id,
            change_data=change_data,
            original_data=original_data,
            justification=justification
        )
        
        # Log the change request
        ApprovalService.log_audit(
            user=user,
            action_type='change_requested',
            target_model=target_model,
            target_id=target_id,
            action_data={
                'change_type': change_type,
                'pending_change_id': str(pending_change.uuid),
                'justification': justification
            },
            related_change=pending_change
        )
        
        # Send email notification to other admins
        ApprovalService.send_approval_notification(pending_change)
        
        return pending_change
    
    @staticmethod
    def approve_change(pending_change, approver, ip_address, user_agent, notes=""):
        """Approve a pending change"""
        
        if not pending_change.can_be_approved_by(approver):
            raise PermissionError("You cannot approve this change")
        
        if pending_change.status != 'pending':
            raise ValueError("Change is not in pending status")
        
        if pending_change.is_expired():
            pending_change.status = 'expired'
            pending_change.save()
            raise ValueError("Change has expired")
        
        # Create approval signature
        signature = ApprovalSignature.objects.create(
            pending_change=pending_change,
            signed_by=approver,
            ip_address=ip_address,
            user_agent=user_agent,
            approval_notes=notes
        )
        
        # Update pending change
        pending_change.status = 'approved'
        pending_change.approved_by = approver
        pending_change.approved_at = timezone.now()
        pending_change.save()
        
        # Log approval
        ApprovalService.log_audit(
            user=approver,
            action_type='change_approved',
            target_model=pending_change.target_model,
            target_id=pending_change.target_id,
            action_data={
                'pending_change_id': str(pending_change.uuid),
                'signature_hash': signature.signature_hash,
                'notes': notes
            },
            related_change=pending_change,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Apply the change
        ApprovalService.apply_approved_change(pending_change, approver, ip_address, user_agent)
        
        return signature
    
    @staticmethod
    def reject_change(pending_change, rejector, reason, ip_address, user_agent):
        """Reject a pending change"""
        
        if not pending_change.can_be_approved_by(rejector):
            raise PermissionError("You cannot reject this change")
        
        pending_change.status = 'rejected'
        pending_change.rejection_reason = reason
        pending_change.save()
        
        # Log rejection
        ApprovalService.log_audit(
            user=rejector,
            action_type='change_rejected',
            target_model=pending_change.target_model,
            target_id=pending_change.target_id,
            action_data={
                'pending_change_id': str(pending_change.uuid),
                'reason': reason
            },
            related_change=pending_change,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Send notification to requester
        ApprovalService.send_rejection_notification(pending_change, reason)
    
    @staticmethod
    def apply_approved_change(pending_change, applier, ip_address, user_agent):
        """Apply an approved change to the actual model"""
        
        try:
            if pending_change.change_type == 'service_create':
                from ops.ops_services.models import Service
                service = Service.objects.create(**pending_change.change_data)
                pending_change.target_id = str(service.uuid)
                pending_change.save()
                
            elif pending_change.change_type == 'service_update':
                from ops.ops_services.models import Service
                service = Service.objects.get(uuid=pending_change.target_id)
                for field, value in pending_change.change_data.items():
                    setattr(service, field, value)
                service.save()
                
            elif pending_change.change_type == 'service_delete':
                from ops.ops_services.models import Service
                service = Service.objects.get(uuid=pending_change.target_id)
                service.delete()
                
            elif pending_change.change_type == 'schema_create':
                from json_enforcer.models import JsonSchema
                from ops.ops_services.models import Service
                
                # Handle service relationship
                change_data = pending_change.change_data.copy()
                service_id = change_data.pop('service_id', None)
                service = None
                if service_id:
                    try:
                        service = Service.objects.get(id=service_id)
                    except Service.DoesNotExist:
                        service = None
                
                schema = JsonSchema.objects.create(service=service, **change_data)
                pending_change.target_id = str(schema.id)
                pending_change.save()
                
            elif pending_change.change_type == 'schema_update':
                from json_enforcer.models import JsonSchema
                from ops.ops_services.models import Service
                
                schema = JsonSchema.objects.get(id=pending_change.target_id)
                
                # Handle service relationship
                change_data = pending_change.change_data.copy()
                service_id = change_data.pop('service_id', None)
                
                if service_id:
                    try:
                        service = Service.objects.get(id=service_id)
                        schema.service = service
                    except Service.DoesNotExist:
                        schema.service = None
                else:
                    schema.service = None
                
                # Update other fields
                for field, value in change_data.items():
                    setattr(schema, field, value)
                schema.save()
                
            elif pending_change.change_type == 'schema_delete':
                from json_enforcer.models import JsonSchema
                schema = JsonSchema.objects.get(id=pending_change.target_id)
                schema.delete()
            
            # Log successful application
            ApprovalService.log_audit(
                user=applier,
                action_type='change_applied',
                target_model=pending_change.target_model,
                target_id=pending_change.target_id,
                action_data={
                    'pending_change_id': str(pending_change.uuid),
                    'applied_data': pending_change.change_data
                },
                related_change=pending_change,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
        except Exception as e:
            # Log error
            ApprovalService.log_audit(
                user=applier,
                action_type='change_applied',
                target_model=pending_change.target_model,
                target_id=pending_change.target_id,
                action_data={
                    'pending_change_id': str(pending_change.uuid),
                    'error': str(e),
                    'applied_data': pending_change.change_data
                },
                related_change=pending_change,
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise
    
    @staticmethod
    def apply_change_directly(user, change_type, target_model, change_data, 
                            target_id=None, original_data=None, ip_address=None, user_agent=None):
        """Apply change directly without approval (single admin scenario)"""
        
        # Log emergency override
        ApprovalService.log_audit(
            user=user,
            action_type='emergency_override',
            target_model=target_model,
            target_id=target_id,
            action_data={
                'change_type': change_type,
                'change_data': change_data,
                'reason': 'Single admin - no approval required'
            },
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Create a fake pending change for logging purposes
        pending_change = PendingChange(
            change_type=change_type,
            requested_by=user,
            target_model=target_model,
            target_id=target_id,
            change_data=change_data,
            original_data=original_data,
            status='approved',
            approved_by=user,
            approved_at=timezone.now()
        )
        
        # Apply the change
        ApprovalService.apply_approved_change(pending_change, user, ip_address, user_agent)
        
        return pending_change
    
    @staticmethod
    def send_approval_notification(pending_change):
        """Send email notification for approval request"""
        
        # Get all admin users except the requester
        admins = User.objects.filter(
            is_superuser=True, 
            is_active=True
        ).exclude(id=pending_change.requested_by.id)
        
        if not admins.exists():
            return
        
        subject = f"[RITAPI] Approval Required: {pending_change.get_change_summary()}"
        
        message = f"""
A new change request requires your approval:

Change Type: {pending_change.get_change_type_display()}
Requested by: {pending_change.requested_by.username}
Requested at: {pending_change.requested_at}
Expires at: {pending_change.expires_at}

Summary: {pending_change.get_change_summary()}

Justification: {pending_change.justification}

Please review and approve/reject this change in the admin dashboard.

Change ID: {pending_change.uuid}
        """
        
        recipient_emails = [admin.email for admin in admins if admin.email]
        
        if recipient_emails:
            try:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@ritapi.local'),
                    recipient_list=recipient_emails,
                    fail_silently=False
                )
            except Exception as e:
                # Log email failure but don't fail the approval request
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to send approval notification: {e}")
    
    @staticmethod
    def send_rejection_notification(pending_change, reason):
        """Send email notification for rejection"""
        
        if not pending_change.requested_by.email:
            return
        
        subject = f"[RITAPI] Change Request Rejected: {pending_change.get_change_summary()}"
        
        message = f"""
Your change request has been rejected:

Change Type: {pending_change.get_change_type_display()}
Summary: {pending_change.get_change_summary()}
Requested at: {pending_change.requested_at}

Reason for rejection: {reason}

Change ID: {pending_change.uuid}
        """
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@ritapi.local'),
                recipient_list=[pending_change.requested_by.email],
                fail_silently=False
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send rejection notification: {e}")
    
    @staticmethod
    def log_audit(user, action_type, target_model, target_id, action_data, 
                 related_change=None, ip_address=None, user_agent=None):
        """Create an audit log entry"""
        
        return AuditLog.objects.create(
            action_type=action_type,
            user=user,
            target_model=target_model,
            target_id=target_id,
            action_data=action_data,
            related_change=related_change,
            ip_address=ip_address or '127.0.0.1',
            user_agent=user_agent or 'Unknown'
        )
    
    @staticmethod
    def cleanup_expired_changes():
        """Cleanup expired pending changes"""
        
        expired_changes = PendingChange.objects.filter(
            status='pending',
            expires_at__lt=timezone.now()
        )
        
        for change in expired_changes:
            change.status = 'expired'
            change.save()
            
            # Log expiration
            ApprovalService.log_audit(
                user=change.requested_by,
                action_type='change_expired',
                target_model=change.target_model,
                target_id=change.target_id,
                action_data={
                    'pending_change_id': str(change.uuid),
                    'expired_at': timezone.now().isoformat()
                },
                related_change=change
            )
        
        return expired_changes.count()
