import json
import logging
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views import View
from django.core.paginator import Paginator
from django.contrib import messages
from django.urls import reverse
from .models import PendingChange, ApprovalSignature, AuditLog
from .services import ApprovalService
from utils.ip import get_client_ip

logger = logging.getLogger(__name__)


@login_required
def approval_dashboard(request):
    """Dashboard view untuk mengelola pending approvals"""
    try:
        # Filter pending changes
        pending_changes_qs = PendingChange.objects.filter(
            status='pending'
        ).order_by('-requested_at')
        
        # Get pending changes count for each user
        my_pending = pending_changes_qs.filter(requested_by=request.user).count()
        
        # Add can_approve flag to each change
        pending_changes = []
        awaiting_my_approval_count = 0
        for change in pending_changes_qs:
            change.can_approve = change.can_be_approved_by(request.user)
            if change.can_approve:
                awaiting_my_approval_count += 1
            pending_changes.append(change)
        
        # Paginate pending changes
        paginator = Paginator(pending_changes, 10)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        # Get recent audit logs
        recent_logs = AuditLog.objects.all().order_by('-timestamp')[:20]
        
        context = {
            'pending_changes': page_obj,
            'my_pending_count': my_pending,
            'awaiting_my_approval_count': awaiting_my_approval_count,
            'recent_logs': recent_logs,
            'total_admins': ApprovalService.get_admin_count(),
            'requires_approval': ApprovalService.requires_approval(),
            'page_title': 'Approval Dashboard',
        }
        return render(request, 'approval_system/dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Error displaying approval dashboard: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Return empty data to avoid template errors
        return render(request, 'approval_system/dashboard.html', {
            'pending_changes': [],
            'my_pending_count': 0,
            'awaiting_my_approval_count': 0,
            'recent_logs': [],
            'total_admins': 1,
            'requires_approval': False,
            'error': str(e),
            'page_title': 'Approval Dashboard',
        })


@login_required
def pending_change_detail(request, change_uuid):
    """View untuk detail pending change"""
    try:
        pending_change = get_object_or_404(PendingChange, uuid=change_uuid)
        
        context = {
            'pending_change': pending_change,
            'can_approve': pending_change.can_be_approved_by(request.user),
            'signatures': pending_change.signatures.all(),
            'page_title': f'Change Request - {pending_change.get_change_summary()}',
        }
        return render(request, 'approval_system/change_detail.html', context)
        
    except Exception as e:
        logger.error(f"Error displaying change detail {change_uuid}: {e}")
        messages.error(request, f"Error loading change details: {e}")
        return redirect('approval_system:dashboard')


@method_decorator([login_required], name="dispatch")
class ApprovalActionView(View):
    """View untuk approve/reject pending changes"""
    
    def post(self, request, change_uuid):
        try:
            pending_change = get_object_or_404(PendingChange, uuid=change_uuid)
            data = json.loads(request.body)
            action = data.get('action')  # 'approve' or 'reject'
            notes = data.get('notes', '')
            
            if not pending_change.can_be_approved_by(request.user):
                return JsonResponse({
                    'status': 'error',
                    'message': 'You cannot approve this change'
                }, status=403)
            
            client_ip = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
            
            if action == 'approve':
                try:
                    signature = ApprovalService.approve_change(
                        pending_change=pending_change,
                        approver=request.user,
                        ip_address=client_ip,
                        user_agent=user_agent,
                        notes=notes
                    )
                    
                    return JsonResponse({
                        'status': 'success',
                        'message': 'Change approved and applied successfully',
                        'signature_hash': signature.signature_hash
                    })
                    
                except Exception as e:
                    logger.error(f"Error approving change {change_uuid}: {e}")
                    return JsonResponse({
                        'status': 'error',
                        'message': str(e)
                    }, status=400)
                    
            elif action == 'reject':
                reason = data.get('reason', 'No reason provided')
                
                try:
                    ApprovalService.reject_change(
                        pending_change=pending_change,
                        rejector=request.user,
                        reason=reason,
                        ip_address=client_ip,
                        user_agent=user_agent
                    )
                    
                    return JsonResponse({
                        'status': 'success',
                        'message': 'Change rejected successfully'
                    })
                    
                except Exception as e:
                    logger.error(f"Error rejecting change {change_uuid}: {e}")
                    return JsonResponse({
                        'status': 'error',
                        'message': str(e)
                    }, status=400)
            
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid action'
                }, status=400)
                
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON format'
            }, status=400)
        except Exception as e:
            logger.error(f"Error processing approval action: {e}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)


@method_decorator([login_required], name="dispatch")
class PendingChangesListView(View):
    """API view untuk daftar pending changes"""
    
    def get(self, request):
        try:
            status_filter = request.GET.get('status', 'pending')
            my_requests = request.GET.get('my_requests', 'false').lower() == 'true'
            
            pending_changes = PendingChange.objects.all()
            
            if status_filter != 'all':
                pending_changes = pending_changes.filter(status=status_filter)
            
            if my_requests:
                pending_changes = pending_changes.filter(requested_by=request.user)
            
            pending_changes = pending_changes.order_by('-requested_at')
            
            changes_data = []
            for change in pending_changes:
                changes_data.append({
                    'uuid': str(change.uuid),
                    'change_type': change.change_type,
                    'change_type_display': change.get_change_type_display(),
                    'status': change.status,
                    'status_display': change.get_status_display(),
                    'summary': change.get_change_summary(),
                    'requested_by': change.requested_by.username,
                    'requested_at': change.requested_at.isoformat(),
                    'expires_at': change.expires_at.isoformat(),
                    'can_approve': change.can_be_approved_by(request.user),
                    'is_expired': change.is_expired(),
                    'approved_by': change.approved_by.username if change.approved_by else None,
                    'approved_at': change.approved_at.isoformat() if change.approved_at else None,
                })
            
            return JsonResponse({
                'status': 'success',
                'count': len(changes_data),
                'changes': changes_data
            })
            
        except Exception as e:
            logger.error(f"Error fetching pending changes: {e}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)


@method_decorator([login_required], name="dispatch")
class AuditLogView(View):
    """API view untuk audit logs"""
    
    def get(self, request):
        try:
            action_filter = request.GET.get('action')
            user_filter = request.GET.get('user')
            limit = int(request.GET.get('limit', 50))
            
            audit_logs = AuditLog.objects.all()
            
            if action_filter:
                audit_logs = audit_logs.filter(action_type=action_filter)
            
            if user_filter:
                audit_logs = audit_logs.filter(user__username=user_filter)
            
            audit_logs = audit_logs.order_by('-timestamp')[:limit]
            
            logs_data = []
            for log in audit_logs:
                logs_data.append({
                    'uuid': str(log.uuid),
                    'action_type': log.action_type,
                    'action_type_display': log.get_action_type_display(),
                    'user': log.user.username,
                    'timestamp': log.timestamp.isoformat(),
                    'target_model': log.target_model,
                    'target_id': log.target_id,
                    'action_data': log.action_data,
                    'ip_address': log.ip_address,
                    'related_change_id': str(log.related_change.uuid) if log.related_change else None,
                })
            
            return JsonResponse({
                'status': 'success',
                'count': len(logs_data),
                'logs': logs_data
            })
            
        except Exception as e:
            logger.error(f"Error fetching audit logs: {e}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)


@require_http_methods(["POST"])
@login_required
def cleanup_expired_changes(request):
    """Endpoint untuk cleanup expired changes (admin only)"""
    try:
        if not request.user.is_superuser:
            return JsonResponse({
                'status': 'error',
                'message': 'Permission denied'
            }, status=403)
        
        count = ApprovalService.cleanup_expired_changes()
        
        return JsonResponse({
            'status': 'success',
            'message': f'Cleaned up {count} expired changes',
            'count': count
        })
        
    except Exception as e:
        logger.error(f"Error cleaning up expired changes: {e}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)
