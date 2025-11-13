# ops/views.py
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from json_enforcer.models import JsonSchema
from django.views.decorators.http import require_POST
from ops.ops_services.models import Service
from ops.approval_system.services import ApprovalService
from uuid import UUID
import json
from django.http import JsonResponse


@login_required
def jsonschema_dashboard(request):
    """
    Dashboard CRUD JsonSchema dengan modal
    """
    schemas = JsonSchema.objects.all().order_by("-timestamp")
    paginator = Paginator(schemas, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    
    services = Service.objects.all().order_by("-timestamp")

    return render(request, "ops_template/json_dashboard.html", {
        "page_obj": page_obj,
        "services": services,
    })


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@login_required
def jsonschema_create(request):
    if request.method == "POST":
        name = request.POST.get("name")
        endpoint = request.POST.get("endpoint")
        method = request.POST.get("method", "POST")
        schema_json = request.POST.get("schema_json")
        description = request.POST.get("description")
        service_uuid = request.POST.get("service_uuid")
        justification = request.POST.get("justification", "")
        rollout_mode = request.POST.get("rollout_mode", "monitor")

        try:
            schema_data = json.loads(schema_json) if schema_json else {}
        except json.JSONDecodeError as e:
            return JsonResponse({
                "success": False,
                "message": f"Schema JSON Invalid"
            }, status=400)

        # Prepare change data
        change_data = {
            'name': name,
            'endpoint': endpoint,
            'method': method,
            'schema_json': schema_data,
            'description': description,
            'rollout_mode': rollout_mode,
        }
        
        # Add service reference if provided
        if service_uuid:
            try:
                service = Service.objects.get(uuid=UUID(service_uuid))
                change_data['service_id'] = service.id
            except (Service.DoesNotExist, ValueError):
                return JsonResponse({
                    "success": False,
                    "message": "Service tidak ditemukan"
                }, status=400)

        try:
            # Check if approval is required
            if ApprovalService.requires_approval():
                # Create pending change for approval
                pending_change = ApprovalService.create_pending_change(
                    user=request.user,
                    change_type='schema_create',
                    target_model='JsonSchema',
                    change_data=change_data,
                    justification=justification
                )
                
                return JsonResponse({
                    "success": True,
                    "message": f"Schema creation request submitted for approval. Change ID: {pending_change.uuid}",
                    "requires_approval": True,
                    "change_id": str(pending_change.uuid)
                })
            else:
                # Apply change directly (single admin scenario)
                ip_address = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
                
                ApprovalService.apply_change_directly(
                    user=request.user,
                    change_type='schema_create',
                    target_model='JsonSchema',
                    change_data=change_data,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                return JsonResponse({
                    "success": True,
                    "message": "Schema berhasil dibuat",
                    "requires_approval": False
                })
                
        except Exception as e:
            return JsonResponse({
                "success": False,
                "message": f"Gagal memproses permintaan: {str(e)}"
            }, status=500)
    return JsonResponse({"success": False}, status=400)


@login_required
def jsonschema_update(request, pk):
    schema = get_object_or_404(JsonSchema, pk=pk)
    if request.method == "POST":
        name = request.POST.get("name")
        endpoint = request.POST.get("endpoint")
        method = request.POST.get("method", "POST")
        schema_json = request.POST.get("schema_json")
        description = request.POST.get("description")
        service_uuid = request.POST.get("service_uuid")
        justification = request.POST.get("justification", "")
        rollout_mode = request.POST.get("rollout_mode", "monitor")

        try:
            schema_data = json.loads(schema_json) if schema_json else {}
        except json.JSONDecodeError as e:
            return JsonResponse({
                "success": False,
                "message": f"Schema JSON Invalid"
            }, status=400)
        
        # Prepare original data for audit
        original_data = {
            'name': schema.name,
            'endpoint': schema.endpoint,
            'method': schema.method,
            'schema_json': schema.schema_json,
            'description': schema.description,
            'service_id': schema.service.id if schema.service else None,
            'rollout_mode': schema.rollout_mode,
        }
        
        # Prepare change data
        change_data = {
            'name': name,
            'endpoint': endpoint,
            'method': method,
            'schema_json': schema_data,
            'description': description,
            'rollout_mode': rollout_mode,
        }
        
        # Add service reference if provided
        if service_uuid:
            try:
                service = Service.objects.get(uuid=UUID(service_uuid))
                change_data['service_id'] = service.id
            except (Service.DoesNotExist, ValueError):
                return JsonResponse({
                    "success": False,
                    "message": "Service tidak ditemukan"
                }, status=400)
        else:
            change_data['service_id'] = None

        try:
            # Check if approval is required
            if ApprovalService.requires_approval():
                # Create pending change for approval
                pending_change = ApprovalService.create_pending_change(
                    user=request.user,
                    change_type='schema_update',
                    target_model='JsonSchema',
                    target_id=str(schema.id),
                    change_data=change_data,
                    original_data=original_data,
                    justification=justification
                )
                
                return JsonResponse({
                    "success": True,
                    "message": f"Schema update request submitted for approval. Change ID: {pending_change.uuid}",
                    "requires_approval": True,
                    "change_id": str(pending_change.uuid)
                })
            else:
                # Apply change directly (single admin scenario)
                ip_address = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
                
                ApprovalService.apply_change_directly(
                    user=request.user,
                    change_type='schema_update',
                    target_model='JsonSchema',
                    target_id=str(schema.id),
                    change_data=change_data,
                    original_data=original_data,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                return JsonResponse({
                    "success": True,
                    "message": "Schema berhasil diperbarui",
                    "requires_approval": False
                })
                
        except Exception as e:
            return JsonResponse({
                "success": False,
                "message": f"Gagal memproses permintaan: {str(e)}"
            }, status=500)
    return JsonResponse({"success": False}, status=400)


@login_required
def jsonschema_delete(request, pk):
    schema = get_object_or_404(JsonSchema, pk=pk)
    
    if request.method == "POST":
        justification = request.POST.get("justification", "")
        
        # Prepare original data for audit
        original_data = {
            'name': schema.name,
            'endpoint': schema.endpoint,
            'method': schema.method,
            'schema_json': schema.schema_json,
            'description': schema.description,
            'service_id': schema.service.id if schema.service else None,
        }

        try:
            # Check if approval is required
            if ApprovalService.requires_approval():
                # Create pending change for approval
                pending_change = ApprovalService.create_pending_change(
                    user=request.user,
                    change_type='schema_delete',
                    target_model='JsonSchema',
                    target_id=str(schema.id),
                    change_data={},  # No new data for delete
                    original_data=original_data,
                    justification=justification
                )
                
                return JsonResponse({
                    "success": True,
                    "message": f"Schema deletion request submitted for approval. Change ID: {pending_change.uuid}",
                    "requires_approval": True,
                    "change_id": str(pending_change.uuid)
                })
            else:
                # Apply change directly (single admin scenario)
                ip_address = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
                
                ApprovalService.apply_change_directly(
                    user=request.user,
                    change_type='schema_delete',
                    target_model='JsonSchema',
                    target_id=str(schema.id),
                    change_data={},
                    original_data=original_data,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                return JsonResponse({
                    "success": True,
                    "message": "Schema berhasil dihapus",
                    "requires_approval": False
                })
                
        except Exception as e:
            return JsonResponse({
                "success": False,
                "message": f"Gagal memproses permintaan: {str(e)}"
            }, status=500)
    
    # For GET request or non-POST, return error
    return JsonResponse({"success": False, "message": "Method not allowed"}, status=405)

@login_required
@require_POST
def jsonschema_toggle(request, pk):
    schema = get_object_or_404(JsonSchema, pk=pk)
    justification = request.POST.get("justification", "")
    
    # Prepare original data for audit
    original_data = {
        'name': schema.name,
        'endpoint': schema.endpoint,
        'method': schema.method,
        'schema_json': schema.schema_json,
        'description': schema.description,
        'service_id': schema.service.id if schema.service else None,
        'is_active': schema.is_active,
    }
    
    # Prepare change data (toggle the is_active status)
    change_data = {
        'name': schema.name,
        'endpoint': schema.endpoint,
        'method': schema.method,
        'schema_json': schema.schema_json,
        'description': schema.description,
        'service_id': schema.service.id if schema.service else None,
        'is_active': not schema.is_active,
    }

    try:
        # Check if approval is required
        if ApprovalService.requires_approval():
            # Create pending change for approval
            pending_change = ApprovalService.create_pending_change(
                user=request.user,
                change_type='schema_update',
                target_model='JsonSchema',
                target_id=str(schema.id),
                change_data=change_data,
                original_data=original_data,
                justification=justification or f"Toggle schema status to {'inactive' if schema.is_active else 'active'}"
            )
            
            return JsonResponse({
                "success": True,
                "message": f"Schema toggle request submitted for approval. Change ID: {pending_change.uuid}",
                "requires_approval": True,
                "change_id": str(pending_change.uuid),
                "current_status": schema.is_active
            })
        else:
            # Apply change directly (single admin scenario)
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
            
            ApprovalService.apply_change_directly(
                user=request.user,
                change_type='schema_update',
                target_model='JsonSchema',
                target_id=str(schema.id),
                change_data=change_data,
                original_data=original_data,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Refresh schema to get updated status
            schema.refresh_from_db()
            
            return JsonResponse({
                "success": True,
                "message": f"Schema status berhasil diubah",
                "requires_approval": False,
                "is_active": schema.is_active
            })
            
    except Exception as e:
        return JsonResponse({
            "success": False,
            "message": f"Gagal memproses permintaan: {str(e)}"
        }, status=500)
