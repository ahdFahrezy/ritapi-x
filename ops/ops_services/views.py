import os
import json
import logging
import uuid
from django.conf import settings
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views import View
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.core.validators import URLValidator
from .models import Service
from ops.approval_system.services import ApprovalService
from utils.ip import get_client_ip

logger = logging.getLogger(__name__)


@login_required
def service_dashboard(request):
    """Dashboard view untuk mengelola service dengan search dan pagination"""
    try:
        search_query = request.GET.get("search", "")
        max_services = int(os.getenv("MAX_SERVICES", 10))  # default 10

        if search_query:
            services = Service.objects.filter(
                target_base_url__icontains=search_query
            ).order_by("timestamp")[:max_services]
        else:
            services = Service.objects.all().order_by("timestamp")[:max_services]

        paginator = Paginator(services, 10)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)
        total_services = services.count()

        context = {
            "services": page_obj,
            "page_obj": page_obj,
            "total_services": total_services,
            "search_query": search_query,
            "page_title": "Service Management Dashboard",
        }
        return render(request, "ops_template/service_dashboard.html", context)

    except Exception as e:
        logger.error(f"Error displaying service dashboard: {e}")
        return render(
            request,
            "ops_template/service_dashboard.html",
            {
                "services": [],
                "total_services": 0,
                "page_title": "Service Management Dashboard",
            },
        )


@login_required
def service_detail_view(request, service_uuid):
    """View untuk menampilkan detail service"""
    try:
        service = get_object_or_404(Service, uuid=service_uuid)
        context = {
            "service": service,
            "page_title": f"Service Detail - {service.target_base_url}",
        }
        return render(request, "ops_template/service_detail.html", context)
    except Exception as e:
        logger.error(f"Error displaying service detail {service_uuid}: {e}")
        return redirect("ops_services:service_dashboard")


@method_decorator([login_required], name="dispatch")
class ServiceListView(View):
    """View untuk menampilkan daftar semua service yang tersedia"""

    def get(self, request):
        try:
            services = Service.objects.all().order_by("-timestamp")
            service_list = [
                {
                    "uuid": str(s.uuid),
                    "host_name": s.host_name,
                    "target_base_url": s.target_base_url,
                    "allowed_origins": s.get_allowed_origins(),
                    "timestamp": s.timestamp.isoformat(),
                    "status": "active",
                }
                for s in services
            ]
            return JsonResponse(
                {"status": "success", "count": len(service_list), "services": service_list}
            )
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    def post(self, request):
        try:
            data = json.loads(request.body)
            host_name = data.get("host_name", "")
            target_url = data.get("target_base_url")
            allowed_origins = data.get("allowed_origins", "")
            justification = data.get("justification", "")

            if not target_url:
                return JsonResponse(
                    {"status": "error", "message": "target_base_url is required"},
                    status=400,
                )

            max_services = int(os.getenv("MAX_SERVICES", 10))
            if Service.objects.count() >= max_services:
                return JsonResponse(
                    {
                        "status": "error",
                        "message": f"Maximum number of services ({max_services}) reached.",
                    },
                    status=400,
                )
                
            if host_name and len(host_name) > 255:
                return JsonResponse(
                    {"status": "error", "message": "host_name too long (max 255 chars)"}, status=400
                )

            # Validate URL
            try:
                URLValidator()(target_url)
            except ValidationError:
                return JsonResponse(
                    {"status": "error", "message": "Invalid URL format"}, status=400
                )

            change_data = {
                "host_name": host_name,
                "target_base_url": target_url,
                "allowed_origins": allowed_origins,
                "allowed_paths": data.get("allowed_paths", ""),
                "allowed_methods": data.get("allowed_methods", ""),
                "allowed_schemes": data.get("allowed_schemes", "https"),
            }

            # Check if approval is required
            if ApprovalService.requires_approval():
                # Create pending change for approval
                pending_change = ApprovalService.create_pending_change(
                    user=request.user,
                    change_type='service_create',
                    target_model='Service',
                    change_data=change_data,
                    justification=justification
                )
                
                return JsonResponse(
                    {
                        "status": "pending_approval",
                        "message": "Service creation request submitted for approval",
                        "pending_change_id": str(pending_change.uuid),
                        "expires_at": pending_change.expires_at.isoformat(),
                    },
                    status=202,
                )
            else:
                # Single admin - apply directly
                client_ip = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
                
                pending_change = ApprovalService.apply_change_directly(
                    user=request.user,
                    change_type='service_create',
                    target_model='Service',
                    change_data=change_data,
                    ip_address=client_ip,
                    user_agent=user_agent
                )
                
                # Get the created service
                service = Service.objects.get(uuid=pending_change.target_id)
                
                return JsonResponse(
                    {
                        "status": "success",
                        "message": "Service created successfully (single admin - no approval required)",
                        "service": {
                            "uuid": str(service.uuid),
                            "host_name": getattr(service, "host_name", ""), 
                            "target_base_url": service.target_base_url,
                            "allowed_origins": service.get_allowed_origins(),
                            "timestamp": service.timestamp.isoformat(),
                        },
                    },
                    status=201,
                )
                
        except json.JSONDecodeError:
            return JsonResponse(
                {"status": "error", "message": "Invalid JSON format"}, status=400
            )
        except Exception as e:
            logger.error(f"Error creating service: {e}")
            return JsonResponse({"status": "error", "message": str(e)}, status=500)


@method_decorator([login_required], name="dispatch")
class ServiceDetailView(View):
    """View untuk detail, update, dan delete service"""

    def get(self, request, service_uuid):
        try:
            service = get_object_or_404(Service, uuid=service_uuid)
            return JsonResponse(
                {
                    "status": "success",
                    "service": {
                        "uuid": str(service.uuid),
                        "host_name": getattr(service, "host_name", ""),
                        "target_base_url": service.target_base_url,
                        "allowed_origins": service.get_allowed_origins(),
                        "timestamp": service.timestamp.isoformat(),
                        "allowed_schemes": service.allowed_schemes,
                    },
                }
            )
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    def put(self, request, service_uuid):
        try:
            service = get_object_or_404(Service, uuid=service_uuid)
            data = json.loads(request.body)
            justification = data.get("justification", "")

            # Store original data for audit
            original_data = {
                "host_name": getattr(service, "host_name", ""), 
                "target_base_url": service.target_base_url,
                "allowed_origins": service.allowed_origins,
                "allowed_paths": service.allowed_paths,
                "allowed_methods": service.allowed_methods,
                "allowed_schemes": service.allowed_schemes,
            }

            # Prepare change data
            change_data = {}
            
            if "host_name" in data:
                new_host = data.get("host_name", "")
                if new_host != getattr(service, "host_name", ""):
                    if len(new_host) > 255:
                        return JsonResponse(
                            {"status": "error", "message": "host_name too long (max 255 chars)"},
                            status=400,
                        )
                    change_data["host_name"] = new_host
            
            target_url = data.get("target_base_url")
            if target_url and target_url != service.target_base_url:
                try:
                    URLValidator()(target_url)
                    change_data["target_base_url"] = target_url
                except ValidationError:
                    return JsonResponse(
                        {"status": "error", "message": "Invalid URL format"}, status=400
                    )

            for field in ["allowed_origins", "allowed_paths", "allowed_methods", "allowed_schemes"]:
                if field in data and data[field] != getattr(service, field):
                    change_data[field] = data[field]

            if not change_data:
                return JsonResponse(
                    {"status": "info", "message": "No changes detected"}, status=200
                )

            # Check if approval is required
            if ApprovalService.requires_approval():
                # Create pending change for approval
                pending_change = ApprovalService.create_pending_change(
                    user=request.user,
                    change_type='service_update',
                    target_model='Service',
                    target_id=str(service.uuid),
                    change_data=change_data,
                    original_data=original_data,
                    justification=justification
                )
                
                return JsonResponse(
                    {
                        "status": "pending_approval",
                        "message": "Service update request submitted for approval",
                        "pending_change_id": str(pending_change.uuid),
                        "expires_at": pending_change.expires_at.isoformat(),
                        "changes": change_data,
                    },
                    status=202,
                )
            else:
                # Single admin - apply directly
                client_ip = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
                
                ApprovalService.apply_change_directly(
                    user=request.user,
                    change_type='service_update',
                    target_model='Service',
                    target_id=str(service.uuid),
                    change_data=change_data,
                    original_data=original_data,
                    ip_address=client_ip,
                    user_agent=user_agent
                )
                
                # Refresh service from DB
                service.refresh_from_db()
                
                return JsonResponse(
                    {
                        "status": "success",
                        "message": "Service updated successfully (single admin - no approval required)",
                        "service": {
                            "uuid": str(service.uuid),
                            "host_name": getattr(service, "host_name", ""),
                            "target_base_url": service.target_base_url,
                            "allowed_origins": service.get_allowed_origins(),
                            "allowed_schemes": service.allowed_schemes,
                            "timestamp": service.timestamp.isoformat(),
                        },
                    }
                )
                
        except json.JSONDecodeError:
            return JsonResponse(
                {"status": "error", "message": "Invalid JSON format"}, status=400
            )
        except Exception as e:
            logger.error(f"Error updating service: {e}")
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    def delete(self, request, service_uuid):
        try:
            service = get_object_or_404(Service, uuid=service_uuid)
            
            # Store original data for audit
            original_data = {
                "target_base_url": service.target_base_url,
                "allowed_origins": service.allowed_origins,
                "allowed_paths": service.allowed_paths,
                "allowed_methods": service.allowed_methods,
                "allowed_schemes": service.allowed_schemes,
            }
            
            # Get justification from request body if provided
            justification = ""
            try:
                if request.body:
                    data = json.loads(request.body)
                    justification = data.get("justification", "")
            except json.JSONDecodeError:
                pass  # No justification provided

            # Check if approval is required
            if ApprovalService.requires_approval():
                # Create pending change for approval
                pending_change = ApprovalService.create_pending_change(
                    user=request.user,
                    change_type='service_delete',
                    target_model='Service',
                    target_id=str(service.uuid),
                    change_data={},  # No new data for deletion
                    original_data=original_data,
                    justification=justification
                )
                
                return JsonResponse(
                    {
                        "status": "pending_approval",
                        "message": "Service deletion request submitted for approval",
                        "pending_change_id": str(pending_change.uuid),
                        "expires_at": pending_change.expires_at.isoformat(),
                    },
                    status=202,
                )
            else:
                # Single admin - apply directly
                client_ip = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
                
                ApprovalService.apply_change_directly(
                    user=request.user,
                    change_type='service_delete',
                    target_model='Service',
                    target_id=str(service.uuid),
                    change_data={},
                    original_data=original_data,
                    ip_address=client_ip,
                    user_agent=user_agent
                )
                
                return JsonResponse(
                    {"status": "success", "message": "Service deleted successfully (single admin - no approval required)"}
                )
                
        except Exception as e:
            logger.error(f"Error deleting service: {e}")
            return JsonResponse({"status": "error", "message": str(e)}, status=500)


@require_http_methods(["GET"])
def service_status(request):
    """Endpoint untuk health check dan status service"""
    try:
        total_services = Service.objects.count()
        active_services = Service.objects.filter(target_base_url__isnull=False).count()
        return JsonResponse(
            {
                "status": "healthy",
                "services": {"total": total_services, "active": active_services},
                "waf": {"status": "operational", "version": "1.0.0"},
            }
        )
    except Exception as e:
        return JsonResponse({"status": "unhealthy", "error": str(e)}, status=500)
