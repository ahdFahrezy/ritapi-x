# ops/views.py
import ipaddress
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render
from ip_reputation.models import IpReputation
from ip_reputation.services import IpReputationService
from django.contrib import messages
from django.utils import timezone
from uuid import UUID
from django.http import JsonResponse
from ip_reputation.models import InternalIPList
from django.views.decorators.http import require_http_methods
from ops.ops_services.models import Service

@login_required
def ip_reputation_dashboard(request):
    """
    IP Reputation dashboard: check new IP + show history.
    """
    result = None
    error_message = None

    if request.method == "POST":
        ip_address = request.POST.get("ip_address")
        if ip_address:
            # ✅ Validate IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                error_message = f"'{ip_address}' is not a valid IP address."
            else:
                result = IpReputationService.check_reputation(ip_address)
                if not result:
                    error_message = f"No reputation data found for IP {ip_address}."
                else:
                    messages.success(request, f"Reputation check for IP {ip_address} completed successfully.")

    # ✅ Fetch history with pagination
    records = IpReputation.objects.all().order_by("-timestamp")
    paginator = Paginator(records, 10)
    page_number = request.GET.get("page")
    history = paginator.get_page(page_number)

    return render(request, "ops_template/ip_reputation.html", {
        "result": result,
        "error_message": error_message,  # ✅ pass to template
        "history": history,
    })

@login_required
def internal_ip_dashboard(request):
    """
    Dashboard to manage internal allow/deny IP list
    """
    entries = InternalIPList.objects.select_related("service").order_by("-created_at")
    paginator = Paginator(entries, 20)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    services = Service.objects.all().order_by("target_base_url")

    return render(request, "ops_template/internal_ip_dashboard.html", {
        "page_obj": page_obj,
        "services": services,
    })
    
@login_required
@require_http_methods(["POST"])
def internal_ip_create(request):
    try:
        ip_address = request.POST.get("ip_address")
        list_type = request.POST.get("list_type")
        service_uuid = request.POST.get("service_uuid")
        expires_at = request.POST.get("expires_at")
        reason = request.POST.get("reason", "")

        ipaddress.ip_address(ip_address)

        service = None
        if service_uuid:
            service = Service.objects.get(uuid=UUID(service_uuid))

        entry = InternalIPList(
            ip_address=ip_address,
            list_type=list_type,
            service=service,
            reason=reason
        )

        if expires_at:
            entry.expires_at = timezone.datetime.fromisoformat(expires_at)

        entry.save()
        return JsonResponse({"success": True, "message": "Entry created"})

    except Exception as e:
        return JsonResponse({"success": False, "message": str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def internal_ip_update(request, pk):
    try:
        entry = InternalIPList.objects.get(pk=pk)
        ip_address = request.POST.get("ip_address")
        list_type = request.POST.get("list_type")
        service_uuid = request.POST.get("service_uuid")
        expires_at = request.POST.get("expires_at")
        reason = request.POST.get("reason", "")

        ipaddress.ip_address(ip_address)

        service = None
        if service_uuid:
            service = Service.objects.get(uuid=UUID(service_uuid))

        entry.ip_address = ip_address
        entry.list_type = list_type
        entry.service = service
        entry.reason = reason

        if expires_at:
            entry.expires_at = timezone.datetime.fromisoformat(expires_at)
        else:
            entry.expires_at = None

        entry.save()
        return JsonResponse({"success": True, "message": "Entry updated"})

    except Exception as e:
        return JsonResponse({"success": False, "message": str(e)}, status=400)

@login_required
@require_http_methods(["POST"])
def internal_ip_delete(request, pk):
    try:
        entry = InternalIPList.objects.get(pk=pk)
        entry.delete()
        return JsonResponse({"success": True, "message": "Entry deleted"})
    except InternalIPList.DoesNotExist:
        return JsonResponse({"success": False, "message": "Entry not found"}, status=404)
