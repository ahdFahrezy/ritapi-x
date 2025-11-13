from django.shortcuts import render
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import GeoBlockSetting


def parse_bool(value):
    """Interpret checkbox/boolean form inputs properly."""
    if not value:
        return False
    return str(value).lower() in ["true", "on", "1", "yes"]

@login_required
def geo_block_dashboard(request):
    """
    Dashboard to manage Geo Block rules
    """
    entries = GeoBlockSetting.objects.all().order_by("-updated_at")
    paginator = Paginator(entries, 20)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(request, "ops_template/geo_block_dashboard.html", {
        "page_obj": page_obj,
    })


@login_required
@require_http_methods(["POST"])
def geo_block_create(request):
    """
    Create a new geo block rule
    """
    try:
        country_code = request.POST.get("country_code")
        action = request.POST.get("action", "block")
        description = request.POST.get("description", "")
        is_active = parse_bool(request.POST.get("is_active"))

        if not country_code:
            return JsonResponse({"success": False, "message": "Country code is required"}, status=400)

        # create or update if already exists
        entry, created = GeoBlockSetting.objects.update_or_create(
            country_code=country_code.upper(),
            defaults={
                "action": action,
                "description": description,
                "is_active": is_active,
                "updated_at": timezone.now(),
            },
        )

        message = "Geo block rule created" if created else "Geo block rule updated"
        return JsonResponse({"success": True, "message": message})

    except Exception as e:
        return JsonResponse({"success": False, "message": str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def geo_block_update(request, pk):
    """
    Update existing geo block rule
    """
    try:
        entry = GeoBlockSetting.objects.get(pk=pk)
        country_code = request.POST.get("country_code")
        action = request.POST.get("action")
        description = request.POST.get("description", "")
        is_active = parse_bool(request.POST.get("is_active"))

        if not country_code:
            return JsonResponse({"success": False, "message": "Country code is required"}, status=400)

        entry.country_code = country_code.upper()
        entry.action = action
        entry.description = description
        entry.is_active = is_active
        entry.save()

        return JsonResponse({"success": True, "message": "Geo block rule updated"})

    except GeoBlockSetting.DoesNotExist:
        return JsonResponse({"success": False, "message": "Entry not found"}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "message": str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def geo_block_delete(request, pk):
    """
    Delete a geo block rule
    """
    try:
        entry = GeoBlockSetting.objects.get(pk=pk)
        entry.delete()
        return JsonResponse({"success": True, "message": "Geo block rule deleted"})
    except GeoBlockSetting.DoesNotExist:
        return JsonResponse({"success": False, "message": "Entry not found"}, status=404)
