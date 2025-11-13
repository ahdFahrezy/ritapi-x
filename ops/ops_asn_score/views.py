import ipaddress
from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from asn_score.models import AsnInfo, AsnTrustConfig
from asn_score.services import AsnScoreService


@login_required
def asn_checker(request):
    """
    Main ASN Checker view — lookup ASN by IP, show history and trust configs.
    """
    result = None
    error_message = None

    if request.method == "POST":
        ip = request.POST.get("ip")
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                error_message = f"'{ip}' is not a valid IP address."
            else:
                record = AsnScoreService.lookup_asn(ip)
                if record:
                    trust_score = AsnScoreService.get_trust_score(record.asn_number)
                    record.trust_score = trust_score
                    record.save(update_fields=["trust_score"])
                    result = record
                    messages.success(request, f"ASN for IP {ip} was found successfully.")
                else:
                    error_message = f"No ASN record found for IP {ip}."

    # ✅ Filter & paginate ASN history
    search_query = request.GET.get("search", "")
    history_qs = AsnInfo.objects.all().order_by("-timestamp")
    if search_query:
        history_qs = history_qs.filter(ip_address__icontains=search_query)

    paginator = Paginator(history_qs, 10)
    page_number = request.GET.get("page")
    history = paginator.get_page(page_number)

    context = {
        "result": result,
        "error_message": error_message,
        "history": history,
        "search_query": search_query,
    }
    return render(request, "ops_template/asn_checker.html", context)

@login_required
def asn_config_view(request):
    """
    View untuk menampilkan dan mencari ASN Trust Configs.
    - Pencarian berdasarkan asn_number (partial match, case-insensitive)
    - Pagination dengan parameter 'cfg_page'
    """
    cfg_search = request.GET.get("cfg_search", "").strip()
    configs_qs = AsnTrustConfig.objects.all().order_by("-updated_at")

    if cfg_search:
        configs_qs = configs_qs.filter(asn_number__icontains=cfg_search)

    paginator = Paginator(configs_qs, 10)
    cfg_page = request.GET.get("cfg_page")
    configs = paginator.get_page(cfg_page)

    context = {
        "configs": configs,
        "cfg_search": cfg_search,
    }
    return render(request, "ops_template/asn_config.html", context)

@login_required
def asn_update_score(request):
    if request.method == "POST":
        asn_number = request.POST.get("asn_number")
        name = request.POST.get("name", "")
        score = request.POST.get("score", 0)

        config, created = AsnTrustConfig.objects.update_or_create(
            asn_number=asn_number,
            defaults={"name": name, "score": score},
        )
        if created:
            messages.success(request, f"ASN {asn_number} berhasil ditambahkan dengan score {score}")
        else:
            messages.success(request, f"ASN {asn_number} berhasil diperbarui menjadi score {score}")

    return redirect("ops_asn_config")
