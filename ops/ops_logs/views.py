from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from decision_engine.models import RequestLog  
from django.core.paginator import Paginator
from django.http import HttpResponse
from openpyxl import Workbook
from django.core.serializers import serialize
from django.http import JsonResponse
from django.db.models import Count
from django.db.models.functions import TruncDate
from datetime import timedelta
from django.utils import timezone
from ops.ops_services.models import Service 


@login_required
def requestlog_list(request):
    query = request.GET.get("q", "")
    decision_filter = request.GET.get("decision", "")
    service_id = request.GET.get("service_id", "")
    page_number = request.GET.get("page", 1)

    logs = RequestLog.objects.all().order_by("-timestamp")

    if query:
        logs = logs.filter(ip_address__icontains=query)

    if decision_filter:
        logs = logs.filter(decision=decision_filter)
        
    if service_id:
        logs = logs.filter(service_id=service_id)

    paginator = Paginator(logs, 10)  # 10 rows per page
    page_obj = paginator.get_page(page_number)
    
    # Ambil semua service untuk dropdown filter di UI
    services = Service.objects.all().order_by("host_name")

    context = {
        "logs": page_obj,
        "query": query,
        "decision_filter": decision_filter,
        "service_id": service_id,
        "services": services,
    }
    return render(request, "ops_template/requestlog_list.html", context)

@login_required
def export_requestlog_excel(request):
    # Ambil parameter filter dari query string
    query = request.GET.get("q", "")
    decision_filter = request.GET.get("decision", "")
    service_id = request.GET.get("service_id", "")

    # Query dasar
    logs = RequestLog.objects.all().order_by("-timestamp")

    # 🔍 Filter berdasarkan IP (search)
    if query:
        logs = logs.filter(ip_address__icontains=query)

    # 🧱 Filter berdasarkan allow/block
    if decision_filter:
        logs = logs.filter(decision=decision_filter)

    # 🧩 Filter berdasarkan service
    if service_id:
        logs = logs.filter(service_id=service_id)

    # Buat workbook Excel
    wb = Workbook()
    ws = wb.active
    ws.title = "Request Logs"

    # Header (dengan kolom Service)
    ws.append([
        "No.", "Service", "IP Address", "Path", "Method", "Body Size",
        "Score", "Decision", "Reason", "Timestamp"
    ])

    # Isi data ke Excel
    for idx, log in enumerate(logs, start=1):
        ws.append([
            idx,
            log.service.host_name if log.service else "-",  # Nama service (jika ada)
            log.ip_address,
            log.path,
            log.method,
            log.body_size,
            log.score,
            log.decision,
            log.reason or "-",
            log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        ])

    # Siapkan response untuk download
    response = HttpResponse(
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response["Content-Disposition"] = 'attachment; filename="request_logs.xlsx"'

    wb.save(response)
    return response

@login_required
def requestlog_data(request):
    query = request.GET.get("q", "")
    decision_filter = request.GET.get("decision", "")
    service_id = request.GET.get("service_id", "")

    logs = RequestLog.objects.all().order_by("-timestamp")

    # 🔍 Filter berdasarkan IP (search)
    if query:
        logs = logs.filter(ip_address__icontains=query)

    # 🧱 Filter berdasarkan allow/block
    if decision_filter:
        logs = logs.filter(decision=decision_filter)

    # 🧩 Filter berdasarkan service
    if service_id:
        logs = logs.filter(service_id=service_id)

    # ⚡ Batasi hasil agar ringan
    logs = logs[:200]

    data = []
    for log in logs:
        data.append({
            "ip_address": log.ip_address,
            "path": log.path,
            "method": log.method,
            "score": log.score,
            "decision": log.decision,
            "reason": log.reason or "-",
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "service": getattr(log.service, "host_name", "-")
        })

    return JsonResponse({"data": data})

@login_required
def requestlog_chart_data(request):
    # Ambil parameter filter service dari query string
    service_id = request.GET.get("service_id", "")

    # Ambil data 7 hari terakhir
    end_date = timezone.now()
    start_date = end_date - timedelta(days=7)

    # Query dasar
    logs = RequestLog.objects.filter(timestamp__range=(start_date, end_date))

    # 🧩 Filter berdasarkan service (jika dipilih)
    if service_id:
        logs = logs.filter(service_id=service_id)

    # Hitung jumlah allow dan block per hari
    logs = (
        logs.annotate(date=TruncDate("timestamp"))
        .values("date", "decision")
        .annotate(count=Count("id"))
        .order_by("date")
    )

    # Format ke bentuk chart-friendly
    chart_data = {}
    for entry in logs:
        date_str = entry["date"].strftime("%Y-%m-%d")
        decision = entry["decision"]
        count = entry["count"]

        if date_str not in chart_data:
            chart_data[date_str] = {"allow": 0, "block": 0}
        chart_data[date_str][decision] = count

    labels = list(chart_data.keys())
    allow_data = [chart_data[d]["allow"] for d in labels]
    block_data = [chart_data[d]["block"] for d in labels]

    return JsonResponse({
        "labels": labels,
        "allow_data": allow_data,
        "block_data": block_data,
    })