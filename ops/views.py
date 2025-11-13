from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta

from alert_blocking.models import Alert, BlockedIP
from tls_analyzer.models import TlsAnalyzer
from json_enforcer.models import JsonSchema
from decision_engine.models import RequestLog
from ops.ops_services.models import Service 

@login_required
def dashboard(request):
    total_alerts = Alert.objects.count()
    total_blocked = BlockedIP.objects.count()
    total_tls = TlsAnalyzer.objects.count()
    total_schemas = JsonSchema.objects.filter(is_active=True).count()

    # ✅ Buat dulu list tanggal 7 hari terakhir
    today = timezone.now().date()
    last7days = [today - timedelta(days=i) for i in range(6, -1, -1)]

    # ✅ Baru isi data per hari
    request_stats = []
    for day in last7days:
        allowed = RequestLog.objects.filter(decision="allow", timestamp__date=day).count()
        blocked = RequestLog.objects.filter(decision="block", timestamp__date=day).count()
        request_stats.append({
            "date": day.strftime("%d %b"),
            "allowed": allowed,
            "blocked": blocked,
        })
    total_requests_allow = RequestLog.objects.filter(decision="allow").count()
    total_requests_block = RequestLog.objects.filter(decision="block").count()
    services = Service.objects.all().order_by("host_name")
    context = {
        "total_alerts": total_alerts,
        "total_blocked": total_blocked,
        "total_requests_allow": total_requests_allow,
        "total_requests_block": total_requests_block,
        "request_stats": request_stats,
        "services": services,
        "recent_alerts": Alert.objects.order_by("-timestamp")[:5],
        "recent_blocked": BlockedIP.objects.order_by("-blocked_at")[:5],
        "recent_tls": TlsAnalyzer.objects.order_by("-timestamp")[:5],
    }
    return render(request, "ops_template/dashboard.html", context)

