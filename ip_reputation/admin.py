from django.contrib import admin
from .models import IpReputation, InternalIPList

@admin.register(IpReputation)
class IpReputationAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "reputation_score", "timestamp")
    search_fields = ("ip_address",)
    list_filter = ("reputation_score",)

@admin.register(InternalIPList)
class InternalIPListAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "list_type", "service", "expires_at", "reason")
    list_filter = ("list_type", "service")
    search_fields = ("ip_address",)