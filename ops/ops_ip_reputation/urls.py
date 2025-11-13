from django.urls import path
from . import views

urlpatterns = [
    path("", views.ip_reputation_dashboard, name="ops_ip_reputation_check"),
    path("internal-ip/", views.internal_ip_dashboard, name="internal_ip_dashboard"),
    path("internal-ip/create/", views.internal_ip_create, name="internal_ip_create"),
    path("internal-ip/update/<int:pk>/", views.internal_ip_update, name="internal_ip_update"),
    path("internal-ip/delete/<int:pk>/", views.internal_ip_delete, name="internal_ip_delete"),
]
