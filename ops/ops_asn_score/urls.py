from django.urls import path
from . import views

urlpatterns = [
    path("asn-checker/", views.asn_checker, name="ops_asn_checker"),
    path("asn-config/", views.asn_config_view, name="ops_asn_config"),
    path("asn-update-score/", views.asn_update_score, name="ops_asn_update_score"),
]
