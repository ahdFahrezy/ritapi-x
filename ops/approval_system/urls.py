from django.urls import path
from . import views

app_name = 'approval_system'

urlpatterns = [
    # Dashboard
    path('', views.approval_dashboard, name='dashboard'),
    
    # Change details
    path('change/<uuid:change_uuid>/', views.pending_change_detail, name='change_detail'),
    
    # Approval actions
    path('change/<uuid:change_uuid>/action/', views.ApprovalActionView.as_view(), name='approval_action'),
    
    # API endpoints
    path('api/changes/', views.PendingChangesListView.as_view(), name='api_changes'),
    path('api/audit/', views.AuditLogView.as_view(), name='api_audit'),
    path('api/cleanup/', views.cleanup_expired_changes, name='api_cleanup'),
]
