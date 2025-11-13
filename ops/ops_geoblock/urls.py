from django.urls import path
from . import views

urlpatterns = [
    # Geo Block
    path("geo-block/", views.geo_block_dashboard, name="geo_block_dashboard"),
    path("geo-block/create/", views.geo_block_create, name="geo_block_create"),
    path("geo-block/update/<int:pk>/", views.geo_block_update, name="geo_block_update"),
    path("geo-block/delete/<int:pk>/", views.geo_block_delete, name="geo_block_delete"),
]
