import os
from celery import Celery

# Default ke settings Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ritapi_plugin.settings.dev")

app = Celery("ritapi_plugin")

# Baca config Celery dari Django settings, prefix CELERY_
app.config_from_object("django.conf:settings", namespace="CELERY")

# Autodiscover tasks dari semua apps + folder tasks/
app.autodiscover_tasks(lambda: ["tasks", "asn_score", "tls_analyzer"])
