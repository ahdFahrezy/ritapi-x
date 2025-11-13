from pathlib import Path
import environ
import os
from dotenv import load_dotenv
from utils.daily_log_handler import DailyDateNamedFileHandler

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

DJANGO_ENV = os.getenv("DJANGO_ENV", "dev")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
DEBUG = os.getenv("DEBUG", "0").strip() == "0"
# Guards
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is missing! Please set it in your environment.")

# Guards
if DJANGO_ENV == "prod":
    if not SECRET_KEY:
        raise ValueError("❌ SECRET_KEY is missing in production!")
    if DEBUG:
        raise ValueError("❌ DEBUG must be False in production!")

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "127.0.0.1,localhost,api.situswaf.com,default.example.co3,default.example.comxs").split(",")
ALLOW_IPS = os.getenv("ALLOW_IPS", "127.0.0.1").split(",")
ALLOW_IPS = [ip.strip() for ip in ALLOW_IPS if ip.strip()]

# Tambahkan folder apps ke sys.path agar import 'ipapi', 'common', dll. mudah
import sys
sys.path.append(str(BASE_DIR / "apps"))

INSTALLED_APPS = [
    "django.contrib.admin", 
    "django.contrib.auth", 
    "django.contrib.contenttypes",
    "django.contrib.sessions", 
    "django.contrib.messages", 
    "django.contrib.staticfiles",
    "corsheaders",
    
    # Third-party
    "rest_framework",
    "django_extensions",
    "widget_tweaks",
    'django_crontab',
    
    # custom apps
    "ai_behaviour",
    "alert_blocking",
    "asn_score",
    "ip_reputation",
    "json_enforcer",
    "tls_analyzer",
    "decision_engine",
    "demo",
    
    # ops
    "ops",
    "ops.ops_tls",
    "ops.ops_ip_reputation",
    "ops.ops_json_schema",
    "ops.ops_alert_blocking",
    "ops.ops_asn_score",
    "ops.ops_services",
    "ops.ops_license_manager",
    "ops.ops_logs",
    "ops.approval_system",
    "ops.ops_geoblock",
]

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",     # default JSON response
        "rest_framework.renderers.BrowsableAPIRenderer",  # nice web UI
    ],
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.FormParser",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
        # Kalau mau pakai JWT nanti bisa tambahin:
        # "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated"  # bisa diganti ke IsAuthenticated
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
}

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    'middlewares.dynamic_cors.DynamicCORSMiddleware',
    "middlewares.rate_limit.RateLimiterMiddleware",
    "middlewares.security.RemoveServerHeaderMiddleware", 
    "ops.ops_license_manager.middleware.LicenseCheckMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "middlewares.no_store.NoStoreMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # "middlewares.security_headers.SecurityHeadersMiddleware",
    "decision_engine.middleware.DecisionProxyMiddleware",
]

ROOT_URLCONF = "ritapi_advance.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    'DIRS': [BASE_DIR / "templates"],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.debug",
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
        "ops.ops_license_manager.context_processors.license_status"
    ]},
}]
WSGI_APPLICATION = "ritapi_advance.wsgi.application"
ASGI_APPLICATION = "ritapi_advance.asgi.application"

# DB dev: sqlite; production: ganti di prod.py ke Postgres
# === Database (Postgres in Production) ===
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "db_ritapi_advance"),
        "USER": os.getenv("POSTGRES_USER", "postgres"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
        "HOST": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

CRON_TRAIN_IFOREST = os.getenv("CRON_TRAIN_IFOREST", "0 */6 * * *")
CRONJOBS = [
    (CRON_TRAIN_IFOREST, 'django.core.management.call_command', ['train_iforest']),
]

LANGUAGE_CODE = "id"
TIME_ZONE = "Asia/Jakarta"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/ops/"
LOGOUT_REDIRECT_URL = "/login/"
TARGET_BACKEND = os.getenv("TARGET_BACKEND", "http://127.0.0.1:7000")



# Email Settings (Mailtrap)
EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = os.getenv("EMAIL_HOST", "sandbox.smtp.mailtrap.io")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True") == "True"
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "False") == "True"
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "no-reply@ritapi.local")

SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 1800
CSRF_COOKIE_SAMESITE = "Lax"

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "detailed": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "detailed",
        },

        # ✅ File khusus untuk ai_behaviour
        "file_ai_behaviour": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": str(LOG_DIR / "train_iforest.log"),
            "formatter": "detailed",
            "when": "midnight",
            "interval": 1,
            "backupCount": 14,
            "encoding": "utf-8",
        },

        # ✅ Handler log harian untuk semua selain ai_behaviour
        "daily_file": {
            "()": DailyDateNamedFileHandler,
            "log_dir": str(LOG_DIR),
            "formatter": "detailed",
            "backupCount": 14,
            "encoding": "utf-8",
        },
    },

    "loggers": {
        # ✅ Logger khusus ai_behaviour
        "ai_behaviour": {
            "handlers": ["console", "file_ai_behaviour"],
            "level": "INFO",
            "propagate": False,
        },
        
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },

        # ✅ Semua logger lainnya
        "": {
            "handlers": ["console", "daily_file"],
            "level": "INFO",
            "propagate": True,
        },
    },
}

# === Redis / Cache Settings ===
# Flag untuk ON/OFF caching backend response
ENABLE_BACKEND_CACHE = False
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
# TTL (seconds) untuk cache response backend
BACKEND_RESPONSE_CACHE_TTL = int(os.getenv("BACKEND_RESPONSE_CACHE_TTL", "30"))
ASN_TLS_CACHE_TTL = int(os.getenv("ASN_TLS_CACHE_TTL", "30"))

# === License Management Settings ===
# License API configuration
LICENSE_API_KEY = os.getenv("LICENSE_API_KEY", "ritapi-client-key-2025")

# License check configuration
SKIP_LICENSE_CHECK = os.getenv("SKIP_LICENSE_CHECK", "False") == "True"
LICENSE_CHECK_FAIL_OPEN = os.getenv("LICENSE_CHECK_FAIL_OPEN", "True") == "True"

# License API URLs (will try in order)
LICENSE_API_URLS = [
    "https://uat.ritapi.io/api/license"
]


TRUSTED_PROXIES = ["127.0.0.1", "10.0.0.1"]
# Celery pakai Redis
# URL broker (Redis)
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://ritapi_redis:6379/0")

# Tempat Celery menyimpan hasil task (juga Redis)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://ritapi_redis:6379/0")

GEOLITE2_DB = "/usr/share/GeoIP/GeoLite2-Country.mmdb"

LICENSE_LIFETIME = False         # True = never expires
LICENSE_EXPIRE_DAYS = 7

