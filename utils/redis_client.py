import logging
import os
from django.conf import settings

logger = logging.getLogger(__name__)

class RedisClientSingleton:
    _instance = None

    @classmethod
    def get_client(cls):
        if cls._instance is None:
            try:
                import redis
                cls._instance = redis.from_url(
                    getattr(settings, "REDIS_URL", os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")),
                    decode_responses=False
                )
                cls._instance.ping()  # test koneksi
                logger.info("Redis client initialized (singleton)")
            except Exception as e:
                logger.warning("Redis unavailable, cache disabled: %s", e)
                cls._instance = None
        return cls._instance
