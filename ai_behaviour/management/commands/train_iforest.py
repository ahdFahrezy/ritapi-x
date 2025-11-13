import logging
import joblib
import json
import hashlib
import pandas as pd
from pathlib import Path
from django.conf import settings
from django.utils.timezone import now
from django.core.management.base import BaseCommand
from ai_behaviour.models import BehaviourLogs
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("ai_behaviour")

MODEL_DIR = Path(settings.BASE_DIR) / "models"
MODEL_PATH = MODEL_DIR / "iforest.pkl"
CHECKSUM_PATH = MODEL_DIR / "iforest.sha256"
METADATA_PATH = MODEL_DIR / "iforest.meta.json"

class Command(BaseCommand):
    help = "Train IsolationForest model for behaviour anomaly detection"

    def handle(self, *args, **kwargs):
        logger.info("=== Train IsolationForest started ===")

        try:
            logs = BehaviourLogs.objects.all().order_by("-timestamp")[:5000]
            logger.info("Fetched %s logs for training", len(logs))

            if len(logs) < 50:
                logger.warning("Not enough data for training (found=%s, need>=50)", len(logs))
                return

            df = pd.DataFrame(list(logs.values("payload_size", "response_time_ms", "status_code")))
            X = df[["payload_size", "response_time_ms", "status_code"]]

            # Normalize
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            clf = IsolationForest(contamination=0.02, random_state=42)
            clf.fit(X_scaled)

            MODEL_DIR.mkdir(parents=True, exist_ok=True)

            # Simpan model + scaler dalam 1 dict
            joblib.dump({"model": clf, "scaler": scaler}, MODEL_PATH)

            # Hitung checksum
            with open(MODEL_PATH, "rb") as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
            CHECKSUM_PATH.write_text(checksum)

            # Simpan metadata
            meta = {
                "trained_at": now().isoformat(),
                "num_samples": len(X),
                "features": list(X.columns),
                "checksum": checksum,
                "version": now().strftime("v%Y%m%d%H%M%S")
            }
            METADATA_PATH.write_text(json.dumps(meta, indent=2))

            logger.info("Training completed. Model saved at %s", MODEL_PATH)
            logger.info("Checksum: %s", checksum)
            logger.info("Metadata saved at %s", METADATA_PATH)

        except Exception as e:
            logger.exception("Training failed: %s", str(e))
