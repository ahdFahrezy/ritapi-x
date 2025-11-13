import pandas as pd
from django.utils import timezone
from sklearn.ensemble import IsolationForest
from .models import BehaviourLogs, BehaviourAnomaly
import joblib
import os
import hashlib

MODEL_PATH = "models/iforest.pkl"
CHECKSUM_PATH = "models/iforest.sha256"

def is_checksum_valid(model_path: str, checksum_path: str) -> bool:
    try:
        with open(model_path, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        with open(checksum_path, "r") as f:
            expected = f.read().strip()
        return actual == expected
    except Exception:
        return False

class AiProfilerService:
    model_bundle = None 

    @staticmethod
    def log_request(endpoint, ip, method, payload_size, user_agent, status_code, response_time_ms):
        """
        Simpan request log ke BehaviourLogs + deteksi anomali
        """
        log = BehaviourLogs.objects.create(
            endpoint=endpoint,
            ip_address=ip,
            method=method,
            payload_size=payload_size,
            user_agent=user_agent,
            status_code=status_code,
            response_time_ms=response_time_ms,
        )

        # cek anomali
        AiProfilerService.detect_anomaly(log)

        return log
    
    @staticmethod
    def load_model():
        if AiProfilerService.model_bundle is None:
            if not os.path.exists(MODEL_PATH):
                raise RuntimeError("IsolationForest model not found")

            if not is_checksum_valid(MODEL_PATH, CHECKSUM_PATH):
                raise RuntimeError("Model checksum mismatch or invalid")

            AiProfilerService.model_bundle = joblib.load(MODEL_PATH)

    @staticmethod
    def detect_anomaly(log: BehaviourLogs):
        anomalies = []
        # RULE-BASED
        if log.payload_size > 10_000:
            anomalies.append(("LARGE_PAYLOAD", 70))
        if log.response_time_ms > 2000:
            anomalies.append(("SLOW_RESPONSE", 50))
        if log.payload_size > 0 and log.payload_size % 13 == 0:
            anomalies.append(("SUSPICIOS_PAYLOAD_PATTERN", 60))

        for anomaly_type, score in anomalies:
            BehaviourAnomaly.objects.create(
                log=log,
                ip_address=log.ip_address,
                anomaly_type=anomaly_type,
                risk_score=score,
                detected_at=timezone.now(),
                detected_by="rule",
            )
        if anomalies:
            # kembalikan True dan nama rule pertama sebagai reason
            return True, anomalies[0][0] 
        
        # ML-BASED
        try:
            AiProfilerService.load_model()
        except Exception as e:
            return False

        model = AiProfilerService.model_bundle["model"]
        scaler = AiProfilerService.model_bundle["scaler"]
        df = pd.DataFrame([{
            "payload_size": log.payload_size,
            "response_time_ms": log.response_time_ms,
            "status_code": log.status_code
        }])
        X_scaled = scaler.transform(df)
        pred = model.predict(X_scaled)[0]
        print("ML Prediction:", pred)
        if pred == -1:
            BehaviourAnomaly.objects.create(
                log=log,
                ip_address=log.ip_address,
                anomaly_type="IsolationForest Detected Anomaly",
                risk_score=80,
                detected_by="ml",
            )
            return True, "ISOLATIONFOREST_DETECTED_ANOMALY"

        return False, None


