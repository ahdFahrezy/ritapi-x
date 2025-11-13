import os
import time
from pathlib import Path

def cleanup_old_logs(log_dir, keep_days=14):
    """
    Delete log files older than `keep_days` days in the given `log_dir`.
    """
    cutoff = time.time() - (keep_days * 86400)  # 86400 = seconds in a day
    deleted = []

    for file in Path(log_dir).glob("*.log"):
        if file.is_file() and file.stat().st_mtime < cutoff:
            try:
                file.unlink()
                deleted.append(file.name)
            except Exception:
                pass
    return deleted
