import os
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime


class DailyDateNamedFileHandler(TimedRotatingFileHandler):
    """
    Custom log handler that rotates logs daily
    and uses the current date as the filename, e.g., 2025-09-25.log
    """
    def __init__(self, log_dir, *args, **kwargs):
        self.log_dir = log_dir
        self.baseFilename = self._get_dated_filename()
        super().__init__(
            filename=self.baseFilename,
            when='midnight',
            interval=1,
            backupCount=kwargs.get('backupCount', 14),
            encoding=kwargs.get('encoding', 'utf-8'),
            delay=False,
            utc=False
        )

    def _get_dated_filename(self):
        date_str = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"{date_str}.log")

    def doRollover(self):
        # Update filename for new day
        self.baseFilename = self._get_dated_filename()
        super().doRollover()
