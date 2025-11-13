import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class BackgroundTaskManager:
    _instance = None
    _executor = ThreadPoolExecutor(max_workers=4)
    _loop = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        try:
            self._loop = asyncio.get_event_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

    def enqueue_task(self, func, *args, **kwargs):
        """Enqueue a task to run in background"""
        try:
            future = self._executor.submit(func, *args, **kwargs)
            future.add_done_callback(self._handle_result)
        except Exception as e:
            logger.error(f"Failed to enqueue task: {e}")

    def _handle_result(self, future):
        """Handle task completion"""
        try:
            result = future.result()
            logger.debug(f"Background task completed: {result}")
        except Exception as e:
            logger.error(f"Background task failed: {e}")

class TaskMonitor:
    _tasks = {}
    
    @classmethod
    def register_task(cls, task_id, task_type):
        cls._tasks[task_id] = {
            'type': task_type,
            'start_time': datetime.now(),
            'status': 'running'
        }
    
    @classmethod
    def complete_task(cls, task_id, success=True):
        if task_id in cls._tasks:
            cls._tasks[task_id]['status'] = 'success' if success else 'failed'
            cls._tasks[task_id]['end_time'] = datetime.now()

    @classmethod
    def get_stats(cls):
        return {
            'total': len(cls._tasks),
            'running': sum(1 for t in cls._tasks.values() if t['status'] == 'running'),
            'failed': sum(1 for t in cls._tasks.values() if t['status'] == 'failed')
        }