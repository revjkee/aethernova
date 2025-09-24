from celery import Celery
from celery.schedules import crontab
import os

# Загрузка конфигурации из переменных окружения
BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')

app = Celery('teslaai_tasks',
             broker=BROKER_URL,
             backend=RESULT_BACKEND,
             include=['src.tasks.task_modules'])

# Общие настройки Celery
app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    worker_max_tasks_per_child=100,
    worker_concurrency=4,
)

# Пример периодического задания (можно расширить в будущем)
app.conf.beat_schedule = {
    'cleanup-every-midnight': {
        'task': 'src.tasks.task_modules.cleanup_temp_files',
        'schedule': crontab(minute=0, hour=0),
    },
}

if __name__ == '__main__':
    app.start()
