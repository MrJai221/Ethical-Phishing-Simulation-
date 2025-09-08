# worker.py
import eventlet
eventlet.monkey_patch()

from __init__ import create_app
from extensions import celery

app = create_app()
app.app_context().push()