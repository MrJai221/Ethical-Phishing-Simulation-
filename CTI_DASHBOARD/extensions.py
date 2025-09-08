from flask_pymongo import PyMongo
from flask_socketio import SocketIO
from celery import Celery
mongo = PyMongo()
socketio = SocketIO()
celery = Celery(__name__, broker='redis://localhost:6379/0', backend='redis://localhost:6379/0')