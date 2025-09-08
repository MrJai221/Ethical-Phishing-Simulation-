# __init__.py
from flask import Flask
from extensions import mongo, socketio, celery
import tasks

def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    mongo.init_app(app)
    socketio.init_app(app)

    # --- ADD THIS BLOCK TO ENABLE AUTOMATIC DATABASE SEEDING ---
    with app.app_context():
        # Check if the 'threats' collection is empty
        if mongo.db.threats.count_documents({}) == 0:
            from models import seed_database_with_random_data
            # If it's empty, run the seeder function
            seed_database_with_random_data()
    # -----------------------------------------------------------

    celery.conf.update(
        broker_url=app.config['CELERY_BROKER_URL'],
        result_backend=app.config['CELERY_RESULT_BACKEND']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    celery.Task = ContextTask
    
    with app.app_context():
        import routes
        app.register_blueprint(routes.main)

    return app