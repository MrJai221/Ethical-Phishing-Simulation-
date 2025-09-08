import os

SECRET_KEY = os.urandom(24)
MONGO_URI = "mongodb://localhost:27017/cti_dashboard"
VIRUSTOTAL_API_KEY = "ac13e45e191044d03522052929761c7fd7ed07dec21050d6e36bc15f84751c7d"
ABUSEIPDB_API_KEY = "638e9fc061dbe5c1602e32ccfcc55eb5039d974e8d3298748c57bc580c20f52a0ea6855958f896e9"
THREATFOX_API_KEY = "37093186aa222051621a8648599b554f2ddf3593fb474b11"  # Replace with your ThreatFox API key
PULSEDIVE_API_KEY = "e8d9ca3b388e21f3ae03551922d22889e0dc3cffff31f1141bf0c92a04245d00"  # Replace with your PulseDive API key


# Redis and Celery Configuration
REDIS_URL = "redis://localhost:6379/0"
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL

# Celery Beat Schedule
CELERYBEAT_SCHEDULE = {
    'poll-threats-every-30-seconds': {
        'task': 'tasks.poll_threat_feeds',
        'schedule': 30.0,
    },
}