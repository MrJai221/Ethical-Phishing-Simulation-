# tasks.py
import random
from extensions import celery, socketio
from utils import query_abuseipdb, process_abuseipdb_data, query_threatfox, process_threatfox_data

# A list of known malicious IPs to simulate a "live feed"
KNOWN_THREAT_IPS = [
    "185.220.101.4", "91.219.29.55", "198.54.117.199",
    "172.67.139.117", "104.21.23.149", "195.133.40.25"
]

@celery.task(name='tasks.poll_threat_feeds')
def poll_threat_feeds():
    """This background task simulates finding a new threat."""
    print("LIVE FEED: Polling for new threats...")
    indicator = random.choice(KNOWN_THREAT_IPS)
    print(f"LIVE FEED: Found new indicator: {indicator}")

    from __init__ import create_app
    app = create_app()
    with app.app_context():
        # Query AbuseIPDB
        abuseipdb_results = query_abuseipdb(indicator)
        if abuseipdb_results:
            processed_data = process_abuseipdb_data(abuseipdb_results)
            if processed_data:
                print(f"LIVE FEED: Pushing {indicator} from AbuseIPDB to dashboards via WebSocket.")
                
                ### ADD THIS LINE ###
                print("!!!!!! DEBUG: ATTEMPTING TO EMIT ABUSEIPDB DATA !!!!!!") 
                
                socketio.emit('new_threat_data', {
                    'source': 'Live Threat Feed (AbuseIPDB)',
                    'data': processed_data
                })
                if processed_data.get('latitude'):
                    socketio.emit('new_geo_threat', processed_data)

        # Query ThreatFox
        threatfox_results = query_threatfox(indicator)
        if threatfox_results:
            processed_data = process_threatfox_data(threatfox_results)
            if processed_data:
                print(f"LIVE FEED: Pushing {indicator} from ThreatFox to dashboards via WebSocket.")
                
                ### ADD THIS LINE ###
                print("!!!!!! DEBUG: ATTEMPTING TO EMIT THREATFOX DATA !!!!!!")

                socketio.emit('new_threat_data', {
                    'source': 'Live Threat Feed (ThreatFox)',
                    'data': processed_data
                })

    return f"Polling complete for {indicator}."