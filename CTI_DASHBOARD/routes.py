# routes.py
from flask import Blueprint, render_template, Response, jsonify, request # <-- jsonify and request were needed
import models
from extensions import socketio
import config # <-- THIS IMPORT WAS MISSING
from utils import (
    query_virustotal,
    query_abuseipdb,
    query_threatfox,
    query_pulsedive,
    process_vt_data,
    process_abuseipdb_data,
    process_threatfox_data,
    process_pulsedive_data
)
import json
import csv
import io

main = Blueprint('main', __name__)

# --- Page Routes ---
@main.route('/')
def dashboard():
    return render_template('index.html')

@main.route('/investigations')
def investigations():
    return render_template('investigations.html')

@main.route('/reports')
def reports():
    threats, stats = models.get_report_data()
    return render_template('reports.html', threats=threats, stats=stats)

@main.route('/settings')
def settings():
    # Read API key status from the config object
    api_status = {
        'VirusTotal': 'Configured' if config.VIRUSTOTAL_API_KEY and 'YOUR' not in config.VIRUSTOTAL_API_KEY else 'Missing',
        'AbuseIPDB': 'Configured' if config.ABUSEIPDB_API_KEY and 'YOUR' not in config.ABUSEIPDB_API_KEY else 'Missing',
        'ThreatFox': 'Configured' if config.THREATFOX_API_KEY and 'YOUR' not in config.THREATFOX_API_KEY else 'Missing',
        'PulseDive': 'Configured' if config.PULSEDIVE_API_KEY and 'YOUR' not in config.PULSEDIVE_API_KEY else 'Missing',
    }
    return render_template('settings.html', api_status=api_status)

@main.route('/threat_models')
def threat_models():
    return render_template('threat_models.html')
    
@main.route('/trends')
def trends():
    return render_template('trends.html')

@main.route('/api/threat_trends')
def threat_trends_data():
    trends_data = models.get_threat_trends()
    formatted_data = {
        "labels": [f"{d['_id']['year']}-{d['_id']['month']}-{d['_id']['day']}" for d in trends_data],
        "data": [d['count'] for d in trends_data]
    }
    return jsonify(formatted_data) #<-- jsonify is now defined

@main.route('/export')
def export_threats():
    threats = models.get_all_threats_for_export()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['Indicator', 'Source', 'Timestamp', 'Data', 'Tags'])

    for threat in threats:
        writer.writerow([
            threat.get('indicator'),
            threat.get('source'),
            threat.get('timestamp'),
            json.dumps(threat.get('data')),
            ", ".join(threat.get('tags', []))
        ])

    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=threat_data.csv"})


# --- API Routes ---
@main.route('/api/clear_db', methods=['POST'])
def clear_database():
    """API endpoint to clear the database."""
    deleted_count = models.delete_all_threats()
    return jsonify({'message': f'Successfully deleted {deleted_count} records from the database.', 'status': 'success'}) #<-- jsonify is now defined

@main.route('/api/dashboard/kpis')
def dashboard_kpis():
    """Provides data for the top KPI cards."""
    kpi_data = models.get_dashboard_kpi_data()
    return jsonify(kpi_data)

@main.route('/api/dashboard/threats_by_source')
def threats_by_source_data():
    """Provides data for the 'Threats by Source' doughnut chart."""
    source_data = models.get_threats_by_source()
    # Format for Chart.js
    formatted_data = {
        "labels": [d['_id'] for d in source_data],
        "data": [d['count'] for d in source_data]
    }
    return jsonify(formatted_data)
@main.route('/api/dashboard/threats_by_severity')
def threats_by_severity_data():
    """Provides data for the 'Threats by Severity' doughnut chart."""
    severity_data = models.get_threats_by_severity()
    formatted_data = {
        "labels": [d['_id'].capitalize() for d in severity_data],
        "data": [d['count'] for d in severity_data]
    }
    return jsonify(formatted_data)

@main.route('/api/dashboard/top_countries')
def top_countries_data():
    """Provides data for the 'Top Countries' widget."""
    countries_data = models.get_top_countries()
    # Find the max count to calculate percentages for the progress bars
    max_count = max([d['count'] for d in countries_data]) if countries_data else 0
    
    formatted_data = [{
        "name": d['_id'],
        "count": d['count'],
        "percentage": int((d['count'] / max_count) * 100) if max_count > 0 else 0
    } for d in countries_data]
    
    return jsonify(formatted_data)

# --- WebSocket Event Handlers ---
@socketio.on('lookup_indicator')
def handle_lookup_event(json_data):
    """Handles the lookup event from the client via WebSocket."""
    indicator = json_data.get('indicator')
    if not indicator:
        return

    socketio.emit('status_update', {'message': f'BEGINNING ANALYSIS FOR {indicator}...'})
    
    # --- This function now sends results one by one for a "real-time" feel ---

    # VirusTotal
    socketio.emit('status_update', {'message': f'Querying VirusTotal...'})
    vt_results = query_virustotal(indicator)
    if vt_results:
        processed_vt = process_vt_data(vt_results, indicator)
        if processed_vt:
            models.save_threat_data(indicator, 'VirusTotal', processed_vt)
            socketio.emit('new_threat_data', {'source': 'VirusTotal', 'data': processed_vt})
    
    # AbuseIPDB
    socketio.emit('status_update', {'message': f'Querying AbuseIPDB...'})
    abuseipdb_results = query_abuseipdb(indicator)
    if abuseipdb_results:
        processed_abuse = process_abuseipdb_data(abuseipdb_results)
        if processed_abuse:
            models.save_threat_data(indicator, 'AbuseIPDB', processed_abuse)
            if processed_abuse.get('latitude'):
                socketio.emit('new_geo_threat', processed_abuse)
            socketio.emit('new_threat_data', {'source': 'AbuseIPDB', 'data': processed_abuse})

    # ThreatFox
    socketio.emit('status_update', {'message': f'Querying ThreatFox...'})
    threatfox_results = query_threatfox(indicator)
    if threatfox_results:
        processed_threatfox = process_threatfox_data(threatfox_results)
        if processed_threatfox:
            models.save_threat_data(indicator, 'ThreatFox', processed_threatfox)
            socketio.emit('new_threat_data', {'source': 'ThreatFox', 'data': processed_threatfox})
    
    # PulseDive
    socketio.emit('status_update', {'message': f'Querying PulseDive...'})
    pulsedive_results = query_pulsedive(indicator)
    if pulsedive_results:
        processed_pulsedive = process_pulsedive_data(pulsedive_results)
        if processed_pulsedive:
            models.save_threat_data(indicator, 'PulseDive', processed_pulsedive)
            socketio.emit('new_threat_data', {'source': 'PulseDive', 'data': processed_pulsedive})


    socketio.emit('status_update', {'message': 'Analysis complete.'})

@socketio.on('add_tag')
def handle_add_tag_event(json_data):
    threat_id = json_data.get('threat_id')
    tag = json_data.get('tag')
    if threat_id and tag:
        models.add_tag_to_threat(threat_id, tag)
        socketio.emit('tag_added', {'threat_id': threat_id, 'tag': tag})