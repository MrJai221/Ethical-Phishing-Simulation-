import requests
from flask import current_app

def query_virustotal(indicator):
    """Queries the VirusTotal API."""
    api_key = current_app.config['VIRUSTOTAL_API_KEY']
    is_ip = '.' in indicator and all(part.isdigit() for part in indicator.split('.'))
    url_fragment = 'ip_addresses' if is_ip else 'domains'
    url = f"https://www.virustotal.com/api/v3/{url_fragment}/{indicator}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error querying VirusTotal: {e}")
        return None

def query_abuseipdb(ip_address):
    """Queries the AbuseIPDB API."""
    is_ip = '.' in ip_address and all(part.isdigit() for part in ip_address.split('.'))
    if not is_ip:
        return None
    api_key = current_app.config['ABUSEIPDB_API_KEY']
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error querying AbuseIPDB: {e}")
        return None

def query_threatfox(indicator):
    """Queries the ThreatFox API."""
    api_key = current_app.config['THREATFOX_API_KEY']
    url = 'https://threatfox-api.abuse.ch/api/v1/'
    data = {
        'query': 'search_ioc',
        'search_term': indicator
    }
    headers = {'API-KEY': api_key}
    try:
        response = requests.post(url, json=data, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error querying ThreatFox: {e}")
        return None

def query_pulsedive(indicator):
    """Queries the PulseDive API."""
    api_key = current_app.config['PULSEDIVE_API_KEY']
    url = f"https://pulsedive.com/api/info.php?indicator={indicator}&key={api_key}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error querying PulseDive: {e}")
        return None

def process_vt_data(results, indicator):
    """Processes VirusTotal JSON data for the frontend."""
    if not results or 'data' not in results or 'attributes' not in results['data']:
        return None
    attrs = results['data']['attributes']
    stats = attrs.get('last_analysis_stats', {})
    malicious_score = stats.get('malicious', 0)
    severity = 'low'
    if malicious_score > 5: severity = 'high'
    elif malicious_score > 0: severity = 'medium'
    return {
        'indicator': indicator, 'owner': attrs.get('as_owner', 'N/A'),
        'country': attrs.get('country', 'N/A'), 'malicious_score': malicious_score,
        'suspicious_score': stats.get('suspicious', 0), 'severity': severity,
        'iocs': attrs.get('last_analysis_results', {})
    }

def process_abuseipdb_data(results):
    """Processes AbuseIPDB JSON data for the frontend."""
    if not results or 'data' not in results:
        return None
    data = results['data']
    abuse_score = data.get('abuseConfidenceScore', 0)
    severity = 'low'
    if abuse_score >= 90: severity = 'high'
    elif abuse_score >= 40: severity = 'medium'
    return {
        'indicator': data.get('ipAddress'), 'country': data.get('countryCode', 'N/A'),
        'isp': data.get('isp', 'N/A'), 'domain': data.get('domain', 'N/A'),
        'abuse_score': abuse_score, 'latitude': data.get('latitude'),
        'longitude': data.get('longitude'), 'severity': severity,
        'iocs': data.get('reports', [])
    }

def process_threatfox_data(results):
    """Processes ThreatFox JSON data for the frontend."""
    if not results or 'data' not in results:
        return None
    data = results['data'][0]
    severity = 'low'
    confidence = data.get('confidence_level', 0)
    if confidence > 75: severity = 'high'
    elif confidence > 25: severity = 'medium'
    return {
        'indicator': data.get('ioc'), 'threat_type': data.get('threat_type'),
        'malware': data.get('malware_printable'), 'confidence': confidence,
        'severity': severity, 'iocs': [data]
    }

def process_pulsedive_data(results):
    """Processes PulseDive JSON data for the frontend."""
    if not results or 'indicator' not in results:
        return None
    risk = results.get('risk', 'low')
    severity = 'low'
    if risk == 'high' or risk == 'critical': severity = 'high'
    elif risk == 'medium': severity = 'medium'
    return {
        'indicator': results.get('indicator'), 'risk': risk,
        'type': results.get('type'), 'seen': results.get('seen'),
        'severity': severity, 'iocs': results.get('attributes', {})
    }