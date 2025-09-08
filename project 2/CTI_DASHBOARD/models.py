from extensions import mongo
from datetime import datetime
import pymongo

def save_threat_data(indicator, source, data):
    existing_record = mongo.db.threats.find_one({
        'indicator': indicator,
        'source': source,
        'timestamp': {'$gte': datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)}
    })
    if existing_record:
        mongo.db.threats.update_one({'_id': existing_record['_id']}, {'$set': {'data': data, 'timestamp': datetime.utcnow()}})
        return existing_record['_id']
    else:
        threat = {'indicator': indicator, 'source': source, 'data': data, 'timestamp': datetime.utcnow(), 'tags': []}
        result = mongo.db.threats.insert_one(threat)
        return result.inserted_id

def get_threats_by_indicator(indicator):
    return list(mongo.db.threats.find({'indicator': indicator}))

def get_recent_threats(limit=50):
    return list(mongo.db.threats.find().sort('timestamp', pymongo.DESCENDING).limit(limit))

def add_tag_to_threat(threat_id, tag):
    mongo.db.threats.update_one({'_id': threat_id}, {'$addToSet': {'tags': tag}})

def get_threats_by_tag(tag, limit=50):
    return list(mongo.db.threats.find({'tags': tag}).sort('timestamp', pymongo.DESCENDING).limit(limit))

def get_threat_trends():
    pipeline = [
        {"$group": {
            "_id": {
                "year": {"$year": "$timestamp"},
                "month": {"$month": "$timestamp"},
                "day": {"$dayOfMonth": "$timestamp"}
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    return list(mongo.db.threats.aggregate(pipeline))

def get_all_threats_for_export():
    return list(mongo.db.threats.find({}, {'_id': 0, 'indicator': 1, 'source': 1, 'timestamp': 1, 'data': 1, 'tags': 1}))


def get_report_data(limit=100):
    """Fetches recent threats and calculates summary statistics for reports."""
    threats = list(mongo.db.threats.find().sort('timestamp', pymongo.DESCENDING).limit(limit))
    
    stats = {
        'total_threats': mongo.db.threats.count_documents({}),
        'high_severity': mongo.db.threats.count_documents({'data.severity': 'high'}),
        'medium_severity': mongo.db.threats.count_documents({'data.severity': 'medium'}),
        'low_severity': mongo.db.threats.count_documents({'data.severity': 'low'})
    }
    return threats, stats

def delete_all_threats():
    """Deletes all documents from the threats collection."""
    result = mongo.db.threats.delete_many({})
    return result.deleted_count

def get_dashboard_kpi_data():
    """Calculates the main KPIs for the dashboard."""
    total_threats = mongo.db.threats.count_documents({})
    high_severity = mongo.db.threats.count_documents({'data.severity': 'high'})
    medium_severity = mongo.db.threats.count_documents({'data.severity': 'medium'})
    
    # To get unique indicators, we use the distinct method
    unique_indicators = len(mongo.db.threats.distinct('indicator'))
    
    return {
        'total_threats': total_threats,
        'high_severity': high_severity,
        'medium_severity': medium_severity,
        'unique_indicators': unique_indicators
    }

def get_threats_by_source():
    """Aggregates threat counts by their source API."""
    pipeline = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    return list(mongo.db.threats.aggregate(pipeline))

# models.py
# ... (all your existing functions are here) ...

def get_threats_by_severity():
    """Aggregates threat counts by their severity level."""
    pipeline = [
        # Unwind the data to access nested 'severity' field if needed, or access directly
        # This assumes 'severity' is at the top level of the 'data' object
        {"$group": {"_id": "$data.severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    # Filter out null or empty severity
    results = [doc for doc in mongo.db.threats.aggregate(pipeline) if doc['_id']]
    return results

def get_top_countries(limit=5):
    """Aggregates threat counts by country and returns the top N."""
    pipeline = [
        {"$match": {"data.country": {"$ne": "N/A", "$ne": None}}},
        {"$group": {"_id": "$data.country", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": limit}
    ]
    return list(mongo.db.threats.aggregate(pipeline))

# ... (all your existing functions are at the top) ...

import random
from datetime import datetime, timedelta

def seed_database_with_random_data(count=250):
    """
    Populates the database with a large set of random, historical threat data.
    This function should only be called once when the database is empty.
    """
    print(f"DATABASE IS EMPTY. Seeding with {count} random threat records...")

    # Define realistic sample data
    severities = ['low'] * 60 + ['medium'] * 30 + ['high'] * 10  # Weighted for realism
    sources = ['VirusTotal', 'AbuseIPDB', 'ThreatFox', 'PulseDive']
    countries = [
        ('USA', 'US'), ('Russia', 'RU'), ('China', 'CN'), ('India', 'IN'),
        ('Germany', 'DE'), ('Brazil', 'BR'), ('Iran', 'IR'), ('UK', 'GB'),
        ('Nigeria', 'NG'), ('North Korea', 'KP'), ('France', 'FR')
    ]

    threats_to_insert = []
    for _ in range(count):
        selected_country = random.choice(countries)
        
        # Create a threat document that matches the structure your frontend expects
        threat = {
            'indicator': f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
            'source': random.choice(sources),
            'timestamp': datetime.utcnow() - timedelta(days=random.randint(0, 60), hours=random.randint(0, 23)),
            'data': {
                'severity': random.choice(severities),
                'country': selected_country[1],  # e.g., 'US'
                'countryName': selected_country[0], # e.g., 'USA'
                # Simulate some geo-data for the map
                'latitude': random.uniform(20, 50), # Rough Northern Hemisphere
                'longitude': random.uniform(-100, 100)
            },
            'tags': []
        }
        threats_to_insert.append(threat)

    # Insert all generated threats in a single, efficient operation
    if threats_to_insert:
        mongo.db.threats.insert_many(threats_to_insert)
        print(f"DATABASE SEEDING COMPLETE. Inserted {len(threats_to_insert)} records.")