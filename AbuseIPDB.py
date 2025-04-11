#### IMPORTANT: These scripts are stored in Splunk Add-on Builder and run in the context of Splunk. ####
#### This means they are copied over from there, so others can view the code achieved here ####

import json
import requests
import os
from dotenv import load_dotenv

# Load environment variables
# API URL for AbuseIPDB (Fetching recent reports)
API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
API_KEY = os.getenv("ABUSEIP_API_KEY")

# Function to fetch data from AbuseIPDB
def fetch_abuseipdb_data():
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'page': 1,  # Fetch first page of results
        'limit': 50  # Max allowed reports per request
    }
    try:
        response = requests.get(API_URL, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch AbuseIPDB data: {str(e)}")
    return None

# Function to flatten JSON (to simplify complex nested structures)
### This function takes a nested JSON object (which might have dictionaries or lists inside it) and "flattens" it into a simple one-level dictionary.
def flatten_json(json_obj, parent_key='', separator='_'):
    items = []
    for key, value in json_obj.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key
        if isinstance(value, dict):
            items.extend(flatten_json(value, new_key, separator=separator).items())
        elif isinstance(value, list):
            for i, item in enumerate(value):
                items.extend(flatten_json({f"{new_key}_{i}": item}, separator=separator).items())
        else:
            items.append((new_key, value))
    return dict(items)

# Function to validate input parameters
def validate_input(helper, definition):
    """Validate the input configuration."""
    dummy_var = helper.get_arg("dummy_var")  # Required by Splunk
    return True

# Function to collect events
def collect_events(helper, ew):
    """Data collection logic for Splunk modular input"""
    dummy_var = helper.get_arg('dummy_var')  # Required but not used
    abuseipdb_data = fetch_abuseipdb_data()
    if abuseipdb_data and 'data' in abuseipdb_data:
        reports = abuseipdb_data['data']
        for report in reports:
            flattened_report = flatten_json(report)
            event_data = json.dumps(flattened_report)
            event = helper.new_event(
                data=event_data,
                sourcetype="threat_intel3",
                source="abuseipdb",
                index="add_on_builder_index",
                done=True,
                unbroken=True
            )
            ew.write_event(event)
        helper.log_info(f"Successfully processed {len(reports)} reports from AbuseIPDB.")
    else:
        helper.log_error("Failed to fetch AbuseIPDB data or no data available.")
