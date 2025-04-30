#### IMPORTANT: These scripts are stored in Splunk Add-on Builder and run in the context of Splunk. ####
#### This means they are copied over from there, so others can view the code achieved here ####

import json
import requests
import os
from dotenv import load_dotenv

# Load environment variables (expects .env file with ABUSEIP_API_KEY)
load_dotenv()

# API endpoint and key for AbuseIPDB
API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
API_KEY = os.getenv("ABUSEIP_API_KEY")  # API key stored securely in environment variable

# Function to fetch data from AbuseIPDB's blacklist API
def fetch_abuseipdb_data():
    headers = {
        'Key': API_KEY,               # API key for authentication
        'Accept': 'application/json'  # Expect JSON response
    }
    params = {
        'page': 1,    # Fetch the first page
        'limit': 50   # Limit number of results to 50 (max allowed)
    }

    try:
        # Make GET request with headers and parameters
        response = requests.get(API_URL, headers=headers, params=params)
        response.raise_for_status()  # Raise error for HTTP status codes >= 400
        return response.json()       # Return parsed JSON response

    # Handle specific types of request errors and print debug messages
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch AbuseIPDB data: {str(e)}")

    return None  # Return None if request failed

# Recursive function to flatten nested JSON into a flat dictionary
def flatten_json(json_obj, parent_key='', separator='_'):
    items = []
    for key, value in json_obj.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key
        if isinstance(value, dict):
            # Recursively flatten nested dictionaries
            items.extend(flatten_json(value, new_key, separator=separator).items())
        elif isinstance(value, list):
            # Recursively flatten list items
            for i, item in enumerate(value):
                items.extend(flatten_json({f"{new_key}_{i}": item}, separator=separator).items())
        else:
            # Add simple key-value pair
            items.append((new_key, value))
    return dict(items)

# Function to validate input parameters passed from Splunk
def validate_input(helper, definition):
    """Validate the input configuration."""
    dummy_var = helper.get_arg("dummy_var")  # Splunk requires one input argument
    return True

# Main function called by Splunk to collect and index data
def collect_events(helper, ew):
    """Data collection logic for Splunk modular input"""

    dummy_var = helper.get_arg('dummy_var')  # Required argument (unused)

    # Fetch data from AbuseIPDB
    abuseipdb_data = fetch_abuseipdb_data()

    # Check if response contains expected 'data' key
    if abuseipdb_data and 'data' in abuseipdb_data:
        reports = abuseipdb_data['data']

        for report in reports:
            # Flatten the report JSON
            flattened_report = flatten_json(report)
            event_data = json.dumps(flattened_report)

            # Create a new Splunk event
            event = helper.new_event(
                data=event_data,
                sourcetype="threat_intel3",
                source="abuseipdb",
                index="add_on_builder_index",
                done=True,
                unbroken=True
            )

            # Write event to Splunk index
            ew.write_event(event)

        helper.log_info(f"Successfully processed {len(reports)} reports from AbuseIPDB.")
    else:
        # Log error if data not fetched or is empty
        helper.log_error("Failed to fetch AbuseIPDB data or no data available.")
