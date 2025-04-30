#### IMPORTANT: These scripts are stored in Splunk Add-on Builder and run in the context of Splunk. ####
#### This means they are copied over from there, so others can view the code achieved here ####

import json
import requests
import os
from dotenv import load_dotenv

# Load environment variables (expects a .env file with API_KEY defined)
load_dotenv()

# API endpoint and key for AlienVault OTX
API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"  # Hardcoded API URL
API_KEY = os.getenv("API_KEY")  # API key stored securely in environment variable

# Function to fetch threat intel data from AlienVault OTX
def fetch_otx_data():
    headers = {'X-OTX-API-KEY': API_KEY}  # Header with API key for authentication
    try:
        # Make GET request to OTX API
        response = requests.get(API_URL, headers=headers)
        response.raise_for_status()  # Raise error for HTTP status codes >= 400
        return response.json()       # Return parsed JSON response

    # Handle specific types of request errors and print debug messages
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch OTX data: {str(e)}")

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
    dummy_var = helper.get_arg("dummy_var")  # Required by Splunk, even if unused
    return True

# Main function called by Splunk to collect and index data
def collect_events(helper, ew):
    """Data collection logic for Splunk modular input"""

    dummy_var = helper.get_arg('dummy_var')  # Required but not used

    # Fetch data from AlienVault OTX
    otx_data = fetch_otx_data()

    # Check if response contains expected 'results' key
    if otx_data and 'results' in otx_data:
        for pulse in otx_data['results']:
            # Flatten the pulse JSON for easier Splunk indexing
            flattened_pulse = flatten_json(pulse)
            event_data = json.dumps(flattened_pulse)

            # Create a new Splunk event
            event = helper.new_event(
                data=event_data,
                sourcetype="threat_intel2",
                source="alienvault_otx",
                index="add_on_builder_index",
                done=True,
                unbroken=True
            )

            # Write event to Splunk index
            ew.write_event(event)

        helper.log_info(f"Successfully processed {len(otx_data['results'])} pulses from AlienVault OTX.")
    else:
        # Log error if data not fetched or is empty
        helper.log_error("Failed to fetch AlienVault OTX data or no data available.")
