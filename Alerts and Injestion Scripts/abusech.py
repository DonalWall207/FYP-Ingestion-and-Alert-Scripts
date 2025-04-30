#### IMPORTANT: These scripts are stored in Splunk Add-on Builder and run in the context of Splunk. ####
#### This means they are copied over from there, so others can view the code achieved here ####

import json
import requests

# API endpoint for Abuse.ch URLHaus - hardcoded, no user input required
API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# Function to fetch data from the Abuse.ch URLHaus API
def fetch_abusech_data():
    try:
        # Make a GET request to the API
        response = requests.get(API_URL)
        response.raise_for_status()  # Raise an exception for non-200 responses
        return response.json()       # Return parsed JSON response

    # Handle specific request errors and log them using Splunk's helper
    except requests.exceptions.HTTPError as http_err:
        helper.log_error(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        helper.log_error(f"Connection error occurred: {conn_err}")
    except requests.exceptions.RequestException as e:
        helper.log_error(f"Failed to fetch Abuse.ch data: {str(e)}")

    return None  # Return None if an error occurred

# Recursive function to flatten nested JSON structures into a single-level dictionary
def flatten_json(json_obj, parent_key='', separator='_'):
    items = []

    for key, value in json_obj.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key

        if isinstance(value, dict):
            # Recursively flatten nested dictionaries
            items.extend(flatten_json(value, new_key, separator=separator).items())

        elif isinstance(value, list):
            # Recursively flatten items in a list
            for i, item in enumerate(value):
                items.extend(flatten_json({f"{new_key}_{i}": item}, separator=separator).items())

        else:
            # Append flat key-value pair
            items.append((new_key, value))

    return dict(items)

# Function to validate input parameters provided to the modular input
def validate_input(helper, definition):
    """Validate the input configuration."""
    dummy_var = helper.get_arg("dummy_var")  # Splunk requires at least one input variable
    return True

# Function to collect data and write it to Splunk
def collect_events(helper, ew):
    """Data collection logic for Splunk modular input"""

    dummy_var = helper.get_arg('dummy_var')  # Required argument (unused)

    # Fetch recent URL data from Abuse.ch
    abusech_data = fetch_abusech_data()

    # Check if the response contains a 'urls' list
    if abusech_data and 'urls' in abusech_data:
        # Limit the number of events to avoid hitting daily indexing limits (e.g., in free Splunk)
        limited_urls = abusech_data['urls'][:100]

        for url_info in limited_urls:
            # Flatten the nested JSON data
            flattened_url_info = flatten_json(url_info)
            # Convert flattened data to JSON string
            event_data = json.dumps(flattened_url_info)

            # Create a new Splunk event
            event = helper.new_event(
                data=event_data,
                sourcetype="threat_intel1",
                source="abuse_ch_urlhaus",
                index="add_on_builder_index",
                done=True,
                unbroken=True
            )

            # Write the event to Splunk
            ew.write_event(event)

        helper.log_info(f"Successfully processed {len(limited_urls)} URLs from Abuse.ch (limited to 100).")

    else:
        # Log error if data is missing or fetch failed
        helper.log_error("Failed to fetch Abuse.ch URLHaus data or no data available.")
