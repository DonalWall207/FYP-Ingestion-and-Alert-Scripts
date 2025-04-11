#### IMPORTANT: These scripts are stored locally and run locally on this machine. ####
#### This means they are not exposed to the internet and are not publicly accessible. ####

import smtplib
import time
import requests
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

# Load environment variables from .env file into the environment
load_dotenv()

# Function to send email alerts for detected threats
def send_email(author_name, description, targeted_countries, event_time):
    # Load SMTP configuration from environment variables
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    username = os.getenv("EMAIL_USERNAME")
    password = os.getenv('SMTP_PASSWORD')  # Securely get SMTP password

    # Email sender and recipient details
    from_addr = os.getenv("EMAIL_USERNAME")
    to_addr = os.getenv("EMAIL_USERNAME2")

    # Subject and body content of the email
    subject = f"Splunk Alert: Threat Targeting {targeted_countries} Detected"
    body = f"""
    A new threat has been detected:

    Author Name: {author_name}
    Description: {description}
    Targeted Countries: {targeted_countries}
    Event Time: {event_time}

    Please review the event for more details.
    """

    # Construct the email message
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))  # Add plain text body to the email

    try:
        # Connect to the SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Use TLS to secure the connection
        server.login(username, password)  # Authenticate with SMTP server
        server.sendmail(from_addr, to_addr, msg.as_string())  # Send email
        print("Email sent successfully!")  # Log success
    except Exception as e:
        # Log any errors that occur during the process
        print(f"Error sending email: {e}")
    finally:
        # Ensure the SMTP connection is closed
        if 'server' in locals():
            server.quit()

# Function to check and process results from a saved Splunk search
def check_saved_search():
    # Splunk API URL and the saved search to dispatch
    splunk_url = 'https://127.0.0.1:8089'
    saved_search_name = 'Threat Alert Email Action2'

    # Create an HTTP session for API calls
    session = requests.Session()
    
    # Splunk authentication (update credentials in production)
    auth = ('admin', 'changeme')

    # URL to dispatch the saved search
    dispatch_url = f'{splunk_url}/servicesNS/admin/search/saved/searches/{saved_search_name}/dispatch'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Trigger the saved search via a POST request
    response = session.post(dispatch_url, auth=auth, headers=headers, data={'output_mode': 'json'}, verify=False)

    # Check if the dispatch was successful
    if response.status_code != 201:
        print(f"Failed to dispatch search: {response.text}")
        return

    # Extract the search job ID from the response
    response_json = response.json()
    job_id = response_json.get('sid')
    if not job_id:
        print(f"Failed to get job ID. Response: {response.text}")
        return

    print(f"Dispatched search job ID: {job_id}")

    # Poll for search completion status
    status_url = f'{splunk_url}/services/search/jobs/{job_id}?output_mode=json'
    for _ in range(10):  # Poll for up to 10 seconds
        time.sleep(1)
        status_response = session.get(status_url, auth=auth, verify=False)
        if status_response.status_code == 200:
            job_status = status_response.json()
            if job_status.get('entry', [{}])[0].get('content', {}).get('isDone'):
                print("Search completed!")
                break
    else:
        # Timeout if search does not complete in time
        print("Search did not complete in time.")
        return

    # Fetch the completed search results
    results_url = f'{splunk_url}/services/search/jobs/{job_id}/results?output_mode=json'
    result_response = session.get(results_url, auth=auth, verify=False)

    # Process the results if retrieval was successful
    if result_response.status_code == 200:
        results = result_response.json()
        print("Search results received:", results)  # Log results

        # Iterate through results and send an email for each threat
        if 'results' in results and results['results']:
            for result in results['results']:
                author_name = result.get('author_name', 'Unknown')
                description = result.get('description', 'No Description')
                targeted_countries = result.get('targeted_countries_0', 'Unknown')
                event_time = result.get('_time', 'Unknown Time')

                # Send alert via email
                send_email(author_name, description, targeted_countries, event_time)
        else:
            print("No threat detected in search results.")
    else:
        # Log error if unable to fetch results
        print(f"Failed to fetch results: {result_response.text}")

# Entry point to run the threat detection and alerting logic
check_saved_search()
