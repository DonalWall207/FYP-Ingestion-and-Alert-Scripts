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

# Load environment variables from a .env file into the environment
load_dotenv()

# Function to send email alerts when a threat is detected
def send_email(threat, source_ip, dest_ip, reporter):
    # Load SMTP configuration from environment variables
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    username = os.getenv("EMAIL_USERNAME")
    password = os.getenv('SMTP_PASSWORD')  # SMTP password (or app-specific password)

    # Email sender and recipient information
    from_addr = os.getenv("EMAIL_USERNAME")
    to_addr = os.getenv("EMAIL_USERNAME2")

    # Subject and body of the email alert
    subject = f"Splunk Alert: {threat} Detected"
    body = f"""
    A new threat has been detected:

    Threat: {threat}
    Source IP: {source_ip}
    Destination IP: {dest_ip}
    Reported By: {reporter}

    Please review the event for more details.
    """

    # Create an email message object
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))  # Attach the email body as plain text

    try:
        # Connect to the SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection with TLS
        server.login(username, password)  # Authenticate with the SMTP server
        server.sendmail(from_addr, to_addr, msg.as_string())  # Send the email
        print("Email sent successfully!")  # Log success
    except Exception as e:
        print(f"Error sending email: {e}")  # Log any exceptions
    finally:
        server.quit()  # Close the connection to the server

# Function to check a specific saved search in Splunk and send alerts
def check_saved_search():
    # Base URL of the Splunk instance
    splunk_url = 'https://127.0.0.1:8089'
    
    # Name of the saved search configured in Splunk
    saved_search_name = 'Threat Alert Email Action'

    # Create a session for making HTTP requests
    session = requests.Session()
    
    # Splunk credentials (update 'changeme' for production!)
    auth = ('admin', 'changeme')

    # Construct the URL to dispatch the saved search
    dispatch_url = f'{splunk_url}/servicesNS/admin/search/saved/searches/{saved_search_name}/dispatch'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Send a request to start (dispatch) the saved search job
    response = session.post(dispatch_url, auth=auth, headers=headers, data={'output_mode': 'json'}, verify=False)

    # Check if the search was successfully dispatched
    if response.status_code != 201:
        print(f"Failed to dispatch search: {response.text}")
        return

    # Parse the job ID from the JSON response
    response_json = response.json()
    job_id = response_json.get('sid')
    if not job_id:
        print(f"Failed to get job ID. Response: {response.text}")
        return

    print(f"Dispatched search job ID: {job_id}")

    # Poll Splunk to check if the search job is done
    status_url = f'{splunk_url}/services/search/jobs/{job_id}?output_mode=json'
    
    for _ in range(10):  # Try for up to 10 seconds
        time.sleep(1)
        status_response = session.get(status_url, auth=auth, verify=False)
        if status_response.status_code == 200:
            job_status = status_response.json()
            if job_status.get('entry', [{}])[0].get('content', {}).get('isDone'):
                print("Search completed!")
                break
    else:
        # If the job didn't complete in time, exit
        print("Search did not complete in time.")
        return

    # Fetch the search results
    results_url = f'{splunk_url}/services/search/jobs/{job_id}/results?output_mode=json'
    result_response = session.get(results_url, auth=auth, verify=False)

    if result_response.status_code == 200:
        results = result_response.json()
        print("Search results received:", results)

        # If there are any results, extract threat details and send email notifications
        if 'results' in results and results['results']:
            for result in results['results']:
                send_email(
                    result.get('threat', 'Unknown Threat'),
                    result.get('source_ip', 'Unknown'),
                    result.get('dest_ip', 'Unknown'),
                    result.get('reporter', 'Unknown')
                )
        else:
            print("No threat detected in search results.")
    else:
        print(f"Failed to fetch results: {result_response.text}")

# Entry point - run the search check
check_saved_search()
