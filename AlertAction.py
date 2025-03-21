import smtplib
import time
import requests
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Function to send email alerts
def send_email(threat, source_ip, dest_ip, reporter):
    ### SMTP server and port were found, public info for gmail
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    username = os.getenv("EMAIL_USERNAME")
    password = os.getenv('SMTP_PASSWORD')  # Fetch SMTP password from environment variables

    from_addr = os.getenv("EMAIL_USERNAME")
    to_addr = os.getenv("EMAIL_USERNAME2")
    subject = f"Splunk Alert: {threat} Detected"
    body = f"""
    A new threat has been detected:

    Threat: {threat}
    Source IP: {source_ip}
    Destination IP: {dest_ip}
    Reported By: {reporter}

    Please review the event for more details.
    """

    # Create email message with the threat details
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)  # Login with provided credentials
        server.sendmail(from_addr, to_addr, msg.as_string())
        print("Email sent successfully!")  # Log successful email send
    except Exception as e:
        print(f"Error sending email: {e}")  # Log any errors that occur
    finally:
        server.quit()  # Ensure server is properly closed after the operation


# Function to check the saved search results
def check_saved_search():
    # Splunk REST API settings - These were found Splunk official Website
    splunk_url = 'https://127.0.0.1:8089'
    saved_search_name = 'Threat Alert Email Action'

    session = requests.Session()
    auth = ('admin', 'changeme')  # Change to your Splunk credentials

    # Dispatch the saved search via Splunk's REST API
    dispatch_url = f'{splunk_url}/servicesNS/admin/search/saved/searches/{saved_search_name}/dispatch'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Send request to dispatch the saved search job
    response = session.post(dispatch_url, auth=auth, headers=headers, data={'output_mode': 'json'}, verify=False)

    if response.status_code != 201:
        print(f"Failed to dispatch search: {response.text}")
        return

    # Extract search job ID from the response
    response_json = response.json()
    job_id = response_json.get('sid')
    if not job_id:
        print(f"Failed to get job ID. Response: {response.text}")
        return

    print(f"Dispatched search job ID: {job_id}")

    # Wait for the search job to complete (poll for status)
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
        print("Search did not complete in time.")  # Log if the search doesn't complete in time
        return

    # Fetch the results of the completed search
    results_url = f'{splunk_url}/services/search/jobs/{job_id}/results?output_mode=json'
    result_response = session.get(results_url, auth=auth, verify=False)

    if result_response.status_code == 200:
        results = result_response.json()
        print("Search results received:", results)  # Log the results for debugging

        # If results contain any threats, send email notifications
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
        print(f"Failed to fetch results: {result_response.text}")  # Log failure to fetch results


# Run the search check
check_saved_search()  # Execute the function to check the saved search and send email alerts
