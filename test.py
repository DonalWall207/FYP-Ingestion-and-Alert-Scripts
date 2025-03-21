import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_test_email():
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    username = 'noreplysplunkalert@gmail.com'  # Your email address
    password = 'cicq ccdn pyhq sqvf'  # Use app password if you have 2FA enabled

    from_addr = 'noreplysplunkalert@gmail.com'  # Sender's email address
    to_addr = 'donaljohnwall@gmail.com'  # Recipient's email address
    subject = 'Test Email from Python'
    body = 'This is a test email sent from Python using Gmail SMTP.'

    # Prepare the email
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(username, password)  # Log in to the server
        server.sendmail(from_addr, to_addr, msg.as_string())  # Send the email
        print("Test email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")
    finally:
        server.quit()

# Run the function to send the test email
send_test_email()
