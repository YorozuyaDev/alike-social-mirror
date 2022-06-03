import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from messages import *
import configparser
import os


MAIL_USERNAME = os.environ['MAIL_USERNAME']
config = configparser.ConfigParser()
config.read('/run/secrets/secret')
MAIL_PASSWORD = config['AUTH']['MAIL_PASSWORD']


sender_email = MAIL_USERNAME
message = MIMEMultipart("alternative")
 
def request_confirmation(receiver_email, username, confirmation_url):
    message["Subject"] = "Alike | Email Confirmation"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Create the plain-text and HTML version of your message
    text = confirmation_text.format(username=username,confirmation_url=confirmation_url)

    html = confirmation_html.format(username=username,confirmation_url=confirmation_url)
    send_mail(sender_email, receiver_email, text, html)
    return True

def send_mail(sender_email, receiver_email, text, html):
    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )

def request_password(receiver_email, change_password_url):
    message["Subject"] = "Alike | Password Change"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Create the plain-text and HTML version of your message
    text =  change_password_text.format(change_password_url=change_password_url)
    html = change_password_html.format(change_password_url=change_password_url)
    send_mail(sender_email, receiver_email, text, html)
    return True
