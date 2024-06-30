import logging
import os
import sys
import time
import smtplib
import base64
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.exceptions import RefreshError
from imap_tools import MailBox
import pyioga

IMAP_SERVER = 'imap.gmail.com'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_EMAIL = "example_user@gmail.com"
SCOPES = ['https://mail.google.com/']
logging.basicConfig(level=logging.INFO)

TOKEN_FILE = './oauth_credentials/token.json'
CREDENTIALS_FILE = './oauth_credentials/credentials.json'

def authenticate_and_get_token():
    creds = None
    try:
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
    except RefreshError as e:
        logging.error(f"RefreshError: {e}. Re-authenticating.")
        # Re-initiate the authentication flow
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    return creds.token if creds else None

def send_email(recipient, subject, content):
    token = authenticate_and_get_token()
    if not token:
        logging.error("Failed to obtain a valid token. Email not sent.")
        return False
    
    session = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    session.starttls()
    auth_string = b'user=' + bytes(SMTP_EMAIL, 'ascii') + b'\1auth=Bearer ' + token.encode() + b'\1\1'
    session.docmd('AUTH', 'XOAUTH2 ' + (base64.b64encode(auth_string)).decode('ascii'))
    headers = f"From: {SMTP_EMAIL}\r\nTo: {recipient}\r\nSubject: {subject}\r\n\r\n"
    session.sendmail(SMTP_EMAIL, recipient, headers + content)
    session.quit()

def main():
    # Setup the key files
    username = SMTP_EMAIL
    if not os.path.exists(TOKEN_FILE):
        authenticate_and_get_token()
    access_token = pyioga.get_access_token(TOKEN_FILE)

    # Loop receiving and sending emails
    while True:
        with MailBox(IMAP_SERVER).xoauth2(username, access_token) as mailbox:
            for msg in mailbox.fetch():
                print(f"---- New email received ----\nFrom: {msg.from_}\nSubject: {msg.subject}\n----------------------------")
                if msg.subject == "get_flag()":
                    with open("flag.txt", "r") as f:
                        FLAG = f.readline().strip()
                    send_email(msg.from_, "Re: " + msg.subject, f"{FLAG}")
                    print(f"Flag sent to {msg.from_}\n")

                mailbox.delete(msg.uid)
        time.sleep(30)

if __name__ == '__main__':
    main()

