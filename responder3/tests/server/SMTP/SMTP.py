#!/usr/bin/env python3.6
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from responder3.core.test_helper import setup_test

username = 'alma'
password = 'alma'

r3, global_config = setup_test(__file__)
r3_process = r3.start_process()

time.sleep(1)

server = smtplib.SMTP('localhost', 25)

# Next, log in to the server
server.login(username, password)

# Send the mail
msg = MIMEMultipart()       # create a message

# add in the actual person name to the message template
message = 'HELLO!'

# setup the parameters of the message
msg['From']   = 'alma@gmail.com'
msg['To']     = 'korte@gmail.com, test@gmail.com'
msg['Subject']= "This is TEST\r\nhaha!'\r\n\r\n\r\n.\r\n\r\n"

# add in the message body
msg.attach(MIMEText(message, 'plain'))

# send the message via the server set up earlier.
server.send_message(msg)
server.close()
