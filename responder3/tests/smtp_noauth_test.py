from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

server = smtplib.SMTP('localhost', 25)

#Send the mail
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
