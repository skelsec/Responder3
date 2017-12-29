import smtplib
server = smtplib.SMTP('localhost', 25)

#Next, log in to the server
server.login("alma", "alma")

#Send the mail
msg = "Hello!" # The /n separates the message from the headers
server.sendmail("you@gmail.com", "target@example.com", msg)