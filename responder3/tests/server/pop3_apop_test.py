import poplib

user = 'alma'
password = 'alma'
Mailbox = poplib.POP3('localhost', '110')  
Mailbox.apop(user,password) 
