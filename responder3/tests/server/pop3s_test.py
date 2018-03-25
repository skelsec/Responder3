import poplib

user = 'alma'
password = 'alma'
Mailbox = poplib.POP3_SSL('localhost', '995') 
Mailbox.user(user) 
Mailbox.pass_(password) 