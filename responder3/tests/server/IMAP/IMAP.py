#!/usr/bin/env python3.6
import time
import imaplib
from responder3.core.test_helper import setup_test

username = 'alma'
password = 'alma'

r3, global_config = setup_test(__file__)
r3_process = r3.start_process()

time.sleep(1)


#Test1
M = imaplib.IMAP4('localhost', 143)
M.login(username, password)
M.select()
typ, data = M.search(None, 'ALL')
M.close()
M.logout()

#Test2
M = imaplib.IMAP4_SSL('localhost', 993)
M.login(username, password)
M.select()
typ, data = M.search(None, 'ALL')
M.close()
M.logout()
