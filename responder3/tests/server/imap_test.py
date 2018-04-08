#!/usr/bin/env python3.6

import imaplib

username = 'alma'
password = 'alma'

M = imaplib.IMAP4('localhost', 143)
M.login(username, password)
M.select()
typ, data = M.search(None, 'ALL')
M.close()
M.logout()
