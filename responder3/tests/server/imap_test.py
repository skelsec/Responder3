import imaplib

M = imaplib.IMAP4('localhost', 143)
M.login('alma','alma')
M.select()
typ, data = M.search(None, 'ALL')
M.close()
M.logout()