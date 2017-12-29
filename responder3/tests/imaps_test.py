import imaplib

M = imaplib.IMAP4_SSL('localhost', 993)
M.login('alma','alma')
M.select()
typ, data = M.search(None, 'ALL')
M.close()
M.logout()