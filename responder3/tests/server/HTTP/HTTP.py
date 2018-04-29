#!/usr/bin/env python3.6
import time
import sys
import requests
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from responder3.core.test_helper import setup_test, read_to_creds


username = 'BIGCORP\\alma'
password = 'alma'

r3, global_config, output_queue = setup_test(__file__)
r3_process = r3.start()

time.sleep(1)

requests.get('http://127.0.0.1/', auth=HTTPBasicAuth(username, password), verify=False)
cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #1 PASS')


requests.get('https://127.0.0.1/', auth=HTTPBasicAuth(username, password), verify=False)
cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #2 PASS')


requests.get('http://127.0.0.1:81/', auth=HttpNtlmAuth(username, password), verify=False)
cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #3 PASS')


requests.get('https://127.0.0.1:444/', auth=HttpNtlmAuth(username, password), verify=False)
cred = read_to_creds(output_queue)
assert cred.username == username
assert cred.password == password
print('[+] Test #4 PASS')
sys.exit()

proxies = { 'http' : 'http://%s:%s@127.0.0.1:8080' % (username, password) }
r = requests.get('https://github.com', proxies=proxies, verify=False)

proxies = { 'https' : 'https://%s:%s@127.0.0.1:8443' % (username, password) }
r = requests.get('https://google.com', proxies=proxies, verify=False)


