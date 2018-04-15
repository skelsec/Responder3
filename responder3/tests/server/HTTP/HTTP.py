#!/usr/bin/env python3.6
import time
from responder3.core.test_helper import setup_test
import requests
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth

username = 'bigcorp\\alma'
password = 'alma'

r3, global_config = setup_test(__file__)
r3_process = r3.start_process()

time.sleep(1)

requests.get('http://127.0.0.1/', auth=HTTPBasicAuth(username, password))
requests.get('https://127.0.0.1/', auth=HTTPBasicAuth(username, password))
requests.get('http://127.0.0.1/', auth=HttpNtlmAuth(username, password))
requests.get('https://127.0.0.1/', auth=HttpNtlmAuth(username, password))

proxies = { 'http' : 'http://%s:%s@127.0.0.1:8080' % (username, password) }
r = requests.get('https://github.com', proxies=proxies)

proxies = { 'https' : 'https://%s:%s@127.0.0.1:8443' % (username, password) }
r = requests.get('https://google.com', proxies=proxies)