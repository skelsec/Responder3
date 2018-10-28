import ldap3
from ldap3 import Server, Connection, SASL, PLAIN, DIGEST_MD5, NTLM
from pprint import pprint

import logging
logging.basicConfig(level=logging.DEBUG)
from ldap3.utils.log import set_library_log_activation_level
set_library_log_activation_level(logging.DEBUG)


server_uri = 'ldap://192.168.9.100'
#server_uri = 'ldap://192.168.9.1'
search_base = 'ou=users,dc=example,dc=com'
search_filter = '(uid=rob)'
attrs = ['*']

server = ldap3.Server(server_uri)




print('ANONYMOUS')
try:
	with ldap3.Connection(server, auto_bind=True) as conn:
		conn.search(search_base, search_filter, attributes=attrs)
		pprint(conn.entries)
except Exception as e:
	pass

	
print('SIMPLE')

try:
	with ldap3.Connection(server, auto_bind=True, user='AAAAAAA', password='BBBBBBBBBBBBBBB') as conn:
			conn.search(search_base, search_filter, attributes=attrs)
			pprint(conn.entries)
except Exception as e:
	pass
		


print('SASL - PLAIN')
try:
	with ldap3.Connection(server, auto_bind=True, authentication=SASL, sasl_mechanism=PLAIN, sasl_credentials=(None, 'AAAAAA', 'BBBBBBBPPPPWWWWW')) as conn:
			conn.search(search_base, search_filter, attributes=attrs)
			pprint(conn.entries)
except Exception as e:
	pass
"""

print('SASL - DIGESTMD5')
try:
	with ldap3.Connection(server, auto_bind=True, authentication = SASL, sasl_mechanism = DIGEST_MD5, sasl_credentials = (None, 'username', 'password', None)) as conn:
			conn.search(search_base, search_filter, attributes=attrs)
			pprint(conn.entries)
except Exception as e:
	pass
	


print('NTLM')
try:
	with ldap3.Connection(server, auto_bind=True, user="AUTHTEST\\Administrator", password="E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C", authentication=NTLM) as conn:
			conn.search(search_base, search_filter, attributes=attrs)
			pprint(conn.entries)
except Exception as e:
	pass
	

print('NTLM')
try:
	with ldap3.Connection(server, auto_bind=True, user="AUTHTEST\\Administrator", password="E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C", authentication=NTLM) as conn:
			conn.search(search_base, search_filter, attributes=attrs)
			pprint(conn.entries)
except Exception as e:
	pass
"""