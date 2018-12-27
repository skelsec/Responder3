startup = {
	'mode'    : 'DEV',  # STANDARD or DEV or SERVICE
}

logsettings = {
	'handlers' : {
		'remote_ws': ['remote_ws'],
	},
	'remote_ws': {
		'mode': 'CLIENT',
		'server_url' : 'wss://127.0.0.1:6666',
		'ssl_ctx' : {
			'protocols'  : 'PROTOCOL_SSLv23',
			'options'    : 'OP_CIPHER_SERVER_PREFERENCE',
			'verify_mode': 'CERT_REQUIRED',
			'server_side': False,
			'check_hostname' : False,
			'ciphers'    : 'ALL',
			'certfile'   : 'C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tests\\testca\\test_client.crt',
			'keyfile'    : 'C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tests\\testca\\test_client.pem',
			'cafile'     : 'C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tests\\testca\\r3testCA.crt',
		},
	},
	'log': {
		'version'   : 1,
		'formatters': {
			'detailed': {
				'class' : 'logging.Formatter',
				'format': '%(asctime)s %(name)-15s %(levelname)-8s %(processName)-10s %(message)s'
			}
		},
		'handlers'  : {
			'console': {
				'class': 'logging.StreamHandler',
				'level': 'DEBUG',
			}
		},
		'root'      : {
			'level'   : 'DEBUG',
			'handlers': ['console']
		}
	}
}

servers = [
	{
		'handler'    : 'FTP',
	},
	{
		'handler'    : 'HTTP',
	},
	{
		'handler'    : 'SMTP',
	},
	{
		'handler'    : 'POP3',
	},
	{
		'handler'    : 'IMAP',
	},
	{
		'handler'    : 'KERBEROS',
	},
	{
		'handler'    : 'LDAP',
	},
	{
		'handler'    : 'VNC',
	},
	{
		'handler'    : 'SOCKS5',
	},
	{
		'handler'    : 'TELNET',
	},
]

