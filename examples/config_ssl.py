startup = {
	'mode'    : 'STANDARD',  # STANDARD or DEV or SERVICE
}

logsettings = {
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
				'level': 'INFO',
			}
		},
		'root'      : {
			'level'   : 'INFO',
			'handlers': ['console']
		}
	}
}

servers = [
	#
	#Below is a simple config for a generic HTTP listener
	#
	{
		'handler'    : 'HTTP',
	},
	#
	#Below is the config for HTTPS server on port 8080. 
	#The certificate and key file are supplied in 'certfile' and 'keyfile'.
	#Please use full path to file to make sure responder can find them
	#
	{
		'handler'    : 'HTTP',
		'bind_port'  : [(8080, 'tcp')],
		'bind_iface' : 'lo',
		'bind_family': 4,
		'bind_sslctx': {
			'protocols'  : 'PROTOCOL_SSLv23',
			'options'    : 'OP_CIPHER_SERVER_PREFERENCE',
			'verify_mode': 'CERT_NONE',
			'ciphers'    : 'ALL',
			'certfile'   : 'C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tests\\testca\\test_server.crt',
			'keyfile'    : 'C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tests\\testca\\test_server.pem',
				
		},
	},
	#
	#Below is the config for HTTPS server on port 8081. 
	#The certificate and key data supplied in 'certdata' and 'keydata'.
	#This is handy when you with to distribute the config without having to write to filesystem.
	#!!BUT!! Thanks to way Python is written, the underlying engine will write a file :(
	#There is no way as of now to load a cert and/or key to an ssl context without writing it to dis first.
	#
	{
		'handler'    : 'HTTP',
		'bind_port'  : [(8081, 'tcp')],
		'bind_iface' : 'lo',
		'bind_family': 4,
		'bind_sslctx': {
			'protocols'  : 'PROTOCOL_SSLv23',
			'options'    : 'OP_CIPHER_SERVER_PREFERENCE',
			'verify_mode': 'CERT_NONE',
			'ciphers'    : 'ALL',
			'certdata'   : '-----BEGIN CERTIFICATE-----\r\n'\
							'MIIDEzCCAfugAwIBAgIBAjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhyM3Rl\r\n'\
							'c3RDQTAeFw0xODExMDEyMDM3MDBaFw0yODExMDEyMDM3MDBaMBYxFDASBgNVBAMM\r\n'\
							'C3Rlc3Rfc2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtd1A\r\n'\
							'TN7yDtJH5h1PHDOjBSZzd4PO1/EL35UyeRJ7uwUk6NyCgiwUicr+sMEVqKkiAaNN\r\n'\
							'xbhGiJv9+uWtJWkSyhpBb2kDlXq/aBA1aAJ1U7y1CAK6QOTrxO9+ugLJuILsY5i/\r\n'\
							'N4GERITeJgCwRdDaOCR3EzeG8mt+znQNwE3vdD3DCpNGSDMenyCF/STjBcpdXABF\r\n'\
							'1CNeSnzEZUZ5enp2yg2oCTCbgN8yuTftM04gWyhojeYXitRJRYAE7INNqYGPyg73\r\n'\
							'mXY4rN6mIgeVIhaWSYxpjp6g7LXOr0xNsBnt2pctf9zpYbq40HxI4SNBqB/9lwXV\r\n'\
							'7PPC2cuWg2QEuCZANQIDAQABo28wbTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTv\r\n'\
							'Wx/+SvpZgV8dyYVoGZ3norTwWzALBgNVHQ8EBAMCBeAwEQYJYIZIAYb4QgEBBAQD\r\n'\
							'AgZAMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQEL\r\n'\
							'BQADggEBAGB56E1cfRmoum67ska+3qo4xM41uU40rm+VnGQpcBhloNEZ8fGL/vB6\r\n'\
							'0eJXsGe2uju49QfXccIV7JEawOauifc7cYYMNGKDCcPAXa3FXsCzRkkw+hO8l5zK\r\n'\
							'qgtbcqy+ov0I2bn09iM3CdB9ZhyISPBcPTtGFQjRJSX2NXQbfOTlz5CWyqb8bR/g\r\n'\
							'QqF1upvc0xzjJRjg/5VSxBdsBwqbH80vyiFBP9C919IfpUm+HDLe4Gps5NV5w+VT\r\n'\
							'GVC3WHkWU5PUUbwaD0b1O32rYiihYrPLYWFLqDPzhWPTZjpBr/Ehu/WbGVtSQmFv\r\n'\
							'g1T4Y9c1mGDYzyOy2/zeQWpWGZ0VnaE=\r\n'\
							'-----END CERTIFICATE-----\r\n',
			'keydata'    :  '-----BEGIN RSA PRIVATE KEY-----\r\n'\
							'MIIEowIBAAKCAQEAtd1ATN7yDtJH5h1PHDOjBSZzd4PO1/EL35UyeRJ7uwUk6NyC\r\n'\
							'giwUicr+sMEVqKkiAaNNxbhGiJv9+uWtJWkSyhpBb2kDlXq/aBA1aAJ1U7y1CAK6\r\n'\
							'QOTrxO9+ugLJuILsY5i/N4GERITeJgCwRdDaOCR3EzeG8mt+znQNwE3vdD3DCpNG\r\n'\
							'SDMenyCF/STjBcpdXABF1CNeSnzEZUZ5enp2yg2oCTCbgN8yuTftM04gWyhojeYX\r\n'\
							'itRJRYAE7INNqYGPyg73mXY4rN6mIgeVIhaWSYxpjp6g7LXOr0xNsBnt2pctf9zp\r\n'\
							'Ybq40HxI4SNBqB/9lwXV7PPC2cuWg2QEuCZANQIDAQABAoIBAGLA4MCdM22u69Hd\r\n'\
							'ym5y76vFRF/6l+AUiTEAcCbkTYGxemhkDQ4oZ4KnUwOh5WPva4LeLUYXGV3m7tRF\r\n'\
							'0W6GDujltvCLYqHRxIv6eTWgWBt/VgIikQbaB9ipf/P7vZPOrBQtBnBaiPs39vVF\r\n'\
							'3HIcxdJEotAxj7qlenca97ib2VIRqGKI4xr36UdYs3XW2Ip1zatZPLTMBVroyLpY\r\n'\
							'f9ytiXz7QlQH5mBE99oIksKrAz/z38zXZ18yIZJQRwnbC/nOapEeokMpRu61opEl\r\n'\
							'e50K/qIKhrdGJJ+20BLIAa05W8jRC8ezZ7Hb+5XI4bl5HJF8IpVMqi1ZVLssQo3F\r\n'\
							'S1N9egECgYEA6syeCP/b5hbV6z28SH4lT7fXAaakxxUt0otzt0lV2wUvsfvF3S9p\r\n'\
							'WV4OYKvJrSapbzsGLseSjQE8ho9OIxpscPX4iqALhnbnY21DeSMY/zigLHPHX0mP\r\n'\
							'SDInlfI+W+LapnHNU6ofZA5K+tN5WWAzskXmC5G3TPsGIv6A1YOANLUCgYEAxkkK\r\n'\
							'mZIgMA5yGyv8t8jAe1B6cF40X2+77lM220ZgMTLfvFmjnQgypwPXxez4jHoAAgth\r\n'\
							'/1ivxV7fvny6xl/J6IM8orKmKk8GQAganyzq50KxxxoSd8yasmqGlXoHVDsMbEoK\r\n'\
							'RBFI9BtEn5OJ2impWYdE12mpt4IumkVgOw/0jYECgYEAqSr3ieBeHO7C/ZQjPc+1\r\n'\
							'LjR0MnpQKie2NgXHP30U4JJiBMgzjOMF8h90GG5tBdXfKYbLM5USn4kOhJxnXZ9C\r\n'\
							'FjkB807QPvcYS2iDvpls/yVbMevQ73ReSVPpdX1tNGLDyjwgBXGC4GHz37fRrHVF\r\n'\
							'ieIWlqtL96i8iSX4yNzP2CkCgYBca+Ev8YdlPuZ6uccCluT41WssgwxgS4FKNalF\r\n'\
							'DYl6hR75+MIlSJPrewQQ8kJrn9XvHgUgcuMC2RTrAdJA8pb29GzH3QNMhyb/o4dd\r\n'\
							'GB+piVG53vIqusiETtjKRWWzIg7JTr14OqJJfYg/5RIFCRQxcbZpvYtoyJoWOC4B\r\n'\
							'eY9ggQKBgDEMW8ZkNFgXpj+j7zxGpp/TQUtM4LL/uGa4Du3Wicz7T/Ho6lmVkLCZ\r\n'\
							'GWQrsJZjqI512qFKDTVWX7nOap+oGqGBF4VnefvO9RVoB6wVqb3FpZRx8elUyPXN\r\n'\
							'oChY/SCgtGktqGgtcHYiFXVUqHW8cHTk9Sb0YL4T8xLMrab2j13C\r\n'\
							'-----END RSA PRIVATE KEY-----\r\n',
			
		},
	},
]
