startup = {
        'mode' : 'DEV', #STANDARD or DEV or SERVICE
        'settings' : {
                'pidfile' : "/var/run/responder.pid", #must be defined if mode==SERVICE, other modes ignore this
        },
}

logsettings = {
        'log' : {
                'version': 1,
                'formatters': {
                        'detailed': {
                                'class': 'logging.Formatter',
                                        'format': '%(asctime)s %(name)-15s %(levelname)-8s %(processName)-10s %(message)s'
                        }
                },
                'handlers': {
                        'console': {
                                'class': 'logging.StreamHandler',
                                'level': 'DEBUG',
                        }
                },
                'root': {
                        'level': 'DEBUG',
                        'handlers': ['console']
                }
        }
}

servers = [
        {
                'handler'  : 'MDNS',
                'settings': {
                        'mode' : 'SPOOF',
                        'spooftable' :{
                                '.*':'127.0.0.1',
                        }
                },
        },
        {
                'handler' : 'DNS',
                'bind_family': 4,
                'settings': {
                                                'mode': 'spoof', #mode can be either analyse or spoof
                                                'spooftable': [
                                                         {'github.com' : '::1'},
                                                         {'.*' : '192.168.44.23'},
                                                ],
                                                'passthru' : {
                                                        #'dnsserver': '2001:4860:4860::8888:53',
                                                        'dnsserver': '8.8.8.8:53',
                                                        'bind_iface' : 'ens33',
                                                        #'bind_proto' : '',
                                                        #'bind_addr'  : '',

                                                },
                
                                        }, 
        },
        {
                'handler'  : 'LLMNR',
                'settings': {
                        'mode' : 'SPOOF',
                        'spooftable' :{
                                '.*':'192.168.30.11',
                        }
                },
        },
        {
                'bind_iface': 'ens37',
                'handler' : 'NBTNS', 
                'bind_family': 4, #no point in ipv6, it's not supported by design (but it works with it regardless :P)
                'settings': 
                        {
                                'mode': 'spoof', #mode can be either analyse or spoof
                                'spooftable': [
                                                 {'github.com' : '127.0.0.2'},
                                                 {'.*' : '192.168.44.23'},
                                        ],

                        },
        },
        {
                'bind_family': 4, 
                'handler' : 'DHCP',
                'settings': {
                                                'mode': 'spoof', #mode can be either analyse or spoof
                                                'subnetmask' : 'FF:FF:FF:00',
                                                'leasetime'  : 199,
                                                'ip_pool'    : '192.168.111.100-200',
                                                'ack_options': 
                                                        [
                                                                ('42',['192.168.111.1',]), 
                                                                ('6',['192.168.111.1',])
                                                        ]
                                        }, 
        },
        {
                'handler' : 'NTP',
                'bind_family': 4,
                'settings': {
                        'faketime': 'Apr 27 2018 13:37',
                        'timefmt' : '%b %d %Y %H:%M',
                }
        },

]
