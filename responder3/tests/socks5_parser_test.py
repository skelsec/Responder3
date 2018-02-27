import re
import collections

settings = {
        'proxyTable' : [
                {
                        'alma.com': [
                                {
                                        '1 - 500' : '127.0.0.1:80'
                                }
                        ],
                },
                {
                        '.*.com': [
                                {
                                        '1 - 65535' : '192.168.1.1:99'
                                }
                        ],
                },
                

        ],
}


def fake_dest_lookup(dest_ip, dest_port):
        for ipregx in proxyTable:
                print(ipregx)
                print(ipregx.match(dest_ip))
                if ipregx.match(dest_ip):
                        print(proxyTable[ipregx])
                        for portranged in proxyTable[ipregx]:
                                print(portranged)
                                for portrange in portranged:
                                        print(portrange)
                                        if dest_port in portrange:
                                                print(dest_port)
                                                return portranged[portrange]

        return None, None

#ordereddisct is used to be able to check regexps in the order that is specified by the user.
#the input ifor this level is a list, because ordereddict is a python pbject and cannot be serialized as a dict, rather than a list
proxyTable = collections.OrderedDict()

for entry in settings['proxyTable']:
        for ip in entry:
                print(ip)
                iprex = re.compile(ip)
                proxyTable[iprex] = []
                for portranged in entry[ip]:
                        print(portranged)
                        for portrange in portranged:
                                print(portrange)
                                if portrange.find('-') != -1:
                                        start, stop = portrange.split('-')
                                        prange = range(int(start.strip()),int(stop.strip())+1)
                                        print(prange)
                                
                                else:
                                        prange = range(int(portrange),int(portrange)+1)
                                
                                if portranged[portrange].find(':') != -1:
                                        #additional parsing to enable IPv6 addresses...
                                        marker = portranged[portrange].rfind(':')
                                        proxyTable[iprex].append({prange : (portranged[portrange][:marker], int(portranged[portrange][marker+1:]))})
                                else:
                                        raise Exception('The target address MUST be supplied in IP:PORT format! Problem: %s' % portranged[portrange])

print(proxyTable)

print(fake_dest_lookup('alma.com',500))