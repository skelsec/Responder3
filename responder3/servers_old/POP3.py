import os
import logging
import traceback
from responder3.core.servertemplate import ResponderServer, ResponderProtocolTCP, ProtocolSession
from responder3.protocols.POP3 import *


class POP3Session(ProtocolSession):
        def __init__(self):
                ProtocolSession.__init__(self)
                self.encoding     = 'ascii'
                self.cmdParser    = POP3CommandParser(encoding = self.encoding)
                self.currentState = POP3State.AUTHORIZATION
                self.User = None
                self.Pass = None
                

class POP3(ResponderServer):
        def __init__(self):
                ResponderServer.__init__(self)                
                
        def modulename(self):
                return 'POP3'

        def setup(self):
                self.protocol = POP3Protocol
                
                #put settings parsing here!
                return

        def sendWelcome(self, transport):
                transport.write(POP3Response(POP3ResponseStatus.OK, ['<1896.697170952@dbc.mtview.ca.us>']).toBytes())

        def handle(self, packet, transport, session):
                try:
                        if 'R3DEEPDEBUG' in os.environ:
                                self.log(logging.INFO,'Session state: %s Command: %s' % (session.currentState.name, packet.command.name if packet is not None else 'NONE'), session)
                        if session.currentState == POP3State.AUTHORIZATION:
                                if packet.command == POP3Command.USER:
                                        session.User = packet.params[0]
                                        if session.Pass is not None:
                                                self.check_credentials(transport)
                                        else:        
                                                transport.write(POP3Response(POP3ResponseStatus.OK, ['password required.']).toBytes())
                                        return

                                elif packet.command == POP3Command.PASS:
                                        session.Pass = packet.params[0]
                                        if session.User is not None:
                                                self.check_credentials(transport, session)
                                        else:
                                                transport.write(POP3Response(POP3ResponseStatus.OK, ['username required.']).toBytes())
                                        return

                                elif packet.command == POP3Command.QUIT:
                                        transport.write(POP3Response(POP3ResponseStatus.OK, ['Goodbye!']).toBytes())
                                        return

                                else:
                                        transport.write(POP3Response(POP3ResponseStatus.ERR, ['Auth req.']).toBytes())
                                        return

                        elif session.currentState == POP3State.TRANSACTION:
                                ##this would be the place to send emails/statuses to the clinet but it's not implemented
                                ##therefore we send an okay message and terminate the connection
                                ##tottaly breaking RFC :P
                                transport.write(POP3Response(POP3ResponseStatus.OK, ['Goodbye!']).toBytes())
                                transport.close()
                                raise Exception('Not implemented!')

                        
                        else:
                                transport.write(POP3Response(POP3ResponseStatus.OK, ['Goodbye!']).toBytes())
                                transport.close()
                                return


                except Exception as e:
                        self.log(logging.INFO,'Exception! %s' % (str(e),))
                        pass

        def check_credentials(self, transport, session):
                self.logResult(session, {
                                                        'type'     : 'Cleartext', 
                                                        'client'   : session.connection.remote_ip, 
                                                        'user'     : session.User,
                                                        'cleartext': session.Pass, 
                                                        'fullhash' : session.User + ':' + session.Pass
                                                        })
                
                if session.User == 'aaaaaaaaaa' and session.Pass == 'bbbbbbb124234123':
                        #login sucsess
                        session.currentState = POP3State.TRANSACTION
                        transport.write(POP3Response(POP3ResponseStatus.OK, ['CreZ good!']).toBytes())
                else:
                        transport.write(POP3Response(POP3ResponseStatus.ERR, ['invalid password']).toBytes())
                        transport.close()


                

class POP3Protocol(ResponderProtocolTCP):
        
        def __init__(self, server):
                ResponderProtocolTCP.__init__(self, server)
                self._buffer_maxsize = 1*1024
                self._session = POP3Session()

        def _connection_made(self):
                self._server.sendWelcome(self._transport)

        def _data_received(self, raw_data):
                return

        def _connection_lost(self, exc):
                return

        def _parsebuff(self):
                #POP3 commands are terminated by new line chars
                #here we grabbing one command from the buffer, and parsing it
                marker = self._buffer.find(b'\n')
                if marker == -1:
                        return

                cmd = self._session.cmdParser.parse(io.BytesIO(self._buffer[:marker+1]))

                #after parsing it we send it for processing to the handle
                self._server.handle(cmd, self._transport, self._session)

                #IMPORTANT STEP!!!! ALWAYS CLEAR THE BUFFER FROM DATA THAT IS DEALT WITH!
                self._buffer = self._buffer[marker + 1 :]
                
                if self._buffer != b'':
                        self._parsebuff()

class POP3S(POP3):
        def modulename(self):
                return 'POP3S'