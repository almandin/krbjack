# Description:
#   A set of custom scapy pipes to overcome some lacking features
#   in the available ones.

from scapy.all import Drain, Source
import socket


# A custom drain to perform a task when triggered.
# Takes a function in argument to be run when triggered.
class OnTriggered(Drain):
    def __init__(self, f, *args, name=None, **kwargs):
        super().__init__(name)
        self.f = f
        self.args = args
        self.kwargs = kwargs

    def on_trigger(self, trg):
        return self.f(trg, *self.args, **self.kwargs)


# A custom drain to perform a task when receiving a message
# on low or high inputs.
# Takes a function as argument to be run when a message is received.
# The function takes one argument, which will be the message received.
class OnMessage(Drain):
    def __init__(self, f, *args, name=None, **kwargs):
        super().__init__(name)
        self.f = f
        self.args = args
        self.kwargs = kwargs

    def push(self, msg):
        self.f(msg, *self.args, **self.kwargs)
        self._send(msg)

    def high_push(self, msg):
        self.f(msg, *self.args, **self.kwargs)
        self._high_send(msg)


# A custom drain to filter messages received. When it receives
# a message, it evaluates a condition against it to decide wether
# it should forward it or not.
# Take a function as argument. This function takes the message as an
# argument and must return True or False to decides wether this message
# can be forwarded or not.
class ConditionDrain(Drain):
    """Pass messages when a condition is met
    .. code::
         +-------------+
      >>-|-[condition]-|->>
         |             |
       >-|-[condition]-|->
         +-------------+
    """
    def __init__(self, f, name=None):
        Drain.__init__(self, name=name)
        self.f = f

    def push(self, msg):
        if self.f(msg):
            self._send(msg)

    def high_push(self, msg):
        if self.f(msg):
            self._high_send(msg)


# Just like TCPConnectPipe though it does not connect to the destination
# at creation but only when triggered.
class TriggeredTCPConnectPipe(Source):
    """Exactly like a TCPConnectPipe but only connects to its destination when
        triggered and not before.
    .. code::
         +------^------+
      >>-|             |->>
         |             |
       >-|-[ message ]-|->
         +------^------+
    """
    __selectable_force_select__ = True

    def __init__(self, addr="", port=0, name=None):
        Source.__init__(self, name=name)
        self.addr = addr
        self.port = port
        self.fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False

    def start(self):
        ...  # wait for trigger

    def on_trigger(self, data):
        self.fd.connect((self.addr, self.port))
        self.connected = True

    def stop(self):
        if self.fd and self.connected:
            self.fd.close()
            self.connected = False

    def push(self, msg):
        self.fd.send(msg)

    def fileno(self):
        return self.fd.fileno()

    def deliver(self):
        if self.connected:
            try:
                msg = self.fd.recv(65536)
            except (socket.error, ValueError, ConnectionResetError):
                self.stop()
                raise
            if msg:
                self._send(msg)
