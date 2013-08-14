Egresser
========

* Author: geoff.jones@cyberis.co.uk
* Copyright: Cyberis Limited 2013
* License: GPLv3 (See LICENSE)

Client/server scripts designed to test outbound (egress) firewall rules.

Description
-----------
Egresser is a tool to enumerate outbound firewall rules, designed for penetration testers to assess whether egress filtering is adequate from within a corporate network. Probing each TCP port in turn, the Egresser server will respond with the client’s source IP address and port, allowing the client to determine whether or not the outbound port is permitted (both on IPv4 and IPv6) and to assess whether NAT traversal is likely to be taking place.

*How it works*

The server-side script works in combination with Iptables - redirecting all TCP traffic to port 8080 where the ‘real’ server resides. The server-side script is written in Perl and is a pre-forking server utilising Net::Server::Prefork, listening on both IPv4 and IPv6 if available. Any TCP connection results in a simple response containing a null terminated string made up of the connecting client’s IP and port. Feel free to use Telnet to interact with the service if you are in a restricted environment without access to the Egresser client (our Egresser server can be found at egresser.labs.cyberis.co.uk, which you are free to use for legitimate purposes). 

The client is also written in Perl and is threaded for speed. By default it will scan TCP ports 1-1024, although this is configurable within the script. It is possible to force IPv4 with the ‘-4’ command line argument, or IPv6 with ‘-6’; by default it will choose the protocol preferred by your operating system. If you want to explicitly list all open/closed ports, specify the verbose flag (-v), as normal output is a concise summary of permitted ports only.

*Why?*

It is recommended that outbound firewall rules are restricted within corporate environments to ensure perimeter controls are not easily circumvented. For example, inadequate egress filtering within an organisation would allow  a malicious user to trivially bypass a web proxy providing filtering/AV/logging simply by changing a browser’s connection settings. Many other examples also exist - many worms spread over SMB protocols, malware can use  numerous channels to exfiltrate data, and potentially unauthorised software (e.g. torrent/P2P file sharing) can freely operate, wasting corporate resources and significantly increasing the likelihood of malicious code being introduced into the environment.

Generally, it is recommended that all outbound protocols should be restricted, allowing exceptions from specific hosts on a case-by-case basis. Web browsing should be conducted via dedicated web proxies only, with any attempted direct connections logged by the perimeter firewall and investigated as necessary.
Egresser is a simple to use tool to allow a penetration tester to quickly enumerate allowed ports within a corporate environment.

Dependencies
------------
iptables 1.4.17 or above, and a kernel 3.7+ is required for ipv6 nat support.

The following Perl modules are required for the client:

```perl
Thread::Queue ;
IO::Socket::IP;
Getopt::Long;
```

The following Perl modules are required for the server:

```perl
Net::Server::PreFork
```

Issues
------
Kindly report all issues via https://github.com/cyberisltd/Egresser/issues
