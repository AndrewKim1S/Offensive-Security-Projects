
###############################################################################
#                        Network Basics for Hackers                           #
#                         Start Date: August 2 2024                           #
#                         End Date:                                           #
#                            Status: In-Progress                              #
###############################################################################
General:
  1. Network Basics
    * IP Addresses                     * DHCP
    * NAT                              * IP
    * Ports                            * TCP
    * UDP                              * OSI Layers
  2. Subnetting and CIDR Notation
    * Subnet                           * Subnet Masks
    * CIDR
  3. Network Analysis
  4. Linux Firewalls
    * Iptables                         * Iptables Commands
  5. Wi-Fi Networks
    * Terminology                      * 

############################## Network Basics #################################

# IP Addresses (Internet Protocol Addresses)
* IPV4 - 4 bytes or 32 bits
* Classes of IP Addrs
  - Class A: 0.0.0.0   - 127.255.255.255
  - Class B: 128.0.0.0 - 191.255.255.255
  - Class C: 192.0.0.0 - 223.255.255.255

* Private IP Addrs
  - A group of IP addrs within a LAN (Local Area Network) that are not 
    usable over the internet. These addrs can be reused within each LAN but not
    over the internet
    192.168.0.0 - 192.168.255.255
    10.0.0.0    - 10.255.255.255
    172.16.0.0  - 172.16.255.255
    
# DHCP (Dynamic Host Configuration Protocol)
  - Assigns IP addrs dynamically. When device is connected to LAN, it requests
    private IP addr by sending request to DHCP server. It then assigns IP addr 
    to that system for a fixed length of time (lease)
    
# NAT (Network Address Translation)
  - Private IP addrs are translated to public IP addrs that can be routed 
    through internet. 
    
# Ports
  - A sub-addr for service.  
=     Port Number   Protocol   Port Type
=         21          FTP       TCP, UDP
=         22          SSH       TCP, UDP
=         23         Telnet     TCP, UDP
=         25          SMTP      TCP, UDP
=         53          DNS       TCP, UDP
=       67/68         DHCP        UDP
=         80          HTTP      TCP, UDP
=        110          POP3      TCP, UDP
=        143          IMAP        TCP
=      161/162        SNMP      TCP, UDP
=        389          LDAP      TCP, UDP
=        427          SLP       TCP, UDP
=        443         HTTPS      TCP, UDP
=        445        SMB/CIFS      TCP
=        548          AFP         TCP
=       3389          ROP       TCP, UDP       
  - netcat can be used 

# IP (Internet Protocol)
* Protocol used to define the src and dst IP addr of a packet as it traverses
  the internet. Often used in conjunction with other protocols like TCP
 
= IP packet header
=     0 _____________ 1 _____________ 2 _____________ 3 _____________  <+
=   0|_ Ver _ |  IHL  | Type of Serv  | ________ Total Length _______|  |
=   4|_________ Identification ______ | flags | __ Fragment Offset __|  |
=   8|______ TTL ____ | _ Protocol __ | ______ Header Checksum ______|  | IHL
=  12|________________________ Source Address _______________________|  |
=  16|_____________________ Destination Address _____________________|  |
=  20|_______ IP Option (variable length, optional not common) ______| <+

  - Version: Defines the version of IP, (v4 or v6)
  - IHL: header length
  - ToS: type of service of this packet
  - Total Length: Total length of IP datagram
  - Identification: unique id
  - IP flags:
  - Fragment Offset: where packets should be reassembled 
  - TTL: time to live - how many hops across the internet before packet expires
  - Protocol: what protocol is being used
  - Header Checksum: error checking field
  - Source/Destination: src & dst ip addr
  - Options & padding

# TCP (Transmission Control Protocol)

= TCP header
=    0 ______________ 8 _____________ 16 ____________ 24 ___________ 32    
=    |__________ Source Port ________ | _____ Destination Port ______|
=    |________________________ Sequence Number ______________________|
=    |____________________ Acknowledgement Number ___________________|
=    | Dt off | Rsrvd | ___ flags ___ | ________ Window Size ________|
=    |___________ Checksum __________ | _______ Urgent Pointer ______|
=    |____________________ Options __________________ | __ Padding __|

  - Source/Destination Port: src & dst ports
  - Sequence Number: Ensure packets are arranged in proper sequence
  - Acknowledgement Number: Echo of Sequence # sent back by receiving system
  - Flags
    SYN: opening of new connection
    FIN: normal "soft closing of connection
    ACK: acknowledgement of a packet
    RST: hard-close of connection to say packet arrived at wrong port/ip
    URG: data is urgent
    PSH: push data past the buffer to the application
  - Window Size: communicate size of window that the TCP stack has not buffer 
    packets
  - Checksum: error checking field
  - URG pointer: points to the last byte of the sequence # of urgent data
  
* TCP Three-Way Handshake
  - Every TCP connection starts with 3-way handshake
  1. Client sending packet with SYN flag  
  2. Server respond packet with SYN & ACK flags
  3. Client sending packet with ACK flag
 
# UDP (User Datagram Protocol)
* Connectionless protocol (doesn't require a connection like 3-way handshake)
  Sends packets and forgets about them
 
# OSI model

=  OSI Layers                               Attacks
= _________________________________________________________
=  Application ---------------------------> Exploit
=    end user layer
=    HTTP, FTP, IRC, SSH, DNS
=  Presentation --------------------------> Phishing
=    syntax layer
=    SSL, SSH, IMAP, FTP, MPEG, JPEG
=  Session -------------------------------> Hijacking
=    synch & send to port
=    API's sockets, WinSock
=  Transport -----------------------------> Reconnaissance
=    end-to-end encryption
=    TCP, UDP
=  Network -------------------------------> MITM
=    packets
=    IP, ICMP, IPSec, IGMP
=  Data Link -----------------------------> Spoofing
=    Frames
=    Ethernet, PPP, Switch, Bridge
=  Physical ------------------------------> Sniffing
=    Fiber, Hubs

######################## Subnetting and CIDR Notation #########################

# Sub-nets
* A network within a network, namely a Class A, B, or C. Subnets are created
  by using one or more of the host bits to extend the network ID 
  - Class A networks has a 8-bit network ID
  - Class B networks has standard 16-bit network ID
  - Class C networks has standard 24-bit network ID
  
=  Class   Leading   Size of   Number of   Addrs per    Start       End 
=           Bits     Network    Networks    Network     Addr        Addr
=  ____________________________________________________________________________
=    A       0          8        128     16,777,216   0.0.0.0    127.255.255.255
=    B       10        16      16,384      65,536    128.0.0.0   191.255.255.255
=    C      110        24     2,097,152     256      192.0.0.0   223.255.255.255

* A network mask, is a binary mask applied to an IP address to determine 
  whether two IP addrs are in the same subnet. Works by applying binary AND
  operations between the IP addr and the mask
  - Class A subnet mask: 255 0   0   0
  - Class B subnet mask: 255 255 0   0
  - Class C subnet mask: 255 255 255 0
  
# Sub-Net Masks
* when subnet mask bit is set to one. it is part of the network. Bit marked
  zero is part of host ID.
  Subnet mask: 255.255.255.0
               11111111 11111111 11111111 00000000
  IP Address:  192.168.1.5
               11000000 10101000 00000001 00000101
  Network Prefix: 192.168.1.0
               11000000 10101000 00000001 00000000

# CIDR Notation (Classless Inter-Domain Routing)
* A way of representing IP addr and network mask associated with it.
  Specificies IP addr / and a decimal # like 24, where it represents the number
  of bits in the network mask

=  Example
=  Class C network: 192.168.1.0
=  Class C Subnet Mask: 255.255.255.0 11111111 11111111 11111111 00000000
=  254 host addrs, 1 broadcast, 1 network
=  Create 5 different networks with no more than 30 hosts per network
=  To create 5 networks, 2^3 or 8 networks. or 11100000. 
=  Means 2^5 -2 host addrs per subnet
=  subnet mask: 255.255.255.224

############################# Network Analysis ################################
* Essentially Wireshark and tcpdump

############################## Linux Firewalls ################################
* Firewall is a subsystem on a computer that blocks certain network traffic 
  from going into or out of a computer. Can be software or hardware based.
  
# Iptables
* Firewall utility that uses cmd line to setup policy chains to allow or 
  block traffic. When there is a connection, iptables looks for a rule to match
  the type of traffic. If none is found, it falls back to default action
* Tables
  - An iptables construct that defines categories of functionality (FILTER, 
    NAT, MANGLE, and RAW)
  - FILTER: default table 
  - NAT: rewrite the src or dst addr of packets
  - MANGLE: packet alteration
  - RAW: configuring exemptions from connection tracking 
* Chains
  - Each table has own chains which are lists of rules within a table (INPUT,
    OUTPUT, FORWARD)
  - INPUT: for packets destined for the local system
  - OUTPUT: for packets leaving the local system
  - FORWARD: for packets being routed through the local system
  - MATCH: when ppacket meets the condition established by the rule. iptables
      then processes the packet according to the action in the rule
* Targets
  - iptables support a set targets that trigger an action when the packet meets
    the condition of the rule. ACCEPT (allow packet to pass), DROP (drop the 
    packet), LOG, REJECT (drop packet and send back error), RETURN

# Iptables Commands
  // List default policy on chains
  $ sudo iptables -L
  // Block any packets from 192.168.1.102
  $ sudo iptables -A INPUT -s 192.168.1.102 -j DROP
  // Block entire subnetwork with CIDR notation
  $ sudo iptables -A INPUT -s 192.168.1.0/24 -j DROP
  // Block access to websites
  $ sudo iptables -A OUTPUT -p tcp --dport 80 -j DROP
  $ sudo iptables -A OUTPUT -p tcp --dport 443 -j DROP
  // Flush iptables and start over
  $ sudo iptables -F

############################### Wi-Fi Networks ################################

# Terminology
* AP         access point of place where clients connect to Wi-Fi
* PSK        Pre-Shared-Key the password used to authenticate to the AP
* SSID       name used to identify the AP
* ESSID      Extended Service Set Identifier - same as SSID but can be user for 
             multiple APs in a wireless LAN
* BSSID      Basic Service Set Identifier, the unique id for every AP
* Channels   Wi-Fi operates on channels 1-14 but 1-11 in US
* Power      closer to AP stronger the signal
* Security   security protocol to authenticate & encrypt Wi-Fi traffic
* Modes      Wi-Fi can be master, managed, monitor. APs master, wireless 
             network interfaces & hackers, monitor mode
* Range      100m up to 20 miles
* Frequency  2.4 of 5GHZ

  // Viewing Wireless Interfaces
  $ ip addr
  // 

############################ Bluetooth Networks ###############################





 






