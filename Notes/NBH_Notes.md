
###############################################################################
#                        Network Basics for Hackers                           #
#                         Start Date: August 2 2024                           #
#                         End Date:                                           #
#                            Status: In-Progress                              #
###############################################################################
General:
1. Network Basics

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
    
* DHCP (Dynamic Host Configuration Protocol)
  - Assigns IP addrs dynamically. When device is connected to LAN, it requests
    private IP addr by sending request to DHCP server. It then assigns IP addr 
    to that system for a fixed length of time (lease)
    
* NAT (Network Address Translation)
  - Private IP addrs are translated to public IP addrs that can be routed 
    through internet. 
    
* Ports
  - A sub-addr for service.  
=     Port Number   Protocol   Port Type
=         21          FTP       TCP, UDP
=         22          SSH       TCP, UDP
=         23         Telnet     TCP, UDP
=         25          SMTP      TCP, UDP
=         
    
    
    
    
    
    
