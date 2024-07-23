
###############################################################################
#                        Attacking Network Protocols                          #
#                         Start Date: July 18, 2024                           #
#                         End Date:                                           #
#                            Status: In-Progress                              #
###############################################################################
General:
1. The Basics of Networking
  - Network Architecture and Protocols
  - The Internet Protocol Suite
  - Data Encapsulation
  - Network Routing
2. Capturing Application Traffic


########################## The Basics of Networking ###########################

# Network Architecture and Protocols
* Network: A set of two or more computers connected together to share info
  - each connected device (node)

=  Workstation <--- Network ---> Mainframe
=     node             |           node
=                      v
=                    Server
=                     Node

* Network Protocol: set of rules every node uses to communicate with other nodes on network
  - Maintaining session state: create new connections and terminate existing connections
  - Identifying nodes through addressing: Data must be transmited to the correct node 
    on a network
  - Controlling flow: Amount of data transferred across network is limited. Protocol 
    manage data flow to increase throughput and reduce latency
  - Guaranteeing order of transmitted data: reorder data to ensure it's delivered in order
  - Detecting & correcting errors: detect corruption & fix it
  - Formatting & encoding data: encoding data to be suitable for transmitting on network

# The Internet Protocol Suite
* TCP/IP is de factoo protocol that modern networks use. (Transmission Control Protocol) &
  (Internet Protocol)
  - These 2 protocols form part of the Internet Protocol Suite (IPS) a model of how network
    protocols send network traffic over the internet
       
=  Example Protocols     Internet Protocol Suite          External connections
=  ___________________________________________________________________________
=  HTTP, SMTP, DNS     |    Application Layer    |   <-->  User application
=                      |           |             |
=  TCP, UDP            |     Transport Layer     |
=                      |           |             |
=  IPv4, IPv6          |     Internet Layer      |
=                      |           |             |
=  Ethernet, PPP       |       Link Layer        |   <-->  Physical network
=                      |_________________________|
=  Figure 1-2: Internet Protocol Suite Layers

* Link Layer (layer1): lowest level & describes physical mechanisms used to transfer info
  between nodes on a local network
* Internet Layer (layer2): provides mechanisms for addressing network nodes. Unlike layer 1
  nodes don't have to be located on the local network
* Transport Layer (layer 3): responsible for connections between clients & servers, 
  sometimes ensuring correct order of packets & providing service multiplexing. 
  - Service multiplexing allows a single node to support multiple different services by
    assigning a different num (port) for each service. 
* Application layer (layer 4): contains network protocols, HTTP, SMTP, DNS, etc

=   ___________________________________________________
=  |  ________________       __________________        |
=  | | User interface |     | Context parsers  |       |
=  | | HTML rendering | <-> | Text, HTML, JPEG |       |
=  | |________________|     |__________________|       |
=  |            ʌ               ʌ                      |
=  |            |               |                      |
=  |         ___v_______________v___                   |
=  |        | Network Communication |                  |
=  |        |   SMTP, POP3, IMAP    | <------Network---+---> Mail server 
=  |        |_______________________|                  | 
=  |___________________________________________________|
=  Figure 1-3: Example mail application

# Data Encapsulation
* Each layer in the IPS is build on the one below & each layer can encapsulate data from 
  the layer above so it can move between the layers
  - Data transmitted by each layer is called PDU (protocol data unit)

* Headers: prefix to payload data contains info required for payload to be transmitted
  - ex (src & dst addr)
* Footers: suffix to payload data contains values to ensure correct transmission
  - ex (error checking)

=                                                _____________________
=                                               |                     |
=                                               | Application payload | Layer 4:
=                                               |<--------PDU-------->| Application
=                                               |_____________________|
=                                  ___________________________________
=                                 | Src | | Dst |                     |
=                                 | port| | port|     TCP payload     | Layer 3:
=                                 |_____| |_____|                     | Session
=                                 |  TCP header | PDU                 |
=                                 |<------------+-------------------->|
=                                 |_____________|_____________________|
=                    _________________________________________________
=                   | Src | | Dst |                                   |  
=                   | addr| | addr|             IP payload            | Layer 2:
=                   |_____| |_____|                                   | Internet
=                   |  IP header  | PDU                               |
=                   |<------------+---------------------------------->|
=                   |_____________|___________________________________|
=   ___________________________________________________________________________
=  | Src  | | Dst   |                                                 |        |
=  | addr | | addr  |                Ethernet payload                 | Footer | Layer 1:
=  |______| |_______|                                                 |        | Link
=  | Ethernet header|   PDU                                           |        |
=  |<---------------+-------------------------------------------------+------->|
=  |________________|_________________________________________________|________|
=  Figure 1-4: IPS data encapsulation

* The TCP header contins a src & dst port number. The port nums allow a single node to have
  multiple unique network connections. 
  - Port numbers range from 0-65535
  - TCP payload + header are called segment
  - UDP payload + header are called datagram
* The IP protocol uses a src & dst addr. 
  - IP payload + header are called packet
* Ethernet uses a src & dst addr. Also MAC addr 
  - Ethernet header + footer + payload is called a frame

=                              _____________
=                             |             |
=                             | 192.1.1.100 |
=                             |_______ʌ_____|
=   1️⃣️_____________________           |
=  |      192.1.1.101      |          v
=  | MAC: 00-11-22-33-44-55|<----> switch3️⃣️
=  |_______________________|          ʌ
=                                     |
=                          ___________v____________2️⃣️
=                         |       192.1.1.50       |
=                         | MAC: 66-77-88-99-AA-BB |
=                         |________________________|
=  Figure 1-5: A simple Ethernet network 1->2

* node 1 wants to send data using IP to node 2
  1. encapsulates the application & transport layer data & builds an IP packet with a
     src addr of 192.1.1.101 & dst of 192.1.1.50
  2. Can encapsulate the IP data as an ethernet frame, but it might not know the MAC 
     addr of target node. Request the MAC addr for a particular IP addr using ARP
     (Address Resolution Protocol) - which sends request to all nodes on network to find
     the MAC addr for the dst IP 
  3. Once the node receives ARP response, it can build the frame. The new frame is 
     transmitted on the network and received by the switch
  4. The switch forwards the frame to the dst node which unpacks the IP packet & verify
     dst IP addr. IP payload is extracted and passes up to be received by application

# Network Routing
* The src & dst addrs allow data to be routed over different networks until the data
  reaches the desired dst node
  
=   Ethernet network 1                         Ethernet network 2
=   ___________________________________        ________________________________________
=  |                 _____________     |      |      ____________                      |
=  |                |             |    |      |     |            |                     |
=  |                | 192.1.1.100 |    |      |     | 200.0.1.10 |                     |
=  |                |______ ʌ ____|    |      |     |____ ʌ _____|                     |
=  | 1️⃣️___________          |          |      |           |          ____________2️⃣️    |
=  ||             |         v 192.1.1.1|      |200.0.1.1  v         |            |     |
=  || 192.1.1.101 |<---> switch <----->|Router|<-----> switch <---> | 200.0.1.50 |     |
=  ||_____________|         ʌ          |      |           ʌ         |____________|     |
=  |MAC: 00-11-22-33-44-55  |          |      |           |     MAC: 66-77-88-99-AA-BB |
=  |                  _____ v ____     |      |      ____ v ______                     |
=  |                 |            |    |      |     |             |                    |
=  |                 | 192.1.1.50 |    |      |     | 200.0.1.100 |                    |
=  |                 |____________|    |      |     |_____________|                    |
=  |___________________________________|      |________________________________________|
=  Figure 1-6: Example of a routed network connecting two Ethernet networks

* two ethernet networks, each with separate IP network addr ranges. Sending data from the
  node at 1 on network 1 to the node at 2 on network 2
  1. encapsulates the application & transport layer data, & builds an IP packet with a
     src addr & dst addr
  2. The network stack needs to send an Ethernet frame but because the dst IP addr does 
     not exist on any Ethernet network that the node is connected to, the network stack
     consults its OS routing table. If the routing table contains an entry for dst IP addr
     indicates that a router on switch can get to dst addr
  3. OS uses ARP to look up router's MAC addr. the original IP packet is encapsulated 
     within the ethernet frame with that MAC addr
  4. Router receives Ethernet frame and unpacks the IP packet. Router determines the packet
     is not destined for the router but for a different node on another connected network.
     Router looks up MAC addr of dst IP addr, encapsulates the original IP packet into
     new Ethernet frame.
  5. Destination node receives ethernet frame, unpacks the IP packet & processes contents
* The routing process might be repeated multiple times. If router was not directly
  connected to the network containing dst node, it would consult its own routing table
  and find the next router it could send the IP packet to.
* If there is no explicit routing entry for dst, OS provides a default routing table 
  entry (default gateway) which contains the IP addr of a router that can forward IP
  packets to their dst.

####################### Capturing Application Traffic #########################

# Passive Network Traffic Capture

=  Client Application <----> switch <----> Server Application
=                               |
=                               v
=                     Passive capture device

* Passive Network Capture can take place either on the network by tapping the traffic as it
  passes in some way or by sniffing directly on either the client or server host
  























