
###############################################################################
#                        Art of Exploitation Notes                            #
#                         Start Date: May 10 2024                             #
#                         End Date: June 21 2024                              #
#                     Status: Incomplete/Discontinued                         #
###############################################################################
General:
* Computer is little endian so the first byte is is least significant
* Environment: Ubuntu 7, gcc 3.3.6
Sections:
1. Exploitation
2. Networking


################################# Exploitation ################################
Buffer Overflow Exploit

Stack:
Low 
 ______________
|              |
|  buffer two  |  8 bytes 
|______________|
|              |
|  buffer one  |  8 bytes 
|______________|
|              |
|    value     |  4 bytes
|______________|       
High

* If we write 10 bytes into buffer two, 2 bytes (90) will overflow into the the 2 bytes
  after buffer two.
  This causes a buffer overflow error as the first two bytes of buffer one is now (90) 


# auth_overflow.c
* 1 byte is 2 hexadecimal digits
* Variables which are defined earlier in the function will be added to the stack earlier.
  Because the stack grows from high to low, variables defined earlier have higher memory 
  addresses and can be exploited with buffer overflow

Stack:
Low
|___________________|
|                   |
|  password buffer  |  16 bytes 
|___________________|
|                   |
|                   |  28 bytes between start of password buffer and start of flag
|___________________|
|                   |
|     auth flag     |  4 bytes 
|___________________|
|                   |
High

* A 30 digit input such as (Ax30) will result in the last 2 bytes of input (AA) being 
  overflowed into auth flag. This changes the auth flag value from 0x0 to 0x00004141. When 
  treated as an integer as done in the program, the value is 16705 which is non zero thus
  will pass through the if statement
* Interestingly, declaring auth_flag before password buffer will mean that the flag can 
  never be corrupted by an overflow


# auth_overflow2.c
Examining the stack frame for function call shows

esp (stack pointer) pointing to the next availible space
padding
local variable 1 (auth_flag)
local variable 2 (password_buffer)
padding / (saved frame pointer)
return value
arguments

Stack:
Low
|                   |  <-- esp 
|___________________|
|                   |
|      padding      | 
|___________________|
|                   |
|     auth_flag     |  4 bytes 
|___________________|
|                   |
|  password_buffer  |  16 bytes 
|___________________|
|                   |
|    padding/fp     |
|___________________|
|                   |
|    return addr    |  4 bytes 
|___________________|
|                   |
|       args        |
|___________________|
|                   |
High


# NOP Buffer Overflow (Shellcode Injection)
* Once return address has been overflowed, inject own instructions into memory and return
  execution there
* buffer: 
  NOP sled | Shellcode | Repeated Return address
* Can estimate approximate location of buffer by using a nearby stack location as frame 
  of reference

Stack
Low
|________________|
|                |
|  searchstring  |   This will overflow return addr. Jmp to buffer and execute shellcode
|________________|
|                |
|  return addr   |
|________________|
|                |
|      ...       |
|________________| __
|                |   |
|     buffer     |   |
|________________|   |
|                |   |
|  other locals  |   exploit's stack frame 
|________________|   |
|                |   |
|       i        |   |
|________________| __|
|                |
High
* To calculate return address, &i - offset. offset will have to be experimentally found


# Environment Variables (Shellcode Injection)
* Environment variables are located at the bottom the stack (highest address) and can be 
  set from the shell (modern compilers may have Address Space Layout Randomization)
* Add a NOP sled and then shellcode into an environment variable
* A return address can be an address somewhere in that range of the sled 

Stack
Low
|___________________|
|                   |
|  return address   |  overwrite this address with the environment variable address 
|___________________|
|                   |
|        ...        |
|___________________|
|                   |
|  environment var  |  Environment variable has NOP sled with shellcode 
|___________________|
|                   |
High


# Heap Overflow notetaker.c
* Same as buffer overflow for stack but with heap.
* We can overflow buffer with 104 meaningless bytes followed by new datafile name
  This will overwrite the datafile and have notes be written to a different file

Heap
High
|____________|
|            |
|  datafile  |  20 bytes 
|____________|
|            |
|  padding   |  4 bytes 
|____________|
|            |
|   buffer   |  100 bytes 
|____________|
|            |
Low

* This can be used to write an entry into /etc/passwd
Each entry has
login name : password : user ID : group ID : username : home dir : login shell
                 ^
      Can be encrypted password

* We want to add an entry that has root priviledges and a known password
* The password can be something we know and can be encrypted with perl crypt()
Example entry
myroot : encrypted password : 0 : 0 : me : /root : /bin/bash 

* To place this entry into the /etc/passwd file, we cannot simply overflow the buffer 
  with both the entry and the file location because the string must end with /etc/passwd
  This would be appeneded to the end of the string so the login shell would be wrong
* Workaround using symbolic file link
* Have a symbolic link from /bin/bash to /tmp/etc/passwd
  Because /etc/passwd is the last part of the string we can write to this file
  Also since the entire /tmp/etc/passwd is a login shell, this will not be affected as well
login name : encrypted password : 0 : 0 : username + overflow : /root : /tmp/etc/passwd


# Function Pointers Overflow
* Function ptrs can be overwritten so that when the function is called can be exploited


# Format Strings
* The vulnerability is doing the following:
  printf(string) instead of printf("%s", string)
* This means that the format function is passed the address of the string as opposed 
  to the address of a formaat string. It iterates through the string and prints out 
  each character.
  If the string contains a format parameter, the format function will try and access the 
  appropriate function arguament, by adding to the frame pointer. Since the appropriate 
  argument is not there adding to the fram pointer will reference a piece of memory in
  preceding stack frame.
* If the format string has been stored anywhere on the stack, it will be located below
  the frame pointer (at higher address) and thus accessible. 
  (in our case 4th arg, %4$p was start of format string)
* Direct Parameter Access:
  %n$d, access the nth parameter and display it as a decimal number

Real
| return address
| fmt_string arg
| text 
| ...

printf expects
| return address
| fmt_string arg
| arg 1
| arg 2
| arg 3
| ...

./fmt_vuln $(printf "\xd7\xfd\xff\xbf")%08x.%08x.%08x.%s
* This will print d7, fd, ff, bf as hexadecimal then ascii. %08x will print out the next 
  12 btyes.Because the 4th arg was determined to be the format string, we can %s to
  attempt to print the string located at the address 0xbffffdd7.

* To write, we can use %n specifier. %n writes the number of characters printed so far 
  into arg
  by overwriting the correct arg with valid memory address, the location will be
  overwritten
./fmt_vuln $(printf "\x94\x97\x04\x08")%x%x%x%n
Where 0x08049794 is the address of a local var.

* Overwriting a memory location with large value such as memory address.
| return address
| fmt_string arg
| 0x08049794  1st %n   arg 4    start of format string 
| JUNK                 arg 5
| 0x08049795  2nd %n   arg 6
| JUNK                 arg 7
| 0x08049796  3rd %n   arg 8
| JUNK                 arg 9
| 0x08049797  4th %n   arg 10

./fmt_vuln $(printf "\x94\x97\x04\x08JUNK\x95\x97\x04\x08JUNK\x96\
x97\x04\x08JUNK\x97\x97\x04\x08")%x%x%126x%n%17x%n%17x%n%17x%n

Will output:
format string (??JUNK??JUNK??JUNK??), arg1, arg2, arg3x126, write to arg4 (mem addr 1), 
arg5x17 (JUNK), write to arg6 (mem addr 2), arg7x17 (JUNK), write to arg8 (mem addr 3),
arg9x17 (JUNK), write to arg10 (mem addr 4)
* The JUNK are simple placeholders for the %x to output a certain number of characters

# Detours with .dtors
* In binary programs compiled with the GNU C compiler, special table sections called .dtors 
  and .ctors are made for destructors and constructors, respectively. 
* The behavior of automativally executing a function on exit is controlled by the .dtors 
  table section of the binary. It is an array of 32 bit addresses terminated by a NULL 
  address. The array begins with 0xffffffff and ends with the NULL address of 0x00000000. 
  Between these are the addresses of all the functions that have been declared with the 
  destructor attribute
* The nm command displays information about symbols in specified file 
* Using the Format string vulnerability we can write to the .dtors section the address of 
  an environment variable that has shellcode. If the program is suid then we can get root 
  access.


################################## Networking #################################

# OSI layers
7 Application Layer
  - applications can access network
6 Presentation Layer
  - data is in usable format 
5 Session Layer
  - sockets and responsible for controlling ports and sessions
4 Transport Layer
  - TCP/UDP transmission protocols
  - TCP flags, URG (urgent), ACK (acknowledgement), PSH (push), RST (reset), SYN (synchronize),
    FIN (finish)
  - TCP header:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  - UDP contains much less overhead and built-in functionality than TCP.
  - UDP header contains, source port, destination port, length, checksum
3 Network Layer
  - IP address physical path that the data will take
  - IP header:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|     Fragment Offset     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  - ICMP (Internet Control Message Protocol) used for messaging and diagnostic.
    Example is ping command where ICMP Echo request and Echo Reply are used
2 Data-Link Layer
  - Ethernet addressing between Ethernet ports MAC (Media Address Control) addresses. Every 
    Ethernet device is assigned a globally unique addr. MAC is hard coded into the device
    by manufacturer, not meant to change.
  - Ethernet header contains source and destination MAC addr for Ethernet packet
  - ARP (address resolution protocol) allows "seating charts" to be made to associate an IP addr
    with a piece of hardware
  - Broadcast addr is Ethernet addressing which will be sent to all the connected devices
  - ARP request is a message sent to the broadcast addr, that contains the sender's IP addr 
    and MAC addr and asks for corresponding MAC addr for IP addr
  - ARP reply is the response that is sent to the requester's MAC addr & IP addr
1 Physical Layer
  - Wire and protocol used to send bits from one device to another

# Sockets
* standard way to perform network communication through the OS (an abstraction)
* Stream sockets are reliable two way communication using TCP so that packets of data will 
  arrive without errors in sequence
* Datagram socket is one way and unreliable using UDP

socket(int domain, int type, int protocol)
  Used to create a new socket, returns a file descriptor for the socket or
  -1 on error.

connect(int fd, struct sockaddr *remote_host, socklen_t addr_length)
  Connects a socket (described by file descriptor fd) to a remote host.
  Returns 0 on success and -1 on error.

bind(int fd, struct sockaddr *local_addr, socklen_t addr_length)
  Binds a socket to a local address so it can listen for incoming connections.
  Returns 0 on success and -1 on error.

listen(int fd, int backlog_queue_size)
  Listens for incoming connections and queues connection requests up to
  backlog_queue_size. Returns 0 on success and -1 on error.

accept(int fd, sockaddr *remote_host, socklen_t *addr_length)
  Accepts an incoming connection on a bound socket. 
  The address information from the remote host is written into the remote_host structure and
  the actual size of the address structure is written into *addr_length. This
  function returns a new socket file descriptor to identify the connected socket or -1 on error.

send(int fd, void *buffer, size_t n, int flags)
  Sends n bytes from *buffer to socket fd; returns the number of bytes sent
  or -1 on error.

recv(int fd, void *buffer, size_t n, int flags)
  Receives n bytes from socket fd into *buffer; returns the number of bytes
  received or -1 on error

# Socket Addresses
* SOCKADDR_COMMON defines the address family of the address because of protocols.
* Since an address can contain different types of information depending on the address family.
  a dockaddr structure can point to an address structure for IPv4 IPv6 .. which allows the socket
  functions to operate on a variety of protocols 
* Specific socketaddr such as socketaddr_in holds port number and internet address because that 
  defines a socket address 

# Socket Programming/Network Programming 
* Step 1: create a socket (socket())
* Step 2: bind the socket to a port (bind())
* Step 3: Listen for incoming connection requests & identify ones (listen())
* Step 4: Accept the identified connection request and open the socket (accept())
* Step 5: Attempt to establish a connection (connect())

# Web Server
* We can create a web server that can send and recieve http requests. (tinyweb.c)
* loopback address 127.0.0.1 called localhost which allows a device to send and recieve its own
  data packets. 

# Network Sniffing
* On an unswitched network, Ethernet packets pass through every device on the network, expecting 
  each system device to only look at the packets sent to its destination address. 
* Promiscuous mode, causes it to look at all packets, regardless of the destination addr. 

* Raw Socket Sniffer. Can access the network at lower layers using raw sockets. raw_tcpsniff.c
  This can be done by opening a raw TCP socket and listening for packets.
  (architecture dependent code)



###############################################################################
#                              Other Exploits                                 #
#                                                                             #
###############################################################################
General:
* Collection of other exploits from CTFs, websites, etc
Sections:
1. Return to libc
2. Path Priveledge Escalation


############################## Return to libc #################################
https://css.csail.mit.edu/6.858/2014/readings/return-to-libc.pdf
* libc is a standard C library that contains various basic functions like printf and exit. These
  functions are shared so any program that uses the printf() function directs execution into the 
  appropriate location in libc.
* Stack for the return into libc call should look like this

Function address | Return address | arg 1 | arg2 ...
(addr of system)   (can be fake)    (/bin/sh)


########################### Path Priviledge Escalation ######################## 
https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/
* $PATH is an environment variable which specifies all bin and sbin which are where all
  executable programs are stored (ls, cat, echo, mount, shutdown, etc). When the user
  runs any command on ther terminal the request to the shell searches for executables
  with the help of the PATH variable. 
- echo $PATH

* If there is a '.' in environment PATH variable it means that the logged user can 
  execute binaries from the current directory. 

* Otherwise it is possible to add location to PATH
- export PATH=dir:$PATH

* The commands we want such as opening a shell can be added to a file with same name as
  the command name 
- echo "/bin/bash" > touch
- cp /bin/sh touch 
- ln -s /bin/sh ps 

* This will execute the contents of the touch file and thus allow for priviledge esc 



