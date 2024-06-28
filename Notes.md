A running file of notes regarding hacking and cybersecurity

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

# overflow.c
Example of buffer overflow exploit.

Stack:
Low 
|______________|
|              |
|  buffer two  |  8 bytes 
|______________|
|              |
|  buffer one  |  8 bytes 
|______________|
|              |
|    value     |  4 bytes
|______________|
|              |
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
#                         Practical Binary Analysis                           #
#                         Start Date: June 21, 2024                           #
#                         End Date:                                           #
#                            Status: In Progress                              #
###############################################################################
General:
* Environment: Ubuntu 16, gcc 5.6

Sections:
1. Anatomy of a Binary
  - C compilation
  - Symbols & Stripped Binaries
  - Disassembling a Binary
  - Loading & Executing a Binary
2. The ELF Format
  - The Executable Header
  - Section Header
  - Sections
  - Program Header
3. The PE Format
4. Building a Binary Loader


############################ Anatomy of a Binary ##############################

# C compilation Process
* Typically 1 source file = 1 assembly file = 1 object file
* Preprocessing Phase
  - Expands any #define and #include directives in the source file (so all that is left 
    is pure C) The headers are included in its entirety with all of its type defs, global 
    vars, and function prototypes "copied" into the source file.
* Compilation Phase
  - Takes the perprocessed code and translates it into assembly 
* Assembly Phase
  - Given the assembly files generated in compilation phase, the output is a set of object 
    files. Object files contain machine instructions 
  - Object file can be relocatable, which don't rely on being placed at a particular addr 
    in memory. Object files are compiled independently from each other, so the assembler 
    has no way of knowing the memory addresses of other obj files. (This is why obj files 
    need to relocatable so they can be linked together in any order to form a complete 
    binary executable)
* Linking Phase
  - (Linker) links together all the object files into a single binary executable
  - Object files may reference functions of variables in other obj files or in libraries 
    that are external to the program. Before the linking phase, the addresses at which the 
    referenced code and data will be placed is not known, so obj files only contain 
    relocation symbols.
    - References that rely on a relocation symbol are called symbolic references
  - Relocation Symbols specify how function and variable references should be resolved
  - Static Libraries 
    - They are merged into the binary executable, allowing any references to them to 
      be resolved entirely
  - Dynamic (shared) Libraries are shared in memory among all programs that run on the system.
    - Rather than copying the library into the binary, they are loaded into memory only once and any
      binary that wants to use it must use this shared copy. This addr is not known during Linking so
      the linker leaves symbolic references to these libraries even in the final exec. 
      They are resolved when the binary is actually loaded into memory.

# Symbols and Stripped Binaries
* When compiling a program, compilers emit symbols which keep track of funcs & vars
  - $readelf --syms a.out
  - Shows dynamic symbols (for resolveing dynamic dependencies) & static symbols
* Stripping a binary removes symbol & other information from a binary
  - $strip --strip-all a.out

# Disassembling a Binary
* We can use the objdump utility to disassemble obj and bin files
  - objdump -sj .rodata compilation_example.o  (show read only data section)
  - objdump -M intel -d compilation_example.o  (disassembles all the code in obj file)
* When disassembling a binary
  - .text section is the main code section & contains main function
  - When binary is stripped functions in .text section are all merged 

# Loading and Executing a Binary
* How a binary is represented in memory (Linux)

  |____________|
  |            |
  |   Kernel   |
  |____________|
  |____________|
  |            |
  |   Stack    |
  |____________|
  |____________|
  |            |
  |   Memory   |  Interpreter 
  |  Mapping   |  lib1.so
  |    Area    |  lib2.so
  |____________|
  |____________|
  |            |
  |    Heap    |
  |____________|
  |____________|  Header
  |            |  Data Section 1
  |    Data    |  Data Section 2
  |____________|
  |            |  Code Section 1
  |    Code    |  Code Section 2
  |____________|
  |            |      Binary
  Virtual Memory

* When starting to run a binary
  - The OS starts by setting a new process for the program to run in, including a va space
  - The OS maps and interpreter (user space program) into the process's virtual mem. 
    - Linux ld-linux.so, Windows ntdll.dll
    - Linux ELF binaries come with a section called .interp that specifies the path to 
    interpreter that will be used to load the binary
  - Interpreter loads binary into its va. Then parses the binary to find what dynamic libs 
    the binary uses. This is then mapped into the va space and performs any nessecary 
    relocations in the binary's code sections to fill in the correct addresses for 
    references to dynamic libs
  - Lazy Binding, is when relocations are not done right away when loaded but deffered
    until the first reference to the unresolved location is made
  - After relocation is complete, the interpreter looks up the entry point of the binary 
    and transfers control to it, beginning normal execution of the binary
    

############################## The ELF Format #################################
https://refspecs.linuxfoundation.org/elf/elf.pdf

* Executable and Linkable Format (ELF) is the default binary format on linux-based systems
  It is used for executable files, object files, chared libraries, and core dumps
* ELF binary components
  1. executable header
  2. program headers (optional)
  3. sections
  4. section headers (optional) one per section
* The program header and section header tables need not be located at any particular offset 
  in the binary file
  
      ___ |_____________________|
     |    |                     |
  Header  |  Executable header  |
     |___ |_____________________|
     |    |                     |
     |    |_____________________|
  Program |                     |
  headers |   Program header    | 
     |    |_____________________|
     |___ |_____________________|
     |    |                     |
     |    |_____________________|
     |    |                     |
  Section |       Section       |
     |    |_____________________|
     |    |                     |
     |___ |_____________________|
     |    |_____________________|
     |    |                     |
  Section |   Section header    |
  headers |_____________________|
     |    |                     |
     |___ |_____________________|
             64-bit ELF binary 

# The Executable Header
  typedef struct {
    unsigned char e_ident[16];   // Magic number (0x7f, E, L, F) and other info
    uint16_t      e_type;        // Object file type
    uint16_t      e_machine;     // Architecture
    uint32_t      e_version;     // Object file version
    uint64_t      e_entry;       // Entry point virtual address
    uint64_t      e_phoff;       // Program header table file offset
    uint64_t      e_shoff;       // Section header table file offset
    uint32_t      e_flags;       // Processor-specific flags
    uint16_t      e_ehsize;      // ELF header size in bytes
    uint16_t      e_phentsize;   // Program header table entry size
    uint16_t      e_phnum;       // Program header table entry count
    uint16_t      e_shentsize;   // Section header table entry size
    uint16_t      e_shnum;       // Section header table entry count
    uint16_t      e_shstrndx;    // Section header string table index
                                 // string table section .shstrtab (ASCII string of names)
  } Elf64_Ehdr;

* "Every ELF file starts with an executable header which is just a structured series of
  bytes telling you that it's an ELF file, what kind of ELF file, and where to find other 
  contents"
* show ELF header
  - $ readelf -h a.out 

# Section Headers 
* The code and data in an ELF binary are logically divided into contiguous nonoverlapping 
  chunks. These sections do not have any predetermined structure, and varies depending on 
  contents
  - Every Section is described by a section header 
* Becuase sections are intended to provide a view for the linker only, the section header 
  table is optional. ELF files that don't need linking are not required to have a section  
  header table

  typedef struct {
    uint32_t sh_name;       // Section name - index into string table .shrstrtab
    uint32_t sh_type;       // Section type
                            // SHT_PROGBITS contain program data (instr or constants)
                            // SHT_SYMTAB static symtab, SHT_DYNSYM dynamic symtab
                            // SHT_REL, SHT_RELA contain relocation entries (tells linker
                            // about a particular location in binary where a relocation is
                            // needed and which symbol the relocation should be resolved to
    uint64_t sh_flags;      // Section flags
                            // SHF_WWRITE indicates that the section is writable at runtime
                            // SHF_ALLOC contents of the section are to loaded into virtual 
                            // memory when executing the binary
                            // SHF_EXECINSTR the section contains executable instructions
    uint64_t sh_addr;       // Section virtual addr at execution
    uint64_t sh_offset;     // Section file offset
    uint64_t sh_size;       // Section size in bytes
    uint32_t sh_link;       // Link to another section
    uint32_t sh_info;       // Additional section information
    uint64_t sh_addralign;  // Section alignment
    uint64_t sh_entsize;    // Entry size if section holds table
  } Elf64_Shdr;

# Sections
* .init     // Section runs before any other code. Trasnfers control to main entry point
* .fini     // Section which runs after the main program completes
* .text     // Section where the main code of the program resides. 
  - The .text section of a typical binary compiled by gcc contains a number of standard 
    functions that perform initialization and finalization tasks (_start, 
    register_tm_clones, frame_dummy)
  - _start is the entry point of the binary. At the end it calls main
* .bss      // (Block Started by Symbol) holds uninitialized variables
* .data     // Contains default values of initialized variables
* .rodata   // Read Only data holds constant values 

* Lazy Binding utilizes the sections .plt and .got
* Procedure Linkage Table (.plt)
  - .plt is a code section that contains executable code
  - The PLT consists entirely of stubs dedicated to directing calls from the .text 
    section to the appropriate library location

             Code
   ________________________
  |                        |
  |  .plt                  |
  |________________________|        ________________
  |                        |       |                |
  |  <default stub>:       |       |  .got.plt      |
  |    push QWORD PTR []   |       |________________|
  |    jmp  QWORD PTR []   |       |                |
  |                        | ----> |  .got.plt[n]:  |
  |  <puts@plt>:           |       |    <addr>      |
  |    jmp  QWORD PTR []   |       |________________|
  |    push 0x0            |       |                |
  |    jmp <default stub>  |       |________________|
  |________________________|
  |                        |
  |  .text                 |
  |________________________|
  |                        |
  |  <main>:               |
  |    ...                 |
  |    call puts@plt       |
  |________________________|

Disassembly of a .plt section

1️⃣️00000000004003f0 <puts@plt-0x10>:
  4003f0: push QWORD PTR [rip+0x200c12] # 601008 <_GLOBAL_OFFSET_TABLE_+0x8>
  4003f6: jmp  QWORD PTR [rip+0x200c14] # 601010 <_GLOBAL_OFFSET_TABLE_+0x10>
  4003fc: nop  DWORD PTR [rax+0x0]
  
2️⃣️0000000000400400 <puts@plt>:
  400400: jmp QWORD PTR [rip+0x200c12] # 601018 <_GLOBAL_OFFSET_TABLE_+0x18>
  400406: push 3️⃣️0x0
  40040b: jmp 4003f0 <_init+0x28>

4️⃣️0000000000400410 <__libc_start_main@plt>:
  400410: jmp QWORD PTR [rip+0x200c0a] # 601020 <_GLOBAL_OFFSET_TABLE_+0x20>
  400416: push 5️⃣️0x1
  40041b: jmp 4003f0 <_init+0x28>

  - 1 is a default stub
  - 2,4 are function stubs, one per library function
  - 3,5 for each consecutive function stub, the value pushed onto the stack is incremented

* Dynamically Resolving a Library Function Using the PLT
  - To call i.e. puts function, I make a call to the corresponding PLT stub, puts@plt
  - PLT stub begins with an indirect jump instruction into .got.plt section. Before lazy
    binding has happened this addr is the next instr (push)
  - The push instr pushes an integer (0x0) to the stack. This is an identifier for the PLT
  - The next instr jumps to the default stub shared by all PLT function stubs. It pushes
    another identifier from GOT identifying the executable itself and jumps to dynamic 
    linker
  - Using the identifier pushed by the PLT stubs, the dynamic linker figures that it
    should resolve the addr of puts and should do so on behalf of the main executable 
    loaded into the process
  - The dynamic linker then looks up the addr at which puts function is located and plugs
    the addr of that function into the GOT entry associated with puts@plt
    - Thus the GOT entry no longer points back into the PLT stub, but now points to the 
      actual addr of puts
  - Dynamic linker transfers control to puts

* Global Offset Table (.got)
  - .got.plt is a data section that is writable
  - It exists as an extra layer of security so that executable sections like .plt and .text
    can not be writable. (AVOID WRITABLE CODE SECTIONS)

* .rel.* & .rela.*  // Table of relocation entries
* .dynamic          // Lists dependencies 
* .init_array       // Data section that contains any number of fptrs.
                    // These are called when binary is init, before main is called
* .fini_array       // Data section that contains any number of fptrs.
                    // These are called when binary is ending, destructors
* .shstrtab         // Array of strings that contain names of all sections in binary
* .symtab           // Contains a symbol table which is a table of Elf64_Sym structs
                    // Associates a symbolic name with a piece of code or data 
                    // elsewhere in the binary such as function or var.
* .strtab           // Strings containing the symbolic names. 
* .dynsym & .dynstr // Analoguous to .symtab & .strtab, except they contain symbols and 
                    // strings needed for dynamic linking
* Disassemble a specific section
  - $ objdump -M intel --section .plt -d a.out

# Program Headers
* Provides a segment view of binary instead of section view.
  - Section view of an ELF binary is meant for static linking purposes
  - Segment view is used for OS during execution and dynamic linker
* An ELF segment encompasses zero or more sections, essentially bundling these into a 
  single chunk
* Because segments provide an execution view they are needed only for executable ELF files
  
  typedef struct {
    uint32_t        p_type;    // Segment type
    uint32_t        p_flags;   // Segment flags
    uint64_t        p_offset;  // Segment file offset
    uint64_t        p_vaddr;   // Segment virtual addr
    uint64_t        p_paddr;   // Segment physical addr
    uint64_t        p_filesz;  // Segment size in file
    uint64_t        p_memsz;   // Segment size in memory
    uint64_t        p_align;   // Segment alignment
  } Elf64_Phdr;

* Read Program headers
  - $ readelf --wide --segments a.out

############################## PE Format ######################################


#################### Building a Binary Loader Using LIBBFD ####################
* The Binary File Descriptor Library (libbfd) provides common interface for reading
  and parsing all popular binary formats
* Static Symbol Table
  - Created at compile time
  - Not needed for process creation
  - Can be stripped from a binary
* Dynamic Symbol Table
  - Created at runtime 
  - Used by dynamic linker to resolve which dynamic libraries to map into the addr space
    of the program

###################### Basic Binary Analysis in Linux #########################
* file
  - finds what type each file is. Not fooled by extensions
  - $ file -z (peek inside zipped files) file
* head
  - outputs first few (10) lines of a file
* tail
  - outputs last few lines of a file
* base64
  - encode binary data as ASCII text
  - $ base64 -d file
* tar xzvf (unzip using gzip and extract payload) payload
* ldd 
  - find out the shared objects (libraries) required by a program
  

    

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



