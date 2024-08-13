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
  for variable in LIST; do
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











    
    
    
    
    
    
    
    
  





  
  
  

