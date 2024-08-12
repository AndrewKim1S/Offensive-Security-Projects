###############################################################################
#                               Black Hat Bash                                #
#                                                                             #
###############################################################################

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

* until
  runs so long as the condition fails
  until condition; do
    # run commands
  done

