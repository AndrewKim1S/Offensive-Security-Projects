#!/bin/bash

# Sets an array
IP_ADDRS=(192.168.1.1 192.168.1.2 192.168.1.3)

# Prints out the first element
echo ${IP_ADDRS[0]}

# Prints out all the elements
echo ${IP_ADDRS[*]}

# Remove element from array
unset IP_ADDRS[1]
echo "Remove element 1 from the array ${IP_ADDRS[*]}"

# Swap elements from array
IP_ADDRS[0]="192.168.1.10"
echo "Swap element 0 from the array ${IP_ADDRS[*]}"

