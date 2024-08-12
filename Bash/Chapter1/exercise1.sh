#!/bin/bash

# Exercise 1 Chapter 1
# Accepts two args on the cmd line  and assigns them to vars, first & last name
# Creates a new file output.txt
# Writes current date and time to file using date command DD-MM-YYYY
# Write fullname to file
# Makes backup of file backup.txt
# Print out content of output.txt to stdout

firstname="${1}"
lastname="${2}"

touch output.txt
date +%d-%m-%y > output.txt

echo "${firstname} ${lastname}" >> output.txt

cp output.txt backup.txt

cat output.txt

