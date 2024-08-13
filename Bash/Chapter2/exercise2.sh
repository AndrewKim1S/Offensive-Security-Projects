#!/bin/bash

#Accept two arguments name, target domain
# Throw error if the args are missing and exit 
# Ping domain and return indication of whether ping was successful
# Write results to a CSV file with name provided to script, target domain,
# ping result success or fail, current date and time

if [[ $# != 2 ]]; then
  exit 1
else
  name="${1}"
  domain="${2}"
fi

ping -c 1 "${domain}"
result=0

if [[ $? == 0 ]]; then
  echo "ping was successful"
else
  echo "ping was unsuccessful"
  result=1
fi

touch file.csv

echo "${name}, ${domain}, ${result}, $(date)" > file.csv 


