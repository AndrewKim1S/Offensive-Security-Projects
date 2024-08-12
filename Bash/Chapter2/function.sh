#!/bin/bash

checkRoot(){
  if [[ "${EUID}" -eq "0" ]]; then
    return 0
  else 
    return 1
  fi
}

if checkRoot; then
  echo "User is root"
else
  echo "User is not root"
fi
