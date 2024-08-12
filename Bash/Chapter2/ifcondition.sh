#!/bin/bash

FILENAME="flowcontrol.txt"

# File conditions
if [[ -f ${FILENAME} ]]; then
  echo "${FILENAME} already exists"
  exit 1
else 
  touch ${FILENAME}
fi

# String conditions
VARIABLE_ONE="nostarch"
VARIABLE_TWO="nostarch"

if [[ ${VARIABLE_ONE} == ${VARIABLE_TWO} ]]; then
  echo "strings are equivalent"
else 
  echo "strings are not equivalent"
fi

VARIABLE_ONE=10
VARIABLE_TWO=20

if [[ ${VARIABLE_ONE} -gt ${VARIABLE_TWO} ]]; then
  echo "${VARIABLE_ONE} is greater than ${VARIABLE_TWO}"
else 
  echo "${VARIABLE_ONE} is less than ${VARIABLE_TWO}"
fi


