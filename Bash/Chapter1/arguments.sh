#!/bin/bash

SCRIPT_NAME="${0}"
TARGET="${1}"

echo "script name: ${SCRIPT_NAME}"
ping ${TARGET}

echo "all the arguments are: $@"
echo "total number of arguments are: $#"
