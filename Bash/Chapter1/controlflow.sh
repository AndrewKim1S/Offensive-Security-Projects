#!/bin/bash

echo "Sleeping for 10 seconds"
sleep 10 &

echo "Create file"
touch file

echo "Delete file"
rm file
