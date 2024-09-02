#!/bin/bash

job_name="my_scheduled_job"

echo "The time is now $(date)" >> "/tmp/${job_name}"

exit 0
