#!/bin/bash

################################################################################
# Log script for WalT nodes
# - This script is intended to be run on a WalT node to continuously monitor
#   Cowrie logs and send them to the WALT logging system.
# - It waits for the Cowrie log files to be created and then tails them.
# - This script is part of the script that is used for creating the WalT image 
#   (image.sh).
################################################################################

while [ ! -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json ]; do
    sleep 5
done

# Start logging cowrie.json logs to WALT
tail -F /home/cowrie/cowrie/var/log/cowrie/cowrie.json | walt-log-cat cowrie-attacks &

# Start logging cowrie.log logs to WALT
tail -F /home/cowrie/cowrie/var/log/cowrie/cowrie.log | walt-log-cat cowrie-system &

wait
