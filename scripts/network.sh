#!/bin/bash

################################################################################
# Network assignment helper
# - This is a script that assigns a public IP and default route to a
#   machine based on the MAC address of its public interface.
# - Intended for use on boot so the correct node gets the right public address
#   without manual editing.
# - This script is part of the script that is used for creating the WalT image 
#   (image.sh).
################################################################################

# Load the variables from the config file
source /etc/vars.conf

# Check if eth1 actually exists before trying to read its MAC
if [ -f "/sys/class/net/$INTERFACE/address" ]; then
    NODE_MAC=$(cat /sys/class/net/$INTERFACE/address)
else
    echo "Interface $INTERFACE not found. Skipping MAC detection."
    NODE_MAC="unknown"
fi

# Assign Public IP based on the MAC address of the node
if [ "$NODE_MAC" == "$NODE1_MAC" ]; then
    ip addr add $IP_ADDRESS1 dev $INTERFACE || true
    ip link set $INTERFACE up
    ip route add $GATEWAY dev $INTERFACE || true
    ip route add 0.0.0.0/0 via $GATEWAY dev $INTERFACE
elif [ "$NODE_MAC" == "$NODE2_MAC" ]; then
    ip addr add $IP_ADDRESS2 dev $INTERFACE || true
    ip link set $INTERFACE up
    ip route add $GATEWAY dev $INTERFACE || true
    ip route add 0.0.0.0/0 via $GATEWAY dev $INTERFACE
elif [ "$NODE_MAC" == "$NODE3_MAC" ]; then
    ip addr add $IP_ADDRESS3 dev $INTERFACE || true
    ip link set $INTERFACE up
    ip route add $GATEWAY dev $INTERFACE || true
    ip route add 0.0.0.0/0 via $GATEWAY dev $INTERFACE
else
    echo "MAC address $NODE_MAC did not match any known nodes."
fi