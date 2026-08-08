#!/bin/bash

################################################################################
# Wireguard configuration script
# - This script generates a WireGuard key pair for the node and creates a
#   configuration file for the node and a corresponding configuration file for
#   the VPS.
# - It uses the mac address of the public interface to determine which node it 
#   is and assigns the appropriate VPS public key and node public IP.
# - This script doesn't start the WireGuard service, it only creates the 
#   configuration files.
# - This script is part of the script that is used for creating the WalT image 
#   (image.sh).
################################################################################

# Load the variables from the config file
source /etc/vars.conf

# Define WireGuard configuration variables
WG_PORT=<WG_PORT> # WireGuard port (e.g., 51820)
GOOFY_VPS_PUBLICKEY=<GOOFY_VPS_PUBLICKEY> # VPS public key for the first node
PLUTO_VPS_PUBLICKEY=<PLUTO_VPS_PUBLICKEY> # VPS public key for the second node
MICKEY_VPS_PUBLICKEY=<MICKEY_VPS_PUBLICKEY> # VPS public key for the third node

# Check if eth1 actually exists before trying to read its MAC
if [ -f "/sys/class/net/$INTERFACE/address" ]; then
    NODE_MAC=$(cat /sys/class/net/$INTERFACE/address)
else
    echo "Interface $INTERFACE not found. Skipping MAC detection."
    NODE_MAC="unknown"
fi

if [ "$NODE_MAC" == "$NODE1_MAC" ]; then
    VPS_PUBLICKEY=$GOOFY_VPS_PUBLICKEY
    NODE_PUBLIC_IP=${IP_ADDRESS1%%/*}
elif [ "$NODE_MAC" == "$NODE2_MAC" ]; then
    VPS_PUBLICKEY=$PLUTO_VPS_PUBLICKEY
    NODE_PUBLIC_IP=${IP_ADDRESS2%%/*}
elif [ "$NODE_MAC" == "$NODE3_MAC" ]; then
    VPS_PUBLICKEY=$MICKEY_VPS_PUBLICKEY
    NODE_PUBLIC_IP=${IP_ADDRESS3%%/*}
else
    echo "MAC address $NODE_MAC did not match any known nodes."
    exit 1
fi

umask 077
wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey

NODE_PRIVATE_KEY=$(cat /etc/wireguard/privatekey)
NODE_PUBLIC_KEY=$(cat /etc/wireguard/publickey)

cat <<EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.10.10.1/24
ListenPort = $WG_PORT
PrivateKey = $NODE_PRIVATE_KEY
Table = off

[Peer]
PublicKey = $VPS_PUBLICKEY
AllowedIPs = 0.0.0.0/0
EOF

mkdir -p /root/vps-configs

cat <<EOF > /root/vps-configs/vps-wg0.conf
[Interface]
Address = 10.10.10.2/24
PrivateKey = <VPS_PRIVATE_KEY>
Table = off

[Peer]
PublicKey = $NODE_PUBLIC_KEY
Endpoint = $NODE_PUBLIC_IP:$WG_PORT
AllowedIPs = 10.10.10.0/24, 10.10.10.1/32
PersistentKeepalive = 25
EOF
