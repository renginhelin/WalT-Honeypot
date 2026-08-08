#!/bin/bash
# Enable strict error handling:
# -e: Exit immediately if any command fails.
# -u: Exit if an undefined variable is used.
# -o pipefail: Exit if any command in a pipeline (Command A | Command B) fails.
set -euo pipefail

echo "Configuring VPS Routing..."

# Load the variables from the config file
source /etc/vars.conf

apt-get update
apt-get install -y iptables

# -------------------------------------------------------------------------
# By default, a Linux server drops packets that aren't addressed to itself.
# Since the VPS receives packets destined for its own public IP, but needs
# to push them to the Node (10.10.10.1), it must act as a network router.
# -------------------------------------------------------------------------
sysctl -w net.ipv4.ip_forward=1

# -------------------------------------------------------------------------
# Allow return and helper traffic for tracked connections.
# - Matches packets marked by conntrack as `ESTABLISHED` (ongoing sessions)
#   or `RELATED` (new packets tied to an existing session).
# - Insert this rule at the top so reply/related packets are accepted
#   before any restrictive FORWARD rules are evaluated.
# - The `iptables -C ... || iptables -I ...` pattern makes the script
#   check for the rule first and insert it only if missing.
# -------------------------------------------------------------------------
iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# -------------------------------------------------------------------------
# Catch external traffic hitting the VPS on the standard SSH port (22)
# and rewrite the destination to the Cowrie honeypot over WireGuard (2222).
#   -C || -A: Checks (-C) if the rule exists. If it fails, it Appends (-A) it. 
#             This prevents rule duplication without causing downtime.
# -------------------------------------------------------------------------
iptables -t nat -C PREROUTING -i $VPS_INTERFACE -p tcp --dport 22 -j DNAT --to-destination 10.10.10.1:2222 2>/dev/null || \
iptables -t nat -A PREROUTING -i $VPS_INTERFACE -p tcp --dport 22 -j DNAT --to-destination 10.10.10.1:2222

# -------------------------------------------------------------------------
# The PREROUTING rule above changed the destination, but the firewall still 
# needs explicit permission to pass NEW packets from the public web ($VPS_INTERFACE) 
# into the encrypted tunnel (wg0).
# -------------------------------------------------------------------------
iptables -C FORWARD -i $VPS_INTERFACE -o wg0 -p tcp --dport 2222 -d 10.10.10.1 -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i $VPS_INTERFACE -o wg0 -p tcp --dport 2222 -d 10.10.10.1 -j ACCEPT

echo "VPS Routing Configured successfully."