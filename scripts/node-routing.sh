#!/bin/bash
set -euo pipefail

echo "Configuring Node Routing..."

# -------------------------------------------------------------------------
# Linux kernels drop packets if they arrive on an interface but the kernel 
# expects replies to go out a different interface.
# Setting this to '2' (Loose mode) tells the kernel to not drop the packet 
# just because the attacker's public IP arrived via the private wg0 tunnel.
# -------------------------------------------------------------------------
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.default.rp_filter=2
sysctl -w net.ipv4.conf.wg0.rp_filter=2
sysctl -w net.ipv4.conf.eth1.rp_filter=2

# -------------------------------------------------------------------------
# 'ip rule' does not have a clean "Check" (-C) function like iptables.
# To prevent stacking duplicate rules, we intentionally delete the old rule.
#   || true: Prevents the strict 'set -e' from crashing the script if the 
#            rule doesn't exist yet.
# -------------------------------------------------------------------------
ip rule del from 10.10.10.1 lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true

# -------------------------------------------------------------------------
# When Cowrie replies to an attacker, it uses its tunnel IP (10.10.10.1).
# By default, the node would send the reply out the physical network
# because it's going to a public internet IP.
#
# This rule says: "If a packet originates from 10.10.10.1, ignore the main 
# routing table. Force it into Table 100."
# -------------------------------------------------------------------------
ip rule add from 10.10.10.1 lookup 100

# Table 100 only has one instruction: shove the packet back down the tunnel.
ip route add default dev wg0 table 100

# -------------------------------------------------------------------------
# Force the Linux kernel to immediately forget its old cached routing paths 
# and respect the new routing rules.
# -------------------------------------------------------------------------
ip route flush cache

echo "Node Routing Configured successfully."