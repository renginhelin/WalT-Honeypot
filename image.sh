#!/bin/bash

################################################################################
# Image setup script for WalT nodes
# - This script is intended to be run on a fresh WalT node image to set up
#   Cowrie, WireGuard, and routing.
# - It downloads necessary dependencies, configures the network, and sets up 
#   systemd services.
# - MULTIPLE VARIABLES NEED TO BE EDITED BELOW BEFORE RUNNING THIS SCRIPT.
################################################################################

# Exit immediately if a command exits with a non-zero status
set -e

echo "Starting WALT image setup..."

echo "Creating shared variables file..."
cat <<'EOF' > /etc/vars.conf
INTERFACE=<INTERFACE> # Public IP interface name (e.g. eth1)
IP_ADDRESS1=<IP_ADDRESS1> # Public IP address for the first node (xxx.xx.xxx.xx/xx)
IP_ADDRESS2=<IP_ADDRESS2> # Public IP address for the second node (xxx.xx.xxx.xx/xx)
IP_ADDRESS3=<IP_ADDRESS3> # Public IP address for the third node (xxx.xx.xxx.xx/xx)
NODE1_MAC=<NODE1_MAC> # Public interface MAC address for the first node
NODE2_MAC=<NODE2_MAC> # Public interface MAC address for the second node
NODE3_MAC=<NODE3_MAC> # Public interface MAC address for the third node
GATEWAY=<GATEWAY> # Gateway for the public IP addresses (xxx.xx.xxx.xx)
VPS_INTERFACE=<VPS_INTERFACE>  # The public-facing network interface on the VPS (e.g., eth0, ens4, enp0s3, etc.)
WG_PORT=<WG_PORT> # WireGuard port (e.g., 51820)
GOOFY_VPS_PUBLICKEY=<GOOFY_VPS_PUBLICKEY> # VPS public key for the first node
PLUTO_VPS_PUBLICKEY=<PLUTO_VPS_PUBLICKEY> # VPS public key for the second node
MICKEY_VPS_PUBLICKEY=<MICKEY_VPS_PUBLICKEY> # VPS public key for the third node
EOF

# Update package lists
apt-get update

# Install WireGuard tools
echo "Installing WireGuard tools..."
apt-get install -y --no-install-recommends wireguard-tools

# Install dependencies for Cowrie
echo "Installing dependencies for Cowrie..."
apt-get install -y git python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind

# Create a dedicated user for Cowrie if it doesn't exist
if ! id "cowrie" &>/dev/null; then
    echo "Creating a user for Cowrie..."
    adduser --disabled-password --gecos "" cowrie
fi

mkdir -p /persist/downloads /persist/snapshots
chown -R cowrie:cowrie /persist/downloads /persist/snapshots

# ---------------------------------------------------------
# Install and Configure Cowrie
# ---------------------------------------------------------

# Install Cowrie as the cowrie user,
# configure it to use /persist for downloads and snapshots,
# set up userdb.txt for custom login credentials.
echo "Installing Cowrie as the cowrie user..."
su - cowrie -s /bin/bash <<'EOF'
  set -e

  cd /home/cowrie
  
  if [ ! -d "cowrie" ]; then
    git clone http://github.com/cowrie/cowrie
  fi
  
  cd cowrie
  echo "Setting up Python virtual environment..."
  python3 -m venv cowrie-env
  
  echo "Activating virtual environment and installing Cowrie..."
  source cowrie-env/bin/activate
  python -m pip install --upgrade pip
  python -m pip install -e .
  
  deactivate

  echo "/persist configuration..."
  rm -rf /home/cowrie/cowrie/var/lib/cowrie/downloads
  ln -s /persist/downloads /home/cowrie/cowrie/var/lib/cowrie/downloads

  rm -rf /home/cowrie/cowrie/var/lib/cowrie/snapshots
  ln -s /persist/snapshots /home/cowrie/cowrie/var/lib/cowrie/snapshots
EOF

# ---------------------------------------------------------
# Create systemd services for Cowrie and log streaming
# ---------------------------------------------------------

# Create a systemd service to run Cowrie at startup
echo "Creating systemd service for Cowrie..."
cat <<EOF > /etc/systemd/system/cowrie.service
################################################################################
# Systemd service unit for automatically starting Cowrie.
# This service file is created as part of the image script (image.sh).
################################################################################

[Unit]
Description=Cowrie SSH/Telnet Honeypot
Documentation=https://github.com/cowrie/cowrie
After=network.target

[Service]
Type=forking
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie
Environment="PATH=/home/cowrie/cowrie/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/cowrie start
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/cowrie stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Enable the cowrie.service to start on boot
echo "Enabling cowrie.service to start on boot..."
systemctl enable cowrie.service

# Create the log-script.sh file for logging Cowrie logs to WALT
echo "Creating log-script.sh..."
cat <<'EOF' > /usr/local/bin/log-script.sh
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
EOF

# Make the log-script.sh executable
chmod +x /usr/local/bin/log-script.sh

# Create a systemd service to run the log-script.sh at startup
echo "Creating systemd service for Cowrie log streaming..."
cat <<EOF > /etc/systemd/system/cowrie-log.service
################################################################################
# Systemd service unit for streaming Cowrie honeypot logs to WalT monitoring.
# Automatically starts the log-script.sh on boot, depends on cowrie service.
# This service file is created as part of the image script (image.sh).
################################################################################

[Unit]
Description=Cowrie Log Streamer to WalT
After=network.target cowrie.service
Requires=cowrie.service

[Service]
Type=simple

ExecStart=/usr/local/bin/log-script.sh

Restart=always

User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable the cowrie-log.service to start on boot
echo "Enabling cowrie-log.service to start on boot..."
systemctl enable cowrie-log.service

# ---------------------------------------------------------
# Create network configuration script and systemd service
# ---------------------------------------------------------

# Create the network.sh script to configure the public IP based on the node's MAC address
echo "Creating network.sh.."
cat <<'EOF' > /usr/local/bin/network.sh
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
EOF

# Make the network.sh script executable
chmod +x /usr/local/bin/network.sh

# Create a systemd service to run the network.sh at startup
echo "Creating systemd service for network configuration..."
cat <<EOF > /etc/systemd/system/network-config.service
################################################################################
# Systemd service unit for running the network.sh script at startup for
# IP assignment and network configuration.
# This service file is created as part of the image script (image.sh).
################################################################################

[Unit]
Description=Assign Node IP via MAC Address
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/network.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable the network-config.service to start on boot
echo "Enabling network-config.service to start on boot..."
systemctl enable network-config.service

# ---------------------------------------------------------
# Run WireGuard Setup Script
# ---------------------------------------------------------

echo "Creating wireguard.sh..."
cat <<'EOF' > /usr/local/bin/wireguard.sh
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

cat <<WGCONF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.10.10.1/24
ListenPort = $WG_PORT
PrivateKey = $NODE_PRIVATE_KEY
Table = off

[Peer]
PublicKey = $VPS_PUBLICKEY
AllowedIPs = 0.0.0.0/0
WGCONF

mkdir -p /root/vps-configs

cat <<VPSCONF > /root/vps-configs/vps-wg0.conf
[Interface]
Address = 10.10.10.2/24
PrivateKey = <VPS_PRIVATE_KEY>
Table = off

[Peer]
PublicKey = $NODE_PUBLIC_KEY
Endpoint = $NODE_PUBLIC_IP:$WG_PORT
AllowedIPs = 10.10.10.0/24, 10.10.10.1/32
PersistentKeepalive = 25
VPSCONF
EOF

# Make the generated script executable
chmod +x /usr/local/bin/wireguard.sh

# Create a systemd service to run wireguard.sh on boot
echo "Creating systemd service for WireGuard node configuration..."
cat <<'EOF' > /etc/systemd/system/wireguard-setup.service
################################################################################
# Systemd service unit for generating and configuring WireGuard tunnel setup.
# Runs after network IP assignment to run wireguard.sh script to generate
# necessary config files to establish a tunnel between VPS/Node.
# It does not set the Wireguard interface up.
# This service file is created as part of the image script (image.sh).
################################################################################

[Unit]
Description=Generate WireGuard Configs
After=network-config.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wireguard.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable the service to run on boot
systemctl enable wireguard-setup.service

echo "Creating node-routing.sh..."
cat <<'EOF' > /usr/local/bin/node-routing.sh
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
EOF

# Make the node-routing.sh script executable
chmod +x /usr/local/bin/node-routing.sh

echo "Creating vps-routing.sh..."
cat <<'EOF' > /usr/local/bin/vps-routing.sh
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
EOF

echo "VPS WireGuard configuration file created at /root/vps-configs/vps-wg0.conf. Please replace <VPS_PRIVATE_KEY> with the actual private key of the VPS before using it."
echo "You need to run 'wg-quick up wg0' first on the node then 'sudo wg-quick up wg0' on the VPS to establish the WireGuard connection."
echo "After wireguard is up, run the scripts '/usr/local/bin/node-routing.sh' on the node and '/usr/local/bin/vps-routing.sh' on the VPS to configure routing."
echo "Done."