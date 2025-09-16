# WireGuard Installation Guide

WireGuard is a free and open-source VPN protocol and software implementation that aims to be simpler, faster, and more secure than existing VPN protocols. Originally developed by Jason A. Donenfeld, WireGuard provides state-of-the-art cryptography and minimal attack surface. It serves as a modern FOSS alternative to proprietary VPN solutions like Cisco AnyConnect, Palo Alto GlobalProtect, or commercial VPN services, offering enterprise-grade security with significantly better performance and a fraction of the codebase.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (2+ cores recommended for high throughput)
  - RAM: 256MB minimum (512MB+ recommended)
  - Storage: 100MB for installation
  - Network: Stable internet connectivity
- **Operating System**: 
  - Linux: Kernel 5.6+ (or with WireGuard module backported)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows 10 version 1809+ or Windows Server 2019+
  - FreeBSD: 12.1+
- **Network Requirements**:
  - UDP port 51820 (default, configurable)
  - Public IP address or DDNS for server
  - NAT traversal capability
- **Dependencies**:
  - Linux kernel headers (for module compilation if needed)
  - iproute2 or ifconfig
  - iptables or nftables for NAT
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# For RHEL/CentOS 8+, Rocky Linux, AlmaLinux
sudo dnf install -y epel-release elrepo-release
sudo dnf install -y kmod-wireguard wireguard-tools

# For CentOS 7
sudo yum install -y epel-release
sudo yum install -y yum-plugin-elrepo
sudo yum install -y kmod-wireguard wireguard-tools

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Verify installation
wg --version
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install WireGuard
sudo apt install -y wireguard wireguard-tools

# For older Ubuntu versions (< 20.04)
sudo add-apt-repository ppa:wireguard/wireguard
sudo apt update
sudo apt install -y wireguard wireguard-tools

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Verify installation
wg --version
```

### Arch Linux

```bash
# Install WireGuard
sudo pacman -S wireguard-tools

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.d/30-ipforward.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/30-ipforward.conf
sudo sysctl --system

# Verify installation
wg --version
```

### Alpine Linux

```bash
# Install WireGuard
apk add --no-cache wireguard-tools

# Load kernel module
modprobe wireguard

# Make module load persistent
echo "wireguard" >> /etc/modules

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
sysctl -p

# Verify installation
wg --version
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y wireguard-tools

# SLES 15
sudo SUSEConnect -p sle-module-basesystem/15.5/x86_64
sudo zypper install -y wireguard-tools

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Verify installation
wg --version
```

### macOS

```bash
# Using Homebrew
brew install wireguard-tools

# Or download the official macOS app from App Store
# Search for "WireGuard" by WireGuard Development Team

# For command-line usage
brew install wireguard-go

# Verify installation
wg --version
```

### FreeBSD

```bash
# Using pkg
pkg install wireguard wireguard-tools

# Load kernel module
kldload if_wg

# Make module load persistent
echo 'if_wg_load="YES"' >> /etc/rc.conf

# Enable IP forwarding
echo 'gateway_enable="YES"' >> /etc/rc.conf
echo 'ipv6_gateway_enable="YES"' >> /etc/rc.conf

# Apply sysctl settings
sysctl net.inet.ip.forwarding=1
sysctl net.inet6.ip6.forwarding=1

# Verify installation
wg --version
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install wireguard

# Method 2: Using Scoop
scoop bucket add extras
scoop install wireguard

# Method 3: Download installer
# Download from https://www.wireguard.com/install/
# Run the MSI installer

# Enable IP forwarding (PowerShell as Administrator)
Set-NetIPInterface -Forwarding Enabled

# Verify installation (in Command Prompt)
"C:\Program Files\WireGuard\wg.exe" --version
```

## Initial Configuration

### Generate Keys

```bash
# Create directory for WireGuard configuration
sudo mkdir -p /etc/wireguard
sudo chmod 700 /etc/wireguard
cd /etc/wireguard

# Generate server private key
wg genkey | sudo tee server_private.key | wg pubkey | sudo tee server_public.key
sudo chmod 600 server_private.key

# Generate client private key
wg genkey | sudo tee client_private.key | wg pubkey | sudo tee client_public.key
sudo chmod 600 client_private.key
```

### Server Configuration

```bash
# Create server configuration
sudo tee /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.0.0.1/24, fd00:0:0:1::1/64
ListenPort = 51820
PrivateKey = $(cat server_private.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -A FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -D FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client peer
[Peer]
PublicKey = $(cat client_public.key)
AllowedIPs = 10.0.0.2/32, fd00:0:0:1::2/128
EOF

sudo chmod 600 /etc/wireguard/wg0.conf
```

### Client Configuration

```bash
# Create client configuration
sudo tee /etc/wireguard/client.conf <<EOF
[Interface]
Address = 10.0.0.2/24, fd00:0:0:1::2/64
PrivateKey = $(cat client_private.key)
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $(cat server_public.key)
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

sudo chmod 600 /etc/wireguard/client.conf
```

### Start WireGuard

```bash
# Start WireGuard interface
sudo wg-quick up wg0

# Enable at boot
sudo systemctl enable wg-quick@wg0

# Check status
sudo wg show
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable WireGuard service
sudo systemctl enable wg-quick@wg0

# Start WireGuard
sudo systemctl start wg-quick@wg0

# Stop WireGuard
sudo systemctl stop wg-quick@wg0

# Restart WireGuard
sudo systemctl restart wg-quick@wg0

# Check status
sudo systemctl status wg-quick@wg0

# View logs
sudo journalctl -u wg-quick@wg0 -f
```

### OpenRC (Alpine Linux)

```bash
# Create OpenRC service
sudo tee /etc/init.d/wireguard <<'EOF'
#!/sbin/openrc-run
name="WireGuard VPN"
description="WireGuard VPN tunnel"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting WireGuard"
    wg-quick up wg0
    eend $?
}

stop() {
    ebegin "Stopping WireGuard"
    wg-quick down wg0
    eend $?
}
EOF

sudo chmod +x /etc/init.d/wireguard

# Enable and start
rc-update add wireguard default
rc-service wireguard start
```

### rc.d (FreeBSD)

```bash
# Create rc.d script
sudo tee /usr/local/etc/rc.d/wireguard <<'EOF'
#!/bin/sh

# PROVIDE: wireguard
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="wireguard"
rcvar="wireguard_enable"

start_cmd="wireguard_start"
stop_cmd="wireguard_stop"

wireguard_start() {
    /usr/local/bin/wg-quick up wg0
}

wireguard_stop() {
    /usr/local/bin/wg-quick down wg0
}

load_rc_config $name
run_rc_command "$1"
EOF

sudo chmod +x /usr/local/etc/rc.d/wireguard

# Enable in rc.conf
echo 'wireguard_enable="YES"' >> /etc/rc.conf

# Start service
service wireguard start
```

### Windows Service

```powershell
# Install WireGuard service
& "C:\Program Files\WireGuard\wireguard.exe" /installtunnelservice "C:\Path\To\wg0.conf"

# Start service
Start-Service WireGuardTunnel$wg0

# Stop service
Stop-Service WireGuardTunnel$wg0

# Check status
Get-Service WireGuardTunnel$wg0
```

## Advanced Configuration

### Multi-Site VPN Setup

```bash
# Site A configuration (10.1.0.0/24)
cat > /etc/wireguard/site-a.conf <<EOF
[Interface]
Address = 10.100.0.1/24
ListenPort = 51820
PrivateKey = SITE_A_PRIVATE_KEY

# Site B
[Peer]
PublicKey = SITE_B_PUBLIC_KEY
Endpoint = site-b.example.com:51820
AllowedIPs = 10.2.0.0/24, 10.100.0.2/32
PersistentKeepalive = 25

# Site C
[Peer]
PublicKey = SITE_C_PUBLIC_KEY
Endpoint = site-c.example.com:51820
AllowedIPs = 10.3.0.0/24, 10.100.0.3/32
PersistentKeepalive = 25
EOF
```

### Road Warrior Configuration

```bash
# Server configuration for mobile clients
cat > /etc/wireguard/mobile.conf <<EOF
[Interface]
Address = 10.200.0.1/24
ListenPort = 51821
PrivateKey = MOBILE_SERVER_PRIVATE_KEY

# Mobile client 1
[Peer]
PublicKey = MOBILE_CLIENT_1_PUBLIC_KEY
AllowedIPs = 10.200.0.10/32
PresharedKey = PRESHARED_KEY_FOR_EXTRA_SECURITY

# Mobile client 2
[Peer]
PublicKey = MOBILE_CLIENT_2_PUBLIC_KEY
AllowedIPs = 10.200.0.11/32
PresharedKey = ANOTHER_PRESHARED_KEY
EOF
```

### Split Tunnel Configuration

```bash
# Client configuration for split tunneling
cat > /etc/wireguard/split-tunnel.conf <<EOF
[Interface]
Address = 10.0.0.100/24
PrivateKey = CLIENT_PRIVATE_KEY
DNS = 10.0.0.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = vpn.example.com:51820
# Only route specific subnets through VPN
AllowedIPs = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
PersistentKeepalive = 25
EOF
```

## Reverse Proxy Setup

### nginx TCP/UDP Proxy

```nginx
# /etc/nginx/nginx.conf
stream {
    upstream wireguard {
        server 127.0.0.1:51820;
    }
    
    server {
        listen 443 udp;
        proxy_pass wireguard;
        proxy_timeout 1s;
        proxy_responses 1;
        proxy_bind $remote_addr transparent;
    }
}
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
global
    log /dev/log local0
    log /dev/log local1 notice

defaults
    mode tcp
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend wireguard_frontend
    bind *:51820
    mode udp
    default_backend wireguard_backend

backend wireguard_backend
    mode udp
    server wireguard1 127.0.0.1:51821
```

### iptables Port Forwarding

```bash
# Forward external port to WireGuard
iptables -t nat -A PREROUTING -i eth0 -p udp --dport 443 -j REDIRECT --to-port 51820

# Save rules
iptables-save > /etc/iptables/rules.v4
```

## Security Configuration

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 51820/udp
sudo ufw allow from 10.0.0.0/24 to any
sudo ufw reload

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=51820/udp
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/24" accept'
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
sudo iptables -A INPUT -i wg0 -j ACCEPT
sudo iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### Key Management

```bash
#!/bin/bash
# key-rotation.sh - Rotate WireGuard keys

# Generate new keys
NEW_PRIVATE=$(wg genkey)
NEW_PUBLIC=$(echo "$NEW_PRIVATE" | wg pubkey)

# Backup old configuration
cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak

# Update configuration
sed -i "s|PrivateKey = .*|PrivateKey = $NEW_PRIVATE|" /etc/wireguard/wg0.conf

# Restart WireGuard
systemctl restart wg-quick@wg0

echo "New public key: $NEW_PUBLIC"
echo "Update this key on all peers"
```

### Security Hardening

```bash
# Limit connection rate
iptables -A INPUT -p udp --dport 51820 -m state --state NEW -m recent --set
iptables -A INPUT -p udp --dport 51820 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Enable strict RPF
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter

# Disable ICMP redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv6/conf/all/accept_redirects

# Set up fail2ban for WireGuard
cat > /etc/fail2ban/filter.d/wireguard.conf <<EOF
[Definition]
failregex = <HOST>.*Handshake for peer [0-9]+ \(.*\) did not complete after
ignoreregex =
EOF

cat > /etc/fail2ban/jail.d/wireguard.conf <<EOF
[wireguard]
enabled = true
filter = wireguard
logpath = /var/log/messages
maxretry = 5
bantime = 3600
findtime = 600
EOF
```

## Database Setup

Not applicable for WireGuard as it doesn't use a database. Configuration is stored in flat files.

## Performance Optimization

### Kernel Tuning

```bash
# /etc/sysctl.d/99-wireguard.conf
# Network buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 16777216

# Increase netdev budget
net.core.netdev_budget = 600
net.core.netdev_max_backlog = 5000

# UDP specific tuning
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Connection tracking
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

# Apply settings
sysctl -p /etc/sysctl.d/99-wireguard.conf
```

### MTU Optimization

```bash
# Find optimal MTU
ping -M do -s 1472 -c 1 remote_host

# Set MTU in WireGuard config
[Interface]
MTU = 1420  # Default is 1420, adjust based on your network
```

### CPU Affinity

```bash
# Set CPU affinity for WireGuard
# Find WireGuard process
ps aux | grep wireguard

# Set affinity to specific CPU cores
taskset -cp 0,1 $(pgrep wireguard)

# Make persistent with systemd
mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
cat > /etc/systemd/system/wg-quick@wg0.service.d/override.conf <<EOF
[Service]
CPUAffinity=0 1
EOF
```

## Monitoring

### Basic Monitoring

```bash
#!/bin/bash
# wireguard-monitor.sh

while true; do
    clear
    echo "WireGuard Status - $(date)"
    echo "========================="
    
    # Show interface status
    wg show
    
    # Show transfer statistics
    echo -e "\nTransfer Statistics:"
    wg show wg0 transfer
    
    # Show connected peers
    echo -e "\nConnected Peers:"
    wg show wg0 peers
    
    # Show system resources
    echo -e "\nSystem Resources:"
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4"%"}')"
    echo "Memory: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
    echo "Network: $(ip -s link show wg0 | grep -A1 "RX:" | tail -1 | awk '{print "RX: "$1" bytes"}'), $(ip -s link show wg0 | grep -A1 "TX:" | tail -1 | awk '{print "TX: "$1" bytes"}')"
    
    sleep 5
done
```

### Prometheus Exporter

```bash
# Install WireGuard exporter
go get -u github.com/MindFlavor/prometheus_wireguard_exporter

# Configure exporter
cat > /etc/systemd/system/wireguard-exporter.service <<EOF
[Unit]
Description=WireGuard Prometheus Exporter
After=network.target

[Service]
Type=simple
User=prometheus
ExecStart=/usr/local/bin/prometheus_wireguard_exporter -n /etc/wireguard/wg0.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now wireguard-exporter
```

### Logging

```bash
# Enable verbose logging
echo "debug" > /sys/module/wireguard/parameters/debug

# Configure rsyslog for WireGuard
cat > /etc/rsyslog.d/49-wireguard.conf <<EOF
:msg, contains, "wireguard" /var/log/wireguard.log
& stop
EOF

systemctl restart rsyslog

# Log rotation
cat > /etc/logrotate.d/wireguard <<EOF
/var/log/wireguard.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# wireguard-backup.sh

BACKUP_DIR="/backup/wireguard"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/wireguard_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
tar -czf "$BACKUP_FILE" \
    /etc/wireguard/ \
    /etc/systemd/system/wg-quick@*.service.d/ \
    /etc/sysctl.d/*wireguard* \
    2>/dev/null

# Encrypt backup
gpg --cipher-algo AES256 --symmetric "$BACKUP_FILE"
rm "$BACKUP_FILE"

echo "Backup created: $BACKUP_FILE.gpg"

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "wireguard_backup_*.gpg" -mtime +30 -delete
```

### Restore Script

```bash
#!/bin/bash
# wireguard-restore.sh

BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.gpg>"
    exit 1
fi

# Decrypt backup
gpg --decrypt "$BACKUP_FILE" > /tmp/wireguard_restore.tar.gz

# Stop WireGuard
systemctl stop wg-quick@wg0

# Extract backup
tar -xzf /tmp/wireguard_restore.tar.gz -C /

# Set correct permissions
chmod 600 /etc/wireguard/*.conf
chmod 600 /etc/wireguard/*_private.key

# Restart WireGuard
systemctl start wg-quick@wg0

# Clean up
rm /tmp/wireguard_restore.tar.gz

echo "Restore completed"
```

## 6. Troubleshooting

### Common Issues

1. **Connection not establishing**:
```bash
# Check if WireGuard module is loaded
lsmod | grep wireguard

# Load module manually
modprobe wireguard

# Check interface
ip link show wg0

# Check routing
ip route show table all | grep wg0

# Test connectivity
ping -c 4 10.0.0.1
```

2. **Performance issues**:
```bash
# Check for packet loss
mtr -n 10.0.0.1

# Check interface statistics
ip -s link show wg0

# Monitor CPU usage
top -p $(pgrep wireguard)

# Check for errors
dmesg | grep wireguard
```

3. **Key exchange problems**:
```bash
# Verify keys match
wg show wg0 public-key
wg show wg0 peers

# Check handshake status
wg show wg0 latest-handshakes

# Force re-handshake
wg set wg0 peer PEER_PUBLIC_KEY endpoint ENDPOINT:PORT
```

### Debug Mode

```bash
# Enable debug logging
echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control

# View debug logs
dmesg -w | grep wireguard

# Disable debug logging
echo module wireguard -p > /sys/kernel/debug/dynamic_debug/control
```

## Integration Examples

### Python Integration

```python
#!/usr/bin/env python3
# wireguard_manager.py

import subprocess
import json
import ipaddress

class WireGuardManager:
    def __init__(self, interface='wg0'):
        self.interface = interface
    
    def get_status(self):
        """Get WireGuard interface status"""
        try:
            result = subprocess.run(['wg', 'show', self.interface, 'dump'], 
                                  capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            # Parse interface info
            interface_data = lines[0].split('\t')
            status = {
                'interface': self.interface,
                'private_key': interface_data[0],
                'public_key': interface_data[1],
                'listen_port': interface_data[2],
                'fwmark': interface_data[3],
                'peers': []
            }
            
            # Parse peer info
            for line in lines[1:]:
                peer_data = line.split('\t')
                peer = {
                    'public_key': peer_data[0],
                    'preshared_key': peer_data[1],
                    'endpoint': peer_data[2],
                    'allowed_ips': peer_data[3].split(','),
                    'latest_handshake': peer_data[4],
                    'rx_bytes': int(peer_data[5]),
                    'tx_bytes': int(peer_data[6]),
                    'persistent_keepalive': peer_data[7]
                }
                status['peers'].append(peer)
            
            return status
        except subprocess.CalledProcessError as e:
            return {'error': str(e)}
    
    def add_peer(self, public_key, allowed_ips, endpoint=None, preshared_key=None):
        """Add a new peer"""
        cmd = ['wg', 'set', self.interface, 'peer', public_key]
        
        if allowed_ips:
            cmd.extend(['allowed-ips', ','.join(allowed_ips)])
        
        if endpoint:
            cmd.extend(['endpoint', endpoint])
        
        if preshared_key:
            cmd.extend(['preshared-key', preshared_key])
        
        try:
            subprocess.run(cmd, check=True)
            return {'success': True}
        except subprocess.CalledProcessError as e:
            return {'error': str(e)}
    
    def remove_peer(self, public_key):
        """Remove a peer"""
        try:
            subprocess.run(['wg', 'set', self.interface, 'peer', public_key, 'remove'], 
                         check=True)
            return {'success': True}
        except subprocess.CalledProcessError as e:
            return {'error': str(e)}
    
    def generate_config(self, address, private_key, peers):
        """Generate WireGuard configuration"""
        config = f"""[Interface]
Address = {address}
PrivateKey = {private_key}
ListenPort = 51820

"""
        for peer in peers:
            config += f"""[Peer]
PublicKey = {peer['public_key']}
AllowedIPs = {','.join(peer['allowed_ips'])}
"""
            if peer.get('endpoint'):
                config += f"Endpoint = {peer['endpoint']}\n"
            if peer.get('preshared_key'):
                config += f"PresharedKey = {peer['preshared_key']}\n"
            if peer.get('persistent_keepalive'):
                config += f"PersistentKeepalive = {peer['persistent_keepalive']}\n"
            config += "\n"
        
        return config

# Example usage
if __name__ == '__main__':
    wg = WireGuardManager()
    
    # Get status
    status = wg.get_status()
    print(json.dumps(status, indent=2))
    
    # Add a peer
    result = wg.add_peer(
        public_key='PEER_PUBLIC_KEY',
        allowed_ips=['10.0.0.100/32'],
        endpoint='peer.example.com:51820'
    )
    print(f"Add peer result: {result}")
```

### Bash Integration

```bash
#!/bin/bash
# wireguard-cli.sh - WireGuard management CLI

set -euo pipefail

INTERFACE="${WG_INTERFACE:-wg0}"
CONFIG_DIR="/etc/wireguard"

show_help() {
    cat <<EOF
WireGuard CLI Management Tool

Usage: $0 [command] [options]

Commands:
    status          Show interface status
    add-peer        Add a new peer
    remove-peer     Remove a peer
    list-peers      List all peers
    generate-qr     Generate QR code for mobile config
    backup          Backup configuration
    restore         Restore configuration

Examples:
    $0 status
    $0 add-peer --name mobile1 --ip 10.0.0.10
    $0 generate-qr mobile1
EOF
}

status() {
    echo "WireGuard Interface: $INTERFACE"
    echo "========================="
    wg show "$INTERFACE"
}

add_peer() {
    local name="$1"
    local ip="$2"
    
    # Generate keys
    private_key=$(wg genkey)
    public_key=$(echo "$private_key" | wg pubkey)
    preshared_key=$(wg genpsk)
    
    # Add to server config
    cat >> "$CONFIG_DIR/$INTERFACE.conf" <<EOF

[Peer]
# $name
PublicKey = $public_key
PresharedKey = $preshared_key
AllowedIPs = $ip/32
EOF

    # Generate client config
    server_public_key=$(wg show "$INTERFACE" public-key)
    server_endpoint=$(curl -s ifconfig.me)
    
    cat > "$CONFIG_DIR/clients/$name.conf" <<EOF
[Interface]
Address = $ip/24
PrivateKey = $private_key
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $server_public_key
PresharedKey = $preshared_key
Endpoint = $server_endpoint:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # Reload configuration
    wg syncconf "$INTERFACE" <(wg-quick strip "$INTERFACE")
    
    echo "Peer $name added successfully"
    echo "Client configuration saved to: $CONFIG_DIR/clients/$name.conf"
}

remove_peer() {
    local public_key="$1"
    wg set "$INTERFACE" peer "$public_key" remove
    echo "Peer removed"
}

list_peers() {
    echo "Configured Peers:"
    echo "================="
    wg show "$INTERFACE" peers | while read -r peer; do
        echo "Public Key: $peer"
        wg show "$INTERFACE" allowed-ips | grep "$peer" | awk '{print "  Allowed IPs: " $2}'
        wg show "$INTERFACE" latest-handshakes | grep "$peer" | awk '{print "  Last Handshake: " strftime("%Y-%m-%d %H:%M:%S", $2)}'
        echo
    done
}

generate_qr() {
    local config_name="$1"
    local config_file="$CONFIG_DIR/clients/$config_name.conf"
    
    if [ ! -f "$config_file" ]; then
        echo "Configuration file not found: $config_file"
        exit 1
    fi
    
    qrencode -t ansiutf8 < "$config_file"
}

# Main logic
case "${1:-help}" in
    status)
        status
        ;;
    add-peer)
        shift
        add_peer "$@"
        ;;
    remove-peer)
        shift
        remove_peer "$@"
        ;;
    list-peers)
        list_peers
        ;;
    generate-qr)
        shift
        generate_qr "$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf update wireguard-tools kmod-wireguard

# Debian/Ubuntu
sudo apt update && sudo apt upgrade wireguard wireguard-tools

# Arch Linux
sudo pacman -Syu wireguard-tools

# Alpine Linux
apk update && apk upgrade wireguard-tools

# openSUSE
sudo zypper update wireguard-tools

# FreeBSD
pkg update && pkg upgrade wireguard wireguard-tools

# Always backup before updates
/usr/local/bin/wireguard-backup.sh

# Restart after updates
sudo systemctl restart wg-quick@wg0
```

### Regular Maintenance Tasks

```bash
#!/bin/bash
# wireguard-maintenance.sh

LOG_FILE="/var/log/wireguard-maintenance.log"
CONFIG_DIR="/etc/wireguard"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check and remove inactive peers
check_inactive_peers() {
    log "Checking for inactive peers..."
    
    wg show wg0 latest-handshakes | while read -r peer handshake; do
        if [ "$handshake" -eq 0 ]; then
            continue
        fi
        
        current_time=$(date +%s)
        time_diff=$((current_time - handshake))
        
        # Remove peers inactive for more than 30 days
        if [ $time_diff -gt 2592000 ]; then
            log "Removing inactive peer: $peer"
            wg set wg0 peer "$peer" remove
        fi
    done
}

# Verify configuration integrity
verify_config() {
    log "Verifying configuration..."
    
    if wg-quick strip wg0 > /dev/null 2>&1; then
        log "Configuration is valid"
    else
        log "ERROR: Configuration validation failed"
        return 1
    fi
}

# Update geo-blocked IPs (if applicable)
update_geoblock() {
    log "Updating geo-block rules..."
    
    # Example: Update allowed countries
    # This would typically fetch from a geo-IP database
    # and update firewall rules accordingly
}

# Generate usage report
generate_report() {
    log "Generating usage report..."
    
    report_file="/var/log/wireguard-report-$(date +%Y%m%d).txt"
    
    {
        echo "WireGuard Usage Report - $(date)"
        echo "================================"
        echo
        echo "Interface Statistics:"
        wg show wg0 transfer
        echo
        echo "Peer Count: $(wg show wg0 peers | wc -l)"
        echo
        echo "Top 10 Peers by Traffic:"
        wg show wg0 transfer | sort -k3 -nr | head -10
    } > "$report_file"
    
    log "Report saved to: $report_file"
}

# Main maintenance routine
main() {
    log "Starting WireGuard maintenance..."
    
    check_inactive_peers
    verify_config
    update_geoblock
    generate_report
    
    log "Maintenance completed"
}

# Run maintenance
main

# Schedule this script in cron:
# 0 2 * * 0 /usr/local/bin/wireguard-maintenance.sh
```

### Performance Monitoring

```bash
#!/bin/bash
# wireguard-performance.sh

# Monitor interface performance
monitor_performance() {
    local interface="wg0"
    local duration=60
    local interval=5
    
    echo "Monitoring WireGuard performance for $duration seconds..."
    echo "Time,RX_packets,TX_packets,RX_bytes,TX_bytes,RX_errors,TX_errors"
    
    end_time=$(($(date +%s) + duration))
    
    while [ $(date +%s) -lt $end_time ]; do
        stats=$(ip -s link show $interface | awk '/RX:/{getline; rx_p=$1; rx_b=$2; rx_e=$3} /TX:/{getline; tx_p=$1; tx_b=$2; tx_e=$3} END{print rx_p","tx_p","rx_b","tx_b","rx_e","tx_e}')
        echo "$(date +%s),$stats"
        sleep $interval
    done
}

# Check for configuration drift
check_config_drift() {
    local running_config="/tmp/wg0-running.conf"
    local saved_config="/etc/wireguard/wg0.conf"
    
    wg showconf wg0 > "$running_config"
    
    if ! diff -q "$running_config" <(wg-quick strip "$saved_config") > /dev/null; then
        echo "WARNING: Running configuration differs from saved configuration"
        diff "$running_config" <(wg-quick strip "$saved_config")
    else
        echo "Configuration is in sync"
    fi
    
    rm -f "$running_config"
}

# Run performance monitoring
monitor_performance | tee /var/log/wireguard-performance-$(date +%Y%m%d-%H%M%S).csv
```

## Additional Resources

- [Official WireGuard Documentation](https://www.wireguard.com/)
- [WireGuard Quick Start Guide](https://www.wireguard.com/quickstart/)
- [WireGuard White Paper](https://www.wireguard.com/papers/wireguard.pdf)
- [WireGuard GitHub Repository](https://github.com/WireGuard)
- [WireGuard Mailing List](https://lists.zx2c4.com/mailman/listinfo/wireguard)
- [Community Forums](https://www.reddit.com/r/WireGuard/)
- [Performance Tuning Guide](https://www.wireguard.com/performance/)
- [Security Considerations](https://www.wireguard.com/formal-verification/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.