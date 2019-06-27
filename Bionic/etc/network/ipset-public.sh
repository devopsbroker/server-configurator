#!/bin/bash

#
# ipset-public.sh - DevOpsBroker IPSet firewall script for public Internet servers
#
# Copyright (C) 2019 Edward Smith <edwardsmith@devopsbroker.org>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------------
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-22
#
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Preprocessing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Load /etc/devops/ansi.conf if ANSI_CONFIG is unset
if [ -z "$ANSI_CONFIG" ] && [ -f /etc/devops/ansi.conf ]; then
	source /etc/devops/ansi.conf
fi

${ANSI_CONFIG?"[1;91mCannot load '/etc/devops/ansi.conf': No such file[0m"}

# Load /etc/devops/exec.conf if EXEC_CONFIG is unset
if [ -z "$EXEC_CONFIG" ] && [ -f /etc/devops/exec.conf ]; then
	source /etc/devops/exec.conf
fi

${EXEC_CONFIG?"[1;91mCannot load '/etc/devops/exec.conf': No such file[0m"}

# Load /etc/devops/functions.conf if FUNC_CONFIG is unset
if [ -z "$FUNC_CONFIG" ] && [ -f /etc/devops/functions.conf ]; then
	source /etc/devops/functions.conf
fi

${FUNC_CONFIG?"[1;91mCannot load '/etc/devops/functions.conf': No such file[0m"}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Robustness ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

set -o errexit                 # Exit if any statement returns a non-true value
set -o nounset                 # Exit if use an uninitialised variable
set -o pipefail                # Exit if any statement in a pipeline returns a non-true value
IFS=$'\n\t'                    # Default the Internal Field Separator to newline and tab

## Script information
SCRIPT_INFO=( $($EXEC_SCRIPTINFO "$BASH_SOURCE") )
SCRIPT_DIR="${SCRIPT_INFO[0]}"
SCRIPT_EXEC="${SCRIPT_INFO[1]}"

# Display error if not running as root
if [ "$USER" != 'root' ]; then
	printError $SCRIPT_EXEC 'Permission denied (you must be root)'
	exit 1
fi

################################## Variables ##################################

## Bash exec variables
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPSET=/sbin/ipset

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE IPSet Configurator" 'true'

#################################### IPSets ###################################

#
# Set default policies / Flush rules / Delete user-defined chains
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Initializing IPSets'

# Remove all iptables rules before destroying current IPSets
$IPTABLES -t raw -F
$IPTABLES -t raw -X

# Remove all ip6tables rules before destroying current IPSets
$IP6TABLES -t raw -F
$IP6TABLES -t raw -X

$IPSET destroy

echo

printBanner 'Configuring IPSets'

# Banned Clients IP Hashset (IPv4 host addresses)
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Creating banned_clients_ipv4 hashmap'
$IPSET create banned_clients_ipv4 hash:ip family inet hashsize 4096 maxelem 3072 timeout 3600

# Banned Clients IP Hashset (IPv6 host addresses)
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Creating banned_clients_ipv6 hashmap'
$IPSET create banned_clients_ipv6 hash:ip family inet6 hashsize 4096 maxelem 3072 timeout 3600

# Spoofed IP Hashset (IPv4 network addresses)
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Creating spoofed_ips hashmap of IPv4 addresses'
$IPSET create spoofed_ips hash:net family inet hashsize 16 maxelem 12
$IPSET add spoofed_ips 10.0.0.0/8        # Class A Network
$IPSET add spoofed_ips 172.16.0.0/12     # Class B Network
$IPSET add spoofed_ips 192.168.0.0/16    # Class C Network
$IPSET add spoofed_ips 240.0.0.0/4       # Class E Network
$IPSET add spoofed_ips 0.0.0.0/8         # Source hosts
$IPSET add spoofed_ips 127.0.0.0/8       # Loopback
$IPSET add spoofed_ips 169.254.0.0/16    # Link-local

# Snooped Ports Bitmap
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Creating snooped_ports bitmap'
$IPSET create snooped_ports bitmap:port range 1-10240
$IPSET add snooped_ports 20           # Passive FTP
$IPSET add snooped_ports 21           # FTP
$IPSET add snooped_ports 23           # Telnet
$IPSET add snooped_ports 25           # SMTP
$IPSET add snooped_ports 53           # DNS
$IPSET add snooped_ports 67           # DHCP Server
$IPSET add snooped_ports 68           # DHCP Client
$IPSET add snooped_ports 69           # TFTP
$IPSET add snooped_ports 80           # HTTP
$IPSET add snooped_ports 107          # Remote Telnet
$IPSET add snooped_ports 109          # POP2
$IPSET add snooped_ports 110          # POP3
$IPSET add snooped_ports 111          # RPC
$IPSET add snooped_ports 113          # IDENT
$IPSET add snooped_ports 115          # SFTP
$IPSET add snooped_ports 135          # Microsoft RPC
$IPSET add snooped_ports 137          # NetBIOS Name Service
$IPSET add snooped_ports 138          # NetBIOS Datagram Service
$IPSET add snooped_ports 139          # NetBIOS Session Service
$IPSET add snooped_ports 143          # IMAP
$IPSET add snooped_ports 161          # SNMP
$IPSET add snooped_ports 162          # SNMP Traps
$IPSET add snooped_ports 177          # XDMCP
$IPSET add snooped_ports 194          # IRC
$IPSET add snooped_ports 199          # SNMP Multiplexer
$IPSET add snooped_ports 220          # IMAP3
$IPSET add snooped_ports 371          # ClearCase
$IPSET add snooped_ports 389          # LDAP
$IPSET add snooped_ports 443          # HTTPS
$IPSET add snooped_ports 445          # SMB
$IPSET add snooped_ports 465          # SSL/TLS SMTP
$IPSET add snooped_ports 500          # IPsec IKE
$IPSET add snooped_ports 513          # Rlogin
$IPSET add snooped_ports 514          # RSH / RCP
$IPSET add snooped_ports 530          # RPC
$IPSET add snooped_ports 546          # DHCPV6 Client
$IPSET add snooped_ports 547          # DHCPV6 Server
$IPSET add snooped_ports 631          # IPP
$IPSET add snooped_ports 636          # SSL/TLS LDAP
$IPSET add snooped_ports 873          # rsync
$IPSET add snooped_ports 989          # SSL/TLS FTP (Data)
$IPSET add snooped_ports 990          # SSL/TLS FTP
$IPSET add snooped_ports 992          # SSL/TLS Telnet
$IPSET add snooped_ports 993          # SSL/TLS IMAP
$IPSET add snooped_ports 994          # SSL/TLS IRC
$IPSET add snooped_ports 995          # SSL/TLS POP3
$IPSET add snooped_ports 1024-1030    # Microsoft Windows Crap
$IPSET add snooped_ports 1099         # Java RMI Registry
$IPSET add snooped_ports 1194         # OpenVPN
$IPSET add snooped_ports 1352         # Lotus Note
$IPSET add snooped_ports 1433         # Microsoft SQL Server
$IPSET add snooped_ports 1434         # Microsoft SQL Monitor
$IPSET add snooped_ports 1863         # MSN Messenger
$IPSET add snooped_ports 2000         # Cisco SCCP
$IPSET add snooped_ports 2049         # NFS
$IPSET add snooped_ports 2401         # CVS
$IPSET add snooped_ports 3130         # ICP
$IPSET add snooped_ports 3289         # ENPC
$IPSET add snooped_ports 3306         # MySQL
$IPSET add snooped_ports 3690         # SVN
$IPSET add snooped_ports 4500         # IPsec NAT Traversal
$IPSET add snooped_ports 4827         # HTCP
$IPSET add snooped_ports 5050         # Yahoo! Messenger
$IPSET add snooped_ports 5190         # AIM
$IPSET add snooped_ports 5222         # Jabber Client
$IPSET add snooped_ports 5269         # Jabber Server
$IPSET add snooped_ports 5353         # mDNS
$IPSET add snooped_ports 5432         # PostgreSQL
$IPSET add snooped_ports 6000-6007    # X11
$IPSET add snooped_ports 6446         # MySQL Proxy
$IPSET add snooped_ports 8080         # Tomcat
$IPSET add snooped_ports 8610         # Canon MFNP
$IPSET add snooped_ports 8612         # Canon MFNP
$IPSET add snooped_ports 9418         # Git

# Service Ports Bitmap
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Creating tcp_service_ports bitmap'
$IPSET create tcp_service_ports bitmap:port range 1-10240
$IPSET add tcp_service_ports 22       # SSH

################################# IPSET-SAVE ##################################

printInfo 'Persisting IPSet configuration'

# Backup existing /etc/network/ipset.conf
if [ -f /etc/network/ipset.conf ]; then
	$EXEC_CP /etc/network/ipset.conf /etc/network/ipset.conf.bak
fi

# Save /etc/network/ipset.conf
$IPSET save > /etc/network/ipset.conf

echo

exit 0
