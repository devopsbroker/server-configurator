#!/bin/bash

#
# iptables-public.sh - DevOpsBroker IPv4 iptables firewall script for public Internet servers
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
# Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-45
#
# Uses a Block Listing approach (Default Policy: ACCEPT, Rules DROP/REJECT)
#
# Features:
#   o Drop fragmented incoming/outgoing packets
#   o All ICMP and IGMP filtering is done in the RAW table
#   o Valid ICMP, UDP, and IGMP traffic is set to NOTRACK
#   o All traffic on lo is set to NOTRACK
#   o Drop all incoming/outgoing INVALID packets
#   o Disable FORWARD
#   o Protocol-specific FILTER chains for TCP/UDP/ICMP/IGMP
#
# References:
#   o man iptables
#   o man iptables-extensions
#
# Notes:
#   o REJECT rules are not allowed in the RAW table
#
# Useful Linux Command-Line Utilities
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# o List rules currently configured:
# sudo firewall -4 list
# sudo firewall -4 list FILTER INPUT
#
# o See which ports are listening for connections:
# sudo netstat -tulpn
#
# View network statistics:
# netstat -s
#
# How many connections an application is using:
# netstat -neopa
#
# TODO: https://www.snort.org/ - filter packets for "alerts" or concerning traffic
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Preprocessing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
IPTABLES_SAVE=/sbin/iptables-save
IPSET=/sbin/ipset

## Options
NIC="$1"

## Variables
IPv4_ADDRESS=''
IPv4_GATEWAY=''

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [ -z "$NIC" ]; then
	mapfile -t ethList < <($EXEC_IP -br -4 addr show | $EXEC_GREP -Eo '^enp[a-z0-9]+')

	if [ ${#ethList[@]} -eq 1 ]; then
		ethInterface=(${ethList[0]})
	else
		OLD_COLUMNS=$COLUMNS
		COLUMNS=1
		echo "${bold}${yellow}Which Ethernet interface do you want to configure?${white}"
		select ethInterface in ${ethList[@]}; do
			break;
		done
		COLUMNS=$OLD_COLUMNS
	fi

	NIC=$ethInterface
else
	# Display error if network interface parameter is invalid
	if [ ! -L /sys/class/net/$NIC ]; then
		printError "$SCRIPT_EXEC" "Cannot access '$NIC': No such network interface"
		echo
		printUsage "$SCRIPT_EXEC ${gold}[NIC]"

		exit 1
	fi
fi

ethInfo=( $($EXEC_DERIVESUBNET -4 $NIC) )

IPv4_ADDRESS=${ethInfo[0]}
IPv4_GATEWAY=${ethInfo[1]}

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE iptables Configurator" 'true'

echo "${bold}Network Interface: ${green}$NIC"
echo "${white}IPv4 Address: ${green}$IPv4_ADDRESS"
echo "${white}IPv4 Gateway: ${green}$IPv4_GATEWAY"
echo "${reset}"

#
# Set default policies / Flush rules / Delete user-defined chains
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Initializing RAW Table'
$IPTABLES -t raw -P OUTPUT ACCEPT
$IPTABLES -t raw -F
$IPTABLES -t raw -X
$IPSET -t raw -F
$IPSET -t raw -X

printInfo 'Initializing MANGLE Table'
$IPTABLES -t mangle -P INPUT ACCEPT
$IPTABLES -t mangle -P FORWARD ACCEPT
$IPTABLES -t mangle -P OUTPUT ACCEPT
$IPTABLES -t mangle -F
$IPTABLES -t mangle -X

printInfo 'Initializing NAT Table'
$IPTABLES -t nat -P OUTPUT ACCEPT
$IPTABLES -t nat -F
$IPTABLES -t nat -X

printInfo 'Initializing FILTER Table'
$IPTABLES -t filter -P INPUT ACCEPT
$IPTABLES -t filter -P FORWARD ACCEPT
$IPTABLES -t filter -P OUTPUT ACCEPT
$IPTABLES -t filter -F
$IPTABLES -t filter -X

echo

################################## RAW Table ##################################

printBanner 'Configuring RAW Table'

#
# ═══════════════════════ Custom RAW Table Jump Targets ═══════════════════════
#

# Rate limit Ban Client logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N ban_client_drop
$IPTABLES -t raw -A ban_client_drop -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv4_ban_client_drop --hashlimit-htable-size 4096 --hashlimit-htable-max 3072 \
	--hashlimit-htable-expire 3600000 --hashlimit-htable-gcinterval 60000 \
	--hashlimit-upto 3/minute --hashlimit-burst 2 -j LOG --log-prefix '[IPv4 BAN BLOCK] ' --log-level 7
$IPTABLES -t raw -A ban_client_drop -j DROP

# Rate limit Fragment logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N fragment_drop
$IPTABLES -t raw -A fragment_drop -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv4_fragment_drop --hashlimit-htable-size 256 --hashlimit-htable-max 192 \
	--hashlimit-htable-expire 900000 --hashlimit-htable-gcinterval 60000 \
	--hashlimit-upto 3/minute --hashlimit-burst 2 -j LOG --log-prefix '[IPv4 FRAG BLOCK] ' --log-level 7
$IPTABLES -t raw -A fragment_drop -j DROP

# Rate limit ICMP BLOCK logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N icmp_drop
$IPTABLES -t raw -A icmp_drop -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv4_icmp_drop --hashlimit-htable-size 256 --hashlimit-htable-max 192 \
	--hashlimit-htable-expire 900000 --hashlimit-htable-gcinterval 60000 \
	--hashlimit-upto 3/minute --hashlimit-burst 2 -j LOG --log-prefix '[IPv4 ICMP BLOCK] ' --log-level 7
$IPTABLES -t raw -A icmp_drop -j DROP

# Rate limit Network Interface logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N nic_drop
$IPTABLES -t raw -A nic_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 NIC BLOCK] ' --log-level 7
$IPTABLES -t raw -A nic_drop -j DROP

# Perform NOTRACK and ACCEPT
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N do_not_track
$IPTABLES -t raw -A do_not_track -j NOTRACK
$IPTABLES -t raw -A do_not_track -j ACCEPT

# Ban Client / Rate limit logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N ban_client
$IPTABLES -t raw -A ban_client -j SET --add-set banned_clients src
$IPTABLES -t raw -A ban_client -j ban_client_drop

# Banned Clients IP Hashset (IPv4 host addresses)
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPSET -t raw -N banned_clients hash:ip family inet hashsize 4096 maxelem 3072 timeout 3600

# Spoofed IP Hashset (IPv4 network addresses)
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPSET -t raw -N spoofed_ips hash:net family inet hashsize 16 maxelem 12
$IPSET -t raw -A spoofed_ips 10.0.0.0/8        # Class A Network
$IPSET -t raw -A spoofed_ips 172.16.0.0/12     # Class B Network
$IPSET -t raw -A spoofed_ips 192.168.0.0/16    # Class C Network
$IPSET -t raw -A spoofed_ips 240.0.0.0/4       # Class E Network
$IPSET -t raw -A spoofed_ips 0.0.0.0/8         # Source hosts
$IPSET -t raw -A spoofed_ips 127.0.0.0/8       # Loopback
$IPSET -t raw -A spoofed_ips 169.254.0.0/16    # Link-local

# Snooped Ports Bitmap
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
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
$IPSET create tcp_service_ports bitmap:port range 1-10240
$IPSET add tcp_service_ports 22       # SSH

#
# ══════════════════════ Configure RAW PREROUTING Chain ═══════════════════════
#

printInfo 'DROP incoming fragmented packets'
$IPTABLES -t raw -A PREROUTING -f -j fragment_drop

# Create PREROUTING filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## lo
printInfo 'Allow incoming lo interface traffic'
$IPTABLES -t raw -A PREROUTING -i lo -j do_not_track

## NIC
printInfo "Process incoming $NIC interface traffic"
$IPTABLES -t raw -N raw-${NIC}-pre
$IPTABLES -t raw -A PREROUTING -i ${NIC} -j raw-${NIC}-pre

printInfo 'DROP all other incoming interface traffic'
$IPTABLES -t raw -A PREROUTING -j nic_drop

echo

# Create PREROUTING filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo 'DROP incoming packets from banned clients'
$IPTABLES -t raw -A raw-${NIC}-pre -m set --set banned_clients src -j ban_client_drop

printInfo 'DROP incoming packets from spoofed IP addresses'
$IPTABLES -t raw -A raw-${NIC}-pre -m set --set spoofed_ips src -j DROP

printInfo 'Ban clients snooping for open ports'
$IPTABLES -t raw -A raw-${NIC}-pre -m set --set snooped_ports dst -j ban_client

# TODO: Block the External IP as a source if you have a static IP from your ISP

## TCP
printInfo 'Process incoming TCP traffic'
$IPTABLES -t raw -N raw-${NIC}-tcp-pre
$IPTABLES -t raw -A raw-${NIC}-pre -p tcp -j raw-${NIC}-tcp-pre

## UDP
printInfo 'Process incoming UDP traffic'
$IPTABLES -t raw -N raw-${NIC}-udp-pre
$IPTABLES -t raw -A raw-${NIC}-pre -p udp -j raw-${NIC}-udp-pre

## ICMP
printInfo 'Process incoming ICMP traffic'
$IPTABLES -t raw -N raw-${NIC}-icmp-pre
$IPTABLES -t raw -A raw-${NIC}-pre -p icmp -j raw-${NIC}-icmp-pre

## ALL OTHERS
printInfo 'DROP all other incoming protocol traffic'
$IPTABLES -t raw -A raw-${NIC}-pre -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv4_input_drop --hashlimit-htable-size 256 --hashlimit-htable-max 192 \
	--hashlimit-htable-expire 900000 --hashlimit-htable-gcinterval 60000 \
	--hashlimit-upto 3/minute --hashlimit-burst 2 -j LOG --log-prefix '[IPv4 INPUT BLOCK] ' --log-level 7
$IPTABLES -t raw -A raw-${NIC}-pre -j DROP

echo

#
# *****************************
# * raw-${NIC}-icmp-pre Rules *
# *****************************
#

printInfo 'Large Size ICMP Packet Protection (> 576 bytes)'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -m length --length 577:0xffff -j ban_client

# BEGIN raw-${NIC}-echo Rules
$IPTABLES -t raw -N raw-${NIC}-echo
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type echo-request -j raw-${NIC}-echo

printInfo 'Ping of Death Protection (> 96 bytes)'
$IPTABLES -t raw -A raw-${NIC}-echo -m length --length 97:0xffff -j ban_client

printInfo 'Rate limit incoming ICMP echo-request packets'
$IPTABLES -t raw -A raw-${NIC}-echo -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv4_icmp_echo_rate_limit --hashlimit-htable-size 1024 --hashlimit-htable-max 768 \
	--hashlimit-htable-expire 60000 --hashlimit-htable-gcinterval 30000 \
	--hashlimit-upto 2/second --hashlimit-burst 1 -j do_not_track

$IPTABLES -t raw -A raw-${NIC}-echo -j icmp_drop
# END raw-${NIC}-echo Rules

printInfo 'Rate limit incoming ICMP packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -m limit --limit 120/min --limit-burst 40 -j icmp_drop

printInfo 'Allow ICMP destination-unreachable packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type destination-unreachable -j do_not_track

printInfo 'Allow ICMP parameter-problem packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type parameter-problem -j do_not_track

printInfo 'Allow ICMP echo-reply packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type echo-reply -j do_not_track

printInfo 'Allow ICMP time-exceeded packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type time-exceeded -j do_not_track

printInfo 'DROP all other incoming ICMP traffic'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -j icmp_drop

echo

#
# ****************************
# * raw-${NIC}-tcp-pre Rules *
# ****************************
#

printInfo 'Allow incoming HTTP/HTTPS TCP response packets'
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 443 -j ACCEPT
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 80 -j ACCEPT

# Create filter chains for each TCP flag
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## Established Connections
printInfo 'Process incoming TCP ACK packets'
$IPTABLES -t raw -N raw-${NIC}-ack
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST ACK -j raw-${NIC}-ack

## SYN
printInfo 'Process incoming TCP SYN packets'
$IPTABLES -t raw -N raw-${NIC}-syn
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST SYN -j raw-${NIC}-syn

## FIN
printInfo 'Process incoming TCP FIN packets'
$IPTABLES -t raw -N raw-${NIC}-fin
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST FIN -j raw-${NIC}-fin

$IPTABLES -t raw -N raw-${NIC}-fin-ack
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST FIN,ACK -j raw-${NIC}-fin-ack

## RST
printInfo 'Process incoming TCP RST packets'
$IPTABLES -t raw -N raw-${NIC}-rst
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST RST -j raw-${NIC}-rst

$IPTABLES -t raw -N raw-${NIC}-rst-ack
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST RST,ACK -j raw-${NIC}-rst-ack

printInfo 'Ban clients sending TCP packets with invalid flags'
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -j ban_client

echo

#
# ************************
# * raw-${NIC}-ack Rules *
# ************************
#

printInfo 'Allow incoming ACK response packets for valid services'
$IPTABLES -t raw -A raw-${NIC}-ack -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP packets from/to invalid services'
$IPTABLES -t raw -A raw-${NIC}-ack -j ban_client

echo

#
# ************************
# * raw-${NIC}-syn Rules *
# ************************
#

printInfo 'Ban clients sending TCP SYN packets with invalid MSS values'
$IPTABLES -t raw -A raw-${NIC}-syn -p tcp -m tcpmss ! --mss 536:65496 -j ban_client

printInfo 'Ban clients violating TCP SYN packet SSH rate limiting'
$IPTABLES -t raw -A raw-${NIC}-syn -p tcp -m tcp --dport 22 -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv4_ssh_rate_limit --hashlimit-htable-size 1024 --hashlimit-htable-max 768 \
	--hashlimit-htable-expire 7200000 --hashlimit-htable-gcinterval 60000 \
 	--hashlimit-above 27/hour --hashlimit-burst 9 -j ban_client

printInfo 'Allow incoming SYN request packets for valid services'
$IPTABLES -t raw -A raw-${NIC}-syn -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending SYN packets from/to invalid services'
$IPTABLES -t raw -A raw-${NIC}-syn -j ban_client

echo

#
# ************************
# * raw-${NIC}-fin Rules *
# ************************
#

printInfo 'Allow incoming TCP FIN packets for valid services'
$IPTABLES -t raw -A raw-${NIC}-fin -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP FIN packets for invalid services'
$IPTABLES -t raw -A raw-${NIC}-fin -j ban_client

#
# ****************************
# * raw-${NIC}-fin-ack Rules *
# ****************************
#

printInfo 'Allow incoming TCP FIN-ACK packets for valid services'
$IPTABLES -t raw -A raw-${NIC}-fin-ack -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP FIN-ACK packets for invalid services'
$IPTABLES -t raw -A raw-${NIC}-fin-ack -j ban_client

echo

#
# ************************
# * raw-${NIC}-rst Rules *
# ************************
#

printInfo 'Allow incoming TCP RST packets for valid services'
$IPTABLES -t raw -A raw-${NIC}-rst -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP RST packets for invalid services'
$IPTABLES -t raw -A raw-${NIC}-rst -j ban_client

#
# ****************************
# * raw-${NIC}-rst-ack Rules *
# ****************************
#

printInfo 'Allow incoming TCP RST-ACK packets for valid services'
$IPTABLES -t raw -A raw-${NIC}-rst-ack -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP RST-ACK packets for invalid services'
$IPTABLES -t raw -A raw-${NIC}-rst-ack -j ban_client

echo

#
# ****************************
# * raw-${NIC}-udp-pre Rules *
# ****************************
#

printInfo 'Allow incoming DNS UDP response packets'
$IPTABLES -t raw -A raw-${NIC}-udp-pre -p udp -m udp --sport 53 -j ACCEPT

printInfo 'Allow incoming NTP UDP response packets'
$IPTABLES -t raw -A raw-${NIC}-udp-pre -p udp -m udp --sport 123 -j ACCEPT

printInfo 'Ban clients sending UDP packets from/to invalid services'
$IPTABLES -t raw -A raw-${NIC}-udp-pre -j ban_client

echo

#
# ════════════════════════ Configure RAW OUTPUT Chain ═════════════════════════
#

printInfo 'DROP outgoing fragmented packets'
$IPTABLES -t raw -A OUTPUT -f -j fragment_drop

# Create OUTPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## lo
printInfo 'Allow outgoing lo interface traffic'
$IPTABLES -t raw -A OUTPUT -o lo -j do_not_track

## NIC
printInfo "Process outgoing $NIC interface traffic"
$IPTABLES -t raw -N raw-${NIC}-out
$IPTABLES -t raw -A OUTPUT -o ${NIC} -j raw-${NIC}-out

printInfo 'DROP all other outgoing interface traffic'
$IPTABLES -t raw -A OUTPUT -j nic_drop

echo

# Create OUTPUT filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## TCP
printInfo 'Process outgoing TCP traffic'
$IPTABLES -t raw -N raw-${NIC}-tcp-out
$IPTABLES -t raw -A raw-${NIC}-out -p tcp -j raw-${NIC}-tcp-out

## UDP
printInfo 'Process outgoing UDP traffic'
$IPTABLES -t raw -N raw-${NIC}-udp-out
$IPTABLES -t raw -A raw-${NIC}-out -p udp -j raw-${NIC}-udp-out

## ICMP
printInfo 'Allow outgoing ICMP traffic'
$IPTABLES -t raw -A raw-${NIC}-out -p icmp -j do_not_track

## ALL OTHERS
printInfo 'DROP all other outgoing protocol traffic'
$IPTABLES -t raw -A raw-${NIC}-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 OUTPUT BLOCK] ' --log-level 7
$IPTABLES -t raw -A raw-${NIC}-out -j DROP

echo

#
# ****************************
# * raw-${NIC}-tcp-out Rules *
# ****************************
#

printInfo 'Allow outgoing SSH TCP request/response packets'
$IPTABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --sport 22 -j ACCEPT
$IPTABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 22 -j ACCEPT

printInfo 'Allow outgoing HTTP/HTTPS TCP request packets'
$IPTABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 443 -j ACCEPT
$IPTABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 80 -j ACCEPT

printInfo 'DROP all other outgoing TCP traffic'
$IPTABLES -t raw -A raw-${NIC}-tcp-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 TCP BLOCK] ' --log-level 7
$IPTABLES -t raw -A raw-${NIC}-tcp-out -j DROP

echo

#
# ****************************
# * raw-${NIC}-udp-out Rules *
# ****************************
#

printInfo 'Allow outgoing DNS UDP request packets'
$IPTABLES -t raw -A raw-${NIC}-udp-out -p udp -m udp --dport 53 -j ACCEPT

printInfo 'Allow outgoing NTP UDP request packets'
$IPTABLES -t raw -A raw-${NIC}-udp-out -p udp -m udp --dport 123 -j ACCEPT

printInfo 'DROP all other outgoing UDP traffic'
$IPTABLES -t raw -A raw-${NIC}-udp-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 UDP BLOCK] ' --log-level 7
$IPTABLES -t raw -A raw-${NIC}-udp-out -j DROP

echo

################################ MANGLE Table #################################

printBanner 'Configuring MANGLE Table'

#
# ═════════════════════ Configure MANGLE PREROUTING Chain ═════════════════════
#

printInfo 'Allow incoming lo interface traffic'
$IPTABLES -t mangle -A PREROUTING -i lo -j ACCEPT

printInfo 'DROP all incoming INVALID packets'
$IPTABLES -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

#printInfo 'Allow up to three SSH connections per client'
#$IPTABLES -t mangle -A PREROUTING -p tcp --syn --dport 22 -m connlimit --connlimit-upto 3 -j ACCEPT

#
# ═══════════════════════ Configure MANGLE INPUT Chain ════════════════════════
#


#
# ══════════════════════ Configure MANGLE FORWARD Chain ═══════════════════════
#

printInfo 'Disable routing'
$IPTABLES -t mangle -P FORWARD DROP

#
# ═══════════════════════ Configure MANGLE OUTPUT Chain ═══════════════════════
#

printInfo 'Allow outgoing lo interface traffic'
$IPTABLES -t mangle -A OUTPUT -o lo -j ACCEPT

printInfo 'DROP all outgoing INVALID packets'
$IPTABLES -t mangle -A OUTPUT -m conntrack --ctstate INVALID -j DROP

#
# ════════════════════ Configure MANGLE POSTROUTING Chain ═════════════════════
#

echo

################################ FILTER Table #################################

printBanner 'Configuring FILTER Table'

#
# ═════════════════════ Custom FILTER Table Jump Targets ══════════════════════
#


#
# ═══════════════════════ Configure FILTER INPUT Chain ════════════════════════
#

printInfo 'Perform TCP INPUT traffic accounting'
$IPTABLES -A INPUT -i $NIC -p tcp ACCEPT

printInfo 'Perform UDP INPUT traffic accounting'
$IPTABLES -A INPUT -i $NIC -p udp ACCEPT

printInfo 'Perform ICMP INPUT traffic accounting'
$IPTABLES -A INPUT -i $NIC -p icmp ACCEPT

echo

#
# ══════════════════════ Configure FILTER FORWARD Chain ═══════════════════════
#

printInfo 'Set default FORWARD policy to DROP'
$IPTABLES -P FORWARD DROP

echo

#
# ═══════════════════════ Configure FILTER OUTPUT Chain ═══════════════════════
#

printInfo 'Perform TCP OUTPUT traffic accounting'
$IPTABLES -A OUTPUT -o $NIC -p tcp ACCEPT

printInfo 'Perform UDP OUTPUT traffic accounting'
$IPTABLES -A OUTPUT -o $NIC -p udp ACCEPT

printInfo 'Perform ICMP OUTPUT traffic accounting'
$IPTABLES -A OUTPUT -o $NIC -p icmp ACCEPT

echo

################################ IPTABLES-SAVE ################################

printInfo 'Persisting iptables Rules'

# Backup existing /etc/network/iptables.rules
if [ -f /etc/network/iptables.rules ]; then
	$EXEC_CP /etc/network/iptables.rules /etc/network/iptables.rules.bak
fi

# Save /etc/network/iptables.rules
$IPTABLES_SAVE > /etc/network/iptables.rules

echo

exit 0
