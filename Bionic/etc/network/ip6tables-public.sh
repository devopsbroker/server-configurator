#!/bin/bash

#
# ip6tables-public.sh - DevOpsBroker IPv6 iptables firewall script for public Internet servers
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
# sudo firewall -6 list
# sudo firewall -6 list FILTER INPUT
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
IP6TABLES=/sbin/ip6tables
IP6TABLES_SAVE=/sbin/ip6tables-save
IPSET=/sbin/ipset
EXEC_DERIVESUBNET=/usr/local/bin/derivesubnet

## Options
NIC="$1"

## IPv6 Address Scopes
IPv6_ADDRESS_GLOBAL=''
IPv6_ADDRESS_LOCAL=''
IPv6_GATEWAY=''
IPv6_SUBNET_GLOBAL=''

IPv6_SUBNET_LOCAL='fe80::/64'

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [ -z "$NIC" ]; then
	mapfile -t ethList < <($EXEC_IP -br -6 addr show | $EXEC_GREP -Eo '^enp[a-z0-9]+')

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

ethInfo=( $($EXEC_DERIVESUBNET -6 $NIC) )

IPv6_ADDRESS_GLOBAL=${ethInfo[0]}
IPv6_ADDRESS_LOCAL=${ethInfo[1]}
IPv6_GATEWAY=${ethInfo[2]}
IPv6_SUBNET_GLOBAL=${ethInfo[3]}

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE ip6tables Configurator" 'true'

echo "${bold}Network Interface:   ${green}$NIC"
echo "${white}IPv6 Global Address: ${green}$IPv6_ADDRESS_GLOBAL"
echo "${white}IPv6 Local Address:  ${green}$IPv6_ADDRESS_LOCAL"
echo "${white}IPv6 Gateway:        ${green}$IPv6_GATEWAY"
echo "${white}IPv6 Global Subnet:  ${green}$IPv6_SUBNET_GLOBAL"
echo "${white}IPv6 Local Subnet:   ${green}$IPv6_SUBNET_LOCAL"
echo "${reset}"

#
# Set default policies / Flush rules / Delete user-defined chains
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Initializing RAW Table'
$IP6TABLES -t raw -P OUTPUT ACCEPT
$IP6TABLES -t raw -F
$IP6TABLES -t raw -X
$IPSET -t raw -F
$IPSET -t raw -X

printInfo 'Initializing MANGLE Table'
$IP6TABLES -t mangle -P INPUT ACCEPT
$IP6TABLES -t mangle -P FORWARD ACCEPT
$IP6TABLES -t mangle -P OUTPUT ACCEPT
$IP6TABLES -t mangle -F
$IP6TABLES -t mangle -X

printInfo 'Initializing NAT Table'
$IP6TABLES -t nat -P OUTPUT ACCEPT
$IP6TABLES -t nat -F
$IP6TABLES -t nat -X

printInfo 'Initializing FILTER Table'
$IP6TABLES -t filter -P INPUT ACCEPT
$IP6TABLES -t filter -P FORWARD ACCEPT
$IP6TABLES -t filter -P OUTPUT ACCEPT
$IP6TABLES -t filter -F
$IP6TABLES -t filter -X

echo

################################## RAW Table ##################################

printBanner 'Configuring RAW Table'

#
# ═══════════════════════ Custom RAW Table Jump Targets ═══════════════════════
#

# Rate limit Ban Client logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N ban_client_drop
$IP6TABLES -t raw -A ban_client_drop -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv6_ban_client_drop --hashlimit-htable-size 4096 --hashlimit-htable-max 3072 \
	--hashlimit-htable-expire 3600000 --hashlimit-htable-gcinterval 60000 \
	--hashlimit-upto 3/minute --hashlimit-burst 2 -j LOG --log-prefix '[IPv6 BAN BLOCK] ' --log-level 7
$IP6TABLES -t raw -A ban_client_drop -j DROP

# Rate limit Fragment logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N fragment_drop
$IP6TABLES -t raw -A fragment_drop -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv6_fragment_drop --hashlimit-htable-size 256 --hashlimit-htable-max 192 \
	--hashlimit-htable-expire 900000 --hashlimit-htable-gcinterval 60000 \
	--hashlimit-upto 3/minute --hashlimit-burst 2 -j LOG --log-prefix '[IPv6 FRAG BLOCK] ' --log-level 7
$IP6TABLES -t raw -A fragment_drop -j DROP

# Rate limit ICMP BLOCK logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N icmp_drop
$IP6TABLES -t raw -A icmp_drop -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv6_icmp_drop --hashlimit-htable-size 256 --hashlimit-htable-max 192 \
	--hashlimit-htable-expire 900000 --hashlimit-htable-gcinterval 60000 \
	--hashlimit-upto 3/minute --hashlimit-burst 2 -j LOG --log-prefix '[IPv6 ICMP BLOCK] ' --log-level 7
$IP6TABLES -t raw -A icmp_drop -j DROP

# Rate limit Network Interface logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N nic_drop
$IP6TABLES -t raw -A nic_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 NIC BLOCK] ' --log-level 7
$IP6TABLES -t raw -A nic_drop -j DROP

# Perform NOTRACK and ACCEPT
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N do_not_track
$IP6TABLES -t raw -A do_not_track -j NOTRACK
$IP6TABLES -t raw -A do_not_track -j ACCEPT

# Ban Client / Rate limit logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N ban_client
$IP6TABLES -t raw -A ban_client -j SET --add-set banned_clients src
$IP6TABLES -t raw -A ban_client -j ban_client_drop

# Banned Clients IP Hashset (IPv6 host addresses)
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPSET -t raw -N banned_clients hash:ip family inet6 hashsize 4096 maxelem 3072 timeout 3600

# Snooped Ports Bitmap
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPSET -t raw -N snooped_ports bitmap:port range 1-10240
$IPSET -t raw -A snooped_ports 20           # Passive FTP
$IPSET -t raw -A snooped_ports 21           # FTP
$IPSET -t raw -A snooped_ports 23           # Telnet
$IPSET -t raw -A snooped_ports 25           # SMTP
$IPSET -t raw -A snooped_ports 53           # DNS
$IPSET -t raw -A snooped_ports 67           # DHCP Server
$IPSET -t raw -A snooped_ports 68           # DHCP Client
$IPSET -t raw -A snooped_ports 69           # TFTP
$IPSET -t raw -A snooped_ports 80           # HTTP
$IPSET -t raw -A snooped_ports 107          # Remote Telnet
$IPSET -t raw -A snooped_ports 109          # POP2
$IPSET -t raw -A snooped_ports 110          # POP3
$IPSET -t raw -A snooped_ports 111          # RPC
$IPSET -t raw -A snooped_ports 113          # IDENT
$IPSET -t raw -A snooped_ports 115          # SFTP
$IPSET -t raw -A snooped_ports 135          # Microsoft RPC
$IPSET -t raw -A snooped_ports 137          # NetBIOS Name Service
$IPSET -t raw -A snooped_ports 138          # NetBIOS Datagram Service
$IPSET -t raw -A snooped_ports 139          # NetBIOS Session Service
$IPSET -t raw -A snooped_ports 143          # IMAP
$IPSET -t raw -A snooped_ports 161          # SNMP
$IPSET -t raw -A snooped_ports 162          # SNMP Traps
$IPSET -t raw -A snooped_ports 177          # XDMCP
$IPSET -t raw -A snooped_ports 194          # IRC
$IPSET -t raw -A snooped_ports 199          # SNMP Multiplexer
$IPSET -t raw -A snooped_ports 220          # IMAP3
$IPSET -t raw -A snooped_ports 371          # ClearCase
$IPSET -t raw -A snooped_ports 389          # LDAP
$IPSET -t raw -A snooped_ports 443          # HTTPS
$IPSET -t raw -A snooped_ports 445          # SMB
$IPSET -t raw -A snooped_ports 465          # SSL/TLS SMTP
$IPSET -t raw -A snooped_ports 500          # IPsec IKE
$IPSET -t raw -A snooped_ports 513          # Rlogin
$IPSET -t raw -A snooped_ports 514          # RSH / RCP
$IPSET -t raw -A snooped_ports 530          # RPC
$IPSET -t raw -A snooped_ports 546          # DHCPV6 Client
$IPSET -t raw -A snooped_ports 547          # DHCPV6 Server
$IPSET -t raw -A snooped_ports 631          # IPP
$IPSET -t raw -A snooped_ports 636          # SSL/TLS LDAP
$IPSET -t raw -A snooped_ports 873          # rsync
$IPSET -t raw -A snooped_ports 989          # SSL/TLS FTP (Data)
$IPSET -t raw -A snooped_ports 990          # SSL/TLS FTP
$IPSET -t raw -A snooped_ports 992          # SSL/TLS Telnet
$IPSET -t raw -A snooped_ports 993          # SSL/TLS IMAP
$IPSET -t raw -A snooped_ports 994          # SSL/TLS IRC
$IPSET -t raw -A snooped_ports 995          # SSL/TLS POP3
$IPSET -t raw -A snooped_ports 1024-1030    # Microsoft Windows Crap
$IPSET -t raw -A snooped_ports 1099         # Java RMI Registry
$IPSET -t raw -A snooped_ports 1194         # OpenVPN
$IPSET -t raw -A snooped_ports 1352         # Lotus Note
$IPSET -t raw -A snooped_ports 1433         # Microsoft SQL Server
$IPSET -t raw -A snooped_ports 1434         # Microsoft SQL Monitor
$IPSET -t raw -A snooped_ports 1863         # MSN Messenger
$IPSET -t raw -A snooped_ports 2000         # Cisco SCCP
$IPSET -t raw -A snooped_ports 2049         # NFS
$IPSET -t raw -A snooped_ports 2401         # CVS
$IPSET -t raw -A snooped_ports 3130         # ICP
$IPSET -t raw -A snooped_ports 3289         # ENPC
$IPSET -t raw -A snooped_ports 3306         # MySQL
$IPSET -t raw -A snooped_ports 3690         # SVN
$IPSET -t raw -A snooped_ports 4500         # IPsec NAT Traversal
$IPSET -t raw -A snooped_ports 4827         # HTCP
$IPSET -t raw -A snooped_ports 5050         # Yahoo! Messenger
$IPSET -t raw -A snooped_ports 5190         # AIM
$IPSET -t raw -A snooped_ports 5222         # Jabber Client
$IPSET -t raw -A snooped_ports 5269         # Jabber Server
$IPSET -t raw -A snooped_ports 5353         # mDNS
$IPSET -t raw -A snooped_ports 5432         # PostgreSQL
$IPSET -t raw -A snooped_ports 6000-6007    # X11
$IPSET -t raw -A snooped_ports 6446         # MySQL Proxy
$IPSET -t raw -A snooped_ports 8080         # Tomcat
$IPSET -t raw -A snooped_ports 8610         # Canon MFNP
$IPSET -t raw -A snooped_ports 8612         # Canon MFNP
$IPSET -t raw -A snooped_ports 9418         # Git

# Service Ports Bitmap
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPSET -t raw -N tcp_service_ports bitmap:port range 1-10240
$IPSET -t raw -A tcp_service_ports 22       # SSH

#
# ══════════════════════ Configure RAW PREROUTING Chain ═══════════════════════
#

printInfo 'DROP incoming fragmented packets'
$IP6TABLES -t raw -A PREROUTING -m frag --fragmore -j fragment_drop

# Create PREROUTING filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## lo
printInfo 'Allow incoming lo interface traffic'
$IP6TABLES -t raw -A PREROUTING -i lo -j do_not_track

## NIC
printInfo "Process incoming $NIC interface traffic"
$IP6TABLES -t raw -N raw-${NIC}-pre
$IP6TABLES -t raw -A PREROUTING -i ${NIC} -j raw-${NIC}-pre

printInfo 'DROP all other incoming interface traffic'
$IP6TABLES -t raw -A PREROUTING -j nic_drop

echo

# Create PREROUTING filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo 'DROP incoming packets from banned clients'
$IP6TABLES -t raw -A raw-${NIC}-pre -m set --set banned_clients src -j ban_client_drop

printInfo 'Ban clients snooping for open ports'
$IP6TABLES -t raw -A raw-${NIC}-pre -m set --set snooped_ports dst -j ban_client

# TODO: Block the External IP as a source if you have a static IP from your ISP

## TCP
printInfo 'Process incoming TCP traffic'
$IP6TABLES -t raw -N raw-${NIC}-tcp-pre
$IP6TABLES -t raw -A raw-${NIC}-pre -p tcp -j raw-${NIC}-tcp-pre

## UDP
printInfo 'Process incoming UDP traffic'
$IP6TABLES -t raw -N raw-${NIC}-udp-pre
$IP6TABLES -t raw -A raw-${NIC}-pre -p udp -j raw-${NIC}-udp-pre

## ICMPv6
printInfo 'Process incoming ICMPv6 traffic'
$IP6TABLES -t raw -N raw-${NIC}-icmpv6-pre
$IP6TABLES -t raw -A raw-${NIC}-pre -p icmpv6 -j raw-${NIC}-icmpv6-pre

## ALL OTHERS
printInfo 'DROP all other incoming protocol traffic'
$IP6TABLES -t raw -A raw-${NIC}-pre -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv6_input_drop --hashlimit-htable-size 256 --hashlimit-htable-max 192 \
	--hashlimit-htable-expire 900000 --hashlimit-htable-gcinterval 60000 \
	--hashlimit-upto 3/minute --hashlimit-burst 2 -j LOG --log-prefix '[IPv6 INPUT BLOCK] ' --log-level 7
$IP6TABLES -t raw -A raw-${NIC}-pre -j DROP

echo

#
# *******************************
# * raw-${NIC}-icmpv6-pre Rules *
# *******************************
#

printInfo 'Large Size ICMP Packet Protection (> 576 bytes)'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -m length --length 577:0xffff -j ban_client

# BEGIN raw-${NIC}-echo Rules
$IP6TABLES -t raw -N raw-${NIC}-echo
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type echo-request -j raw-${NIC}-echo

printInfo 'Ping of Death Protection (> 96 bytes)'
$IP6TABLES -t raw -A raw-${NIC}-echo -m length --length 97:0xffff -j ban_client

printInfo 'Rate limit incoming ICMPv6 echo-request packets'
$IP6TABLES -t raw -A raw-${NIC}-echo -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv6_icmp_echo_rate_limit --hashlimit-htable-size 1024 --hashlimit-htable-max 768 \
	--hashlimit-htable-expire 60000 --hashlimit-htable-gcinterval 30000 \
	--hashlimit-upto 2/second --hashlimit-burst 1 -j do_not_track

$IP6TABLES -t raw -A raw-${NIC}-echo -j icmp_drop
# END raw-${NIC}-echo Rules

printInfo 'Rate limit incoming ICMPv6 packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -m limit --limit 120/min --limit-burst 40 -j icmp_drop

printInfo 'Allow ICMPv6 destination-unreachable packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type destination-unreachable -j do_not_track

printInfo 'Allow ICMPv6 packet-too-big packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type packet-too-big -j do_not_track

printInfo 'Allow ICMPv6 parameter-problem packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type parameter-problem -j do_not_track

printInfo 'Allow ICMPv6 echo-reply packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type echo-reply -j do_not_track

printInfo 'Allow ICMPv6 time-exceeded packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type time-exceeded -j do_not_track

printInfo 'DROP all other incoming ICMPv6 traffic'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -j icmp_drop

echo

#
# ****************************
# * raw-${NIC}-tcp-pre Rules *
# ****************************
#

printInfo 'Allow incoming HTTP/HTTPS TCP response packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 443 -j ACCEPT
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 80 -j ACCEPT

# Create filter chains for each TCP flag
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## Established Connections
printInfo 'Process incoming TCP ACK packets'
$IP6TABLES -t raw -N raw-${NIC}-ack
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST ACK -j raw-${NIC}-ack

## SYN
printInfo 'Process incoming TCP SYN packets'
$IP6TABLES -t raw -N raw-${NIC}-syn
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST SYN -j raw-${NIC}-syn

## FIN
printInfo 'Process incoming TCP FIN packets'
$IP6TABLES -t raw -N raw-${NIC}-fin
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST FIN -j raw-${NIC}-fin

$IP6TABLES -t raw -N raw-${NIC}-fin-ack
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST FIN,ACK -j raw-${NIC}-fin-ack

## RST
printInfo 'Process incoming TCP RST packets'
$IP6TABLES -t raw -N raw-${NIC}-rst
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST RST -j raw-${NIC}-rst

$IP6TABLES -t raw -N raw-${NIC}-rst-ack
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST RST,ACK -j raw-${NIC}-rst-ack

printInfo 'Ban clients sending TCP packets with invalid flags'
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -j ban_client

echo

#
# ************************
# * raw-${NIC}-ack Rules *
# ************************
#

printInfo 'Allow incoming ACK response packets for valid services'
$IP6TABLES -t raw -A raw-${NIC}-ack -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP packets from/to invalid services'
$IP6TABLES -t raw -A raw-${NIC}-ack -j ban_client

echo

#
# ************************
# * raw-${NIC}-syn Rules *
# ************************
#

printInfo 'Ban clients sending TCP SYN packets with invalid MSS values'
$IP6TABLES -t raw -A raw-${NIC}-syn -p tcp -m tcpmss ! --mss 536:65496 -j ban_client

printInfo 'Ban clients violating TCP SYN packet SSH rate limiting'
$IP6TABLES -t raw -A raw-${NIC}-syn -p tcp -m tcp --dport 22 -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name ipv6_ssh_rate_limit --hashlimit-htable-size 1024 --hashlimit-htable-max 768 \
	--hashlimit-htable-expire 7200000 --hashlimit-htable-gcinterval 60000 \
 	--hashlimit-above 27/hour --hashlimit-burst 9 -j ban_client

printInfo 'Allow incoming SYN request packets for valid services'
$IP6TABLES -t raw -A raw-${NIC}-syn -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending SYN packets from/to invalid services'
$IP6TABLES -t raw -A raw-${NIC}-syn -j ban_client

echo

#
# ************************
# * raw-${NIC}-fin Rules *
# ************************
#

printInfo 'Allow incoming TCP FIN packets for valid services'
$IP6TABLES -t raw -A raw-${NIC}-fin -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP FIN packets for invalid services'
$IP6TABLES -t raw -A raw-${NIC}-fin -j ban_client

#
# ****************************
# * raw-${NIC}-fin-ack Rules *
# ****************************
#

printInfo 'Allow incoming TCP FIN-ACK packets for valid services'
$IP6TABLES -t raw -A raw-${NIC}-fin-ack -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP FIN-ACK packets for invalid services'
$IP6TABLES -t raw -A raw-${NIC}-fin-ack -j ban_client

echo

#
# ************************
# * raw-${NIC}-rst Rules *
# ************************
#

printInfo 'Allow incoming TCP RST packets for valid services'
$IP6TABLES -t raw -A raw-${NIC}-rst -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP RST packets for invalid services'
$IP6TABLES -t raw -A raw-${NIC}-rst -j ban_client

#
# ****************************
# * raw-${NIC}-rst-ack Rules *
# ****************************
#

printInfo 'Allow incoming TCP RST-ACK packets for valid services'
$IP6TABLES -t raw -A raw-${NIC}-rst-ack -m set --set tcp_service_ports dst -j ACCEPT

printInfo 'Ban clients sending TCP RST-ACK packets for invalid services'
$IP6TABLES -t raw -A raw-${NIC}-rst-ack -j ban_client

echo

#
# ****************************
# * raw-${NIC}-udp-pre Rules *
# ****************************
#

printInfo 'Allow incoming DNS UDP response packets'
$IP6TABLES -t raw -A raw-${NIC}-udp-pre -p udp -m udp --sport 53 -j ACCEPT

printInfo 'Allow incoming NTP UDP response packets'
$IP6TABLES -t raw -A raw-${NIC}-udp-pre -p udp -m udp --sport 123 -j ACCEPT

printInfo 'Ban clients sending UDP packets from/to invalid services'
$IP6TABLES -t raw -A raw-${NIC}-udp-pre -j ban_client

echo

#
# ════════════════════════ Configure RAW OUTPUT Chain ═════════════════════════
#

printInfo 'DROP outgoing fragmented packets'
$IP6TABLES -t raw -A OUTPUT -m frag --fragmore -j fragment_drop

# Create OUTPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## lo
printInfo 'Allow outgoing lo interface traffic'
$IP6TABLES -t raw -A OUTPUT -o lo -j do_not_track

## NIC
printInfo "Process outgoing $NIC interface traffic"
$IP6TABLES -t raw -N raw-${NIC}-out
$IP6TABLES -t raw -A OUTPUT -o ${NIC} -j raw-${NIC}-out

printInfo 'DROP all other outgoing interface traffic'
$IP6TABLES -t raw -A OUTPUT -j nic_drop

echo

# Create OUTPUT filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## TCP
printInfo 'Process outgoing TCP traffic'
$IP6TABLES -t raw -N raw-${NIC}-tcp-out
$IP6TABLES -t raw -A raw-${NIC}-out -p tcp -j raw-${NIC}-tcp-out

## UDP
printInfo 'Process outgoing UDP traffic'
$IP6TABLES -t raw -N raw-${NIC}-udp-out
$IP6TABLES -t raw -A raw-${NIC}-out -p udp -j raw-${NIC}-udp-out

## ICMPv6
printInfo 'Allow outgoing ICMPv6 traffic'
$IP6TABLES -t raw -A raw-${NIC}-out -p icmpv6 -j do_not_track

## ALL OTHERS
printInfo 'DROP all other outgoing protocol traffic'
$IP6TABLES -t raw -A raw-${NIC}-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 OUTPUT BLOCK] ' --log-level 7
$IP6TABLES -t raw -A raw-${NIC}-out -j DROP

echo

#
# ****************************
# * raw-${NIC}-tcp-out Rules *
# ****************************
#

printInfo 'Allow outgoing SSH TCP request/response packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --sport 22 -j ACCEPT
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 22 -j ACCEPT

printInfo 'Allow outgoing HTTP/HTTPS TCP request packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 443 -j ACCEPT
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 80 -j ACCEPT

printInfo 'DROP all other outgoing TCP traffic'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 TCP BLOCK] ' --log-level 7
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -j DROP

echo

#
# ****************************
# * raw-${NIC}-udp-out Rules *
# ****************************
#

printInfo 'Allow outgoing DNS UDP request packets'
$IP6TABLES -t raw -A raw-${NIC}-udp-out -p udp -m udp --dport 53 -j ACCEPT

printInfo 'Allow outgoing NTP UDP request packets'
$IP6TABLES -t raw -A raw-${NIC}-udp-out -p udp -m udp --dport 123 -j ACCEPT

printInfo 'DROP all other outgoing UDP traffic'
$IP6TABLES -t raw -A raw-${NIC}-udp-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 UDP BLOCK] ' --log-level 7
$IP6TABLES -t raw -A raw-${NIC}-udp-out -j DROP

echo

################################ MANGLE Table #################################

printBanner 'Configuring MANGLE Table'

#
# ═════════════════════ Configure MANGLE PREROUTING Chain ═════════════════════
#

printInfo 'Allow incoming lo interface traffic'
$IP6TABLES -t mangle -A PREROUTING -i lo -j ACCEPT

printInfo 'DROP all incoming INVALID packets'
$IP6TABLES -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

#printInfo 'Allow up to three SSH connections per client'
#$IP6TABLES -t mangle -A PREROUTING -p tcp --syn --dport 22 -m connlimit --connlimit-upto 3 -j ACCEPT

#
# ═══════════════════════ Configure MANGLE INPUT Chain ════════════════════════
#


#
# ══════════════════════ Configure MANGLE FORWARD Chain ═══════════════════════
#

printInfo 'Disable routing'
$IP6TABLES -t mangle -P FORWARD DROP

#
# ═══════════════════════ Configure MANGLE OUTPUT Chain ═══════════════════════
#

printInfo 'Allow outgoing lo interface traffic'
$IP6TABLES -t mangle -A OUTPUT -o lo -j ACCEPT

printInfo 'DROP all outgoing INVALID packets'
$IP6TABLES -t mangle -A OUTPUT -m conntrack --ctstate INVALID -j DROP

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
$IP6TABLES -A INPUT -i $NIC -p tcp ACCEPT

printInfo 'Perform UDP INPUT traffic accounting'
$IP6TABLES -A INPUT -i $NIC -p udp ACCEPT

printInfo 'Perform ICMP INPUT traffic accounting'
$IP6TABLES -A INPUT -i $NIC -p icmpv6 ACCEPT

echo

#
# ══════════════════════ Configure FILTER FORWARD Chain ═══════════════════════
#

printInfo 'Set default FORWARD policy to DROP'
$IP6TABLES -P FORWARD DROP

echo

#
# ═══════════════════════ Configure FILTER OUTPUT Chain ═══════════════════════
#

printInfo 'Perform TCP OUTPUT traffic accounting'
$IP6TABLES -A OUTPUT -o $NIC -p tcp ACCEPT

printInfo 'Perform UDP OUTPUT traffic accounting'
$IP6TABLES -A OUTPUT -o $NIC -p udp ACCEPT

printInfo 'Perform ICMP OUTPUT traffic accounting'
$IP6TABLES -A OUTPUT -o $NIC -p icmpv6 ACCEPT

echo

################################ IPTABLES-SAVE ################################

printInfo 'Persisting ip6tables Rules'

# Backup existing /etc/network/ip6tables.rules
if [ -f /etc/network/ip6tables.rules ]; then
	$EXEC_CP /etc/network/ip6tables.rules /etc/network/ip6tables.rules.bak
fi

# Save /etc/network/ip6tables.rules
$IP6TABLES_SAVE > /etc/network/ip6tables.rules

echo

exit 0
