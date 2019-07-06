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

# Load /etc/devops/functions-net.conf if FUNC_NET_CONFIG is unset
if [ -z "$FUNC_NET_CONFIG" ] && [ -f /etc/devops/functions-net.conf ]; then
	source /etc/devops/functions-net.conf
fi

${FUNC_NET_CONFIG?"[1;91mCannot load '/etc/devops/functions-net.conf': No such file[0m"}

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
EXEC_DERIVESUBNET=/usr/local/bin/derivesubnet

## Options
NIC="${1:-}"

## IPv6 Address Scopes
IPv6_ADDRESS_GLOBAL=''
IPv6_ADDRESS_LOCAL=''
IPv6_GATEWAY=''
IPv6_SUBNET_GLOBAL=''

IPv6_SUBNET_LOCAL='fe80::/64'

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [ -z "$NIC" ]; then

	# Get default NIC if not present on command-line
	NIC="$(getDefaultNIC)"

else
	# Display error if network interface parameter is invalid
	if [ ! -L /sys/class/net/$NIC ]; then
		printError "$SCRIPT_EXEC" "Cannot access '$NIC': No such network interface"
		echo
		printUsage "$SCRIPT_EXEC ${gold}[NIC]"

		exit 1
	fi
fi

# Make sure server has IPv6 networking configured before continuing
set +o errexit

ethInfo=( $($EXEC_DERIVESUBNET -6 $NIC) )

if [ $? -ne 0 ]; then
	printNotice $SCRIPT_EXEC "This server does not have IPv6 networking enabled"
	exit 0
fi

set -o errexit

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
$IP6TABLES -t raw -A ban_client -j SET --add-set banned_clients_ipv6 src
$IP6TABLES -t raw -A ban_client -j ban_client_drop

#
# ══════════════════════ Configure RAW PREROUTING Chain ═══════════════════════
#

printInfo 'DROP incoming fragmented packets'
$IP6TABLES -t raw -A PREROUTING -m frag --fragmore -j fragment_drop

# Create PREROUTING filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## NIC
printInfo "Process incoming $NIC interface traffic"
$IP6TABLES -t raw -N raw-${NIC}-pre
$IP6TABLES -t raw -A PREROUTING -i ${NIC} -j raw-${NIC}-pre

## lo
printInfo 'Allow incoming lo interface traffic'
$IP6TABLES -t raw -A PREROUTING -i lo -j do_not_track

printInfo 'DROP all other incoming interface traffic'
$IP6TABLES -t raw -A PREROUTING -j nic_drop

echo

# Create PREROUTING filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo 'DROP incoming packets from banned clients'
$IP6TABLES -t raw -A raw-${NIC}-pre -m set --match-set banned_clients_ipv6 src -j ban_client_drop

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

## TCP Ports
printInfo 'Process incoming TCP traffic for allowed ports'
$IP6TABLES -t raw -N raw-${NIC}-tcp-port-in
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -j raw-${NIC}-tcp-port-in

## TCP Flags
printInfo 'Process incoming TCP traffic for valid TCP flags'
$IP6TABLES -t raw -N raw-${NIC}-tcp-flag
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -j raw-${NIC}-tcp-flag

## ACCEPT incoming TCP traffic
printInfo 'ACCEPT incoming TCP traffic'
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -j ACCEPT

echo

#
# ********************************
# * raw-${NIC}-tcp-port-in Rules *
# ********************************
#

printInfo 'Allow incoming TCP traffic for permitted service ports'
$IP6TABLES -t raw -A raw-${NIC}-tcp-port-in -m set --match-set tcp_service_ports dst -j RETURN

printInfo 'Allow incoming TCP traffic for permitted client ports'
$IP6TABLES -t raw -A raw-${NIC}-tcp-port-in -m set --match-set tcp_client_ports src -j RETURN

printInfo 'Ban clients sending TCP packets to invalid ports'
$IP6TABLES -t raw -A raw-${NIC}-tcp-port-in -j ban_client

echo

#
# *****************************
# * raw-${NIC}-tcp-flag Rules *
# *****************************
#

## Established Connections
printInfo 'Accept incoming TCP ACK packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-flag -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST ACK -j RETURN

## SYN
printInfo 'Accept incoming TCP SYN packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-flag -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST SYN -j RETURN

## FIN
printInfo 'Accept incoming TCP FIN packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-flag -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST FIN -j RETURN
$IP6TABLES -t raw -A raw-${NIC}-tcp-flag -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST FIN,ACK -j RETURN

## RST
printInfo 'Accept incoming TCP RST packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-flag -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST RST -j RETURN
$IP6TABLES -t raw -A raw-${NIC}-tcp-flag -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST RST,ACK -j RETURN

printInfo 'Ban clients sending TCP packets with invalid flags'
$IP6TABLES -t raw -A raw-${NIC}-tcp-flag -j ban_client

echo

#
# ****************************
# * raw-${NIC}-udp-pre Rules *
# ****************************
#

## UDP Ports
printInfo 'Allow incoming UDP traffic for permitted service ports'
$IP6TABLES -t raw -A raw-${NIC}-udp-pre -m set --match-set udp_service_ports dst -j ACCEPT

printInfo 'Allow incoming UDP traffic for permitted client ports'
$IP6TABLES -t raw -A raw-${NIC}-udp-pre -m set --match-set udp_client_ports src -j ACCEPT

printInfo 'Ban clients sending all other incoming UDP traffic'
$IP6TABLES -t raw -A raw-${NIC}-udp-pre -j ban_client

echo

#
# ════════════════════════ Configure RAW OUTPUT Chain ═════════════════════════
#

printInfo 'DROP outgoing fragmented packets'
$IP6TABLES -t raw -A OUTPUT -m frag --fragmore -j fragment_drop

# Create OUTPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## NIC
printInfo "Process outgoing $NIC interface traffic"
$IP6TABLES -t raw -N raw-${NIC}-out
$IP6TABLES -t raw -A OUTPUT -o ${NIC} -j raw-${NIC}-out

## lo
printInfo 'Allow outgoing lo interface traffic'
$IP6TABLES -t raw -A OUTPUT -o lo -j do_not_track

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

## TCP Ports
printInfo 'Allow outgoing TCP traffic for permitted service ports'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -m set --match-set tcp_service_ports src -j ACCEPT

printInfo 'Allow outgoing TCP traffic for permitted client ports'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -m set --match-set tcp_client_ports dst -j ACCEPT

printInfo 'DROP all other outgoing TCP traffic'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 TCP BLOCK] ' --log-level 7
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -j DROP

echo

#
# ****************************
# * raw-${NIC}-udp-out Rules *
# ****************************
#

## UDP Ports
printInfo 'Allow outgoing UDP traffic for permitted service ports'
$IP6TABLES -t raw -A raw-${NIC}-udp-out -m set --match-set udp_service_ports src -j ACCEPT

printInfo 'Allow outgoing UDP traffic for permitted client ports'
$IP6TABLES -t raw -A raw-${NIC}-udp-out -m set --match-set udp_client_ports dst -j ACCEPT

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

# Create INPUT filter chain for sshguard
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo "Creating incoming filter chain for sshguard"
$IP6TABLES -N sshguard

echo

# Create INPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## NIC
printInfo "Process incoming $NIC interface traffic"
$IP6TABLES -N filter-${NIC}-in
$IP6TABLES -A INPUT -i ${NIC} -j filter-${NIC}-in

## lo
printInfo 'ACCEPT incoming lo interface traffic'
$IP6TABLES -A INPUT -i lo -j ACCEPT

echo

# Create INPUT filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## TCP
printInfo 'Process incoming TCP traffic'
$IP6TABLES -N filter-${NIC}-tcp-in
$IP6TABLES -A filter-${NIC}-in -p tcp -j filter-${NIC}-tcp-in

## UDP
printInfo 'Perform UDP INPUT traffic accounting'
$IP6TABLES -A filter-${NIC}-in -p udp -j ACCEPT

## ICMP
printInfo 'Perform ICMP INPUT traffic accounting'
$IP6TABLES -A filter-${NIC}-in -p icmp -j ACCEPT

echo

#
# ******************************
# * filter-${NIC}-tcp-in Rules *
# ******************************
#

printInfo 'Refer to sshguard for incoming SSH TCP request packets'
$IP6TABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --dport 22 -j sshguard

printInfo 'Perform TCP INPUT traffic accounting'
$IP6TABLES -A filter-${NIC}-tcp-in -j ACCEPT

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

# Create OUTPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## NIC
printInfo "Process outgoing $NIC interface traffic"
$IP6TABLES -N filter-${NIC}-out
$IP6TABLES -A OUTPUT -o ${NIC} -j filter-${NIC}-out

## lo
printInfo 'ACCEPT outgoing lo interface traffic'
$IP6TABLES -A OUTPUT -o lo -j ACCEPT

echo

#
# ***************************
# * filter-${NIC}-out Rules *
# ***************************
#

printInfo 'Perform TCP OUTPUT traffic accounting'
$IP6TABLES -A filter-${NIC}-out -p tcp -j ACCEPT

printInfo 'Perform UDP OUTPUT traffic accounting'
$IP6TABLES -A filter-${NIC}-out -p udp -j ACCEPT

printInfo 'Perform ICMP OUTPUT traffic accounting'
$IP6TABLES -A filter-${NIC}-out -p icmp -j ACCEPT

echo

############################### IP6TABLES-SAVE ################################

printInfo 'Persisting ip6tables Rules'

# Backup existing /etc/network/ip6tables.rules
if [ -f /etc/network/ip6tables.rules ]; then
	$EXEC_CP /etc/network/ip6tables.rules /etc/network/ip6tables.rules.bak
fi

# Save /etc/network/ip6tables.rules
$IP6TABLES_SAVE > /etc/network/ip6tables.rules

echo

exit 0
