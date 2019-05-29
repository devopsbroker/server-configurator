#!/bin/bash

#
# ip6tables-private.sh - DevOpsBroker IPv6 ip6tables firewall script for private Intranet servers
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
#   o All ICMPv6 filtering is done in the RAW table
#   o Valid ICMPv6 and UDP traffic is set to NOTRACK
#   o All traffic on lo is set to NOTRACK
#   o Drop incoming/outgoing Canon/Epson printer discovery packets
#   o Drop all incoming/outgoing INVALID packets
#   o Disable FORWARD
#   o Protocol-specific FILTER chains for TCP/UDP/ICMPv6
#
# References:
#   o man iptables
#   o man iptables-extensions
#
# Notes:
#   o REJECT rules are not allowed in the RAW table
#   o NOTRACK targets do not stop processing in the RAW table
#   o The global scope IPv6 address is equivalent to a **PUBLIC** IPv4 address
#     and must be treated as such
#
# Useful Linux Command-Line Utilities
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# o List rules currently configured:
# sudo firewall -6 list
# sudo firewall -6 list FILTER INPUT
#
# TODO: https://www.snort.org/ - filter packets for "alerts" or concerning traffic
# TODO: http://manpages.ubuntu.com/manpages/bionic/man8/mtr.8.html
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
EXEC_DERIVESUBNET=/usr/local/bin/derivesubnet

## Options
NIC=${1:-}

## IPv6 Address Scopes
IPv6_ADDRESS_GLOBAL=''
IPv6_ADDRESS_LOCAL=''
IPv6_GATEWAY=''
IPv6_SUBNET_GLOBAL=''

IPv6_SUBNET_LOCAL='fe80::/64'
ALL_NODES_LOCAL='ff02::1'
ALL_ROUTERS_ADDR='ff02::2'
MLDv2_ADDR='ff02::16'
mDNSv6_ADDR='ff02::fb'
SOLICITED_NODE_ADDR='ff02::1:ff00:0/104'

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [ -z "$NIC" ]; then
	mapfile -t ethList < <($EXEC_IP -br -6 addr show | $EXEC_GREP -Eo '^(enp|ens)[a-z0-9]+')

	if [ ${#ethList[@]} -eq 1 ]; then
		ethInterface=(${ethList[0]})
	else
		COLUMNS=1
		echo "${bold}${yellow}Which Ethernet interface do you want to configure?${white}"
		select ethInterface in ${ethList[@]}; do
			break;
		done
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

set +o errexit

ethInfo=( $($EXEC_DERIVESUBNET -6 $NIC) )

if [ $? -ne 0 ]; then
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

# Rate limit Fragment logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N ipv6_fragment_drop
$IP6TABLES -t raw -A ipv6_fragment_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 FRAG BLOCK] ' --log-level 7
$IP6TABLES -t raw -A ipv6_fragment_drop -j DROP

# Rate limit Network Interface logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N ipv6_nic_drop
$IP6TABLES -t raw -A ipv6_nic_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 NIC BLOCK] ' --log-level 7
$IP6TABLES -t raw -A ipv6_nic_drop -j DROP

# Rate limit Canon/Epson logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N ipv6_canon_drop
$IP6TABLES -t raw -A ipv6_canon_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 CANON BLOCK] ' --log-level 7
$IP6TABLES -t raw -A ipv6_canon_drop -j DROP

# Rate limit TCP logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N tcp_drop
$IP6TABLES -t raw -A tcp_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 TCP BLOCK] ' --log-level 7
$IP6TABLES -t raw -A tcp_drop -j DROP

# Perform NOTRACK and ACCEPT
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -t raw -N do_not_track
$IP6TABLES -t raw -A do_not_track -j NOTRACK
$IP6TABLES -t raw -A do_not_track -j ACCEPT

#
# ══════════════════════ Configure RAW PREROUTING Chain ═══════════════════════
#

printInfo 'DROP incoming fragmented packets'
$IP6TABLES -t raw -A PREROUTING -m frag --fragmore -j ipv6_fragment_drop

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
$IP6TABLES -t raw -A PREROUTING -j ipv6_nic_drop

echo

# Create PREROUTING filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

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
printInfo 'Further process all other incoming protocol traffic'
$IP6TABLES -t raw -A raw-${NIC}-pre -j ACCEPT

echo

#
# *******************************
# * raw-${NIC}-icmpv6-pre Rules *
# *******************************
#
# ICMPv6 Type       ICMPv6 Message
# ¯¯¯¯¯¯¯¯¯¯¯       ¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# 133               router-solicitation
# 134               router-advertisement
# 135               neighbor-solicitation
# 136               neighbor-advertisement
# 137               redirect
#

printInfo 'Allow incoming Link-Local ICMPv6 packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -s $IPv6_SUBNET_LOCAL -j do_not_track

printInfo 'Allow ICMPv6 neighbor-advertisement packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 -s $IPv6_SUBNET_GLOBAL -d $ALL_NODES_LOCAL --icmpv6-type neighbor-advertisement -j do_not_track

printInfo 'Allow ICMPv6 destination-unreachable packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type destination-unreachable -j do_not_track

printInfo 'Allow ICMPv6 packet-too-big packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type packet-too-big -j do_not_track

printInfo 'Allow ICMPv6 parameter-problem packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type parameter-problem -j do_not_track

printInfo 'Allow ICMPv6 echo-request packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type echo-request -m limit --limit 2/s --limit-burst 1 -j do_not_track

printInfo 'Allow ICMPv6 echo-reply packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type echo-reply -j do_not_track

printInfo 'Allow ICMPv6 time-exceeded packets'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -p icmpv6 -m icmpv6 --icmpv6-type time-exceeded -j do_not_track

printInfo 'DROP all other incoming ICMPv6 traffic'
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 ICMP BLOCK] ' --log-level 7
$IP6TABLES -t raw -A raw-${NIC}-icmpv6-pre -j DROP

echo

#
# ****************************
# * raw-${NIC}-tcp-pre Rules *
# ****************************
#

printInfo 'DROP incoming Microsoft Remote Desktop packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --dport 3389 -j tcp_drop

printInfo 'Allow incoming Link-Local TCP packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -s $IPv6_SUBNET_LOCAL -j do_not_track

printInfo 'Do not track incoming HTTP/HTTPS TCP response packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 443 -j do_not_track
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 80 -j do_not_track

printInfo 'Do not track incoming DNS TCP response packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 53 -j do_not_track

printInfo 'Further process all other incoming TCP traffic'
$IP6TABLES -t raw -A raw-${NIC}-tcp-pre -j ACCEPT

echo

#
# ****************************
# * raw-${NIC}-udp-pre Rules *
# ****************************
#

printInfo 'DROP incoming Canon/Epson printer discovery packets'
$IP6TABLES -t raw -A raw-${NIC}-udp-pre -p udp -m multiport --sports 8610,8612,3289 -j ipv6_canon_drop

printInfo 'Further process all other incoming UDP traffic'
$IP6TABLES -t raw -A raw-${NIC}-udp-pre -j do_not_track

echo

#
# ════════════════════════ Configure RAW OUTPUT Chain ═════════════════════════
#

printInfo 'DROP outgoing fragmented packets'
$IP6TABLES -t raw -A OUTPUT -m frag --fragmore -j ipv6_fragment_drop

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
$IP6TABLES -t raw -A OUTPUT -j ipv6_nic_drop

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

printInfo 'Allow outgoing Link-Local TCP packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -s $IPv6_SUBNET_LOCAL -j do_not_track

printInfo 'Do not track outgoing HTTP/HTTPS TCP request packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 443 -j do_not_track
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 80 -j do_not_track

printInfo 'Do not track outgoing DNS TCP request packets'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 53 -j do_not_track

printInfo 'Further process all other outgoing TCP traffic'
$IP6TABLES -t raw -A raw-${NIC}-tcp-out -j ACCEPT

echo

#
# ****************************
# * raw-${NIC}-udp-out Rules *
# ****************************
#

printInfo 'DROP outgoing Canon/Epson printer discovery packets'
$IP6TABLES -t raw -A raw-${NIC}-udp-out -p udp -m multiport --dports 8610,8612,3289 -j ipv6_canon_drop

printInfo 'Further process all other outgoing UDP traffic'
$IP6TABLES -t raw -A raw-${NIC}-udp-out -j do_not_track

echo

################################ MANGLE Table #################################

printBanner 'Configuring MANGLE Table'

#
# ═════════════════════ Configure MANGLE PREROUTING Chain ═════════════════════
#

printInfo 'Drop all incoming INVALID packets'
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

# Rate limit ICMP REJECT logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -N icmp_reject
$IP6TABLES -A icmp_reject -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 BLOCK] ' --log-level 7
$IP6TABLES -A icmp_reject -j REJECT --reject-with icmp6-port-unreachable

# Rate limit TCP REJECT logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IP6TABLES -N tcp_reject
$IP6TABLES -A tcp_reject -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 BLOCK] ' --log-level 7
$IP6TABLES -A tcp_reject -p tcp -j REJECT --reject-with tcp-reset

#
# ═══════════════════════ Configure FILTER INPUT Chain ════════════════════════
#

# Create INPUT filter chain for sshguard
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo "Creating incoming filter chain for sshguard"
$IP6TABLES -N sshguard

# Create INPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## lo
printInfo 'ACCEPT incoming lo interface traffic'
$IP6TABLES -A INPUT -i lo -j ACCEPT

## NIC
printInfo "Process incoming $NIC interface traffic"
$IP6TABLES -N filter-${NIC}-in
$IP6TABLES -A INPUT -i ${NIC} -j filter-${NIC}-in

echo

# Create INPUT filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo "Process incoming Link-Local packets on $NIC"
$IP6TABLES -N filter-${NIC}-local-in
$IP6TABLES -A filter-${NIC}-in -s $IPv6_SUBNET_LOCAL -j filter-${NIC}-local-in

## TCP
printInfo 'Process incoming TCP traffic'
$IP6TABLES -N filter-${NIC}-tcp-in
$IP6TABLES -A filter-${NIC}-in -p tcp -j filter-${NIC}-tcp-in

## UDP
printInfo 'Process incoming UDP traffic'
$IP6TABLES -N filter-${NIC}-udp-in
$IP6TABLES -A filter-${NIC}-in -p udp -j filter-${NIC}-udp-in

## ICMPv6
printInfo 'ACCEPT all incoming ICMPv6 traffic not dropped in RAW table'
$IP6TABLES -A filter-${NIC}-in -p icmpv6 -j ACCEPT

## ALL OTHERS
printInfo 'REJECT all other incoming protocol traffic'
$IP6TABLES -A filter-${NIC}-in -j icmp_reject

echo

#
# ********************************
# * filter-${NIC}-local-in Rules *
# ********************************
#

printInfo 'Perform incoming Link-Local TCP traffic accounting'
$IP6TABLES -A filter-${NIC}-local-in -p tcp -j ACCEPT

printInfo 'Perform incoming Link-Local UDP traffic accounting'
$IP6TABLES -A filter-${NIC}-local-in -p udp -j ACCEPT

printInfo 'Perform incoming Link-Local ICMPv6 traffic accounting'
$IP6TABLES -A filter-${NIC}-local-in -p icmpv6 -j ACCEPT

printInfo 'Perform incoming Link-Local OTHER traffic accounting'
$IP6TABLES -A filter-${NIC}-local-in -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 INFO BLOCK] ' --log-level 7
$IP6TABLES -A filter-${NIC}-local-in -j ACCEPT

echo

#
# ******************************
# * filter-${NIC}-tcp-in Rules *
# ******************************
#

printInfo 'ACCEPT incoming HTTP/HTTPS TCP response packets'
$IP6TABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --sport 443 -j ACCEPT
$IP6TABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --sport 80 -j ACCEPT

printInfo 'Refer to sshguard for incoming SSH TCP request packets'
$IP6TABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --dport 22 -j sshguard

printInfo 'ACCEPT incoming SSH TCP request packets'
$IP6TABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --dport 22 -j ACCEPT

printInfo 'ACCEPT incoming DNS TCP response packets'
$IP6TABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --sport 53 -j ACCEPT

printInfo 'REJECT all other incoming TCP traffic'
$IP6TABLES -A filter-${NIC}-tcp-in -j tcp_reject

echo

#
# ******************************
# * filter-${NIC}-udp-in Rules *
# ******************************
#

printInfo 'ACCEPT incoming HTTPS UDP response packets'
$IP6TABLES -A filter-${NIC}-udp-in -p udp -m udp --sport 443 -j ACCEPT

printInfo 'ACCEPT incoming DNS UDP response packets'
$IP6TABLES -A filter-${NIC}-udp-in -p udp -m udp --sport 53 -j ACCEPT

printInfo 'ACCEPT incoming NTP UDP response packets'
$IP6TABLES -A filter-${NIC}-udp-in -p udp -m udp --sport 123 -j ACCEPT

printInfo 'ACCEPT incoming mDNSv6 UDP response packets'
$IP6TABLES -A filter-${NIC}-udp-in -p udp -m udp -s $IPv6_SUBNET_GLOBAL -d $mDNSv6_ADDR --sport 5353 -j ACCEPT

printInfo 'REJECT all other incoming UDP UNICAST traffic'
$IP6TABLES -A filter-${NIC}-udp-in -j icmp_reject

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

## lo
printInfo 'ACCEPT outgoing lo interface traffic'
$IP6TABLES -A OUTPUT -o lo -j ACCEPT

## NIC
printInfo "Process outgoing $NIC interface traffic"
$IP6TABLES -N filter-${NIC}-out
$IP6TABLES -A OUTPUT -o ${NIC} -j filter-${NIC}-out

echo

# Create OUTPUT filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo "Process outgoing Link-Local packets on $NIC"
$IP6TABLES -N filter-${NIC}-local-out
$IP6TABLES -A filter-${NIC}-out -s $IPv6_SUBNET_LOCAL -j filter-${NIC}-local-out

## TCP
printInfo 'Process outgoing TCP traffic'
$IP6TABLES -N filter-${NIC}-tcp-out
$IP6TABLES -A filter-${NIC}-out -p tcp -j filter-${NIC}-tcp-out

## UDP
printInfo 'Process outgoing UDP traffic'
$IP6TABLES -N filter-${NIC}-udp-out
$IP6TABLES -A filter-${NIC}-out -p udp -j filter-${NIC}-udp-out

## ICMPv6
printInfo 'ACCEPT all outgoing ICMPv6 traffic'
$IP6TABLES -A filter-${NIC}-out -p icmpv6 -j ACCEPT

## ALL OTHERS
printInfo 'REJECT all other outgoing protocol traffic'
$IP6TABLES -A filter-${NIC}-out -j icmp_reject

echo

#
# *********************************
# * filter-${NIC}-local-out Rules *
# *********************************
#

printInfo 'Perform outgoing Link-Local TCP traffic accounting'
$IP6TABLES -A filter-${NIC}-local-out -p tcp -j ACCEPT

printInfo 'Perform outgoing Link-Local UDP traffic accounting'
$IP6TABLES -A filter-${NIC}-local-out -p udp -j ACCEPT

printInfo 'Perform outgoing Link-Local ICMPv6 traffic accounting'
$IP6TABLES -A filter-${NIC}-local-out -p icmpv6 -j ACCEPT

printInfo 'Perform outgoing Link-Local OTHER traffic accounting'
$IP6TABLES -A filter-${NIC}-local-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 INFO BLOCK] ' --log-level 7
$IP6TABLES -A filter-${NIC}-local-out -j ACCEPT

echo

#
# *******************************
# * filter-${NIC}-tcp-out Rules *
# *******************************
#

printInfo 'ACCEPT outgoing HTTP/HTTPS TCP request packets'
$IP6TABLES -A filter-${NIC}-tcp-out -p tcp -m tcp --dport 443 -j ACCEPT
$IP6TABLES -A filter-${NIC}-tcp-out -p tcp -m tcp --dport 80 -j ACCEPT

printInfo 'ACCEPT outgoing SSH TCP response packets'
$IP6TABLES -A filter-${NIC}-tcp-out -p tcp -m tcp --sport 22 -j ACCEPT

printInfo 'ACCEPT outgoing DNS TCP request packets'
$IP6TABLES -A filter-${NIC}-tcp-out -p tcp -m tcp --dport 53 -j ACCEPT

printInfo 'REJECT all other outgoing TCP traffic'
$IP6TABLES -A filter-${NIC}-tcp-out -j tcp_reject

echo

#
# *******************************
# * filter-${NIC}-udp-out Rules *
# *******************************
#

printInfo 'ACCEPT outoging HTTPS UDP request packets'
$IP6TABLES -A filter-${NIC}-udp-out -p udp -m udp --dport 443 -j ACCEPT

printInfo 'ACCEPT outoging DNS UDP request packets'
$IP6TABLES -A filter-${NIC}-udp-out -p udp -m udp --dport 53 -j ACCEPT

printInfo 'ACCEPT outgoing NTP UDP request packets'
$IP6TABLES -A filter-${NIC}-udp-out -p udp -m udp --dport 123 -j ACCEPT

printInfo 'ACCEPT outgoing mDNSv6 UDP request packets'
$IP6TABLES -A filter-${NIC}-udp-out -p udp -m udp --dport 5353 -d $mDNSv6_ADDR -j ACCEPT

printInfo 'REJECT all other outgoing UDP traffic'
$IP6TABLES -A filter-${NIC}-udp-out -j icmp_reject

echo

################################ IP6TABLES-SAVE ################################

printInfo 'Persisting ip6tables Rules'

# Backup existing /etc/network/ip6tables.rules
if [ -f /etc/network/ip6tables.rules ]; then
	$EXEC_CP /etc/network/ip6tables.rules /etc/network/ip6tables.rules.bak
fi

# Save /etc/network/ip6tables.rules
$IP6TABLES_SAVE > /etc/network/ip6tables.rules

echo

exit 0
