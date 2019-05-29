#!/bin/bash

#
# iptables-private.sh - DevOpsBroker IPv4 iptables firewall script for private Intranet servers
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
#   o Drop all incoming/outgoing Canon/Epson printer discovery packets
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
EXEC_DERIVESUBNET=/usr/local/bin/derivesubnet

## Options
NIC=${1:-}

## Variables
IPv4_ADDRESS=''
IPv4_GATEWAY=''
IPv4_INTERNAL=''

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [ -z "$NIC" ]; then
	mapfile -t ethList < <($EXEC_IP -br -4 addr show | $EXEC_GREP -Eo '^en(p|s)[a-z0-9]+')

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

ethInfo=( $($EXEC_DERIVESUBNET -4 $NIC) )

if [ $? -ne 0 ]; then
	exit 0
fi

IPv4_ADDRESS=${ethInfo[0]}
IPv4_GATEWAY=${ethInfo[1]}

# Check if we are on a Google Compute Engine platform
if [[ "${ethInfo[2]}" =~ ^10\.128\. ]]; then
	isGCE="$($EXEC_GREP -F google-sudoers /etc/group)"

	if [ "$isGCE" ]; then
		IPv4_INTERNAL='10.128.0.0/9'
	else
		IPv4_INTERNAL=${ethInfo[2]}
	fi
else
	IPv4_INTERNAL=${ethInfo[2]}
fi

set -o errexit

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE iptables Configurator" 'true'

echo "${bold}Network Interface: ${green}$NIC"
echo "${white}IPv4 Address:  ${green}$IPv4_ADDRESS"
echo "${white}IPv4 Gateway:  ${green}$IPv4_GATEWAY"
echo "${white}IPv4 Internal: ${green}$IPv4_INTERNAL"
echo "${reset}"

#
# Set default policies / Flush rules / Delete user-defined chains
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo 'Initializing RAW Table'
$IPTABLES -t raw -P OUTPUT ACCEPT
$IPTABLES -t raw -F
$IPTABLES -t raw -X

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

# Rate limit Fragment logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N ipv4_fragment_drop
$IPTABLES -t raw -A ipv4_fragment_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 FRAG BLOCK] ' --log-level 7
$IPTABLES -t raw -A ipv4_fragment_drop -j DROP

# Rate limit Network Interface logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N ipv4_nic_drop
$IPTABLES -t raw -A ipv4_nic_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 NIC BLOCK] ' --log-level 7
$IPTABLES -t raw -A ipv4_nic_drop -j DROP

# Rate limit Canon/Epson logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N ipv4_canon_drop
$IPTABLES -t raw -A ipv4_canon_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 CANON BLOCK] ' --log-level 7
$IPTABLES -t raw -A ipv4_canon_drop -j DROP

# Rate limit TCP logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N tcp_drop
$IPTABLES -t raw -A tcp_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 TCP BLOCK] ' --log-level 7
$IPTABLES -t raw -A tcp_drop -j DROP

# Rate limit IGMP logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N igmp_drop
$IPTABLES -t raw -A igmp_drop -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 IGMP BLOCK] ' --log-level 7
$IPTABLES -t raw -A igmp_drop -j DROP

# Perform NOTRACK and ACCEPT
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -t raw -N do_not_track
$IPTABLES -t raw -A do_not_track -j NOTRACK
$IPTABLES -t raw -A do_not_track -j ACCEPT

#
# ══════════════════════ Configure RAW PREROUTING Chain ═══════════════════════
#

printInfo 'DROP incoming fragmented packets'
$IPTABLES -t raw -A PREROUTING -f -j ipv4_fragment_drop

# Create PREROUTING filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## NIC
printInfo "Process incoming $NIC interface traffic"
$IPTABLES -t raw -N raw-${NIC}-pre
$IPTABLES -t raw -A PREROUTING -i ${NIC} -j raw-${NIC}-pre

## lo
printInfo 'Allow incoming lo interface traffic'
$IPTABLES -t raw -A PREROUTING -i lo -j do_not_track

printInfo 'DROP all other incoming interface traffic'
$IPTABLES -t raw -A PREROUTING -j ipv4_nic_drop

echo

# Create PREROUTING filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo 'Allow incoming IPv4 Internal packets'
$IPTABLES -t raw -A raw-${NIC}-pre -s $IPv4_INTERNAL -j do_not_track

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

## IGMP
printInfo "DROP all incoming IGMP traffic not on $IPv4_INTERNAL"
$IPTABLES -t raw -A raw-${NIC}-pre -j igmp_drop

## ALL OTHERS
printInfo 'Further process all other incoming protocol traffic'
$IPTABLES -t raw -A raw-${NIC}-pre -j ACCEPT

echo

#
# *****************************
# * raw-${NIC}-icmp-pre Rules *
# *****************************
#

printInfo 'Allow ICMP destination-unreachable packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type destination-unreachable -j do_not_track

printInfo 'Allow ICMP parameter-problem packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type parameter-problem -j do_not_track

printInfo 'Allow ICMP echo-request packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type echo-request -m limit --limit 2/s --limit-burst 1 -j do_not_track

printInfo 'Allow ICMP echo-reply packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type echo-reply -j do_not_track

printInfo 'Allow ICMP time-exceeded packets'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -p icmp -m icmp --icmp-type time-exceeded -j do_not_track

printInfo 'DROP all other incoming ICMP traffic'
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 ICMP BLOCK] ' --log-level 7
$IPTABLES -t raw -A raw-${NIC}-icmp-pre -j DROP

echo

#
# ****************************
# * raw-${NIC}-tcp-pre Rules *
# ****************************
#

printInfo 'Do not track incoming HTTP/HTTPS TCP response packets'
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 443 -j do_not_track
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --sport 80 -j do_not_track

printInfo 'Do not track incoming SSH TCP request packets'
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -p tcp -m tcp --dport 22 -j do_not_track

printInfo 'Further process all other incoming TCP traffic'
$IPTABLES -t raw -A raw-${NIC}-tcp-pre -j ACCEPT

echo

#
# ****************************
# * raw-${NIC}-udp-pre Rules *
# ****************************
#

printInfo 'DROP all incoming DHCP request packets'
$IPTABLES -t raw -A raw-${NIC}-udp-pre -p udp -m udp -s 0.0.0.0 -d 255.255.255.255 --sport 68 --dport 67 -j DROP

printInfo 'DROP incoming Canon/Epson printer discovery packets'
$IPTABLES -t raw -A raw-${NIC}-udp-pre -p udp -m multiport --sports 8610,8612,3289 -j ipv4_canon_drop

printInfo 'Further process all other incoming UDP traffic'
$IPTABLES -t raw -A raw-${NIC}-udp-pre -j do_not_track

echo

#
# ════════════════════════ Configure RAW OUTPUT Chain ═════════════════════════
#

printInfo 'DROP outgoing fragmented packets'
$IPTABLES -t raw -A OUTPUT -f -j ipv4_fragment_drop

# Create OUTPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## NIC
printInfo "Process outgoing $NIC interface traffic"
$IPTABLES -t raw -N raw-${NIC}-out
$IPTABLES -t raw -A OUTPUT -o ${NIC} -j raw-${NIC}-out

## lo
printInfo 'Allow outgoing lo interface traffic'
$IPTABLES -t raw -A OUTPUT -o lo -j do_not_track

printInfo 'DROP all other outgoing interface traffic'
$IPTABLES -t raw -A OUTPUT -j ipv4_nic_drop

echo

# Create OUTPUT filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo 'Allow outgoing IPv4 Internal packets'
$IPTABLES -t raw -A raw-${NIC}-out -d $IPv4_INTERNAL -j do_not_track

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

## IGMP
printInfo "DROP all outgoing IGMP traffic not on $IPv4_INTERNAL"
$IPTABLES -t raw -A raw-${NIC}-out -j igmp_drop

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

printInfo 'Do not track outgoing HTTP/HTTPS TCP request packets'
$IPTABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 443 -j do_not_track
$IPTABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --dport 80 -j do_not_track

printInfo 'Do not track outgoing SSH TCP response packets'
$IPTABLES -t raw -A raw-${NIC}-tcp-out -p tcp -m tcp --sport 22 -j do_not_track

printInfo 'Further process all other outgoing TCP traffic'
$IPTABLES -t raw -A raw-${NIC}-tcp-out -j ACCEPT

echo

#
# ****************************
# * raw-${NIC}-udp-out Rules *
# ****************************
#

printInfo 'DROP outgoing Canon/Epson printer discovery packets'
$IPTABLES -t raw -A raw-${NIC}-udp-out -p udp -m multiport --dports 8610,8612,3289 -j ipv4_canon_drop

printInfo 'Further process all other outgoing UDP traffic'
$IPTABLES -t raw -A raw-${NIC}-udp-out -p udp -j do_not_track

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

# Rate limit ICMP REJECT logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -N icmp_reject
$IPTABLES -A icmp_reject -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 BLOCK] ' --log-level 7
$IPTABLES -A icmp_reject -j REJECT --reject-with icmp-port-unreachable

# Rate limit TCP REJECT logging
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
$IPTABLES -N tcp_reject
$IPTABLES -A tcp_reject -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 BLOCK] ' --log-level 7
$IPTABLES -A tcp_reject -p tcp -j REJECT --reject-with tcp-reset

#
# ═══════════════════════ Configure FILTER INPUT Chain ════════════════════════
#

# Create INPUT filter chain for sshguard
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
printInfo "Creating incoming filter chain for sshguard"
$IPTABLES -N sshguard

# Create INPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## NIC
printInfo "Process incoming $NIC interface traffic"
$IPTABLES -N filter-${NIC}-in
$IPTABLES -A INPUT -i ${NIC} -j filter-${NIC}-in

## lo
printInfo 'ACCEPT incoming lo interface traffic'
$IPTABLES -A INPUT -i lo -j ACCEPT

echo

# Create INPUT filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo "Process incoming IPv4 Internal packets on $NIC"
$IPTABLES -N filter-${NIC}-local-in
$IPTABLES -A filter-${NIC}-in -s $IPv4_INTERNAL -j filter-${NIC}-local-in

## TCP
printInfo 'Process incoming TCP traffic'
$IPTABLES -N filter-${NIC}-tcp-in
$IPTABLES -A filter-${NIC}-in -p tcp -j filter-${NIC}-tcp-in

## UDP
printInfo 'Process incoming UDP traffic'
$IPTABLES -N filter-${NIC}-udp-in
$IPTABLES -A filter-${NIC}-in -p udp -j filter-${NIC}-udp-in

## ICMP
printInfo 'ACCEPT all incoming ICMP traffic not dropped in RAW table'
$IPTABLES -A filter-${NIC}-in -p icmp -j ACCEPT

## ALL OTHERS
printInfo 'REJECT all other incoming protocol traffic'
$IPTABLES -A filter-${NIC}-in -j icmp_reject

echo

#
# ********************************
# * filter-${NIC}-local-in Rules *
# ********************************
#

printInfo 'Perform incoming IPv4 Internal TCP traffic accounting'
$IPTABLES -A filter-${NIC}-local-in -p tcp -j ACCEPT

printInfo 'Perform incoming IPv4 Internal UDP traffic accounting'
$IPTABLES -A filter-${NIC}-local-in -p udp -j ACCEPT

printInfo 'Perform incoming IPv4 Internal IGMP traffic accounting'
$IPTABLES -A filter-${NIC}-local-in -p igmp -j ACCEPT

printInfo 'Perform incoming IPv4 Internal ICMP traffic accounting'
$IPTABLES -A filter-${NIC}-local-in -p icmp -j ACCEPT

printInfo 'Perform incoming IPv4 Internal OTHER traffic accounting'
$IPTABLES -A filter-${NIC}-local-in -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv4 INFO BLOCK] ' --log-level 7
$IPTABLES -A filter-${NIC}-local-in -j ACCEPT

echo

#
# ******************************
# * filter-${NIC}-tcp-in Rules *
# ******************************
#

printInfo 'ACCEPT incoming HTTP/HTTPS TCP response packets'
$IPTABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --sport 443 -j ACCEPT
$IPTABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --sport 80 -j ACCEPT

printInfo 'Refer to sshguard for incoming SSH TCP request packets'
$IPTABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --dport 22 -j sshguard

printInfo 'ACCEPT incoming SSH TCP request packets'
$IPTABLES -A filter-${NIC}-tcp-in -p tcp -m tcp --dport 22 -j ACCEPT

printInfo 'REJECT all other incoming TCP traffic'
$IPTABLES -A filter-${NIC}-tcp-in -j tcp_reject

echo

#
# ******************************
# * filter-${NIC}-udp-in Rules *
# ******************************
#

printInfo 'ACCEPT incoming DNS UDP response packets'
$IPTABLES -A filter-${NIC}-udp-in -p udp -m udp --sport 53 -j ACCEPT

printInfo 'ACCEPT incoming NTP UDP response packets'
$IPTABLES -A filter-${NIC}-udp-in -p udp -m udp --sport 123 -j ACCEPT

printInfo 'ACCEPT incoming DHCP UDP response packets'
$IPTABLES -A filter-${NIC}-udp-in -p udp -m udp --sport 67 --dport 68 -j ACCEPT

printInfo 'REJECT all other incoming UDP traffic'
$IPTABLES -A filter-${NIC}-udp-in -j icmp_reject

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

# Create OUTPUT filter chains for each network interface
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

## NIC
printInfo "Process outgoing $NIC interface traffic"
$IPTABLES -N filter-${NIC}-out
$IPTABLES -A OUTPUT -o ${NIC} -j filter-${NIC}-out

## lo
printInfo 'ACCEPT outgoing lo interface traffic'
$IPTABLES -A OUTPUT -o lo -j ACCEPT

echo

# Create OUTPUT filter chains for each protocol
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

printInfo "Process outgoing IPv4 Internal packets on $NIC"
$IPTABLES -N filter-${NIC}-local-out
$IPTABLES -A filter-${NIC}-out -d $IPv4_INTERNAL -j filter-${NIC}-local-out

## TCP
printInfo 'Process outgoing TCP traffic'
$IPTABLES -N filter-${NIC}-tcp-out
$IPTABLES -A filter-${NIC}-out -p tcp -j filter-${NIC}-tcp-out

## UDP
printInfo 'Process outgoing UDP traffic'
$IPTABLES -N filter-${NIC}-udp-out
$IPTABLES -A filter-${NIC}-out -p udp -j filter-${NIC}-udp-out

## ICMP
printInfo 'ACCEPT all outgoing ICMP traffic'
$IPTABLES -A filter-${NIC}-out -p icmp -j ACCEPT

## ALL OTHERS
printInfo 'REJECT all other outgoing protocol traffic'
$IPTABLES -A filter-${NIC}-out -j icmp_reject

echo

#
# *********************************
# * filter-${NIC}-local-out Rules *
# *********************************
#

printInfo 'Perform outgoing IPv4 Internal TCP traffic accounting'
$IPTABLES -A filter-${NIC}-local-out -p tcp -j ACCEPT

printInfo 'Perform outgoing IPv4 Internal UDP traffic accounting'
$IPTABLES -A filter-${NIC}-local-out -p udp -j ACCEPT

printInfo 'Perform outgoing IPv4 Internal IGMP traffic accounting'
$IPTABLES -A filter-${NIC}-local-out -p igmp -j ACCEPT

printInfo 'Perform outgoing IPv4 Internal ICMP traffic accounting'
$IPTABLES -A filter-${NIC}-local-out -p icmp -j ACCEPT

printInfo 'Perform outgoing IPv4 Internal OTHER traffic accounting'
$IPTABLES -A filter-${NIC}-local-out -m limit --limit 3/min --limit-burst 2 -j LOG --log-prefix '[IPv6 INFO BLOCK] ' --log-level 7
$IPTABLES -A filter-${NIC}-local-out -j ACCEPT

echo

#
# *******************************
# * filter-${NIC}-tcp-out Rules *
# *******************************
#

printInfo 'ACCEPT outgoing HTTP/HTTPS TCP request packets'
$IPTABLES -A filter-${NIC}-tcp-out -p tcp -m tcp --dport 443 -j ACCEPT
$IPTABLES -A filter-${NIC}-tcp-out -p tcp -m tcp --dport 80 -j ACCEPT

printInfo 'ACCEPT outgoing SSH TCP response packets'
$IPTABLES -A filter-${NIC}-tcp-out -p tcp -m tcp --sport 22 -j ACCEPT

printInfo 'REJECT all other outgoing TCP traffic'
$IPTABLES -A filter-${NIC}-tcp-out -j tcp_reject

echo

#
# *******************************
# * filter-${NIC}-udp-out Rules *
# *******************************
#

printInfo 'ACCEPT outoging DNS UDP request packets'
$IPTABLES -A filter-${NIC}-udp-out -p udp -m udp --dport 53 -j ACCEPT

printInfo 'ACCEPT outgoing NTP UDP request packets'
$IPTABLES -A filter-${NIC}-udp-out -p udp -m udp --dport 123 -j ACCEPT

printInfo 'ACCEPT outgoing DHCP UDP request packets'
$IPTABLES -A filter-${NIC}-udp-out -p udp -m udp --sport 68 --dport 67 -j ACCEPT

printInfo 'REJECT all other outgoing UDP traffic'
$IPTABLES -A filter-${NIC}-udp-out -j icmp_reject

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
