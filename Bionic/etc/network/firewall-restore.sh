#!/bin/bash

#
# firewall-restore - DevOpsBroker script to restore iptables/ip6tables/nf_conntrack during boot
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
# The following tasks are performed with this script:
#   o Restore IPv4 firewall rules
#   o Restore IPv6 firewall rules
#   o Configure nf_conntrack kernel parameters
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Robustness ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

set -o errexit                 # Exit if any statement returns a non-true value
set -o nounset                 # Exit if use an uninitialised variable
set -o pipefail                # Exit if any statement in a pipeline returns a non-true value

################################## Variables ##################################

## Bash exec variables
IPTABLES_RESTORE=/sbin/iptables-restore
IP6TABLES_RESTORE=/sbin/ip6tables-restore
EXEC_SYSCTL=/sbin/sysctl

## Variables
NF_CONNTRACK_MAX=''
NF_CONNTRACK_EXPECT_MAX=''

################################### Actions ###################################

# Restore IPv4 iptables firewall rules
if [ -f /etc/network/iptables.rules ]; then
	/usr/bin/logger -p syslog.notice -i [iptables-restore] Loading /etc/network/iptables.rules rules;
	$IPTABLES_RESTORE < /etc/network/iptables.rules
fi

# Restore IPv6 ip6tables firewall rules
if [ -f /etc/network/ip6tables.rules ]; then
	/usr/bin/logger -p syslog.notice -i [iptables-restore] Loading /etc/network/ip6tables.rules rules;
	$IP6TABLES_RESTORE < /etc/network/ip6tables.rules
fi

#
# Configure the nf_conntrack kernel module
#

/usr/bin/logger -p syslog.notice -i [20-nf_conntrack] Setting net.netfilter.nf_conntrack kernel parameters;

NF_CONNTRACK_MAX=$(/bin/cat /sys/module/nf_conntrack/parameters/hashsize)
NF_CONNTRACK_EXPECT_MAX=$(/bin/cat /sys/module/nf_conntrack/parameters/expect_hashsize)

# Optimize generic timeout to 2 minutes
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_generic_timeout=120

# Disable Conntrack Helpers
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_helper=0

# Set the Netfilter Conntrack Maximum Table Size
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_expect_max=$NF_CONNTRACK_EXPECT_MAX
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_max=$NF_CONNTRACK_MAX

# Enable TCP Strict Policy
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_loose=0

# Optimize TCP Timeout Close and Close-Wait
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_close=10
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=20

# Optimize TCP Established Timeout to 12 hours
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_established=43200

# Optimize TCP FIN_WAIT Timeout to 20 seconds
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=20

# Optimize TCP Last ACK Timeout to 10 seconds
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_last_ack=10

# Optimize TCP Maximum Retransmit Timeout to 60 seconds
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_max_retrans=60

# Optimize TCP SYN Receive Timeout to 15 seconds
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_syn_recv=15

# Optimize TCP SYN Send Timeout to 30 seconds
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_syn_sent=30

# Optimize TCP TIME_WAIT Timeout to 60 seconds
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=60

# Optimize TCP Unacknowledged Timeout to 60 seconds
$EXEC_SYSCTL -w net.netfilter.nf_conntrack_tcp_timeout_unacknowledged=60

exit 0
