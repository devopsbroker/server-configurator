#!/bin/bash

#
# hosts.tpl - DevOpsBroker template for generating /etc/hosts configuration
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
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-15
#
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Robustness ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

set -o errexit                 # Exit if any statement returns a non-true value
set -o nounset                 # Exit if use an uninitialised variable
set -o pipefail                # Exit if any statement in a pipeline returns a non-true value

################################## Functions ##################################

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     getHostname
# Description:  Generates the hostname entry for the host
# -----------------------------------------------------------------------------
function getHostname() {
	local fqdnHostname="$($EXEC_HOSTNAME --fqdn)"
	local hostname="$($EXEC_HOSTNAME)"

	if [ "$hostname" == "$fqdnHostname" ]; then
		echo "$hostname"
	else
		echo "$fqdnHostname $hostname"
	fi
}

################################## Variables ##################################

## Bash exec variables
EXEC_HOSTNAME=/bin/hostname

## Variables
YEAR=$($EXEC_DATE +'%Y')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Template
/bin/cat << EOF
#
# hosts - DevOpsBroker /etc/hosts configuration
#
# Copyright (C) $YEAR Edward Smith <edwardsmith@devopsbroker.org>
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
# This file is a simple text file that associates IP addresses with hostnames,
# one line per IP address.  For each host a single line should be present with
# the following information:
#
#          IP_address canonical_hostname [aliases...]
#
# Fields of the entry are separated by any number of blanks and/or tab
# characters.  Text from a "#" character until the end of the line is a
# comment, and is ignored.  Host names may contain only alphanumeric
# characters, minus signs ("-"), and periods (".").  They must begin with an
# alphabetic character and end with an alphanumeric character. Optional aliases
# provide for name changes, alternate spellings, shorter hostnames, or generic
# hostnames (for example, localhost).
# -----------------------------------------------------------------------------
#

# The following lines are desirable for IPv4 capable hosts
127.0.0.1   localhost

# 127.0.1.1 is often used for the FQDN of the machine
127.0.1.1   $(getHostname)

# The following lines are desirable for IPv6 capable hosts
::1       localhost ip6-localhost ip6-loopback
fe00::0   ip6-localnet
ff00::0   ip6-mcastprefix
ff02::1   ip6-allnodes
ff02::2   ip6-allrouters
ff02::3   ip6-allhosts

EOF

exit 0
