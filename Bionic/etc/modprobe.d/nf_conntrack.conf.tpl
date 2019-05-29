#!/bin/bash

#
# nf_conntrack.conf.tpl - DevOpsBroker template for creating /etc/modprobe.d/nf_conntrack.conf
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
# The template will calculate the nf_conntrack hashsize and expect_hashsize
# based upon the following formulas:
#
#   o Set hashsize to a scaled percentage of the RAM total
#   o Set expect_hashsize to 75% of hashsize
#   o Disable Connection Tracking helpers automatic confiugration to listen to a port
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

################################## Functions ##################################

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     getHashSize
# Description:  Returns the hashtable size based on the amount of RAM
#
# Parameter $1: The element to search for
# Parameter $2: The array to search
# -----------------------------------------------------------------------------
function getHashSize() {
	local divisor=$1
	local stepping=$2
	local baseSize=$3
	local result=''

	result=$(echo "scale=5; factor = ($RAM_TOTAL / $divisor) - 1; hashsize = factor * $stepping + $baseSize; scale=0; hashsize /= 1; hashsize" | $EXEC_BC)

	echo $result
}

################################## Variables ##################################

## Bash exec variables
EXEC_BC=/usr/bin/bc

## Configuration
RAM_TOTAL=$(getRamTotal)

## Variables
YEAR=$($EXEC_DATE +'%Y')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Calculations ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if [ $RAM_TOTAL -le 1048576 ]; then                # 1GB RAM > 20480 && <= 163840
	HASHSIZE=$(getHashSize 65536 9557 20480)
elif [ $RAM_TOTAL -le 2097152 ]; then              # 2GB RAM > 163840 && <= 229376
	HASHSIZE=$(getHashSize 1048576 65536 163840)
elif [ $RAM_TOTAL -le 4194304 ]; then              # 4GB RAM > 229376 && <= 327680
	HASHSIZE=$(getHashSize 2097152 98304 229376)
elif [ $RAM_TOTAL -le 8388608 ]; then              # 8GB RAM > 327680 && <= 425984
	HASHSIZE=$(getHashSize 4194304 98304 327680)
else                                               # Over 8GB Ram > 425984
	HASHSIZE=$(getHashSize 8388608 98304 425984)
fi

EXPECT_HASHSIZE=$[ ($HASHSIZE / 4) * 3 ]

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Template
/bin/cat << EOF
#
# nf_conntrack.conf - DevOpsBroker configuration for the nf_conntrack module
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

options nf_conntrack hashsize=$HASHSIZE
options nf_conntrack expect_hashsize=$EXPECT_HASHSIZE
options nf_conntrack nf_conntrack_helper=0

EOF

exit 0
