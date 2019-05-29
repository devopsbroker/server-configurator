#!/bin/bash

#
# configure-security.sh - DevOpsBroker script for configuring /etc/security
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
#   o Install /etc/security/limits.d/60-user-limits.conf
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

# Load /etc/devops/functions-io.conf if FUNC_IO_CONFIG is unset
if [ -z "$FUNC_IO_CONFIG" ] && [ -f /etc/devops/functions-io.conf ]; then
	source /etc/devops/functions-io.conf
fi

${FUNC_IO_CONFIG?"[1;91mCannot load '/etc/devops/functions-io.conf': No such file[0m"}

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

# Ensure the 60-user-limits.conf.tpl script is executable
userLimitsConf=$(isExecutable "$SCRIPT_DIR"/limits.d/60-user-limits.conf.tpl)

################################## Variables ##################################

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Security Configurator" 'true'

#
# /etc/security/limits.d/ Configuration
#

if [ ! -f /etc/security/limits.d/60-user-limits.conf ]; then
	printInfo 'Installing /etc/security/limits.d/60-user-limits.conf'

	# Execute template script
	"$userLimitsConf" > "$TMPDIR"/60-user-limits.conf

	# Install as root:root with rw-r--r-- privileges
	$EXEC_INSTALL -o root -g root -m 644 "$TMPDIR"/60-user-limits.conf /etc/security/limits.d

	# Clean up
	$EXEC_RM "$TMPDIR"/60-user-limits.conf

	echo

elif [ "$userLimitsConf" -nt /etc/security/limits.d/60-user-limits.conf ]; then
	printInfo 'Updating /etc/security/limits.d/60-user-limits.conf'

	# Execute template script
	"$userLimitsConf" > "$TMPDIR"/60-user-limits.conf

	# Install as root:root with rw-r--r-- privileges
	$EXEC_INSTALL -b --suffix .bak -o root -g root -m 644 "$TMPDIR"/60-user-limits.conf /etc/security/limits.d

	# Clean up
	$EXEC_RM "$TMPDIR"/60-user-limits.conf

	echo
fi

exit 0
