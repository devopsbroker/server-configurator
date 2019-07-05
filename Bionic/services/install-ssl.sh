#!/bin/bash

#
# install-ssl.sh - DevOpsBroker installation script for Let's Encrypt SSL Certificates using Certbot
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
# This script was derived from the tutorial found on the EFF website at:
#   o https://certbot.eff.org/lets-encrypt/ubuntubionic-apache
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
EXEC_ADD_APT_REPO=/usr/bin/add-apt-repository
EXEC_CERTBOT=/usr/bin/certbot

## Options

## Variables

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Let's Encrypt SSL Certificate Installer" 'true'

# Exit if /etc/apt/sources.list.d already configured
if [ -f /etc/apt/sources.list.d/certbot-ubuntu-certbot-bionic.list ]; then
	printInfo "Let's Encrypt Certbot already configured"
	echo
	printNotice $SCRIPT_EXEC "Execute 'sudo certbot certonly --apache' to obtain SSL cert and key"
	exit 0
fi

echo

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Installation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Add Certbot PPA
printBanner 'Installing Certbot PPA'
$EXEC_APT update
$EXEC_APT -y install software-properties-common
$EXEC_ADD_APT_REPO universe
$EXEC_ADD_APT_REPO ppa:certbot/certbot
$EXEC_APT update
echo

# Install Certbot
printBanner 'Installing certbot'
$EXEC_APT -y install certbot python-certbot-apache
echo

# Retrieve and install SSL certificate
printBanner 'Retrieve SSL certificate'
$EXEC_CERTBOT certonly --apache
echo

printNotice $SCRIPT_EXEC 'Update your virtual host configuration with the SSL cert and key'

echo

exit 0
