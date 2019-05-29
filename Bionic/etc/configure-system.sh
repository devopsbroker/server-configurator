#!/bin/bash

#
# configure-system.sh - DevOpsBroker script for systemwide configurations
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
# The following systemwide initialization files are configured by this script:
#
# o /etc/adduser.conf
# o /etc/bash.bashrc
# o /etc/hosts
# o /etc/modules
# o /etc/ntp.conf
# o /etc/profile
# o /etc/apparmor.d/local/usr.sbin.unbound
# o /etc/apt/apt.conf.d/10periodic
# o /etc/apt/apt.conf.d/50unattended-upgrades
# o /etc/bash_completion.d/*
# o /etc/devops/ansi.conf
# o /etc/devops/exec.conf
# o /etc/devops/functions.conf
# o /etc/devops/functions-admin.conf
# o /etc/devops/functions-io.conf
# o /etc/modprobe.d/nf_conntrack.conf
# o /etc/network/firewall-restore.sh
# o /etc/pam.d/common-session
# o /etc/ssh/sshd_config
# o /etc/sudoers.d/10-umask
# o /etc/sudoers.d/20-env_keep
# o /etc/sysctl.d/40-ipv6-enable.conf
# o /etc/systemd/system/iptables.service
#
# Other configuration tasks include:
# o Disable root login
#
# Useful Linux Command-Line Utilities
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Print all or part of the Bash shell environment
#   o printenv
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

# Load /etc/devops/functions-admin.conf if FUNC_ADMIN_CONFIG is unset
if [ -z "$FUNC_ADMIN_CONFIG" ] && [ -f /etc/devops/functions-admin.conf ]; then
	source /etc/devops/functions-admin.conf
fi

${FUNC_ADMIN_CONFIG?"[1;91mCannot load '/etc/devops/functions-admin.conf': No such file[0m"}

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

# Set nf_conntrack.conf.tpl location and make it executable
nfConntrackConfTpl=$(isExecutable "$SCRIPT_DIR"/modprobe.d/nf_conntrack.conf.tpl)

# Set hosts.tpl location and make it executable
hostsTpl=$(isExecutable "$SCRIPT_DIR"/hosts.tpl)

################################## Variables ##################################

## Bash exec variables
EXEC_LSCPU=/usr/bin/lscpu
EXEC_LSPCI=/usr/bin/lspci
EXEC_PASSWD=/usr/bin/passwd
EXEC_UPDATE_INITRAMFS=/usr/sbin/update-initramfs

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}
echoOnExit=false
updateInitramfs=false

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE System Configurator" 'true'

# Install /etc/adduser.conf
installConfig 'adduser.conf' "$SCRIPT_DIR" /etc

# Install /etc/bash.bashrc
installConfig 'bash.bashrc' "$SCRIPT_DIR" /etc

# Install /etc/hosts
set +o errexit
if ! $EXEC_GREP -Fq 'DevOpsBroker' /etc/hosts; then
	printBanner 'Installing /etc/hosts'

	# Execute template script
	"$hostsTpl" > "$TMPDIR"/hosts

	# Install as root:root with rw-r--r-- privileges
	$EXEC_INSTALL -b --suffix .orig -o root -g root -m 644 "$TMPDIR"/hosts /etc

	# Clean up
	$EXEC_RM "$TMPDIR"/hosts
fi
set -o errexit

# Install /etc/modules
installConfig 'modules' "$SCRIPT_DIR" /etc

if [ "$INSTALL_CONFIG" == 'true' ]; then
	updateInitramfs=true
fi

# Install /etc/ntp.conf
installConfig 'ntp.conf' "$SCRIPT_DIR" /etc 'ntp'

# Install /etc/profile
installConfig 'profile' "$SCRIPT_DIR" /etc

# Install /etc/apparmor.d/local/usr.sbin.unbound
installConfig 'usr.sbin.unbound' "$SCRIPT_DIR"/apparmor.d/local /etc/apparmor.d/local

set +o errexit
# Install /etc/apt/apt.conf.d/10periodic
if [ -f /etc/apt/apt.conf.d/10periodic ] && [ -z "$( $EXEC_GREP -F --max-count=1 'DevOpsBroker' /etc/apt/apt.conf.d/10periodic )" ]; then
	printInfo 'Installing /etc/apt/apt.conf.d/10periodic'

	# Install as root:root with rw-r--r-- privileges
	/usr/bin/install -o root -g root -m 644 "$SCRIPT_DIR/apt/apt.conf.d/10periodic" /etc/apt/apt.conf.d
fi

# Install /etc/apt/apt.conf.d/50unattended-upgrades
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ] && [ -z "$( $EXEC_GREP -F --max-count=1 'DevOpsBroker' /etc/apt/apt.conf.d/50unattended-upgrades )" ]; then
	printInfo 'Installing /etc/apt/apt.conf.d/50unattended-upgrades'

	# Install as root:root with rw-r--r-- privileges
	/usr/bin/install -o root -g root -m 644 "$SCRIPT_DIR/apt/apt.conf.d/50unattended-upgrades" /etc/apt/apt.conf.d
fi
set -o errexit

# Install /etc/bash_completion.d/*
$EXEC_CP -uv "$SCRIPT_DIR"/bash_completion.d/* /etc/bash_completion.d
$EXEC_CHMOD --changes 644 /etc/bash_completion.d/*

if [ -d "$SCRIPT_DIR"/devops ]; then
	# Install /etc/devops/ansi.conf
	installConfig 'ansi.conf' "$SCRIPT_DIR/devops" /etc/devops

	# Install /etc/devops/exec.conf
	installConfig 'exec.conf' "$SCRIPT_DIR/devops" /etc/devops

	# Install /etc/devops/functions.conf
	installConfig 'functions.conf' "$SCRIPT_DIR/devops" /etc/devops

	# Install /etc/devops/functions-admin.conf
	installConfig 'functions-admin.conf' "$SCRIPT_DIR/devops" /etc/devops

	# Install /etc/devops/functions-io.conf
	installConfig 'functions-io.conf' "$SCRIPT_DIR/devops" /etc/devops
fi

# Install /etc/modprobe.d/nf_conntrack.conf
if [ ! -f /etc/modprobe.d/nf_conntrack.conf ] || \
	[ "$nfConntrackConfTpl" -nt /etc/modprobe.d/nf_conntrack.conf ]; then

	# Execute template script
	"$nfConntrackConfTpl" > "$TMPDIR"/nf_conntrack.conf

	# Install /etc/modprobe.d/nf_conntrack.conf
	installConfig 'nf_conntrack.conf' "$TMPDIR" /etc/modprobe.d

	# Clean up
	$EXEC_RM "$TMPDIR"/nf_conntrack.conf

	updateInitramfs=true
	echoOnExit=true
fi

# Install /etc/network/firewall-restore.sh
installConfig 'firewall-restore.sh' "$SCRIPT_DIR"/network /etc/network

if [ "$INSTALL_CONFIG" == 'true' ]; then
	$EXEC_CHMOD 755 /etc/network/firewall-restore.sh
fi

# Install /etc/pam.d/common-session
installConfig 'common-session' "$SCRIPT_DIR"/pam.d /etc/pam.d

# Install /etc/ssh/sshd_config
installConfig 'sshd_config' "$SCRIPT_DIR"/ssh /etc/ssh 'ssh'

# Install /etc/sudoers.d/10-umask
if [ ! -f /etc/sudoers.d/10-umask ]; then
	printInfo 'Installing /etc/sudoers.d/10-umask'

	# Install as root:root with r--r----- privileges
	$EXEC_INSTALL -o root -g root -m 440 "$SCRIPT_DIR"/sudoers.d/10-umask /etc/sudoers.d

	echoOnExit=true
fi

# Install /etc/sudoers.d/20-env_keep
if [ ! -f /etc/sudoers.d/20-env_keep ]; then
	printInfo 'Installing /etc/sudoers.d/20-env_keep'

	# Install as root:root with r--r----- privileges
	$EXEC_INSTALL -o root -g root -m 440 "$SCRIPT_DIR"/sudoers.d/20-env_keep /etc/sudoers.d
	echoOnExit=true
fi

# Install /etc/sysctl.d/40-ipv6-enable.conf
installConfig '40-ipv6-enable.conf' "$SCRIPT_DIR"/sysctl.d /etc/sysctl.d

# Install /etc/systemd/system/iptables.service
installConfig 'iptables.service' "$SCRIPT_DIR"/systemd/system /etc/systemd/system

if [ "$INSTALL_CONFIG" == 'true' ]; then
	$EXEC_SYSTEMCTL daemon-reload

	printInfo 'Enabling iptables.service'
	$EXEC_SYSTEMCTL enable iptables.service

	printInfo 'Starting iptables.service'
	$EXEC_SYSTEMCTL start iptables.service
fi

#
# Disable root login
#

if [[ $($EXEC_PASSWD -S root) != "root L"* ]]; then
	printInfo 'Disabling root login'

	$EXEC_PASSWD -l root

	echoOnExit=true
fi

if [ "$updateInitramfs" == 'true' ]; then
	printInfo 'Updating initramfs'
	$EXEC_UPDATE_INITRAMFS -u
fi

if [ "$echoOnExit" == 'true' ]; then
	echo
fi

exit 0
