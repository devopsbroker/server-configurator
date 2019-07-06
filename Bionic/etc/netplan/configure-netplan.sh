#!/bin/bash

#
# configure-netplan.sh - DevOpsBroker script for configuring /etc/netplan network configuration
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
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-16
#
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

# Load /etc/devops/functions-io.conf if FUNC_IO_CONFIG is unset
if [ -z "$FUNC_IO_CONFIG" ] && [ -f /etc/devops/functions-io.conf ]; then
	source /etc/devops/functions-io.conf
fi

${FUNC_IO_CONFIG?"[1;91mCannot load '/etc/devops/functions-io.conf': No such file[0m"}

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

################################## Functions ##################################


################################## Variables ##################################

## Bash exec variables
EXEC_DERIVESUBNET=/usr/local/bin/derivesubnet
EXEC_NETPLAN=/usr/sbin/netplan
EXEC_VERIFYIP=/usr/local/bin/verifyip

## Variables
YEAR=$($EXEC_DATE +'%Y')
hasIPv6=0                          # Assume IPv6 is enabled
netplanConfig=''
sysctlConfig=''

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Netplan Configurator" 'true'

# Exit if /etc/fstab already configured
if [ -f /etc/netplan/50-cloud-init.yaml.orig ] && [ "${1:-}" != '-f' ]; then
	printNotice $SCRIPT_EXEC '/etc/netplan/50-cloud-init.yaml already configured'
	echo
	printUsage "$SCRIPT_EXEC ${gold}[-f]"

	echo ${bold}
	echo "Valid Options:${romantic}"
	echo -e ${gold}'  -f\t'  ${romantic}'Force /etc/netplan/50-cloud-init.yaml reconfiguration'
	echo ${reset}

	exit 0
fi

#
# Backup 50-cloud-init.yaml
#
if [ ! -f /etc/netplan/50-cloud-init.yaml.orig ]; then
	printBanner 'Configure /etc/netplan/50-cloud-init.yaml'

	# Install as root:root with rw-rw-r-- privileges
	$EXEC_CP --preserve=all /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.orig

else
	printBanner 'Reconfiguring /etc/netplan/50-cloud-init.yaml'

	# Install as root:root with rw-rw-r-- privileges
	$EXEC_CP --preserve=all /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bak
fi

#
# Configure network interfaces
#
mapfile -t ethInterfaceList < <( $EXEC_IP -br link show | $EXEC_AWK '/^e/{ print $1 }' )

COLUMNS=1
for ethInterface in "${ethInterfaceList[@]}"; do

	# Select either Static IP or DHCP
	echo "${bold}${yellow}What kind of IP configuration do you want to use for '${green}$ethInterface${yellow}'?${white}"
	select IP_CONFIG in 'Static IP' 'DHCP' 'Skip'; do
		if [ "$IP_CONFIG" == 'Static IP' ] || [ "$IP_CONFIG" == 'DHCP' ] || [ "$IP_CONFIG" == 'Skip' ]; then
			echo
			break;
		fi
	done

	if [ "$IP_CONFIG" != 'Skip' ]; then

		if [ "$IP_CONFIG" == 'Static IP' ]; then
			IPv4_ADDRESS=''
			IPv4_GATEWAY=''
			IPv4_SUBNET=''

			# Retrieve the current IPv4 configuration
			ethInfo=( $($EXEC_DERIVESUBNET -4 $ethInterface) )

			if [ $? -eq 0 ]; then
				IPv4_ADDRESS=${ethInfo[0]}
				IPv4_GATEWAY=${ethInfo[1]}
				IPv4_SUBNET=${ethInfo[2]}
			fi

			# Procure the IPv4 address
			read -p "${bold}${green}What is the IPv4 address?: ${reset}" -i "$IPv4_ADDRESS" -e IPv4_ADDRESS

			if ! $EXEC_VERIFYIP "$IPv4_ADDRESS"; then
				IPv4_ADDRESS=''
			fi

			while [ -z "$IPv4_ADDRESS" ]; do
				read -p "${bold}${green}What is the IPv4 address?: ${reset}" -i "$IPv4_ADDRESS" -e IPv4_ADDRESS

				if ! $EXEC_VERIFYIP "$IPv4_ADDRESS"; then
					IPv4_ADDRESS=''
				fi
			done

			# Make sure the IPv4 Address has a CIDR suffix
			if [[ ! "$IPv4_ADDRESS" =~ /[0-9]+$ ]]; then
				IPv4_ADDRESS="${IPv4_ADDRESS}/32"
			fi

			# Procure the IPv4 gateway
			read -p "${bold}${green}What is the IPv4 gateway?: ${reset}" -i "$IPv4_GATEWAY" -e IPv4_GATEWAY

			if ! $EXEC_VERIFYIP "$IPv4_GATEWAY"; then
				IPv4_GATEWAY=''
			fi

			while [ -z "$IPv4_GATEWAY" ]; do
				read -p "${bold}${green}What is the IPv4 gateway?: ${reset}" -i "$IPv4_GATEWAY" -e IPv4_GATEWAY

				if ! $EXEC_VERIFYIP "$IPv4_GATEWAY"; then
					IPv4_GATEWAY=''
				fi
			done

			IPv6_ADDRESS_GLOBAL=''
			IPv6_ADDRESS_LOCAL=''
			IPv6_GATEWAY=''

			# Retrieve the current IPv6 configuration
			set +o errexit

			ethInfo=( $($EXEC_DERIVESUBNET -6 $ethInterface) )

			hasIPv6=$?

			set -o errexit

			if [ $hasIPv6 -eq 0 ]; then
				IPv6_ADDRESS_GLOBAL=${ethInfo[0]}
				IPv6_ADDRESS_LOCAL=${ethInfo[1]}
				IPv6_GATEWAY=${ethInfo[2]}

				# Procure the IPv6 global address
				read -p "${bold}${green}What is the IPv6 global address?: ${reset}" -i "$IPv6_ADDRESS_GLOBAL" -e IPv6_ADDRESS_GLOBAL

				if ! $EXEC_VERIFYIP "$IPv6_ADDRESS_GLOBAL"; then
					IPv6_ADDRESS_GLOBAL=''
				fi

				while [ -z "$IPv6_ADDRESS_GLOBAL" ]; do
					read -p "${bold}${green}What is the IPv6 global address?: ${reset}" -i "$IPv6_ADDRESS_GLOBAL" -e IPv6_ADDRESS_GLOBAL

					if ! $EXEC_VERIFYIP "$IPv6_ADDRESS_GLOBAL"; then
						IPv6_ADDRESS_GLOBAL=''
					fi
				done

				# Procure the IPv6 local address
				read -p "${bold}${green}What is the IPv6 local address?: ${reset}" -i "$IPv6_ADDRESS_LOCAL" -e IPv6_ADDRESS_LOCAL

				if ! $EXEC_VERIFYIP "$IPv6_ADDRESS_LOCAL"; then
					IPv6_ADDRESS_LOCAL=''
				fi

				while [ -z "$IPv6_ADDRESS_LOCAL" ]; do
					read -p "${bold}${green}What is the IPv6 local address?: ${reset}" -i "$IPv6_ADDRESS_LOCAL" -e IPv6_ADDRESS_LOCAL

					if ! $EXEC_VERIFYIP "$IPv6_ADDRESS_LOCAL"; then
						IPv6_ADDRESS_LOCAL=''
					fi
				done

				# Procure the IPv6 gateway
				read -p "${bold}${green}What is the IPv6 gateway?: ${reset}" -i "$IPv6_GATEWAY" -e IPv6_GATEWAY

				if ! $EXEC_VERIFYIP "$IPv6_GATEWAY"; then
					IPv6_GATEWAY=''
				fi

				while [ -z "$IPv6_GATEWAY" ]; do
					read -p "${bold}${green}What is the IPv6 gateway?: ${reset}" -i "$IPv6_GATEWAY" -e IPv6_GATEWAY

					if ! $EXEC_VERIFYIP "$IPv6_GATEWAY"; then
						IPv6_GATEWAY=''
					fi
				done
			fi

			# Configure netplan
			netplanConfig="$netplanConfig        $ethInterface:\n"
			netplanConfig="$netplanConfig            wakeonlan: false\n"
			netplanConfig="$netplanConfig            dhcp4: no\n"
			netplanConfig="$netplanConfig            dhcp6: no\n"
			netplanConfig="$netplanConfig            accept-ra: no\n"

			if [ $hasIPv6 -eq 0 ]; then
				netplanConfig="$netplanConfig            addresses: [$IPv4_ADDRESS, \"$IPv6_ADDRESS_GLOBAL\", \"$IPv6_ADDRESS_LOCAL\"]\n"
			else
				netplanConfig="$netplanConfig            addresses: [$IPv4_ADDRESS]\n"
			fi

			netplanConfig="$netplanConfig            gateway4: $IPv4_GATEWAY\n"

			if [ $hasIPv6 -eq 0 ]; then
				netplanConfig="$netplanConfig            gateway6: $IPv6_GATEWAY\n"
			fi

			netplanConfig="$netplanConfig            nameservers:\n"
			if [ $hasIPv6 -eq 0 ]; then
				netplanConfig="$netplanConfig                addresses: [127.0.0.1, \"::1\"]\n"
			else
				netplanConfig="$netplanConfig                addresses: [127.0.0.1]\n"
			fi

			if [ $hasIPv6 -eq 0 ]; then
				# Configure sysctl for static IPv6 address
				sysctlConfig="${sysctlConfig}net.ipv6.conf.$ethInterface.autoconf = 0\n"
				sysctlConfig="${sysctlConfig}net.ipv6.conf.$ethInterface.accept_ra = 0\n"
				sysctlConfig="${sysctlConfig}net.ipv6.conf.$ethInterface.accept_dad = 0\n"
				sysctlConfig="${sysctlConfig}net.ipv6.conf.$ethInterface.dad_transmits = 0\n"
			fi
		else
			MAC_ADDRESS="$($EXEC_IP -br link show $ethInterface | $EXEC_AWK '{ print $3 }')"

			netplanConfig="$netplanConfig        $ethInterface:\n"
			netplanConfig="$netplanConfig            wakeonlan: false\n"
			netplanConfig="$netplanConfig            dhcp4: yes\n"
			netplanConfig="$netplanConfig            match:\n"
			netplanConfig="$netplanConfig                 macaddress: $MAC_ADDRESS\n"
			netplanConfig="$netplanConfig            set-name: $ethInterface\n"
		fi

	fi
done

if [ -z "$netplanConfig" ]; then
	exit 0
fi

if [ $hasIPv6 -eq 0 ]; then

#
# Backup 41-ipv6-static.conf
#
if [ -f /etc/sysctl.d/41-ipv6-static.conf ]; then
	printInfo "Backing up /etc/sysctl.d/41-ipv6-static.conf"
	$EXEC_CP --archive /etc/sysctl.d/41-ipv6-static.conf /etc/sysctl.d/41-ipv6-static.conf.bak
fi

#
# Generate 41-ipv6-static.conf
#

/bin/cat << EOF > /etc/sysctl.d/41-ipv6-static.conf
#
# 41-ipv6-static.conf - DevOpsBroker static IPv6 address configuration file
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

# Disable IPv6 autoconfiguration
$(echo -e $sysctlConfig)

EOF

fi

#
# Backup 50-network-init.yaml
#
if [ -f /etc/netplan/50-network-init.yaml ]; then
	printInfo "Backing up /etc/netplan/50-network-init.yaml"
	$EXEC_CP --archive /etc/netplan/50-network-init.yaml /etc/netplan/50-network-init.yaml.bak
fi

#
# Generate 50-network-init.yaml
#
/bin/cat << EOF > /etc/netplan/50-network-init.yaml
#
# 50-network-init.yaml - DevOpsBroker Netplan network configuration file
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

network:
    version: 2
    renderer: networkd
    ethernets:
$(echo -e $netplanConfig)

EOF

#
# Try the new Netplan network configuration
#
$EXEC_NETPLAN try

exit 0
