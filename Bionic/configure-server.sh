#!/bin/bash

#
# configure-server.sh - DevOpsBroker configuration script for Ubuntu 18.04 Server
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
# Performs the following configurations:
#   o Configures IPv4 firewall and IPv6 firewall using iptables and ip6tables
#   o Installs all DevOpsBroker system administration and user utilities
#   o Installs a number of useful applications, libraries and utilities
#   o Installs any available proprietary drivers
#   o Configures and optimizes the filesystem
#   o Performs Linux kernel tuning optimizations
#   o Performs general system configuration
#   o Configures the fastest APT sources mirror
#   o Configures and optimizes GRUB
#   o Manages DevOpsBroker configuration files (e.g. ansi.conf)
#   o Tunes the default network interface card
#   o Configures systemwide security configuration
#   o Configures the Disk I/O schedulers and tunes each disk independently
#   o Replaces dnsmasq with unbound for the local DNS cache server
#   o Performs user configuration
#
# Unnstalls the following packages:
#   o cloud-guest-utils (if VM guest)
#   o cloud-init (if VM guest)
#   o dnsmasq
#   o geoip-bin
#   o geoip-database
#   o irqbalance
#   o lxd lxd-client lxcfs (if VM guest)
#   o ntfs-3g
#   o snapd
#   o squashfs-tools
#
# Useful Linux Command-Line Utilities
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Dynamic real-time view of running processes:
#   o htop
#
# Snapshot view of active processes:
#   o ps
#
# Check Available RAM:
#   o free -h
#
# Report virtual memory statistics (PGPGIN/PGPGOUT):
#   o vmstat -s
#
# View USB Device Tree:
#   o lsusb -tv
#
# View PCI Device Tree:
#   o lspci -tv
#
# View Filesystem Types and Mountpoints:
#   o lsblk -o NAME,FSTYPE,LABEL,SIZE,UUID,MOUNTPOINT
#
# View status of Linux Kernel modules:
#   o lsmod
#
# View which devices and handlers are currently active:
#   o cat /proc/bus/input/devices
#
# View every program which is listening on sockets for TCP/UDP traffic:
#   o sudo netstat -tulpn
#
# Scan the 192.168.0.0/24 subnet for every device with an open port 631:
#   o nmap -p T:631 192.168.0.0/24 | grep -B4 open
#
# Interrup processing by CPU:
#   o cat /proc/interrupts
#
# Monitor kernel behavior with regard to the dirty pages:
#   o grep -A 1 dirty /proc/vmstat
#
# Check cwnd runtime value:
#   o ss -nli | fgrep cwnd
#
# Determine Connection States:
#   o netstat -tan | grep ':80 ' | awk '{print $6}' | sort | uniq -c
#
# Bounce the network interface:
#   o TODO: How to do this with netplan
#   o sudo ifdown enp4s0 && sudo ifup enp4s0
#
# View TCP/UDP/IP Session Information:
#   o ss -s
#
# Measure read speed of any drive (Hard Drive/SSD/USB):
#   o hdparm -t /dev/sd(a|b|c|d...)
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

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Ubuntu Version Check ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Check which version of Ubuntu is installed
DISTRO_INFO="$(/usr/bin/lsb_release -sc)"

# Display error if not running on Ubuntu 18.04 Bionic
if [ "$DISTRO_INFO" != 'bionic' ]; then
	printError "$SCRIPT_EXEC" "Invalid Linux distribution '$DISTRO_INFO'"
	exit 1
fi

################################## Functions ##################################

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     installPackage
# Description:  Installs the specified package, if not already installed
#
# Parameter $1: The file to check for existence; install if not present
# Parameter $2: The name of the package to install
# -----------------------------------------------------------------------------
function installPackage() {
	INSTALL_PKG='false'

	if [ ! -f "$1" ]; then
		printBanner "Installing $2"
		$EXEC_APT -y install $2
		echo

		INSTALL_PKG='true'
	fi
}

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     uninstallPackage
# Description:  Uninstalls the specified package, if already installed
#
# Parameter $1: The file to check for existence; uninstall if present
# Parameter $2: The name of the package to uninstall
# -----------------------------------------------------------------------------
function uninstallPackage() {
	UNINSTALL_PKG='false'

	if [ -f "$1" ]; then
		printBanner "Uninstalling $2"
		$EXEC_APT -y purge $2
		echo

		UNINSTALL_PKG='true'
	fi
}

################################## Variables ##################################

## Bash exec variables
EXEC_ADD_APT_REPO=/usr/bin/add-apt-repository
EXEC_DMESG=/bin/dmesg
EXEC_LSCPU=/usr/bin/lscpu

## Variables
DEFAULT_NIC=''
DEPLOY_ENV=''
IS_AMD=0
IS_KVM=0
IS_VM_GUEST=0
IPTABLES_SCRIPT=''
IP6TABLES_SCRIPT=''

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Configurator" 'true'

# Detect whether Ubuntu Server is running as a guest in a virtual machine
detectVirtualization

# Detect if we are running on an AMD CPU
if [ "$($EXEC_LSCPU | $EXEC_AWK '/Vendor ID:/{ print $3 }')" == 'AuthenticAMD' ]; then
	IS_AMD=1
fi

# Execute an 'apt update' to refresh the local APT package cache
$EXEC_APT update
echo

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Firewall ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

set +o errexit
mapfile -t ethList < <($EXEC_IP -br -4 addr show | $EXEC_GREP -Eo '^(enp|ens)[a-z0-9]+')
set -o errexit

if [ ${#ethList[@]} -eq 1 ]; then
	DEFAULT_NIC=(${ethList[0]})
else
	COLUMNS=1
	echo "${bold}${yellow}Which Ethernet interface do you want to configure?${white}"
	select DEFAULT_NIC in ${ethList[@]}; do
		break;
	done
fi

echo "${bold}${yellow}Where is this Ubuntu Server deployed?${white}"
select DEPLOY_ENV in 'Public Internet' 'Private Intranet'; do
	if [[ "$DEPLOY_ENV" =~ ^Public ]]; then
		IPTABLES_SCRIPT="$SCRIPT_DIR/etc/network/iptables-public.sh"
		IP6TABLES_SCRIPT="$SCRIPT_DIR/etc/network/ip6tables-public.sh"
	else
		IPTABLES_SCRIPT="$SCRIPT_DIR/etc/network/iptables-private.sh"
		IP6TABLES_SCRIPT="$SCRIPT_DIR/etc/network/ip6tables-private.sh"
	fi
	break;
done

# Install iptables
installPackage '/sbin/iptables' 'iptables'

# Install ipset
installPackage '/sbin/ipset' 'ipset'

# Configure IPv4 firewall
if [ ! -f /etc/network/iptables.rules ] || \
	[ "$IPTABLES_SCRIPT" -nt /etc/network/iptables.rules ]; then

		"$IPTABLES_SCRIPT" $DEFAULT_NIC
		echo
fi

# Configure IPv6 firewall
if [ ! -f /etc/network/ip6tables.rules ] || \
	[ "$IP6TABLES_SCRIPT" -nt /etc/network/ip6tables.rules ]; then

		"$IP6TABLES_SCRIPT" $DEFAULT_NIC
		echo
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~ DevOpsBroker Utilities ~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Install and/or update DevOpsBroker system administration and user utilities
if [ -f "$SCRIPT_DIR"/update-utils.sh ]; then
	"$SCRIPT_DIR"/update-utils.sh
fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~ APT Sources Configuration ~~~~~~~~~~~~~~~~~~~~~~~~~

# Install curl
installPackage '/usr/bin/curl' 'curl'

# Install gawk
installPackage '/usr/bin/gawk' 'gawk'

# Install parallel
installPackage '/usr/bin/parallel' 'parallel'

# Configure /etc/apt/sources.list with configure-apt-mirror.sh script
"$SCRIPT_DIR"/etc/apt/configure-apt-mirror.sh

#~~~~~~~~~~~~~~~~~~~~ Applications / Libraries / Utilities ~~~~~~~~~~~~~~~~~~~~

# Uninstall cloud-init and lxd if running under KVM
if [ $IS_KVM -eq 1 ]; then
	uninstallPackage '/usr/bin/cloud-init' 'cloud-init'

	if [ "$UNINSTALL_PKG" == 'true' ]; then
		$EXEC_RM -rf /etc/cloud
		$EXEC_RM -rf /var/lib/cloud
		/usr/sbin/groupdel lxd
		# TODO: /etc/netplan/50-cloud-init.yaml needs to be replaced by this configuration

		uninstallPackage '/usr/bin/growpart' 'cloud-guest-utils'
		uninstallPackage '/usr/bin/lxd' 'lxd'
		uninstallPackage '/usr/bin/lxc' 'lxd-client'
		uninstallPackage '/usr/bin/lxcfs' 'lxcfs'
		uninstallPackage '/usr/share/doc/liblxc1/copyright' 'liblxc1'
		uninstallPackage '/usr/share/doc/liblxc-common/copyright' 'liblxc-common'
	fi
fi

# Install aspell
installPackage '/usr/bin/aspell' 'aspell'

# Install dnsutils
installPackage '/usr/bin/dig' 'dnsutils'

# Uninstall fail2ban (use sshguard instead)
uninstallPackage '/usr/bin/fail2ban-client' 'fail2ban'

# Uninstall geoip-bin
uninstallPackage '/usr/bin/geoiplookup' 'geoip-bin'

# Uninstall geoip-database
uninstallPackage '/usr/share/GeoIP/GeoIP.dat' 'geoip-database'

# Install htop
installPackage '/usr/bin/htop' 'htop'

# Install hwinfo
installPackage '/usr/sbin/hwinfo' 'hwinfo'

# Install ioping
installPackage '/usr/bin/ioping' 'ioping'

# Uninstall irqbalance
uninstallPackage '/usr/sbin/irqbalance' 'irqbalance'

# Install linux-generic-hwe-18.04
set +o errexit
isGCPKernel="$( /bin/uname -r | $EXEC_GREP gcp$ )"
set -o errexit

if [ -z "$isGCPKernel" ]; then
	installPackage '/usr/share/doc/linux-generic-hwe-18.04/copyright' 'linux-generic-hwe-18.04'
fi

# Install logwatch
installPackage '/usr/sbin/logwatch' 'logwatch'

# Install mmdblookup
installPackage '/usr/bin/mmdblookup' 'mmdb-bin'

if [ "$INSTALL_PKG" == 'true' ] || [ ! -d /usr/share/GeoLite2 ]; then
	# Install GeoLite2 City geolocation database
	/usr/local/bin/geoip update
	echo
fi

# Install mutt
installPackage '/usr/bin/mutt' 'mutt'

# Install net-tools
installPackage '/bin/netstat' 'net-tools'

# Install networkd-dispatcher
installPackage '/usr/bin/networkd-dispatcher' 'networkd-dispatcher'

if [ "$INSTALL_PKG" == 'true' ]; then
	$EXEC_SYSTEMCTL daemon-reload

	printInfo 'Enabling networkd-dispatcher.service'
	$EXEC_SYSTEMCTL enable networkd-dispatcher.service

	printInfo 'Starting networkd-dispatcher.service'
	$EXEC_SYSTEMCTL start networkd-dispatcher.service
fi

# Install nmap
installPackage '/usr/bin/nmap' 'nmap'

# Uninstall ntfs-3g
uninstallPackage '/bin/ntfs-3g' 'ntfs-3g'

# Install ntp
installPackage '/usr/sbin/ntpd' 'ntp'

# Install openresolv
installPackage '/sbin/resolvconf' 'openresolv'

# Install openssh-client
installPackage '/usr/bin/ssh' 'openssh-client'

# Install openssh-server
installPackage '/usr/sbin/sshd' 'openssh-server'

# Install openssh-sftp-server
installPackage '/usr/lib/openssh/sftp-server' 'openssh-sftp-server'

# Install postfix
installPackage '/usr/sbin/postfix' 'postfix'

# Install sendmail
installPackage '/usr/sbin/sendmail' 'sendmail'

# Install sshguard
installPackage '/usr/sbin/sshguard' 'sshguard'

# Uninstall snapd
uninstallPackage '/usr/bin/snap' 'snapd'
uninstallPackage '/usr/bin/mksquashfs' 'squashfs-tools'

# Install speedtest-cli
installPackage '/usr/bin/speedtest-cli' 'speedtest-cli'

# Install sysfsutils
installPackage '/usr/bin/systool' 'sysfsutils'

# Install sysstat
#installPackage '/usr/bin/iostat' 'sysstat'

# Uninstall thermald if running on AMD
if [ $IS_AMD -eq 1 ]; then
	uninstallPackage '/usr/sbin/thermald' 'thermald'
else
	installPackage '/usr/sbin/thermald' 'thermald'
fi

# Install tree
installPackage '/usr/bin/tree' 'tree'

# Install unbound
installPackage '/usr/sbin/unbound' 'unbound'

# Install util-linux
installPackage '/bin/dmesg' 'util-linux'

# Install whois
installPackage '/usr/bin/whois' 'whois'

# ~~~~~~~~~~~~~~~~~~~~~~~~~ System/User Configuration ~~~~~~~~~~~~~~~~~~~~~~~~~

#
# Filesystem Configuration
#

# Configure /etc/fstab with configure-fstab.sh script
"$SCRIPT_DIR"/etc/configure-fstab.sh

#
# Linux Kernel Tuning
#

# Configure /etc/sysctl.conf with configure-kernel.sh script
"$SCRIPT_DIR"/etc/configure-kernel.sh

#
# General System Configuration
#

# Configure system with configure-system.sh script
"$SCRIPT_DIR"/etc/configure-system.sh

#
# GRUB Configuration
#

# Configure /etc/default/grub with configure-grub.sh script
"$SCRIPT_DIR"/etc/default/configure-grub.sh

#
# Unbound DNS Cache Server Configuration
#

# Configure /etc/unbound/unbound.conf.d/ with configure-unbound.sh script
"$SCRIPT_DIR"/etc/unbound/configure-unbound.sh

#
# Netplan Configuration
#

# Configure /etc/netplan/50-network-init.yaml with configure-netplan.sh script
"$SCRIPT_DIR"/etc/netplan/configure-netplan.sh

#
# Networkd-Dispatcher Configuration
#

# Configure /etc/networkd-dispatcher with configure-nic.sh script
"$SCRIPT_DIR"/etc/networkd-dispatcher/configure-nic.sh $DEFAULT_NIC

#
# Systemwide Security Configuration
#

# Configure /etc/security/limits.d/ with configure-security.sh script
"$SCRIPT_DIR"/etc/security/configure-security.sh

#
# Udev Configuration
#

# Only run UDev configuration if running on bare metal
if [ $IS_VM_GUEST -eq 0 ]; then
	# Configure /etc/udev/rules.d/ with configure-udev.sh script
	"$SCRIPT_DIR"/etc/udev/configure-udev.sh
fi

#
# User Configuration
#

# Configure the user with configure-user.sh script
"$SCRIPT_DIR"/home/configure-user.sh $SUDO_USER

#
# LogWatch Configuration
#

# Configure LogWatch with configure-logwatch.sh script
"$SCRIPT_DIR"/usr/share/logwatch/default.conf/configure-logwatch.sh

# Uninstall dnsmasq
uninstallPackage '/etc/dnsmasq.conf' 'dnsmasq'

#
# Upgrade Ubuntu
#

today=$($EXEC_DATE -I)
if [ ! -f /etc/devops/last-update ] || [ $($EXEC_CAT /etc/devops/last-update) != $today ]; then
  /usr/local/sbin/pms upgrade
fi

echo 'Done!'
echo

exit 0
