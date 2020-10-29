#!/bin/bash

readonly GRAY='\e[1;30m'
readonly GREEN='\e[1;32m'
readonly YELLOW='\e[1;33m'
readonly CYAN='\e[1;36m'
readonly NC='\e[0m'


function echo_json_upd() {
	echo -e "$1"
	[[ -t 3 ]] && echo -e "{\"message\":\"$(echo "$1" | sed 's/\\e\[[0-9;]*m//g')\",\"retcode\":$2}" >&3
}

function WAIT_FOR_APT_GET() {
  ONCE=0
  while [[ $(sudo lslocks -n -o COMMAND,PID,PATH | grep -c 'apt-get\|dpkg\|unattended-upgrades') -ne 0 ]]; do
    if [[ "${ONCE}" -eq 0 ]]; then
      while read -r LOCKINFO; do
        PID=$(echo "${LOCKINFO}" | awk '{print $2}')
        ps -up "${PID}"
        echo "${LOCKINFO}"
      done <<<"$(sudo lslocks -n -o COMMAND,PID,PATH | grep 'apt-get\|dpkg\|unattended-upgrades')"
      ONCE=1
      if [[ ${ARG6} == 'y' ]]; then
        echo "Waiting for apt-get to finish"
      fi
    fi
    if [[ ${ARG6} == 'y' ]]; then
      printf "."
    else
      echo -e "\\r${SP:i++%${#SP}:1} Waiting for apt-get to finish... \\c"
    fi
    sleep 0.3
  done
  echo
  echo -e "\\r\\c"
  stty sane 2>/dev/null
}


function CHECK_SYSTEM() {
  local OS
  local VER
  local TARGET
  local FREEPSPACE_ALL
  local FREEPSPACE_BOOT
  local ARCH

  # Only run if user has sudo.
  sudo true >/dev/null 2>&1
  USRNAME_CURRENT=$(whoami)
  CAN_SUDO=0
  CAN_SUDO=$(timeout --foreground --signal=SIGKILL 1s bash -c "sudo -l 2>/dev/null | grep -v '${USRNAME_CURRENT}' | wc -l ")
  if [[ ${CAN_SUDO} =~ ${RE} ]] && [[ "${CAN_SUDO}" -gt 2 ]]; then
    :
  else
    echo "Script must be run as a user with no password sudo privileges"
    echo "To switch to the root user type"
    echo
    echo "sudo su"
    echo
    echo "And then re-run this command."
    return 1 2>/dev/null || exit 1
  fi

  # Make sure sudo will work
  if [[ $(sudo false 2>&1) ]]; then
    echo "$(hostname -I | awk '{print $1}') $(hostname)" >>/etc/hosts
  fi

  # Make sure home is set.
  if [[ -z "${HOME}" ]]; then
    echo
    echo "Please set the HOME variable."
    echo
    return 1 2>/dev/null || exit 1
  fi

  # Check for systemd
  systemctl --version >/dev/null 2>&1 || {
    cat /etc/*-release
    echo
    echo "systemd is required. Are you using Ubuntu 16.04?" >&2
    return 1 2>/dev/null || exit 1
  }

  # Check for Ubuntu
  if [ -r /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
  elif type lsb_release >/dev/null 2>&1; then
    # linuxbase.org
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
  elif [ -r /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    . /etc/lsb-release
    OS=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
  elif [ -r /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    OS=Debian
    VER=$(cat /etc/debian_version)
  elif [ -r /etc/SuSe-release ]; then
    # Older SuSE/etc.
    ...
  elif [ -r /etc/redhat-release ]; then
    # Older Red Hat, CentOS, etc.
    ...
  else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    VER=$(uname -r)
  fi

  if [ "${OS}" != "Ubuntu" ]; then
    cat /etc/*-release
    echo
    echo "Are you using Ubuntu 16.04 or higher?"
    echo
    return 1 2>/dev/null || exit 1
  fi

  TARGET='16.04'
  if [[ "${VER%.*}" -eq "${TARGET%.*}" ]] && [[ "${VER#*.}" -ge "${TARGET#*.}" ]] || [[ "${VER%.*}" -gt "${TARGET%.*}" ]]; then
    :
  else
    cat /etc/*-release
    echo
    echo "Are you using Ubuntu 16.04 or higher?"
    echo
    return 1 2>/dev/null || exit 1
  fi

  # Make sure it's 64bit.
  ARCH=$(uname -m)
  if [[ "${ARCH}" != "x86_64" ]]; then
    echo
    echo "${ARCH} is not x86_64. A 64bit OS is required."
    echo
    return 1 2>/dev/null || exit 1
  fi

  # Check hd space.
  FREEPSPACE_ALL=$(df -P . | tail -1 | awk '{print $4}')
  FREEPSPACE_BOOT=$(df -P /boot | tail -1 | awk '{print $4}')
  if [ "${FREEPSPACE_ALL}" -lt 1572864 ] || [ "${FREEPSPACE_BOOT}" -lt 131072 ]; then
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get clean
    WAIT_FOR_APT_GET
    sudo apt autoremove
    WAIT_FOR_APT_GET
    sudo dpkg -l linux-* | awk '/^ii/{ print $2}' | grep -v -e "$(uname -r | cut -f1,2 -d "-")" | grep -e '[0-9]' | grep -E "(image|headers)" | xargs sudo DEBIAN_FRONTEND=noninteractive apt-get -y purge
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt -y autoremove
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get clean
    rm -R -- /var/multi-masternode-data/*/

    FREEPSPACE_ALL=$(df -P . | tail -1 | awk '{print $4}')
    FREEPSPACE_BOOT=$(df -P /boot | tail -1 | awk '{print $4}')
    if [ "${FREEPSPACE_ALL}" -lt 1572864 ] || [ "${FREEPSPACE_BOOT}" -lt 131072 ]; then
      echo
      echo "${FREEPSPACE_ALL} Kbytes of free disk space found."
      echo "1572864 Kbytes (1.5 GB) of free space is needed to proceed"
      echo "${FREEPSPACE_BOOT} Kbytes of free disk space found on /boot."
      echo "131072 Kbytes (128 MB) of free space is needed on the boot folder to proceed"
      echo
      return 1 2>/dev/null || exit 1
    fi
  fi

  # Check ram.
  MEM_AVAILABLE=$(sudo cat /proc/meminfo | grep -i 'MemAvailable:\|MemFree:' | awk '{print $2}' | tail -n 1)
  if [[ "${MEM_AVAILABLE}" -lt 65536 ]]; then
    SWAP_FREE=$(free | grep -i 'Swap:' | awk '{print $4}')
    echo
    echo "Free Memory: ${MEM_AVAILABLE} kb"
    stty sane 2>/dev/null
    if [[ "${SWAP_FREE}" -lt 524288 ]]; then
      echo "Free Swap Space: ${SWAP_FREE} kb"
      echo
      echo "This linux box may not have enough resources to run a ${MASTERNODE_NAME} daemon."
      echo "If I were you I'd get a better linux box."
      echo "ctrl-c to exit this script."
      echo
      read -r -t 10 -p "Hit ENTER to continue or wait 10 seconds" 2>&1
    else
      echo "Note: This linux box may not have enough free memory to run a ${MASTERNODE_NAME} daemon."
      read -r -t 5 -p "Hit ENTER to continue or wait 5 seconds" 2>&1
    fi
    echo
  fi
}

function SYSTEM_UPDATE_UPGRADE() {
  (
    sudo -n renice 15 $BASHPID

    local TOTAL_RAM
    local TARGET_SWAP
    local SWAP_SIZE
    local FREE_HD
    local MIN_SWAP

    # Log to a file.
    exec > >(tee -ia "${DAEMON_SETUP_LOG}")
    exec 2> >(tee -ia "${DAEMON_SETUP_LOG}" >&2)

    echo "Make swap file if one does not exist."
    if [ ! -x "$(command -v bc)" ] || [ ! -x "$(command -v jq)" ] || [[ ! -x "$(command -v pv)" ]]; then
      WAIT_FOR_APT_GET
      sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq bc jq pv
    fi
    SWAP_SIZE=$(echo "scale=2; $(grep -i 'Swap' /proc/meminfo | awk '{print $2}' | xargs | jq -s max) / 1024" | bc | awk '{printf("%d\n",$1 + 0.5)}')
    if [ -z "${SWAP_SIZE}" ]; then
      SWAP_SIZE=0
    fi
    TOTAL_RAM=$(echo "scale=2; $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024" | bc | awk '{printf("%d\n",$1 + 0.5)}')
    FREE_HD=$(echo "scale=2; $(df -P . | tail -1 | awk '{print $4}') / 1024" | bc | awk '{printf("%d\n",$1 + 0.5)}')
    MIN_SWAP=4096
    TARGET_SWAP=$((TOTAL_RAM * 5))
    TARGET_SWAP=$((TARGET_SWAP > MIN_SWAP ? TARGET_SWAP : MIN_SWAP))
    TARGET_SWAP=$((FREE_HD / 5 < TARGET_SWAP ? FREE_HD / 5 : TARGET_SWAP))

    if [[ "${SWAP_SIZE}" -lt "${TARGET_SWAP}" ]] && [[ ! -f /var/swap.img ]]; then
      if [[ ! -x "$(command -v pv)" ]]; then
        WAIT_FOR_APT_GET
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq pv
      fi
      TARGET_SWAP=$(echo "${TARGET_SWAP} * 1024 * 1024" | bc)
      sudo touch /var/swap.img
      sudo chmod 666 /var/swap.img
      # Rate limit swap creation to prevent system lockup.
      nice -n 15 head -c "${TARGET_SWAP}" </dev/zero | pv -q --rate-limit 70m >/var/swap.img
      sudo chmod 600 /var/swap.img
      sudo mkswap /var/swap.img
      sudo swapon /var/swap.img
      OUT=$?
      if [ $OUT -eq 255 ]; then
        echo "System does not support swap files."
        sudo rm /var/swap.img
      else
        echo "/var/swap.img none swap sw 0 0" >>/etc/fstab
      fi
    fi

    # Update the system.
    echo "# Updating software"
    WAIT_FOR_APT_GET
    sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq libc6
    WAIT_FOR_APT_GET
    sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get -yq -o DPkg::options::="--force-confdef" \
      -o DPkg::options::="--force-confold" install grub-pc
    WAIT_FOR_APT_GET
    sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq
    WAIT_FOR_APT_GET
    sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -yq
    echo "# Updating system"
    WAIT_FOR_APT_GET
    sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get -yq -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confold" dist-upgrade
    #   WAIT_FOR_APT_GET
    sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -yq

    WAIT_FOR_APT_GET
    sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq unattended-upgrades

    if [ ! -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
      # Enable auto updating of Ubuntu security packages.
      cat <<UBUNTU_SECURITY_PACKAGES | sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null
APT::Periodic::Enable "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
UBUNTU_SECURITY_PACKAGES
    fi

    # Force run unattended upgrade to get everything up to date.
    sudo -n nice -n 15 sudo unattended-upgrade -d
    WAIT_FOR_APT_GET
    sudo -n nice -n 15 sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -yq
  )
}

function INITIAL_PROGRAMS() {
  local LAST_LOGIN_IP
  local LAST_UPDATED
  local UNIX_TIME
  local TIME_DIFF
  local LOGGED_IN_USR
  local COUNTER

  # Fix broken apt-get
  WAIT_FOR_APT_GET
  sudo dpkg --configure -a
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -yq

  # Only run apt-get update if not ran in the last 12 hours.
  LAST_UPDATED=$(stat --format="%X" /var/cache/apt/pkgcache.bin)
  UNIX_TIME=$(date -u +%s)
  TIME_DIFF=$((UNIX_TIME - LAST_UPDATED))
  if [[ "${TIME_DIFF}" -gt 43200 ]]; then
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq
  fi

  # Make sure python3 is available.
  if [ ! -x "$(command -v python3)" ]; then
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq python3
  fi

  # Make sure add-apt-repository is available.
  if [ ! -x "$(command -v add-apt-repository)" ]; then
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq software-properties-common
  fi

  if [[ $(grep /etc/apt/sources.list -ce '^deb.*universe') -eq 0 ]]; then
    WAIT_FOR_APT_GET
    sudo add-apt-repository universe
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq
  fi

  # Clear /var/log/auth.log of this IP before installing denyhosts.
  if ! [ -x "$(command -v denyhosts)" ]; then
    LOGGED_IN_USR=$(whoami)
    LAST_LOGIN_IP=$(sudo last -i | grep -v '0.0.0.0' | grep "${LOGGED_IN_USR}" | head -1 | awk '{print $3}')
    if [ ! -x "${LAST_LOGIN_IP}" ]; then
      echo "sshd: ${LAST_LOGIN_IP}" | sudo tee -a /etc/hosts.allow >/dev/null
    fi
    sudo touch /var/log/auth.log
    sudo chmod 640 /var/log/auth.log
    # Remove failed login attempts for this user so denyhosts doesn't block us right here.
    while read -r IP_UNBLOCK; do
      denyhosts_unblock "$IP_UNBLOCK" 2>/dev/null
      sudo sed -i -e "/$IP_UNBLOCK/d" /etc/hosts.deny
      sudo sed -i -e "/refused connect from $IP_UNBLOCK/d" /var/log/auth.log
      sudo sed -i -e "/from $IP_UNBLOCK port/d" /var/log/auth.log
      sudo iptables -D INPUT -s "${IP_UNBLOCK}" -j DROP 2>/dev/null
    done <<<"$(sudo last -ix | head -n -2 | awk '{print $3 }' | sort | uniq)"

    WAIT_FOR_APT_GET
    sudo dpkg --configure -a
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq denyhosts

    # Allow for 5 bad root login attempts before killing the ip.
    sudo sed -ie 's/DENY_THRESHOLD_ROOT \= 1/DENY_THRESHOLD_ROOT = 5/g' /etc/denyhosts.conf
    sudo sed -ie 's/DENY_THRESHOLD_RESTRICTED \= 1/DENY_THRESHOLD_RESTRICTED = 5/g' /etc/denyhosts.conf
    sudo systemctl restart denyhosts

    WAIT_FOR_APT_GET
    sudo dpkg --configure -a
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -yq
  fi

  # Make sure firewall and some utilities is installed.
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    curl \
    pwgen \
    ufw \
    lsof \
    util-linux \
    gzip \
    unzip \
    unrar \
    xz-utils \
    procps \
    jq \
    htop \
    git \
    gpw \
    bc \
    pv \
    sysstat \
    glances \
    psmisc \
    at \
    python3-pip \
    python-pip \
    subnetcalc \
    net-tools \
    sipcalc \
    python-yaml \
    html-xml-utils \
    apparmor \
    ack-grep \
    pcregrep \
    snapd \
    aria2 \
    dbus-user-session

  # Turn on firewall, allow ssh port first; default is 22.
  SSH_PORT=22
  SSH_PORT_SETTING=$(sudo grep -E '^Port [0-9]*' /etc/ssh/ssh_config | grep -o '[0-9]*' | head -n 1)
  if [[ ! -z "${SSH_PORT_SETTING}" ]] && [[ $SSH_PORT_SETTING =~ $RE ]]; then
    sudo ufw allow "${SSH_PORT_SETTING}" >/dev/null 2>&1
  else
    sudo ufw allow "${SSH_PORT}" >/dev/null 2>&1
  fi
  if [[ -f "${HOME}/.ssh/config" ]]; then
    SSH_PORT_SETTING=$(grep -E '^Port [0-9]*' "${HOME}/.ssh/config" | grep -o '[0-9]*' | head -n 1)
    if [[ ! -z "${SSH_PORT_SETTING}" ]] && [[ $SSH_PORT_SETTING =~ $RE ]]; then
      sudo ufw allow "${SSH_PORT_SETTING}" >/dev/null 2>&1
    fi
  fi
  # Maybe search all users to other ports but this would be highly unsual.

  echo "y" | sudo ufw enable >/dev/null 2>&1
  sudo ufw reload

  WAIT_FOR_APT_GET
  sudo dpkg --configure -a
  # Add in 16.04 repo.
    COUNTER=0
    if ! grep -Fxq "deb http://archive.ubuntu.com/ubuntu/ xenial-updates main restricted" /etc/apt/sources.list; then
      echo "deb http://archive.ubuntu.com/ubuntu/ xenial-updates main restricted" | sudo tee -a /etc/apt/sources.list >/dev/null
      COUNTER=1
    fi
    if ! grep -Fxq "deb http://archive.ubuntu.com/ubuntu/ xenial universe" /etc/apt/sources.list; then
      echo "deb http://archive.ubuntu.com/ubuntu/ xenial universe" | sudo tee -a /etc/apt/sources.list >/dev/null
      COUNTER=1
    fi

    # shellcheck disable=SC2941
    if [[ $(grep -r '/etc/apt' -e 'bitcoin' | wc -l) -eq 0 ]]; then
      WAIT_FOR_APT_GET
      echo | sudo add-apt-repository ppa:bitcoin/bitcoin
      COUNTER=1
    fi

    # Update apt-get info with the new repo.
    if [[ "${COUNTER}" -gt 0 ]]; then
      WAIT_FOR_APT_GET
      sudo dpkg --configure -a
      WAIT_FOR_APT_GET
      sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq
      WAIT_FOR_APT_GET
      sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -yq
    fi

    # Make sure shared libs are installed.
    WAIT_FOR_APT_GET
    sudo dpkg --configure -a
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -yq
    WAIT_FOR_APT_GET
    sudo apt install --reinstall libsodium18=1.0.8-5
    # Install libboost.
    # Install libevent.
    # Install libminiupnpc.
    # Install older db code from bitcoin repo.
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq \
      libboost-system1.58.0 \
      libboost-filesystem1.58.0 \
      libboost-program-options1.58.0 \
      libboost-thread1.58.0 \
      libboost-chrono1.58.0 \
      libevent-2.0-5 \
      libevent-core-2.0-5 \
      libevent-extra-2.0-5 \
      libevent-openssl-2.0-5 \
      libevent-pthreads-2.0-5 \
      libminiupnpc10 \
      libzmq5 \
      libdb4.8-dev \
      libdb4.8++-dev

    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq libdb5.3++-dev

  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -yq

  # Make sure jq is installed.
  if ! [ -x "$(command -v jq)" ]; then
    echo
    echo "jq not installed; exiting. This command failed"
    echo "sudo apt-get install -yq jq"
    echo
    return 1 2>/dev/null || exit 1
  fi
}


echo -e "\n===================================================\
         \n   ${GRAY}██████╗ ██╗   ██╗██████╗ ${NC}███╗   ███╗███╗   ██╗  \
         \n   ${GRAY}██╔══██╗██║   ██║██╔══██╗${NC}████╗ ████║████╗  ██║  \
         \n   ${GRAY}██║  ██║██║   ██║██████╔╝${NC}██╔████╔██║██╔██╗ ██║  \
         \n   ${GRAY}██║  ██║██║   ██║██╔═══╝ ${NC}██║╚██╔╝██║██║╚██╗██║  \
         \n   ${GRAY}██████╔╝╚██████╔╝██║     ${NC}██║ ╚═╝ ██║██║ ╚████║  \
         \n   ${GRAY}╚═════╝  ╚═════╝ ╚═╝     ${NC}╚═╝     ╚═╝╚═╝  ╚═══╝  \
         \n                                ╗ made by ${GREEN}neo3587${NC} ╔\
         \n           Source: ${CYAN}https://github.com/neo3587/dupmn${NC}\
         \n   FAQs: ${CYAN}https://github.com/neo3587/dupmn/wiki/FAQs${NC}\
         \n  BTC Donations: ${YELLOW}3F6J19DmD5jowwwQbE9zxXoguGPVR716a7${NC}\
         \n===================================================\
         \n                                                   "

dupmn_update=$(cat dupmn.sh)

if [[ ! $(command -v sudo) ]]; then
    echo -e "Installing ${CYAN}sudo${NC}..."
    apt-get install sudo
fi

if [[ -f /usr/bin/dupmn && ! $(diff -q <(echo "$dupmn_update") /usr/bin/dupmn) ]]; then
    CHECK_SYSTEM
    SYSTEM_UPDATE_UPGRADE
    INITIAL_PROGRAMS
	echo_json_upd "${GREEN}dupmn${NC} is already updated to the last version" 0
else
	echo -e "Checking needed dependencies..."
	if [[ ! $(command -v lsof) ]]; then
		echo -e "Installing ${CYAN}lsof${NC}..."
		apt-get install lsof
	fi
	if [[ ! $(command -v curl) ]]; then
		echo -e "Installing ${CYAN}curl${NC}..."
		apt-get install curl
	fi
	if [[ ! $(command -v unzip) ]]; then
        echo -e "Installing ${CYAN}unzip${NC}..."
        apt-get install unzip
    fi

    CHECK_SYSTEM
    SYSTEM_UPDATE_UPGRADE
    INITIAL_PROGRAMS

	if [[ ! -d ~/.dupmn ]]; then
		mkdir ~/.dupmn
	fi
	touch ~/.dupmn/dupmn.conf

	update=$([[ -f /usr/bin/dupmn ]] && echo "1" || echo "0")

	echo "$dupmn_update" > /usr/bin/dupmn
	chmod +x /usr/bin/dupmn

	if [[ $update == "1" ]]; then
		echo_json_upd "${GREEN}dupmn${NC} updated to the last version, pretty fast, right?" 1
	else
		echo_json_upd "${GREEN}dupmn${NC} installed, pretty fast, right?" 2
	fi
fi

echo ""
