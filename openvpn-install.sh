#!/bin/bash
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora, Oracle Linux 8, Arch Linux, Rocky Linux and AlmaLinux.
# https://github.com/angristan/openvpn-install

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ Your version of Debian is not supported."
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ Your version of Ubuntu is not supported."
				echo ""
				echo "However, if you're using Ubuntu >= 16.04 or beta, then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ ${VERSION_ID%.*} -lt 7 ]]; then
				echo "⚠️ Your version of CentOS is not supported."
				echo ""
				echo "The script only support CentOS 7 and CentOS 8."
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "Your version of Oracle Linux is not supported."
				echo ""
				echo "The script only support Oracle Linux 8."
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			if [[ $VERSION_ID == "2" ]]; then
				OS="amzn"
			elif [[ "$(echo "$PRETTY_NAME" | cut -c 1-18)" == "Amazon Linux 2023." ]] && [[ "$(echo "$PRETTY_NAME" | cut -c 19)" -ge 6 ]]; then
				OS="amzn2023"
			else
				echo "⚠️ Your version of Amazon Linux is not supported."
				echo ""
				echo "The script only support Amazon Linux 2 or Amazon Linux 2023.6+"
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2, Oracle Linux 8 or Arch Linux system"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "Sorry, you need to run this as root"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN is not available"
		exit 1
	fi
	checkOS
}

function installUnbound() {
	# If Unbound isn't installed, install it
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# Configuration
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "fedora" ]]; then
			dnf install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "arch" ]]; then
			pacman -Syu --noconfirm unbound

			# Get root servers list
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		# IPv6 DNS for all OS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			# DNS Rebinding fix
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else # Unbound is already installed
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# Add Unbound 'server' for the OpenVPN subnet
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	systemctl enable unbound
	systemctl restart unbound
}

function resolvePublicIP() {
	# IP version flags, we'll use as default the IPv4
	CURL_IP_VERSION_FLAG="-4"
	DIG_IP_VERSION_FLAG="-4"

	# Behind NAT, we'll default to the publicly reachable IPv4/IPv6.
	if [[ $IPV6_SUPPORT == "y" ]]; then
		CURL_IP_VERSION_FLAG=""
		DIG_IP_VERSION_FLAG="-6"
	fi

	# If there is no public ip yet, we'll try to solve it using: https://api.seeip.org
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.seeip.org 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: https://ifconfig.me
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://ifconfig.me 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: https://api.ipify.org
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.ipify.org 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: ns1.google.com
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(dig $DIG_IP_VERSION_FLAG TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi

	if [[ -z $PUBLIC_IP ]]; then
		echo >&2 echo "Couldn't solve the public IP"
		exit 1
	fi

	echo "$PUBLIC_IP"
}

function installQuestions() {
	echo "Welcome to the OpenVPN installer!"
	echo "The git repository is available at: https://github.com/angristan/openvpn-install"
	echo ""

	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo ""
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "Unless your server is behind NAT, it should be your public IPv4 address."

	# Detect public IPv4 address and pre-fill for the user
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# Detect public IPv6 address
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP address: " -e -i "$IP" IP
	fi
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		echo "We need it for the clients to connect to the server."

		if [[ -z $ENDPOINT ]]; then
			DEFAULT_ENDPOINT=$(resolvePublicIP)
		fi

		until [[ $ENDPOINT != "" ]]; do
			read -rp "Public IPv4 address or hostname: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
		done
	fi

	echo ""
	echo "Checking for IPv6 connectivity..."
	echo ""
	# "ping6" and "ping -6" availability varies depending on the distribution
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Your host appears to have IPv6 connectivity."
		SUGGESTION="y"
	else
		echo "Your host does not appear to have IPv6 connectivity."
		SUGGESTION="n"
	fi
	echo ""
	# Ask the user if they want to enable IPv6 regardless its availability.
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "Do you want to enable IPv6 support (NAT)? [y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "What port do you want OpenVPN to listen to?"
	echo "   1) Default: 1194"
	echo "   2) Port 53 (DNS - bypasses firewalls)"
	echo "   3) Custom"
	echo "   4) Random [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-4]$ ]]; do
		read -rp "Port choice [1-4]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		# Check if port 53 is already in use
		if ss -tulpn | grep -q ':53 '; then
			echo ""
			echo "WARNING: Port 53 appears to be in use by another process (likely a DNS server)."
			echo "Using port 53 for OpenVPN might cause conflicts with existing services."
			echo ""
			read -rp "Do you still want to use port 53? [y/n]: " -e -i n USE_PORT_53
			
			if [[ $USE_PORT_53 =~ ^[yY]$ ]]; then
				PORT="53"
				echo "Selected Port: 53 (DNS port)"
			else
				echo "Please select another port."
				PORT_CHOICE="3"  # Default to custom port selection
				until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
					read -rp "Custom port [1-65535]: " -e -i 1194 PORT
				done
			fi
		else
			PORT="53"
			echo "Selected Port: 53 (DNS port)"
		fi
		;;
	3)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Custom port [1-65535]: " -e -i 1194 PORT
		done
		;;
	4)
		# Generate random number within private ports range
		PORT=$(shuf -i49152-65535 -n1)
		echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "What DNS resolvers do you want to use with the VPN?"
	echo "   1) Current system resolvers (from /etc/resolv.conf)"
	echo "   2) Self-hosted DNS Resolver (Unbound)"
	echo "   3) Cloudflare (Anycast: worldwide)"
	echo "   4) Quad9 (Anycast: worldwide)"
	echo "   5) Quad9 uncensored (Anycast: worldwide)"
	echo "   6) FDN (France)"
	echo "   7) DNS.WATCH (Germany)"
	echo "   8) OpenDNS (Anycast: worldwide)"
	echo "   9) Google (Anycast: worldwide)"
	echo "   10) Yandex Basic (Russia)"
	echo "   11) AdGuard DNS (Anycast: worldwide)"
	echo "   12) NextDNS (Anycast: worldwide)"
	echo "   13) Custom"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-12]: " -e -i 11 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			echo ""
			echo "Unbound is already installed."
			echo "You can allow the script to configure it in order to use it from your OpenVPN clients"
			echo "We will simply add a second server to /etc/unbound/unbound.conf for the OpenVPN subnet."
			echo "No changes are made to the current configuration."
			echo ""

			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "Apply configuration changes to Unbound? [y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				# Break the loop and cleanup
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Primary DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Secondary DNS (optional): " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "Do you want to use compression? It is not recommended since the VORACLE attack makes use of it."
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"Enable compression? [y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "Choose which compression algorithm you want to use: (they are ordered by efficiency)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "Do you want to customize encryption settings?"
	echo "Unless you know what you're doing, you should stick with the default parameters provided by the script."
	echo "Note that whatever you choose, all the choices presented in the script are safe. (Unlike OpenVPN's defaults)"
	echo "See https://github.com/angristan/openvpn-install#security-and-encryption to learn more."
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "Customize encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "Choose which cipher you want to use for the data channel:"
		echo "   1) AES-128-GCM (recommended)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "Choose what kind of certificate you want to use:"
		echo "   1) ECDSA (recommended)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"Certificate key type [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "Choose which curve you want to use for the certificate's key:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Choose which size you want to use for the certificate's RSA key:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "Choose which cipher you want to use for the control channel:"
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "Choose what kind of Diffie-Hellman key you want to use:"
		echo "   1) ECDH (recommended)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH key type [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "Choose which curve you want to use for the ECDH key:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Choose what size of Diffie-Hellman key you want to use:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		# The "auth" options behaves differently with AEAD ciphers
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "The digest algorithm authenticates data channel packets and tls-auth packets from the control channel."
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "The digest algorithm authenticates tls-auth packets from the control channel."
		fi
		echo "Which digest algorithm do you want to use for HMAC?"
		echo "   1) SHA-256 (recommended)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
		echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
		echo "   1) tls-crypt (recommended)"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
			read -rp "Control channel additional security mechanism [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Set default choices so that no questions will be asked.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}

		# Set PORT based on PORT_CHOICE
		case $PORT_CHOICE in
		1)
			PORT="1194"  # Default port
			;;
		2)
			PORT="53"    # DNS port
			;;
		3) 
			PORT=${PORT:-1194}  # Custom port default
			;;
		4)
			PORT=$(shuf -i49152-65535 -n1)  # Random port
			;;
		esac

		if [[ -z $ENDPOINT ]]; then
			ENDPOINT=$(resolvePublicIP)
		fi
	fi

	# Run setup questions first, and set other variables if auto-install
	installQuestions

	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	# $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		echo
		echo "Can not detect public interface."
		echo "This needs for setup MASQUERADE."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	# If OpenVPN isn't installed yet, install it. This script is more-or-less
	# idempotent on multiple runs, but will only install OpenVPN from upstream
	# the first time.
	if [[ ! -e /etc/openvpn/server.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			# We add the OpenVPN repo to get the latest version.
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			# Ubuntu > 16.04 and Debian > 8 have OpenVPN >= 2.4 without the need of a third party repository.
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'centos' ]]; then
			yum install -y epel-release
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			yum install -y oracle-epel-release-el8
			yum-config-manager --enable ol8_developer_EPEL
			yum install -y openvpn iptables openssl wget ca-certificates curl tar policycoreutils-python-utils
		elif [[ $OS == 'amzn' ]]; then
			amazon-linux-extras install -y epel
			yum install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'amzn2023' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
		elif [[ $OS == 'arch' ]]; then
			# Install required dependencies and upgrade the system
			pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
		fi
		# An old version of easy-rsa was available by default in some openvpn packages
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi

	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# Install the latest version of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.1.2"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		# Create the PKI, set up the CA, the DH params and the server certificate
		./easyrsa init-pki
		EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

		if [[ $DH_TYPE == "2" ]]; then
			# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi

		EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		case $TLS_SIG in
		1)
			# Generate tls-crypt key
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
			;;
		2)
			# Generate tls-auth key
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		# If easy-rsa is already installed, grab the generated SERVER_NAME
		# for client configs
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi

	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "port $PORT" >/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	elif [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	fi

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

	# DNS resolvers
	case $DNS in
	1) # Current system resolvers
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# Copy, if it's a IPv4 |or| if IPv6 is enabled, IPv4/IPv6 does not matter
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	2) # Self-hosted DNS resolver (Unbound)
		echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
		fi
		;;
	3) # Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
		;;
	4) # Quad9
		echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
		;;
	5) # Quad9 uncensored
		echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
		;;
	6) # FDN
		echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
		;;
	7) # DNS.WATCH
		echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
		;;
	8) # OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
		;;
	9) # Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
		;;
	10) # Yandex Basic
		echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
		;;
	11) # AdGuard DNS
		echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
		;;
	12) # NextDNS
		echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
		;;
	13) # Custom DNS
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
		fi
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

	# IPv6 network settings if needed
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
	fi

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >>/etc/openvpn/server.conf
	fi

	case $TLS_SIG in
	1)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
		;;
	2)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn

	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# Apply sysctl rules
	sysctl --system

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Finally, restart and enable OpenVPN
	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' || $OS == 'amzn2023' ]]; then
		# Don't modify package-provided service
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service

		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		# On Ubuntu 16.04, we use the package from the OpenVPN repo
		# This package uses a sysvinit service
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Don't modify package-provided service
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi

	if [[ $DNS == 2 ]]; then
		installUnbound
	fi

	# Add iptables rules in two scripts
	mkdir -p /etc/iptables

	# Script to add rules
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
	fi

	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
	fi

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.txt is created so we have a template to add further users later
	echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/client-template.txt

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
	fi

	# Generate the custom client.ovpn
	newClient
	echo "If you want to add more clients, you simply need to run this script another time!"
}

function newClient() {
	echo ""
	echo "Tell me a name for the client."
	echo "The name must consist of alphanumeric character. It may also include an underscore or a dash."

	until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
		read -rp "Client name: " -e CLIENT
	done

	echo ""
	echo "Do you want to protect the configuration file with a password?"
	echo "(e.g. encrypt the private key with a password)"
	echo "   1) Add a passwordless client"
	echo "   2) Use a password for the client"

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " -e -i 1 PASS
	done

	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "The specified client CN was already found in easy-rsa, please choose another name."
		exit
	else
		cd /etc/openvpn/easy-rsa/ || return
		case $PASS in
		1)
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT" nopass
			;;
		2)
			echo "⚠️ You will be asked for the client password below ⚠️"
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT"
			;;
		esac
		echo "Client $CLIENT added."
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT}" ]; then
		# if $1 is a user name
		homeDir="/home/${CLIENT}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			homeDir="/root"
		else
			homeDir="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		homeDir="/root"
	fi

	# Determine if we use tls-auth or tls-crypt
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi

	# Generates the custom client.ovpn
	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"

	echo ""
	echo "The configuration file has been written to $homeDir/$CLIENT.ovpn."
	echo "Download the .ovpn file and import it in your OpenVPN client."
	
	# If web download is enabled, copy the file and show direct URL
	if [ -d "/var/www/openvpn" ]; then
		cp "$homeDir/$CLIENT.ovpn" /var/www/openvpn/
		chmod 644 /var/www/openvpn/$CLIENT.ovpn
		chown www-data:www-data /var/www/openvpn/$CLIENT.ovpn 2>/dev/null || true
		
		# Get server IP
		IP=$(curl -4 -s ifconfig.me || curl -4 -s icanhazip.com || curl -4 -s ipinfo.io/ip || ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
		
		echo ""
		echo "====== DIRECT DOWNLOAD LINK ======"
		echo "URL: http://$IP:81/$CLIENT.ovpn"
		echo ""
		echo "Share this URL with your client to download the configuration."
		echo "They will need the username and password you set when enabling the web server."
		echo "==================================="
	fi

	exit 0
}

function revokeClient() {
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client certificate you want to revoke"
	echo "------------------------------------------------------"
	echo "Available clients:"
	echo ""
	
	# Enhanced client listing with more information
	echo "ID  | CLIENT NAME    | CREATED ON       | EXPIRES ON"
	echo "----|----------------|------------------|------------------"
	
	CLIENT_LIST=()
	
	while IFS= read -r line; do
		if [[ $line =~ CN=([^/]+) ]]; then
			CLIENT="${BASH_REMATCH[1]}"
			# Get creation date from certificate
			CREATED_ON=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/${CLIENT}.crt -noout -startdate | cut -d= -f2)
			# Get expiry date from certificate
			EXPIRES_ON=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/${CLIENT}.crt -noout -enddate | cut -d= -f2)
			
			# Format dates for better readability
			CREATED_ON=$(date -d "$CREATED_ON" '+%Y-%m-%d')
			EXPIRES_ON=$(date -d "$EXPIRES_ON" '+%Y-%m-%d')
			
			# Add to array for later reference
			CLIENT_LIST+=("$CLIENT")
			
			# Print formatted client details
			printf "%3s | %-14s | %-16s | %-16s\n" "${#CLIENT_LIST[@]}" "$CLIENT" "$CREATED_ON" "$EXPIRES_ON"
		fi
	done < <(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V")
	
	echo ""
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "Select one client [1]: " CLIENTNUMBER
		else
			read -rp "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
	done
	
	# Get client from our array
	CLIENT="${CLIENT_LIST[$CLIENTNUMBER-1]}"
	
	echo ""
	echo "You selected: $CLIENT"
	echo ""
	read -rp "Do you really want to revoke access for this client? [y/N]: " -e REVOKE
	
	if [[ $REVOKE =~ ^[yY]$ ]]; then
		cd /etc/openvpn/easy-rsa/ || return
		./easyrsa --batch revoke "$CLIENT"
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
		rm -f /etc/openvpn/crl.pem
		cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
		chmod 644 /etc/openvpn/crl.pem
		find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
		rm -f "/root/$CLIENT.ovpn"
		sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
		cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}

		echo ""
		echo "Certificate for client $CLIENT has been revoked!"
		
		# Check if client is currently connected
		if [[ -e /var/log/openvpn/status.log ]] && grep -q "^CLIENT_LIST,$CLIENT," /var/log/openvpn/status.log; then
			echo ""
			echo "WARNING: Client $CLIENT appears to be currently connected."
			echo "They will be disconnected within 60 seconds."
		fi
	else
		echo ""
		echo "Revocation canceled!"
	fi
	
	# Return to the main menu
	echo ""
	read -n1 -r -p "Press any key to return to the main menu..."
}

function viewConnectedClients() {
	echo ""
	echo "Connected Clients"
	echo "================="
	
	if [[ ! -e /var/log/openvpn/status.log ]]; then
		echo "No status log found. Make sure OpenVPN is running."
		echo ""
		read -n1 -r -p "Press any key to continue..."
		return
	fi
	
	# Check if there are any connected clients
	NUM_CLIENTS=$(grep -c "^CLIENT_LIST" /var/log/openvpn/status.log)
	
	if [[ $NUM_CLIENTS -eq 0 ]]; then
		echo "No clients currently connected."
		echo ""
		read -n1 -r -p "Press any key to continue..."
		return
	fi
	
	# Display connected clients with more information
	echo ""
	echo "Currently connected clients: $NUM_CLIENTS"
	echo ""
	echo "USERNAME        | REMOTE IP       | VIRTUAL IP      | CONNECTED SINCE          | DATA IN    | DATA OUT"
	echo "----------------|-----------------|-----------------|---------------------------|------------|------------"
	
	# Process each connected client
	while IFS=',' read -r _ CLIENT REAL_IP VIRTUAL_IP BYTES_RECEIVED BYTES_SENT CONNECTED_SINCE _; do
		# Format connected time
		CONNECTED_SINCE=$(date -d "@$CONNECTED_SINCE" '+%Y-%m-%d %H:%M:%S')
		
		# Format data transfer amounts
		if [[ $BYTES_RECEIVED -gt 1073741824 ]]; then
			BYTES_RECEIVED=$(awk "BEGIN {printf \"%.2f GB\", $BYTES_RECEIVED/1073741824}")
		elif [[ $BYTES_RECEIVED -gt 1048576 ]]; then
			BYTES_RECEIVED=$(awk "BEGIN {printf \"%.2f MB\", $BYTES_RECEIVED/1048576}")
		elif [[ $BYTES_RECEIVED -gt 1024 ]]; then
			BYTES_RECEIVED=$(awk "BEGIN {printf \"%.2f KB\", $BYTES_RECEIVED/1024}")
		else
			BYTES_RECEIVED="${BYTES_RECEIVED} B"
		fi
		
		if [[ $BYTES_SENT -gt 1073741824 ]]; then
			BYTES_SENT=$(awk "BEGIN {printf \"%.2f GB\", $BYTES_SENT/1073741824}")
		elif [[ $BYTES_SENT -gt 1048576 ]]; then
			BYTES_SENT=$(awk "BEGIN {printf \"%.2f MB\", $BYTES_SENT/1048576}")
		elif [[ $BYTES_SENT -gt 1024 ]]; then
			BYTES_SENT=$(awk "BEGIN {printf \"%.2f KB\", $BYTES_SENT/1024}")
		else
			BYTES_SENT="${BYTES_SENT} B"
		fi
		
		printf "%-15s | %-15s | %-15s | %-25s | %-10s | %-10s\n" "$CLIENT" "$REAL_IP" "$VIRTUAL_IP" "$CONNECTED_SINCE" "$BYTES_RECEIVED" "$BYTES_SENT"
	done < <(grep "^CLIENT_LIST" /var/log/openvpn/status.log)
	
	# Show connection statistics
	echo ""
	echo "Additional Information"
	echo "---------------------"
	UPTIME=$(grep "^TIME" /var/log/openvpn/status.log | cut -d',' -f2)
	if [[ -n $UPTIME ]]; then
		echo "Server uptime: $(date -d "@$UPTIME" '+%d days, %H hours, %M minutes')"
	fi
	
	MAX_BCAST_CLIENTS=$(grep "^GLOBAL_STATS" /var/log/openvpn/status.log | cut -d',' -f2)
	if [[ -n $MAX_BCAST_CLIENTS ]]; then
		echo "Maximum concurrent clients: $MAX_BCAST_CLIENTS"
	fi
	
	echo ""
	echo "Disconnection Options:"
	echo "   1) Disconnect a client"
	echo "   2) Return to main menu"
	
	until [[ $DISCONNECT_OPTION =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " DISCONNECT_OPTION
	done
	
	case $DISCONNECT_OPTION in
	1)
		echo ""
		echo "Select client to disconnect:"
		CLIENT_LIST=()
		
		while IFS=',' read -r _ CLIENT REAL_IP _ _ _ _ _; do
			CLIENT_LIST+=("$CLIENT")
			echo "   ${#CLIENT_LIST[@]}) $CLIENT ($REAL_IP)"
		done < <(grep "^CLIENT_LIST" /var/log/openvpn/status.log)
		
		until [[ $CLIENT_NUMBER -ge 1 && $CLIENT_NUMBER -le ${#CLIENT_LIST[@]} ]]; do
			read -rp "Select client [1-${#CLIENT_LIST[@]}]: " CLIENT_NUMBER
		done
		
		SELECTED_CLIENT="${CLIENT_LIST[$CLIENT_NUMBER-1]}"
		
		echo ""
		echo "Disconnecting client: $SELECTED_CLIENT"
		
		# Use management interface to disconnect client
		# This is a placeholder - actual implementation needs a daemon with management interface enabled
		echo "NOTE: Direct client disconnection requires management interface to be enabled."
		echo "Currently this is for informational purposes only."
		echo ""
		echo "To enable client disconnection, add these lines to server.conf:"
		echo "management 127.0.0.1 7505"
		echo ""
		echo "Then you can use: echo 'kill $SELECTED_CLIENT' | nc 127.0.0.1 7505"
		;;
	2)
		# Just return to main menu
		;;
	esac
	
	echo ""
	read -n1 -r -p "Press any key to continue..."
}

function changeServerConfig() {
	echo ""
	echo "Server Configuration Options:"
	echo "   1) Change port"
	echo "   2) Change protocol (UDP/TCP)"
	echo "   3) Change DNS servers"
	echo "   4) Enable/Disable IPv6"
	echo "   5) Back to main menu"
	until [[ $CONFIG_OPTION =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " CONFIG_OPTION
	done

	case $CONFIG_OPTION in
	1)
		echo "Current port: $(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)"
		read -rp "Enter new port [1-65535]: " NEW_PORT
		if [[ $NEW_PORT =~ ^[0-9]+$ ]] && [ "$NEW_PORT" -ge 1 ] && [ "$NEW_PORT" -le 65535 ]; then
			sed -i "s/^port .*/port $NEW_PORT/" /etc/openvpn/server.conf
			echo "Port changed to $NEW_PORT"
			systemctl restart openvpn@server
		else
			echo "Invalid port number"
		fi
		;;
	2)
		echo "Current protocol: $(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)"
		read -rp "Enter new protocol (udp/tcp): " NEW_PROTO
		if [[ $NEW_PROTO =~ ^(udp|tcp)$ ]]; then
			sed -i "s/^proto .*/proto $NEW_PROTO/" /etc/openvpn/server.conf
			echo "Protocol changed to $NEW_PROTO"
			systemctl restart openvpn@server
		else
			echo "Invalid protocol"
		fi
		;;
	3)
		echo "Current DNS servers:"
		grep "push \"dhcp-option DNS" /etc/openvpn/server.conf
		echo "Please refer to the installation script for DNS options"
		;;
	4)
		echo "Current IPv6 status: $(grep -q '^server-ipv6' /etc/openvpn/server.conf && echo "Enabled" || echo "Disabled")"
		read -rp "Enable IPv6? (y/n): " ENABLE_IPV6
		if [[ $ENABLE_IPV6 =~ ^[yY]$ ]]; then
			if ! grep -q '^server-ipv6' /etc/openvpn/server.conf; then
				echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >> /etc/openvpn/server.conf
			fi
			echo "IPv6 enabled"
		else
			sed -i '/^server-ipv6/d' /etc/openvpn/server.conf
			sed -i '/^tun-ipv6/d' /etc/openvpn/server.conf
			sed -i '/^push tun-ipv6/d' /etc/openvpn/server.conf
			sed -i '/^push "route-ipv6/d' /etc/openvpn/server.conf
			sed -i '/^push "redirect-gateway ipv6"/d' /etc/openvpn/server.conf
			echo "IPv6 disabled"
		fi
		systemctl restart openvpn@server
		;;
	5)
		return
		;;
	esac
}

# New function for backup/restore
function backupRestore() {
	echo ""
	echo "Backup/Restore Options:"
	echo "   1) Create backup"
	echo "   2) Restore from backup"
	echo "   3) Back to main menu"
	until [[ $BACKUP_OPTION =~ ^[1-3]$ ]]; do
		read -rp "Select an option [1-3]: " BACKUP_OPTION
	done

	case $BACKUP_OPTION in
	1)
		BACKUP_DIR="/root/openvpn-backup-$(date +%Y%m%d-%H%M%S)"
		mkdir -p "$BACKUP_DIR"
		cp -r /etc/openvpn "$BACKUP_DIR"
		cp /etc/iptables/add-openvpn-rules.sh "$BACKUP_DIR"
		cp /etc/iptables/rm-openvpn-rules.sh "$BACKUP_DIR"
		echo "Backup created in $BACKUP_DIR"
		;;
	2)
		read -rp "Enter backup directory path: " RESTORE_DIR
		if [ -d "$RESTORE_DIR" ]; then
			cp -r "$RESTORE_DIR"/openvpn /etc/
			cp "$RESTORE_DIR"/add-openvpn-rules.sh /etc/iptables/
			cp "$RESTORE_DIR"/rm-openvpn-rules.sh /etc/iptables/
			systemctl restart openvpn@server
			echo "Configuration restored"
		else
			echo "Backup directory not found"
		fi
		;;
	3)
		return
		;;
	esac
}

# New function to configure payload settings
function configurePayload() {
	echo ""
	echo "Payload Configuration:"
	echo "   1) Add HTTP Header payload"
	echo "   2) Add SNI payload"
	echo "   3) Add WebSocket payload"
	echo "   4) Add ACL WebSocket Split payload"
	echo "   5) Add GET WebSocket payload"
	echo "   6) Remove payload settings"
	echo "   7) Back to main menu"
	until [[ $PAYLOAD_OPTION =~ ^[1-7]$ ]]; do
		read -rp "Select an option [1-7]: " PAYLOAD_OPTION
	done

	case $PAYLOAD_OPTION in
	1)
		echo ""
		echo "Configure HTTP Header Payload"
		echo "This will modify the client configuration with custom HTTP headers"
		echo ""
		read -rp "Enter Host header value (e.g., example.com): " HTTP_HOST
		read -rp "Enter additional header (leave blank to skip): " HTTP_EXTRA

		# Create a temp file for the HTTP header configuration
		TEMP_FILE=$(mktemp)
		cat > "$TEMP_FILE" << EOF
# Custom HTTP Header Payload
http-proxy-option CUSTOM-HEADER Host $HTTP_HOST
EOF

		if [[ -n "$HTTP_EXTRA" ]]; then
			echo "http-proxy-option CUSTOM-HEADER $HTTP_EXTRA" >> "$TEMP_FILE"
		fi

		echo ""
		echo "HTTP header payload configured successfully."
		echo "Note: You need to set a proxy with option 7 to use this payload."
		echo ""

		# Update client template
		if grep -q "# Custom HTTP Header Payload" /etc/openvpn/client-template.txt; then
			# Remove existing payload section
			sed -i '/# Custom HTTP Header Payload/,/^\s*$/d' /etc/openvpn/client-template.txt
		fi
		# Add new payload settings
		cat "$TEMP_FILE" >> /etc/openvpn/client-template.txt
		rm "$TEMP_FILE"
		;;
	2)
		echo ""
		echo "Configure SNI Payload"
		echo "This will add SNI (Server Name Indication) to the client configuration"
		echo ""
		read -rp "Enter SNI hostname (e.g., example.com): " SNI_HOST

		# Create a temp file for the SNI configuration
		TEMP_FILE=$(mktemp)
		cat > "$TEMP_FILE" << EOF
# Custom SNI Payload
sni $SNI_HOST
EOF

		echo ""
		echo "SNI payload configured successfully."
		echo "Note: This works with OpenVPN 2.4.5+ clients that support the 'sni' option."
		echo ""

		# Update client template
		if grep -q "# Custom SNI Payload" /etc/openvpn/client-template.txt; then
			# Remove existing payload section
			sed -i '/# Custom SNI Payload/,/^\s*$/d' /etc/openvpn/client-template.txt
		fi
		# Add new payload settings
		cat "$TEMP_FILE" >> /etc/openvpn/client-template.txt
		rm "$TEMP_FILE"
		;;
    3)
        echo ""
        echo "Configure WebSocket Payload"
        echo "This will add a WebSocket upgrade request payload"
        echo ""
        read -rp "Enter host value for WebSocket (e.g., example.com): " WS_HOST

        # Create a temp file for the WebSocket configuration
        TEMP_FILE=$(mktemp)
        cat > "$TEMP_FILE" << EOF
# WebSocket Payload Configuration
http-proxy-option CUSTOM-HEADER "Host: $WS_HOST"
http-proxy-option CUSTOM-HEADER "Upgrade: Websocket"
http-proxy-option CUSTOM-HEADER ""
EOF

        echo ""
        echo "WebSocket payload configured successfully."
        echo "Note: You need to set a proxy with option 7 to use this payload."
        echo ""

        # Update client template
        if grep -q "# WebSocket Payload Configuration" /etc/openvpn/client-template.txt; then
            # Remove existing payload section
            sed -i '/# WebSocket Payload Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
        fi
        # Add new payload settings
        cat "$TEMP_FILE" >> /etc/openvpn/client-template.txt
        rm "$TEMP_FILE"
        ;;
    4)
        echo ""
        echo "Configure ACL WebSocket Split Payload"
        echo "This will add a specific ACL/Split WebSocket payload format:"
        echo "[split]HTTP/1.1 [lf]Host: [host][lf]Upgrade: Websocket[lf][lf]"
        echo ""
        read -rp "Enter host value for WebSocket (e.g., example.com): " ACL_HOST

        # Create a temp file for the ACL WebSocket configuration
        TEMP_FILE=$(mktemp)
        cat > "$TEMP_FILE" << EOF
# ACL WebSocket Split Payload Configuration
# Implementation of [split]HTTP/1.1 [lf]Host: [host][lf]Upgrade: Websocket[lf][lf]
# using EXT1 for raw packet injection
http-proxy-option EXT1 "POST http://$ACL_HOST HTTP/1.1"
http-proxy-option EXT1 "Host: $ACL_HOST"
http-proxy-option EXT1 "Upgrade: Websocket"
http-proxy-option EXT1 ""
EOF

        echo ""
        echo "ACL WebSocket Split payload configured successfully."
        echo "Note: This payload requires an HTTP proxy configured in option 7."
        echo "To use this payload properly:"
        echo "1. Configure HTTP proxy in option 7"
        echo "2. Create a new client configuration"
        echo ""

        # Update client template
        if grep -q "# ACL WebSocket Split Payload Configuration" /etc/openvpn/client-template.txt; then
            # Remove existing payload section
            sed -i '/# ACL WebSocket Split Payload Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
        fi
        # Add new payload settings
        cat "$TEMP_FILE" >> /etc/openvpn/client-template.txt
        rm "$TEMP_FILE"
        ;;
    5)
        echo ""
        echo "Configure GET WebSocket Payload"
        echo "This will add a specific GET WebSocket payload format:"
        echo "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: Websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]"
        echo ""
        read -rp "Enter host value for WebSocket (e.g., example.com): " GET_HOST

        # Create a temp file for the GET WebSocket configuration
        TEMP_FILE=$(mktemp)
        cat > "$TEMP_FILE" << EOF
# GET WebSocket Payload Configuration
# Implementation of GET WebSocket with custom User-Agent
http-proxy-option EXT1 "GET / HTTP/1.1"
http-proxy-option EXT1 "Host: $GET_HOST"
http-proxy-option EXT1 "Upgrade: Websocket"
http-proxy-option EXT1 "Connection: Keep-Alive" 
http-proxy-option EXT1 "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
http-proxy-option EXT1 ""
EOF

        echo ""
        echo "GET WebSocket payload configured successfully."
        echo "Note: This payload requires an HTTP proxy configured in option 7."
        echo "To use this payload properly:"
        echo "1. Configure HTTP proxy in option 7"
        echo "2. Create a new client configuration"
        echo ""

        # Update client template
        if grep -q "# GET WebSocket Payload Configuration" /etc/openvpn/client-template.txt; then
            # Remove existing payload section
            sed -i '/# GET WebSocket Payload Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
        fi
        # Add new payload settings
        cat "$TEMP_FILE" >> /etc/openvpn/client-template.txt
        rm "$TEMP_FILE"
        ;;
	6)
		echo ""
		echo "Removing all payload settings..."
		# Remove HTTP header payload
		if grep -q "# Custom HTTP Header Payload" /etc/openvpn/client-template.txt; then
			sed -i '/# Custom HTTP Header Payload/,/^\s*$/d' /etc/openvpn/client-template.txt
		fi
		# Remove SNI payload
		if grep -q "# Custom SNI Payload" /etc/openvpn/client-template.txt; then
			sed -i '/# Custom SNI Payload/,/^\s*$/d' /etc/openvpn/client-template.txt
		fi
        # Remove WebSocket payload
        if grep -q "# WebSocket Payload Configuration" /etc/openvpn/client-template.txt; then
            sed -i '/# WebSocket Payload Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
        fi
        # Remove ACL WebSocket Split payload
        if grep -q "# ACL WebSocket Split Payload Configuration" /etc/openvpn/client-template.txt; then
            sed -i '/# ACL WebSocket Split Payload Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
        fi
        # Remove GET WebSocket payload
        if grep -q "# GET WebSocket Payload Configuration" /etc/openvpn/client-template.txt; then
            sed -i '/# GET WebSocket Payload Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
        fi
		echo "All payload settings removed."
		;;
	7)
		return
		;;
	esac

	echo ""
	echo "Note: Existing client configurations won't be updated automatically."
	echo "Create new client configurations for updated settings."
	read -n1 -r -p "Press any key to continue..."
}

# New function to configure proxy settings
function configureProxy() {
	echo ""
	echo "Proxy Configuration:"
	echo "   1) Configure HTTP proxy"
	echo "   2) Configure SOCKS proxy"
	echo "   3) Remove proxy settings"
	echo "   4) Back to main menu"
	until [[ $PROXY_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " PROXY_OPTION
	done

	case $PROXY_OPTION in
	1)
		echo ""
		echo "Configure HTTP Proxy"
		echo "This will add HTTP proxy settings to the client configuration"
		echo ""
		read -rp "Enter proxy server IP or hostname: " PROXY_HOST
		read -rp "Enter proxy port: " PROXY_PORT
		read -rp "Does the proxy require authentication? (y/n): " PROXY_AUTH_YN

		# Create a temp file for the proxy configuration
		TEMP_FILE=$(mktemp)
		echo "# HTTP Proxy Configuration" > "$TEMP_FILE"
		
		if [[ $PROXY_AUTH_YN =~ ^[yY]$ ]]; then
			read -rp "Enter proxy username: " PROXY_USER
			read -rp "Enter proxy password: " PROXY_PASS
			echo "http-proxy $PROXY_HOST $PROXY_PORT $PROXY_USER $PROXY_PASS" >> "$TEMP_FILE"
		else
			echo "http-proxy $PROXY_HOST $PROXY_PORT" >> "$TEMP_FILE"
		fi
		echo "" >> "$TEMP_FILE"

		echo ""
		echo "HTTP proxy configured successfully."
		echo ""

		# Update client template
		if grep -q "# HTTP Proxy Configuration" /etc/openvpn/client-template.txt; then
			# Remove existing proxy section
			sed -i '/# HTTP Proxy Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
		fi
		# Add new proxy settings
		cat "$TEMP_FILE" >> /etc/openvpn/client-template.txt
		rm "$TEMP_FILE"
		;;
	2)
		echo ""
		echo "Configure SOCKS Proxy"
		echo "This will add SOCKS proxy settings to the client configuration"
		echo ""
		read -rp "Enter proxy server IP or hostname: " PROXY_HOST
		read -rp "Enter proxy port: " PROXY_PORT
		read -rp "SOCKS version (4/5): " SOCKS_VERSION
		
		# Validate SOCKS version
		if [[ ! $SOCKS_VERSION =~ ^[45]$ ]]; then
			echo "Invalid SOCKS version. Please enter 4 or 5."
			return
		fi
		
		read -rp "Does the proxy require authentication? (y/n): " PROXY_AUTH_YN

		# Create a temp file for the proxy configuration
		TEMP_FILE=$(mktemp)
		echo "# SOCKS Proxy Configuration" > "$TEMP_FILE"
		
		if [[ $PROXY_AUTH_YN =~ ^[yY]$ ]] && [[ $SOCKS_VERSION -eq 5 ]]; then
			read -rp "Enter proxy username: " PROXY_USER
			read -rp "Enter proxy password: " PROXY_PASS
			echo "socks-proxy $PROXY_HOST $PROXY_PORT $PROXY_USER $PROXY_PASS" >> "$TEMP_FILE"
		else
			echo "socks-proxy $PROXY_HOST $PROXY_PORT" >> "$TEMP_FILE"
		fi
		echo "" >> "$TEMP_FILE"

		echo ""
		echo "SOCKS proxy configured successfully."
		echo ""

		# Update client template
		if grep -q "# SOCKS Proxy Configuration" /etc/openvpn/client-template.txt; then
			# Remove existing proxy section
			sed -i '/# SOCKS Proxy Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
		fi
		# Add new proxy settings
		cat "$TEMP_FILE" >> /etc/openvpn/client-template.txt
		rm "$TEMP_FILE"
		;;
	3)
		echo ""
		echo "Removing all proxy settings..."
		# Remove HTTP proxy settings
		if grep -q "# HTTP Proxy Configuration" /etc/openvpn/client-template.txt; then
			sed -i '/# HTTP Proxy Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
		fi
		# Remove SOCKS proxy settings
		if grep -q "# SOCKS Proxy Configuration" /etc/openvpn/client-template.txt; then
			sed -i '/# SOCKS Proxy Configuration/,/^\s*$/d' /etc/openvpn/client-template.txt
		fi
		echo "All proxy settings removed."
		;;
	4)
		return
		;;
	esac

	echo ""
	echo "Note: Existing client configurations won't be updated automatically."
	echo "Create new client configurations for updated settings."
	read -n1 -r -p "Press any key to continue..."
}

function removeUnbound() {
	# Remove OpenVPN-related config
	sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
	rm /etc/unbound/openvpn.conf

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		echo ""
		echo "If you were already using Unbound before installing OpenVPN, I removed the configuration related to OpenVPN."
		read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
	done

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		# Stop Unbound
		systemctl stop unbound

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y unbound
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R unbound
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum remove -y unbound
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y unbound
		fi

		rm -rf /etc/unbound/

		echo ""
		echo "Unbound removed!"
	else
		systemctl restart unbound
		echo ""
		echo "Unbound wasn't removed."
	fi
}

# New function to manage routes
function manageRoutes() {
	clear
	echo "==============================================="
	echo "            OpenVPN Route Management           "
	echo "==============================================="
	echo ""
	echo "Current routes configured in server.conf:"
	echo "------------------------------------------"
	
	# Display current routes in server.conf
	if grep -q '^push "route ' /etc/openvpn/server.conf; then
		grep '^push "route ' /etc/openvpn/server.conf | nl
		echo ""
	else
		echo "No custom routes configured."
		echo ""
	fi
	
	echo "What would you like to do?"
	echo "1) Add a new route"
	echo "2) Remove an existing route"
	echo "3) Return to main menu"
	
	read -rp "Select an option [1-3]: " ROUTE_OPTION
	until [[ "$ROUTE_OPTION" =~ ^[1-3]$ ]]; do
		echo "$ROUTE_OPTION: invalid selection."
		read -rp "Select an option [1-3]: " ROUTE_OPTION
	done
	
	case "$ROUTE_OPTION" in
		1)
			# Add new route
			echo ""
			echo "Adding a new route"
			echo "-----------------"
			echo "Format: NETWORK NETMASK"
			echo "Example: 192.168.1.0 255.255.255.0 (for a /24 network)"
			echo ""
			
			read -rp "Enter network address (e.g., 192.168.1.0): " ROUTE_NETWORK
			read -rp "Enter netmask (e.g., 255.255.255.0): " ROUTE_NETMASK
			
			# Validate IP format (basic validation)
			if [[ ! $ROUTE_NETWORK =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
				echo "Invalid network address format. Please use standard IPv4 format (e.g., 192.168.1.0)"
				read -n1 -r -p "Press any key to continue..."
				manageRoutes
				return
			fi
			
			if [[ ! $ROUTE_NETMASK =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
				echo "Invalid netmask format. Please use standard IPv4 format (e.g., 255.255.255.0)"
				read -n1 -r -p "Press any key to continue..."
				manageRoutes
				return
			fi
			
			# Add route to server.conf
			echo "push \"route $ROUTE_NETWORK $ROUTE_NETMASK\"" >> /etc/openvpn/server.conf
			
			echo ""
			echo "Route added successfully: $ROUTE_NETWORK $ROUTE_NETMASK"
			echo "Restarting OpenVPN service to apply changes..."
			
			# Restart OpenVPN to apply changes
			if [[ -f /etc/fedora-release ]]; then
				systemctl restart openvpn-server@server
			elif [[ -f /etc/arch-release ]]; then
				systemctl restart openvpn-server@server
			else
				systemctl restart openvpn@server
			fi
			
			echo "OpenVPN service restarted. New route is now active."
			;;
			
		2)
			# Remove existing route
			if ! grep -q '^push "route ' /etc/openvpn/server.conf; then
				echo "No custom routes to remove."
				read -n1 -r -p "Press any key to continue..."
				manageRoutes
				return
			fi
			
			echo ""
			echo "Select route to remove:"
			grep '^push "route ' /etc/openvpn/server.conf | nl
			
			ROUTE_COUNT=$(grep -c '^push "route ' /etc/openvpn/server.conf)
			read -rp "Enter route number to remove [1-$ROUTE_COUNT]: " ROUTE_NUMBER
			
			until [[ "$ROUTE_NUMBER" =~ ^[0-9]+$ ]] && [ "$ROUTE_NUMBER" -ge 1 ] && [ "$ROUTE_NUMBER" -le "$ROUTE_COUNT" ]; do
				echo "Invalid selection."
				read -rp "Enter route number to remove [1-$ROUTE_COUNT]: " ROUTE_NUMBER
			done
			
			# Get the route line to remove
			ROUTE_TO_REMOVE=$(grep '^push "route ' /etc/openvpn/server.conf | sed -n "${ROUTE_NUMBER}p")
			
			# Remove the route from server.conf
			sed -i "/^${ROUTE_TO_REMOVE//\//\\/}$/d" /etc/openvpn/server.conf
			
			echo ""
			echo "Route removed: $ROUTE_TO_REMOVE"
			echo "Restarting OpenVPN service to apply changes..."
			
			# Restart OpenVPN to apply changes
			if [[ -f /etc/fedora-release ]]; then
				systemctl restart openvpn-server@server
			elif [[ -f /etc/arch-release ]]; then
				systemctl restart openvpn-server@server
			else
				systemctl restart openvpn@server
			fi
			
			echo "OpenVPN service restarted. Route has been removed."
			;;
			
		3)
			# Return to main menu
			return
			;;
	esac
	
	read -n1 -r -p "Press any key to continue..."
	manageRoutes
}

function removeOpenVPN() {
	echo ""
	read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		# Get OpenVPN port from the configuration
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

		# Stop OpenVPN
		if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
			systemctl disable openvpn-server@server
			systemctl stop openvpn-server@server
			# Remove customised service
			rm /etc/systemd/system/openvpn-server@.service
		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Remove customised service
			rm /etc/systemd/system/openvpn\@.service
		fi

		# Remove the iptables rules related to the script
		systemctl stop iptables-openvpn
		# Cleanup
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/add-openvpn-rules.sh
		rm /etc/iptables/rm-openvpn-rules.sh

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
				fi
			fi
		fi

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
				rm /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y openvpn
		fi

		# Cleanup
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/99-openvpn.conf
		rm -rf /var/log/openvpn

		# Unbound
		if [[ -e /etc/unbound/openvpn.conf ]]; then
			removeUnbound
		fi
		
		# Clean up web server components if they exist
		if [[ -d /var/www/openvpn ]]; then
			echo "Removing web download server components..."
			
			# Remove nginx config
			if [[ -f /etc/nginx/conf.d/openvpn-download.conf ]]; then
				rm /etc/nginx/conf.d/openvpn-download.conf
			fi
			
			# Remove web files
			rm -rf /var/www/openvpn
			
			# Remove update script
			if [[ -f /usr/local/bin/update-ovpn-web ]]; then
				rm /usr/local/bin/update-ovpn-web
			fi
			
			# Remove cron job
			crontab -l | grep -v "update-ovpn-web" | crontab -
			
			# Restart nginx if it's running
			if systemctl is-active --quiet nginx; then
				systemctl restart nginx
			fi
			
			echo "Web download server components removed."
		fi
		
		# Remove faizvpn command
		if [[ -e /usr/local/bin/faizvpn ]]; then
			rm /usr/local/bin/faizvpn
			echo "Command 'faizvpn' has been removed."
		fi
		
		echo ""
		echo "OpenVPN removed!"
	else
		echo ""
		echo "Removal aborted!"
	fi
}

# Function to reinstall the faizvpn command
function reinstallFaizvpnCommand() {
	echo ""
	echo "Reinstalling faizvpn command..."
	
	# First, find where the openvpn-install.sh script is located
	SCRIPT_PATH=$(readlink -f $(which openvpn-install.sh 2>/dev/null || echo "$0"))
	
	# Remove existing command if it exists
	if [[ -e /usr/local/bin/faizvpn ]]; then
		rm /usr/local/bin/faizvpn
	fi
	
	# Create the faizvpn command with absolute path to script
	cat > /usr/local/bin/faizvpn << EOF
#!/bin/bash
if [[ \$EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
bash "$SCRIPT_PATH"
EOF
	
	# Make it executable
	chmod +x /usr/local/bin/faizvpn
	
	echo "Command 'faizvpn' has been reinstalled successfully."
	echo "Command located at: $(readlink -f /usr/local/bin/faizvpn)"
	echo "Script path: $SCRIPT_PATH"
	echo ""
	read -n1 -r -p "Press any key to continue..."
	manageMenu
}

function manageMenu() {
	clear
	echo "Welcome to OpenVPN-install!"
	echo "The git repository is available at: https://github.com/angristan/openvpn-install"
	echo ""
	echo "It looks like OpenVPN is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) Revoke an existing user"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	echo "   5) Show connected users [5 min update]"
	echo "   6) Check User Detail"
	echo "   7) Configure DNS settings"
	echo "   8) Add WebSocket Support"
	echo "   9) Configure ACL WebSocket Split"
	echo "   10) Setup Web Download"
	echo "   11) OpenVPN Status"
	echo "   12) Manage Routes"
	echo "   13) Fix Port 53 Issues"
	echo "   14) Reinstall faizvpn command"
	read -p "Select an option [1-14]: " option
	until [[ "$option" =~ ^[1-9]|10|11|12|13|14$ ]]; do
		echo "$option: invalid selection."
		read -p "Select an option [1-14]: " option
	done
	case "$option" in
		1)
			newClient
			;;
		2)
			revokeClient
			;;
		3)
			removeOpenVPN
			
			;;
		4)
			exit 0
			;;
        5)
            viewConnectedClients
            ;;
        6)
            checkUserDetail
            ;;
        7)
            configureDNS
            ;;
        8)
            configureWebSocket
            ;;
        9)
            configureACLWebSocketSplit
            ;;
        10)
            setupWebDownload
            ;;
        11)
            checkOpenVPNStatus
            ;;
        12)
            manageRoutes
            ;;
        13)
            fixPort53Issues
            ;;
        14)
            reinstallFaizvpnCommand
            ;;
	esac
}

# Function to set up web server for OpenVPN config downloads
function setupWebDownload() {
	echo ""
	echo "Setting up Web Download Server on Port 81"
	echo "----------------------------------------"
	echo ""
	echo "This will install a simple web server to allow downloading .ovpn files"
	echo "through a web browser using basic authentication."
	echo ""
	read -rp "Do you want to continue? [y/n]: " -e -i y CONTINUE

	if [[ "$CONTINUE" != "y" ]]; then
		echo "Web server setup aborted."
		return
	fi

	# Check if nginx is already installed
	if ! command -v nginx >/dev/null 2>&1; then
		echo "Installing nginx..."
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get install -y nginx apache2-utils
		elif [[ $OS == 'arch' ]]; then
			pacman -Sy --noconfirm nginx apache
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum install -y nginx httpd-tools
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y nginx httpd-tools
		fi
	fi

	# Create directory for OpenVPN configs
	echo "Creating directory for OpenVPN configs..."
	mkdir -p /var/www/openvpn

	# Setup authentication
	echo ""
	echo "Setting up Basic Authentication"
	echo "------------------------------"
	echo "How would you like to set up authentication?"
	echo "1) Auto-generate password (recommended)"
	echo "2) Enter custom username and password"
	read -rp "Select an option [1-2]: " AUTH_OPTION
	
	until [[ "$AUTH_OPTION" =~ ^[1-2]$ ]]; do
		echo "$AUTH_OPTION: invalid selection."
		read -rp "Select an option [1-2]: " AUTH_OPTION
	done
	
	case "$AUTH_OPTION" in
		1)
			# Auto-generate credentials
			read -rp "Enter username for web access: " WEB_USER
			
			# Generate password
			if command -v openssl >/dev/null 2>&1; then
				AUTO_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
				echo "Generated password: $AUTO_PASS"
				WEB_PASS=$AUTO_PASS
			else
				read -rp "Enter password for web access: " WEB_PASS
			fi
			;;
		2)
			# Manual credentials
			read -rp "Enter username for web access: " WEB_USER
			read -rp "Enter password for web access: " -s WEB_PASS
			echo ""
			read -rp "Confirm password: " -s CONFIRM_PASS
			echo ""
			
			# Validate password match
			until [[ "$WEB_PASS" == "$CONFIRM_PASS" ]]; do
				echo "Passwords do not match. Please try again."
				read -rp "Enter password for web access: " -s WEB_PASS
				echo ""
				read -rp "Confirm password: " -s CONFIRM_PASS
				echo ""
			done
			;;
	esac
	
	# Create htpasswd file
	if [[ $OS =~ (debian|ubuntu) ]]; then
		htpasswd -b -c /etc/nginx/.htpasswd "$WEB_USER" "$WEB_PASS"
	elif [[ $OS == 'arch' ]]; then
		htpasswd -b -c /etc/nginx/.htpasswd "$WEB_USER" "$WEB_PASS"
	elif [[ $OS =~ (centos|amzn|oracle|fedora) ]]; then
		htpasswd -b -c /etc/nginx/.htpasswd "$WEB_USER" "$WEB_PASS"
	fi

	# Create update script to copy .ovpn files
	echo "Creating update script..."
	cat > /usr/local/bin/update-ovpn-web << 'EOF'
#!/bin/bash
# Copy all .ovpn files to web directory
find /root -name "*.ovpn" -exec cp {} /var/www/openvpn/ \;
find /home -maxdepth 2 -name "*.ovpn" -exec cp {} /var/www/openvpn/ \;
chown -R www-data:www-data /var/www/openvpn 2>/dev/null || true
chmod -R 644 /var/www/openvpn/*.ovpn 2>/dev/null || true

# Update routes display
grep '^push "route ' /etc/openvpn/server.conf > /var/www/openvpn/current_routes.txt 2>/dev/null || echo "No custom routes configured." > /var/www/openvpn/current_routes.txt
EOF

	chmod +x /usr/local/bin/update-ovpn-web
	/usr/local/bin/update-ovpn-web

	# Create nginx configuration
	echo "Configuring nginx..."
	cat > /etc/nginx/conf.d/openvpn-download.conf << 'EOF'
server {
    listen 81;
    server_name _;
    
    root /var/www/openvpn;
    index index.html;
    
    location / {
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        autoindex on;
        autoindex_exact_size off;
        autoindex_format html;
        autoindex_localtime on;
    }
    
    # Add route management API endpoint
    location /manage-routes {
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        try_files $uri /route-manager.html;
    }
    
    # Protect route management operations
    location /api/ {
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        include fastcgi_params;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
}
EOF

	# Create a simple HTML index page
	echo "Creating index page..."
	cat > /var/www/openvpn/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OpenVPN Configuration Files</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #3498db;
        }
        .instructions {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .menu {
            margin-bottom: 20px;
        }
        .menu a {
            display: inline-block;
            margin-right: 10px;
            padding: 8px 15px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .menu a:hover {
            background-color: #2980b9;
        }
    </style>
</head>
<body>
    <h1>OpenVPN Management Portal</h1>
    
    <div class="menu">
        <a href="/">OVPN Files</a>
        <a href="/manage-routes">Manage Routes</a>
        <a href="/server-status">Server Status</a>
    </div>
    
    <div class="instructions">
        <p>Click on a .ovpn file to download it, then import it into your OpenVPN client.</p>
        <p><strong>Instructions:</strong></p>
        <ol>
            <li>Download the .ovpn file for your device</li>
            <li>Import it into your OpenVPN client</li>
            <li>Connect to the VPN</li>
        </ol>
    </div>
    <hr>
    <!-- Directory listing will appear below -->
</body>
</html>
EOF

	# Create route manager page
	echo "Creating route manager page..."
	cat > /var/www/openvpn/route-manager.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OpenVPN Route Management</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2 {
            color: #3498db;
        }
        .instructions {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .menu {
            margin-bottom: 20px;
        }
        .menu a {
            display: inline-block;
            margin-right: 10px;
            padding: 8px 15px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .menu a:hover {
            background-color: #2980b9;
        }
        .route-section {
            margin-top: 20px;
            border: 1px solid #ddd;
            padding: 15px;
            border-radius: 5px;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
        }
        input[type="text"] {
            padding: 8px;
            margin: 5px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 200px;
        }
        .form-group {
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <h1>OpenVPN Route Management</h1>
    
    <div class="menu">
        <a href="/">OVPN Files</a>
        <a href="/manage-routes">Manage Routes</a>
        <a href="/server-status">Server Status</a>
    </div>
    
    <div class="instructions">
        <p>This page allows you to view and manage the routes pushed to OpenVPN clients.</p>
        <p>Routes are pushed to all clients and allow access to networks behind the VPN server.</p>
    </div>
    
    <div class="route-section">
        <h2>Current Routes</h2>
        <p>These routes are currently configured in the OpenVPN server:</p>
        <pre id="current-routes">Loading routes...</pre>
    </div>
    
    <div class="route-section">
        <h2>Add New Route</h2>
        <div class="form-group">
            <label for="network">Network Address (e.g., 192.168.1.0):</label><br>
            <input type="text" id="network" placeholder="192.168.1.0">
        </div>
        <div class="form-group">
            <label for="netmask">Netmask (e.g., 255.255.255.0):</label><br>
            <input type="text" id="netmask" placeholder="255.255.255.0">
        </div>
        <button id="add-route">Add Route</button>
        <p id="add-result"></p>
    </div>

    <script>
        // Load current routes
        function loadRoutes() {
            fetch('/current_routes.txt')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('current-routes').textContent = data;
                })
                .catch(error => {
                    document.getElementById('current-routes').textContent = 'Error loading routes';
                });
        }
        
        // Initial load
        document.addEventListener('DOMContentLoaded', loadRoutes);
        
        // The actual route management would need to be implemented
        // via server-side scripts, as the web interface can't directly
        // edit the server.conf file. This would require additional
        // setup with a backend API.
        document.getElementById('add-route').addEventListener('click', function() {
            document.getElementById('add-result').textContent = 
                'Route management from the web interface requires server-side implementation. ' +
                'Please use the command-line tool for now: faizvpn (option 12)';
        });
    </script>
</body>
</html>
EOF

	# Create server status page
	echo "Creating server status page..."
	cat > /var/www/openvpn/server-status.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OpenVPN Server Status</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2 {
            color: #3498db;
        }
        .menu {
            margin-bottom: 20px;
        }
        .menu a {
            display: inline-block;
            margin-right: 10px;
            padding: 8px 15px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .menu a:hover {
            background-color: #2980b9;
        }
        .status-section {
            margin-top: 20px;
            border: 1px solid #ddd;
            padding: 15px;
            border-radius: 5px;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 5px;
        }
        .status-running {
            background-color: #2ecc71;
        }
        .status-stopped {
            background-color: #e74c3c;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <h1>OpenVPN Server Status</h1>
    
    <div class="menu">
        <a href="/">OVPN Files</a>
        <a href="/manage-routes">Manage Routes</a>
        <a href="/server-status">Server Status</a>
    </div>
    
    <div class="status-section">
        <h2>Service Status</h2>
        <p>
            <span class="status-indicator status-running" id="service-status-indicator"></span>
            <span id="service-status">Checking status...</span>
        </p>
        <p>For detailed status information and control options, please use the command-line tool: faizvpn (option 11)</p>
    </div>
    
    <div class="status-section">
        <h2>Connected Clients</h2>
        <pre id="connected-clients">Loading client information...</pre>
    </div>

    <script>
        // This is just a placeholder. In a real implementation, 
        // you would need server-side scripts to fetch the actual status.
        document.addEventListener('DOMContentLoaded', function() {
            // Simulate status (in reality this would come from the server)
            document.getElementById('service-status').textContent = 'Service is running';
            document.getElementById('service-status-indicator').className = 'status-indicator status-running';
            
            // Simulate client data
            document.getElementById('connected-clients').textContent = 
                'For security reasons, detailed client information is only available via the command-line tool: faizvpn (option 5)';
        });
    </script>
</body>
</html>
EOF

	# Restart nginx
	if [[ $OS =~ (debian|ubuntu) ]]; then
		systemctl restart nginx
	elif [[ $OS == 'arch' ]]; then
		systemctl restart nginx
	elif [[ $OS =~ (centos|amzn|oracle|fedora) ]]; then
		systemctl restart nginx
	fi

	# Configure firewall
	echo "Configuring firewall..."
	if [[ $OS =~ (debian|ubuntu) ]]; then
		# Check if ufw is active
		if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
			ufw allow 81/tcp
		fi
	elif [[ $OS =~ (centos|amzn|oracle|fedora) ]]; then
		# Check if firewalld is active
		if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state | grep -q "running"; then
			firewall-cmd --zone=public --add-port=81/tcp --permanent
			firewall-cmd --reload
		fi
	fi

	# Setup cron job to update .ovpn files
	echo "Setting up cron job to update .ovpn files..."
	(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/update-ovpn-web >/dev/null 2>&1") | crontab -

	# Get IPv4 address specifically
	IP=$(curl -4 -s ifconfig.me || curl -4 -s icanhazip.com || curl -4 -s ipinfo.io/ip || ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
	
	echo ""
	echo "Web server setup complete!"
	echo "-----------------------------"
	echo "URL: http://$IP:81"
	echo "Username: $WEB_USER"
	echo "Password: $WEB_PASS"
	echo ""
	echo "Your OpenVPN configuration files will be available at this URL."
	echo "The web interface also provides:"
	echo "- Route management (view only)"
	echo "- Server status (basic information)"
	echo ""
	echo "The files are updated every 5 minutes."
	echo "You can manually update them by running: /usr/local/bin/update-ovpn-web"
	echo ""
	read -n1 -r -p "Press any key to continue..."
}

# Check for root, TUN, OS...
initialCheck

# Check if OpenVPN is already installed
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
	manageMenu
else
	installOpenVPN
	# Create faizvpn command for easy access to management menu
	if [[ ! -e /usr/local/bin/faizvpn ]]; then
		# First, find where the openvpn-install.sh script is located
		SCRIPT_PATH=$(readlink -f $(which openvpn-install.sh 2>/dev/null || echo "$0"))

		# Create the faizvpn command with absolute path to script
		cat > /usr/local/bin/faizvpn << EOF
#!/bin/bash
if [[ \$EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
bash "$SCRIPT_PATH"
EOF

		# Make it executable
		chmod +x /usr/local/bin/faizvpn
		
		echo ""
		echo "Command 'faizvpn' has been created. You can now use this command anytime to access the OpenVPN management menu."
		echo "Command located at: $(readlink -f /usr/local/bin/faizvpn)"
		echo ""
	fi
fi

# Function to check OpenVPN status
function checkOpenVPNStatus() {
	clear
	echo "==============================================="
	echo "            OpenVPN Server Status              "
	echo "==============================================="
	echo ""
	
	# Check service status based on OS
	echo "SERVICE STATUS:"
	echo "==============="
	if [[ -f /etc/fedora-release ]]; then
		systemctl status openvpn-server@server --no-pager | grep "Active:" | sed 's/^[ \t]*//'
	elif [[ -f /etc/arch-release ]]; then
		systemctl status openvpn-server@server --no-pager | grep "Active:" | sed 's/^[ \t]*//'
	elif [[ -f /etc/centos-release || -f /etc/redhat-release || -f /etc/system-release || -f /etc/oracle-release ]]; then
		systemctl status openvpn@server --no-pager | grep "Active:" | sed 's/^[ \t]*//'
	else
		systemctl status openvpn@server --no-pager | grep "Active:" | sed 's/^[ \t]*//'
	fi
	echo ""
	
	# Check uptime
	echo "SERVICE UPTIME:"
	echo "==============="
	if [[ -f /etc/fedora-release ]]; then
		systemctl show openvpn-server@server | grep "ExecMainStartTimestamp=" | cut -d= -f2
	elif [[ -f /etc/arch-release ]]; then
		systemctl show openvpn-server@server | grep "ExecMainStartTimestamp=" | cut -d= -f2
	elif [[ -f /etc/centos-release || -f /etc/redhat-release || -f /etc/system-release || -f /etc/oracle-release ]]; then
		systemctl show openvpn@server | grep "ExecMainStartTimestamp=" | cut -d= -f2
	else
		systemctl show openvpn@server | grep "ExecMainStartTimestamp=" | cut -d= -f2
	fi
	echo ""
	
	# Check resources usage
	echo "RESOURCE USAGE:"
	echo "==============="
	if command -v pidof &>/dev/null; then
		PID=$(pidof openvpn)
		if [[ -n "$PID" ]]; then
			echo "CPU usage: $(ps -p $PID -o %cpu | tail -n 1 | tr -d ' ')%"
			echo "Memory usage: $(ps -p $PID -o %mem | tail -n 1 | tr -d ' ')%"
		else
			echo "OpenVPN process not found"
		fi
	else
		echo "CPU/Memory usage check not available"
	fi
	echo ""
	
	# Network configuration
	echo "NETWORK CONFIGURATION:"
	echo "======================"
	PORT=$(grep "port " /etc/openvpn/server.conf | awk '{print $2}')
	PROTO=$(grep "proto " /etc/openvpn/server.conf | awk '{print $2}')
	echo "Listening on: $PORT/$PROTO"
	
	# Check if port is open
	if command -v netstat &>/dev/null; then
		PORT_STATUS=$(netstat -tuln | grep ":$PORT")
	elif command -v ss &>/dev/null; then
		PORT_STATUS=$(ss -tuln | grep ":$PORT")
	fi
	
	if [[ -n "$PORT_STATUS" ]]; then
		echo "Port $PORT is OPEN"
	else
		echo "Port $PORT is CLOSED"
	fi
	echo ""
	
	# Connected clients
	echo "CONNECTED CLIENTS:"
	echo "=================="
	if [[ -f /var/log/openvpn/status.log ]]; then
		CLIENTS=$(grep -c "^CLIENT_LIST" /var/log/openvpn/status.log)
		echo "Total clients: $((CLIENTS-1))"
		
		# Total data transfer
		BYTESIN=$(grep "^GLOBAL_STATS" /var/log/openvpn/status.log | cut -d, -f3 | cut -d= -f2)
		BYTESOUT=$(grep "^GLOBAL_STATS" /var/log/openvpn/status.log | cut -d, -f2 | cut -d= -f2)
		
		# Convert to MB
		MBIN=$(echo "scale=2; $BYTESIN/1048576" | bc)
		MBOUT=$(echo "scale=2; $BYTESOUT/1048576" | bc)
		
		echo "Total data received: ${MBIN}MB"
		echo "Total data sent: ${MBOUT}MB"
	else
		echo "Status log not found"
	fi
	echo ""
	
	# Recent activity
	echo "RECENT LOG ACTIVITY:"
	echo "===================="
	if command -v journalctl &>/dev/null; then
		if [[ -f /etc/fedora-release ]]; then
			journalctl -u openvpn-server@server --no-pager --since "1 hour ago" | grep -i error | tail -n 5
		elif [[ -f /etc/arch-release ]]; then
			journalctl -u openvpn-server@server --no-pager --since "1 hour ago" | grep -i error | tail -n 5
		else
			journalctl -u openvpn@server --no-pager --since "1 hour ago" | grep -i error | tail -n 5
		fi
	else
		echo "Recent log check not available"
	fi
	echo ""
	
	# Service control options
	echo "SERVICE CONTROL OPTIONS:"
	echo "======================="
	echo "1) Restart OpenVPN service"
	echo "2) Stop OpenVPN service"
	echo "3) Start OpenVPN service"
	echo "4) Return to main menu"
	
	read -p "Select an option [1-4]: " sc_option
	until [[ "$sc_option" =~ ^[1-4]$ ]]; do
		echo "$sc_option: invalid selection."
		read -p "Select an option [1-4]: " sc_option
	done
	
	case "$sc_option" in
		1)
			echo "Restarting OpenVPN service..."
			if [[ -f /etc/fedora-release ]]; then
				systemctl restart openvpn-server@server
			elif [[ -f /etc/arch-release ]]; then
				systemctl restart openvpn-server@server
			else
				systemctl restart openvpn@server
			fi
			echo "Service restarted!"
			;;
		2)
			echo "Stopping OpenVPN service..."
			if [[ -f /etc/fedora-release ]]; then
				systemctl stop openvpn-server@server
			elif [[ -f /etc/arch-release ]]; then
				systemctl stop openvpn-server@server
			else
				systemctl stop openvpn@server
			fi
			echo "Service stopped!"
			;;
		3)
			echo "Starting OpenVPN service..."
			if [[ -f /etc/fedora-release ]]; then
				systemctl start openvpn-server@server
			elif [[ -f /etc/arch-release ]]; then
				systemctl start openvpn-server@server
			else
				systemctl start openvpn@server
			fi
			echo "Service started!"
			;;
		4)
			# Return to main menu
			;;
	esac
	
	read -n 1 -s -r -p "Press any key to continue..."
	manageMenu
}

# Function to check and fix port 53 issues
function fixPort53Issues() {
    clear
    echo "==============================================="
    echo "          OpenVPN Port 53 Troubleshooter       "
    echo "==============================================="
    echo ""
    
    # Check if OpenVPN is using port 53
    CURRENT_PORT=$(grep "^port " /etc/openvpn/server.conf | cut -d " " -f 2)
    CURRENT_PROTO=$(grep "^proto " /etc/openvpn/server.conf | cut -d " " -f 2)
    
    if [[ "$CURRENT_PORT" != "53" ]]; then
        echo "OpenVPN is not currently configured to use port 53."
        echo "Current port is: $CURRENT_PORT/$CURRENT_PROTO"
        
        read -rp "Would you like to switch to port 53? [y/n]: " -e SWITCH_TO_53
        if [[ "$SWITCH_TO_53" != "y" ]]; then
            return
        fi
    else
        echo "OpenVPN is configured to use port 53/$CURRENT_PROTO"
    fi
    
    echo ""
    echo "Checking for common port 53 issues..."
    
    # Check 1: See if systemd-resolved is using port 53
    if pgrep systemd-resolved >/dev/null; then
        echo "systemd-resolved detected - this service might be using port 53."
        echo "Checking systemd-resolved configuration..."
        
        if grep -q "DNSStubListener=yes" /etc/systemd/resolved.conf 2>/dev/null; then
            echo "systemd-resolved is configured to use port 53."
            echo "Modifying configuration to free up port 53..."
            
            # Backup the file
            cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.backup
            
            # Update the configuration to disable DNSStubListener
            sed -i 's/^#*DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
            
            if ! grep -q "DNSStubListener=" /etc/systemd/resolved.conf; then
                echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
            fi
            
            # Restart systemd-resolved
            systemctl restart systemd-resolved
            echo "systemd-resolved has been reconfigured to free up port 53."
        else
            echo "systemd-resolved does not appear to be using port 53."
        fi
    fi
    
    # Check 2: Check for other services using port 53
    echo "Checking for other services using port 53..."
    PORT_USERS=$(ss -tulpn | grep ":53 " | grep -v openvpn)
    
    if [[ -n "$PORT_USERS" ]]; then
        echo "The following services are using port 53:"
        echo "$PORT_USERS"
        echo ""
        echo "Options:"
        echo "1) Disable these services temporarily"
        echo "2) Choose a different port for OpenVPN"
        echo "3) Skip this step (not recommended)"
        
        read -rp "Select an option [1-3]: " -e PORT_OPTION
        case "$PORT_OPTION" in
            1)
                echo "Attempting to stop services using port 53..."
                if ss -tulpn | grep ":53 " | grep "dnsmasq"; then
                    systemctl stop dnsmasq
                    systemctl disable dnsmasq
                    echo "dnsmasq has been stopped and disabled."
                fi
                
                if ss -tulpn | grep ":53 " | grep "named"; then
                    systemctl stop named
                    systemctl disable named
                    echo "named (BIND) has been stopped and disabled."
                fi
                
                # Check again
                if ss -tulpn | grep ":53 " | grep -v openvpn; then
                    echo "Warning: There are still services using port 53."
                    echo "You may need to manually stop these services."
                else
                    echo "Port 53 has been successfully freed."
                fi
                ;;
            2)
                echo "Setting OpenVPN to use a different port..."
                read -rp "Enter new port [1-65535]: " -e -i 1194 NEW_PORT
                
                # Update the port in server.conf
                sed -i "s/^port .*/port $NEW_PORT/" /etc/openvpn/server.conf
                
                # Update iptables rules
                sed -i "s/--dport $CURRENT_PORT/--dport $NEW_PORT/" /etc/iptables/add-openvpn-rules.sh
                sed -i "s/--dport $CURRENT_PORT/--dport $NEW_PORT/" /etc/iptables/rm-openvpn-rules.sh
                
                # Restart iptables service to apply new rules
                systemctl restart iptables-openvpn
                
                echo "OpenVPN port has been changed to $NEW_PORT."
                ;;
            3)
                echo "Skipping port conflict resolution."
                ;;
        esac
    else
        echo "No other services detected using port 53."
    fi
    
    # Check 3: Firewall check
    echo ""
    echo "Checking firewall rules for port 53..."
    
    if command -v ufw >/dev/null; then
        if ufw status | grep -q "active"; then
            if ! ufw status | grep -q "53/$CURRENT_PROTO"; then
                echo "Adding port 53 to UFW firewall rules..."
                ufw allow 53/$CURRENT_PROTO
                echo "Port 53/$CURRENT_PROTO has been allowed through UFW."
            else
                echo "UFW already has a rule for port 53/$CURRENT_PROTO."
            fi
        fi
    fi
    
    if command -v firewall-cmd >/dev/null; then
        if firewall-cmd --state | grep -q "running"; then
            if ! firewall-cmd --list-ports | grep -q "53/$CURRENT_PROTO"; then
                echo "Adding port 53 to firewalld rules..."
                firewall-cmd --permanent --add-port=53/$CURRENT_PROTO
                firewall-cmd --reload
                echo "Port 53/$CURRENT_PROTO has been allowed through firewalld."
            else
                echo "Firewalld already has a rule for port 53/$CURRENT_PROTO."
            fi
        fi
    fi
    
    # Check 4: SELinux check
    if command -v sestatus >/dev/null && sestatus | grep -q "enabled"; then
        echo ""
        echo "SELinux is enabled on this system."
        echo "Checking if port 53 is allowed for OpenVPN..."
        
        if ! semanage port -l | grep -q "openvpn_port_t.*53"; then
            echo "Setting SELinux to allow OpenVPN on port 53..."
            semanage port -a -t openvpn_port_t -p $CURRENT_PROTO 53
            echo "SELinux has been configured to allow OpenVPN on port 53."
        else
            echo "SELinux already allows OpenVPN on port 53."
        fi
    fi
    
    # Final step: Restart OpenVPN
    echo ""
    echo "Restarting OpenVPN service to apply changes..."
    
    if [[ -f /etc/fedora-release ]]; then
        systemctl restart openvpn-server@server
    elif [[ -f /etc/arch-release ]]; then
        systemctl restart openvpn-server@server
    else
        systemctl restart openvpn@server
    fi
    
    # Verify the service status
    echo ""
    echo "Verifying OpenVPN service status..."
    if [[ -f /etc/fedora-release ]]; then
        systemctl status openvpn-server@server --no-pager
    elif [[ -f /etc/arch-release ]]; then
        systemctl status openvpn-server@server --no-pager
    else
        systemctl status openvpn@server --no-pager
    fi
    
    # Check if port is now listening
    echo ""
    echo "Checking if port 53 is now listening..."
    if ss -tulpn | grep -q ":53.*openvpn"; then
        echo "Success! OpenVPN is now listening on port 53."
    else
        echo "Warning: OpenVPN does not appear to be listening on port 53."
        echo "You may need to further troubleshoot this issue."
    fi
    
    echo ""
    read -n1 -r -p "Press any key to return to the main menu..."
    manageMenu
}
