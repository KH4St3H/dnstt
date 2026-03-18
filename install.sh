#!/usr/bin/env bash
set -euo pipefail

# ─── Colors & helpers ────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[1;36m'
NC='\033[0m'

print_status()  { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error()   { echo -e "${RED}[-]${NC} $1"; }
print_line()    { echo -e "${CYAN}────────────────────────────────────────────${NC}"; }

usage() {
    echo "Usage: $0 <domain> <listen-address> <backend-address>" >&2
    echo "  domain           DNS domain the server is authoritative for (e.g. t.example.com)" >&2
    echo "  listen-address   UDP address to listen on (e.g. :5300 or 0.0.0.0:53)" >&2
    echo "  backend-address  TCP address for tunnel backend (e.g. 127.0.0.1:1080)" >&2
    exit 1
}

# ─── OS detection ────────────────────────────────────────────────────────────

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "Cannot detect OS"
        exit 1
    fi
    . /etc/os-release
    OS_NAME="$NAME"

    if   command -v dnf &>/dev/null; then PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then PKG_MANAGER="yum"
    elif command -v apt &>/dev/null; then PKG_MANAGER="apt"
    else
        print_error "Unsupported package manager"
        exit 1
    fi

    print_status "Detected OS: $OS_NAME ($PKG_MANAGER)"
}

# ─── Dependencies ────────────────────────────────────────────────────────────

install_dependencies() {
    print_status "Installing dependencies..."
    case $PKG_MANAGER in
        dnf|yum)
            $PKG_MANAGER install -y epel-release 2>/dev/null || true
            $PKG_MANAGER install -y curl iptables iptables-services 2>/dev/null || true
            ;;
        apt)
            apt update -qq
            DEBIAN_FRONTEND=noninteractive apt install -y curl iptables 2>/dev/null || true
            ;;
    esac
}

# ─── Firewall / iptables ─────────────────────────────────────────────────────

save_iptables_rules() {
    case $PKG_MANAGER in
        dnf|yum)
            mkdir -p /etc/sysconfig
            iptables-save  > /etc/sysconfig/iptables  2>/dev/null || true
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
            systemctl enable iptables 2>/dev/null || true
            ;;
        apt)
            mkdir -p /etc/iptables
            iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            systemctl enable netfilter-persistent 2>/dev/null || true
            ;;
    esac
    print_status "iptables rules saved"
}

configure_firewall() {
    print_status "Configuring firewall..."

    local iface
    iface=$(ip route | awk '/default/ {print $5; exit}')
    iface=${iface:-eth0}

    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="${DNSTT_PORT}"/udp
        firewall-cmd --permanent --add-port=53/udp
        firewall-cmd --reload
        print_status "firewalld rules added"
    elif command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "${DNSTT_PORT}"/udp
        ufw allow 53/udp
        print_status "ufw rules added"
    fi

    print_status "Redirecting UDP port 53 -> ${DNSTT_PORT} on $iface"

    iptables -D INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null || true
    iptables -I INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT
    iptables -t nat -I PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT"

    if command -v ip6tables &>/dev/null && [[ -f /proc/net/if_inet6 ]]; then
        ip6tables -D INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
        ip6tables -t nat -D PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null || true
        ip6tables -I INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
        ip6tables -t nat -I PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null || true
    fi

    save_iptables_rules
}

remove_iptables_rules() {
    print_status "Removing iptables rules..."

    local iface
    iface=$(ip route | awk '/default/ {print $5; exit}')
    iface=${iface:-eth0}

    iptables -D INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null || true

    if command -v ip6tables &>/dev/null; then
        ip6tables -D INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
        ip6tables -t nat -D PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null || true
    fi

    save_iptables_rules
    print_status "iptables rules removed"
}

# ─── Dante SOCKS proxy ───────────────────────────────────────────────────────

setup_dante() {
    print_status "Setting up Dante SOCKS proxy..."

    case $PKG_MANAGER in
        dnf|yum) $PKG_MANAGER install -y dante-server ;;
        apt)     apt install -y dante-server ;;
    esac

    local ext_iface
    ext_iface=$(ip route | awk '/default/ {print $5; exit}')
    ext_iface=${ext_iface:-eth0}

    cat > /etc/danted.conf <<EOF
logoutput: syslog
user.privileged: root
user.unprivileged: nobody

internal: 127.0.0.1 port = 1080
external: $ext_iface

socksmethod: none
compatibility: sameport
extension: bind

client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}
socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    command: bind connect udpassociate
    log: error
}
socks block {
    from: 0.0.0.0/0 to: ::/0
    log: error
}
client block {
    from: 0.0.0.0/0 to: ::/0
    log: error
}
EOF

    systemctl enable danted
    systemctl restart danted
    print_status "Dante running on 127.0.0.1:1080"
}

# ─── Binary download ─────────────────────────────────────────────────────────

download_binary() {
    local bin_os bin_arch asset_name api_url download_url tmp

    bin_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    bin_arch="$(uname -m)"
    case "$bin_arch" in
        x86_64)  bin_arch="amd64" ;;
        aarch64) bin_arch="arm64" ;;
        *)
            print_error "Unsupported architecture: $bin_arch"
            exit 1
            ;;
    esac

    asset_name="${BINARY_NAME}_${bin_os}_${bin_arch}"
    api_url="https://api.github.com/repos/${REPO}/releases/latest"

    print_status "Fetching latest release from GitHub..."
    download_url="$(curl -fsSL "$api_url" \
        | python3 -c "import sys,json; assets=json.load(sys.stdin).get('assets',[]); \
          match=[a['browser_download_url'] for a in assets if a['name']=='${asset_name}']; \
          print(match[0] if match else '')")"

    if [[ -z "$download_url" ]]; then
        print_error "Asset '${asset_name}' not found in latest release"
        exit 1
    fi

    print_status "Downloading: $download_url"
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT
    curl -fsSL -o "$tmp" "$download_url"
    chmod +x "$tmp"

    print_status "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
    mv "$tmp" "${INSTALL_DIR}/${BINARY_NAME}"
}

# ─── Systemd service ─────────────────────────────────────────────────────────

install_service() {
    print_status "Writing systemd service to ${SERVICE_FILE}..."
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=dnstt DNS tunnel server
After=network.target
Documentation=https://www.bamsoftware.com/software/dnstt/

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -udp ${DNSTT_LISTEN} ${DNSTT_DOMAIN} ${DNSTT_BACKEND}

Restart=on-failure
RestartSec=5

User=dnstt
Group=dnstt
DynamicUser=yes

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
StateDirectory=dnstt

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now dnstt-server
}

# ─── Main ────────────────────────────────────────────────────────────────────

[[ $# -eq 3 ]] || usage

DNSTT_DOMAIN="$1"
DNSTT_LISTEN="$2"
DNSTT_BACKEND="$3"
DNSTT_PORT="${DNSTT_LISTEN##*:}"

REPO="KH4St3H/dnstt"
BINARY_NAME="dnstt-server"
INSTALL_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/dnstt-server.service"

print_line
detect_os
install_dependencies
configure_firewall
setup_dante
download_binary
install_service
print_line

print_status "Done. Service status:"
systemctl status dnstt-server --no-pager

