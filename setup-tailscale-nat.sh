#!/bin/bash
#
# Idempotent script to enable IP forwarding and NAT (Masquerade) for Tailscale
# Assumes Tailscale is already installed and configured
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Tailscale interface name (used when Tailscale is running)
TAILSCALE_IFACE="tailscale0"

# Function to check Tailscale status (called only for NAT setup)
check_tailscale() {
    # Check if Tailscale is installed
    if ! command -v tailscale &> /dev/null; then
        log_error "Tailscale is not installed. Please install and configure Tailscale first."
        exit 1
    fi

    # Check if Tailscale is running
    if ! tailscale status &> /dev/null; then
        log_error "Tailscale is not running or not logged in. Please configure Tailscale first."
        exit 1
    fi

    log_info "Tailscale is installed and running"

    # Get Tailscale interface name
    if ! ip link show "$TAILSCALE_IFACE" &> /dev/null; then
        log_error "Tailscale interface ($TAILSCALE_IFACE) not found"
        exit 1
    fi

    log_info "Found Tailscale interface: $TAILSCALE_IFACE"
}

# ============================================
# Enable IP Forwarding (idempotent)
# ============================================

SYSCTL_CONF="/etc/sysctl.d/99-tailscale-forwarding.conf"

enable_ip_forwarding() {
    log_info "Configuring IP forwarding..."

    # Enable IPv4 forwarding immediately
    current_ipv4=$(sysctl -n net.ipv4.ip_forward)
    if [[ "$current_ipv4" -ne 1 ]]; then
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        log_info "IPv4 forwarding enabled"
    else
        log_info "IPv4 forwarding already enabled"
    fi

    # Enable IPv6 forwarding immediately
    current_ipv6=$(sysctl -n net.ipv6.conf.all.forwarding)
    if [[ "$current_ipv6" -ne 1 ]]; then
        sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
        log_info "IPv6 forwarding enabled"
    else
        log_info "IPv6 forwarding already enabled"
    fi

    # Persist settings (idempotent - create or update file)
    cat > "$SYSCTL_CONF" << 'EOF'
# Enable IP forwarding for Tailscale subnet routing
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF

    log_info "IP forwarding settings persisted to $SYSCTL_CONF"
}

# ============================================
# Setup NAT/Masquerade (idempotent)
# ============================================

setup_nat_masquerade() {
    log_info "Configuring NAT/Masquerade for Tailscale..."

    # Check if iptables-persistent is installed, install if not
    if ! dpkg -l | grep -q iptables-persistent; then
        log_info "Installing iptables-persistent..."
        # Pre-answer the debconf questions to avoid interactive prompts
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        apt-get update -qq
        apt-get install -y -qq iptables-persistent
        log_info "iptables-persistent installed"
    else
        log_info "iptables-persistent already installed"
    fi

    # Add MASQUERADE rule for traffic coming from Tailscale (idempotent)
    # This allows devices on Tailscale to access the local network through this machine

    # For IPv4: Masquerade traffic from Tailscale to other interfaces
    if ! iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        log_info "Added IPv4 MASQUERADE rule for eth0"
    else
        log_info "IPv4 MASQUERADE rule for eth0 already exists"
    fi

    # Also add masquerade for wlan0 if it exists
    if ip link show wlan0 &> /dev/null; then
        if ! iptables -t nat -C POSTROUTING -o wlan0 -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
            log_info "Added IPv4 MASQUERADE rule for wlan0"
        else
            log_info "IPv4 MASQUERADE rule for wlan0 already exists"
        fi
    fi

    # Allow forwarding from Tailscale interface (idempotent)
    if ! iptables -C FORWARD -i "$TAILSCALE_IFACE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$TAILSCALE_IFACE" -j ACCEPT
        log_info "Added FORWARD ACCEPT rule for incoming $TAILSCALE_IFACE traffic"
    else
        log_info "FORWARD ACCEPT rule for incoming $TAILSCALE_IFACE traffic already exists"
    fi

    # Allow established/related connections back to Tailscale (idempotent)
    if ! iptables -C FORWARD -o "$TAILSCALE_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -o "$TAILSCALE_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
        log_info "Added FORWARD rule for established connections to $TAILSCALE_IFACE"
    else
        log_info "FORWARD rule for established connections to $TAILSCALE_IFACE already exists"
    fi

    # IPv6 rules (if needed)
    if ! ip6tables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null; then
        ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        log_info "Added IPv6 MASQUERADE rule for eth0"
    else
        log_info "IPv6 MASQUERADE rule for eth0 already exists"
    fi

    if ! ip6tables -C FORWARD -i "$TAILSCALE_IFACE" -j ACCEPT 2>/dev/null; then
        ip6tables -A FORWARD -i "$TAILSCALE_IFACE" -j ACCEPT
        log_info "Added IPv6 FORWARD ACCEPT rule for incoming $TAILSCALE_IFACE traffic"
    else
        log_info "IPv6 FORWARD ACCEPT rule for incoming $TAILSCALE_IFACE traffic already exists"
    fi

    if ! ip6tables -C FORWARD -o "$TAILSCALE_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        ip6tables -A FORWARD -o "$TAILSCALE_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
        log_info "Added IPv6 FORWARD rule for established connections to $TAILSCALE_IFACE"
    else
        log_info "IPv6 FORWARD rule for established connections to $TAILSCALE_IFACE already exists"
    fi
}

# ============================================
# Persist iptables rules
# ============================================

persist_iptables() {
    log_info "Persisting iptables rules..."

    # Save current rules
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6

    log_info "iptables rules saved to /etc/iptables/rules.v4 and rules.v6"

    # Ensure netfilter-persistent service is enabled
    if systemctl is-enabled netfilter-persistent &> /dev/null; then
        log_info "netfilter-persistent service already enabled"
    else
        systemctl enable netfilter-persistent
        log_info "netfilter-persistent service enabled"
    fi
}

# ============================================
# Configure Tailscale Exit Node
# ============================================

TAILSCALE_EXIT_NODE="raspberrypi4"

configure_tailscale_exit_node() {
    log_info "Configuring Tailscale exit node settings..."

    # Set exit node and allow LAN access
    if tailscale set --exit-node="$TAILSCALE_EXIT_NODE" --exit-node-allow-lan-access=true; then
        log_info "Tailscale exit node configured:"
        log_info "  Exit node: $TAILSCALE_EXIT_NODE"
        log_info "  LAN access: enabled"
    else
        log_warn "Failed to configure Tailscale exit node"
        log_warn "You may need to configure it manually:"
        log_warn "  tailscale set --exit-node=$TAILSCALE_EXIT_NODE --exit-node-allow-lan-access=true"
    fi

    # Show current Tailscale status
    log_info "Current Tailscale status:"
    tailscale status --peers=false 2>/dev/null || true
}

# ============================================
# Setup Static IP on Next Boot
# ============================================

STATIC_IP_CONFIG="/etc/static-ip-config"
STATIC_IP_SCRIPT="/usr/local/bin/apply-static-ip.sh"
STATIC_IP_SERVICE="/etc/systemd/system/apply-static-ip.service"

# ============================================
# Network Detection Functions
# ============================================

detect_primary_interface() {
    # Get the interface with the default route
    local iface=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    if [[ -z "$iface" ]]; then
        # Fallback: find first non-loopback interface that's UP
        iface=$(ip -o link show | grep -v "lo:" | grep "state UP" | awk -F': ' '{print $2}' | head -1)
    fi
    echo "${iface:-eth0}"
}

detect_current_ip() {
    local interface="$1"
    ip -4 addr show "$interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1
}

detect_current_netmask() {
    local interface="$1"
    ip -4 addr show "$interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\K\d+' | head -1
}

detect_current_gateway() {
    ip route show default 2>/dev/null | grep -oP 'via \K\d+(\.\d+){3}' | head -1
}

detect_current_dns() {
    # Try to get DNS from resolv.conf
    grep -m1 "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}'
}

get_network_prefix() {
    # Extract network prefix from IP (e.g., 192.168.1.30 -> 192.168.1)
    local ip="$1"
    echo "$ip" | grep -oP '^\d+\.\d+\.\d+'
}

show_current_network_info() {
    local interface=$(detect_primary_interface)
    local current_ip=$(detect_current_ip "$interface")
    local current_netmask=$(detect_current_netmask "$interface")
    local current_gateway=$(detect_current_gateway)
    local current_dns=$(detect_current_dns)

    log_info "Current network configuration:"
    log_info "  Interface: $interface"
    log_info "  IP Address: ${current_ip:-not found}"
    log_info "  Netmask: /${current_netmask:-not found}"
    log_info "  Gateway: ${current_gateway:-not found}"
    log_info "  DNS: ${current_dns:-not found}"
}

setup_static_ip_service() {
    log_info "Setting up static IP configuration service..."

    # Create the script that will apply the static IP
    cat > "$STATIC_IP_SCRIPT" << 'SCRIPT_EOF'
#!/bin/bash
#
# Smart static IP configuration script
# Only applies the static IP if on the target network, otherwise keeps DHCP
#

CONFIG_FILE="/etc/static-ip-config"
LOG_TAG="apply-static-ip"

log() {
    logger -t "$LOG_TAG" "$1"
    echo "$1"
}

get_network_prefix() {
    local ip="$1"
    echo "$ip" | grep -oP '^\d+\.\d+\.\d+'
}

# Wait for network to be available
wait_for_network() {
    local max_attempts=30
    local attempt=0
    while [[ $attempt -lt $max_attempts ]]; do
        if ip route show default &>/dev/null; then
            return 0
        fi
        sleep 1
        ((attempt++))
    done
    return 1
}

if [[ ! -f "$CONFIG_FILE" ]]; then
    log "No static IP config found at $CONFIG_FILE, skipping"
    exit 0
fi

# Source the configuration
source "$CONFIG_FILE"

if [[ -z "$STATIC_IP" ]] || [[ -z "$GATEWAY" ]] || [[ -z "$INTERFACE" ]]; then
    log "ERROR: Missing required variables in $CONFIG_FILE"
    exit 1
fi

# Default values
NETMASK="${NETMASK:-24}"
DNS1="${DNS1:-8.8.8.8}"
DNS2="${DNS2:-8.8.4.4}"
TARGET_NETWORK="${TARGET_NETWORK:-}"

log "Static IP configuration loaded:"
log "  Interface: $INTERFACE"
log "  Target IP: $STATIC_IP/$NETMASK"
log "  Target Gateway: $GATEWAY"
log "  Target Network: ${TARGET_NETWORK:-auto-detect from gateway}"

# Wait for initial network connectivity (DHCP)
log "Waiting for initial network connectivity..."
if ! wait_for_network; then
    log "WARNING: No network connectivity detected, attempting static IP anyway"
fi

# Get current network info (from DHCP)
CURRENT_GATEWAY=$(ip route show default 2>/dev/null | grep -oP 'via \K\d+(\.\d+){3}' | head -1)
CURRENT_IP=$(ip -4 addr show "$INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

log "Current network state:"
log "  Current IP: ${CURRENT_IP:-none}"
log "  Current Gateway: ${CURRENT_GATEWAY:-none}"

# Determine if we're on the target network
TARGET_NET_PREFIX=$(get_network_prefix "$GATEWAY")
CURRENT_NET_PREFIX=$(get_network_prefix "$CURRENT_GATEWAY")

# Check if we should apply the static IP
SHOULD_APPLY=false

if [[ -n "$TARGET_NETWORK" ]]; then
    # Explicit target network specified
    if [[ "$CURRENT_NET_PREFIX" == "$(get_network_prefix "$TARGET_NETWORK")" ]]; then
        log "Current network matches target network $TARGET_NETWORK"
        SHOULD_APPLY=true
    else
        log "Current network ($CURRENT_NET_PREFIX.x) does not match target ($TARGET_NETWORK)"
    fi
elif [[ "$CURRENT_NET_PREFIX" == "$TARGET_NET_PREFIX" ]]; then
    # Auto-detect: current gateway network matches target gateway network
    log "Current network matches target gateway network ($TARGET_NET_PREFIX.x)"
    SHOULD_APPLY=true
elif [[ -z "$CURRENT_GATEWAY" ]]; then
    # No current gateway - might be on isolated network, try applying
    log "No current gateway detected, attempting to apply static IP"
    SHOULD_APPLY=true
else
    log "Current network ($CURRENT_NET_PREFIX.x) does not match target network ($TARGET_NET_PREFIX.x)"
    log "Keeping current DHCP configuration"
fi

if [[ "$SHOULD_APPLY" != "true" ]]; then
    log "Static IP not applied - device not on target network"
    log "Configuration preserved for next boot"
    exit 0
fi

log "Applying static IP configuration..."

# Detect network configuration method and apply accordingly
if [[ -d /etc/network/interfaces.d ]] || [[ -f /etc/network/interfaces ]]; then
    # Debian/DietPi style - using /etc/network/interfaces
    log "Detected Debian-style network configuration"

    INTERFACES_FILE="/etc/network/interfaces"
    INTERFACES_D="/etc/network/interfaces.d"

    # Backup original
    if [[ -f "$INTERFACES_FILE" ]]; then
        cp "$INTERFACES_FILE" "${INTERFACES_FILE}.backup.$(date +%Y%m%d%H%M%S)"
    fi

    # Check if interface is configured in main file or interfaces.d
    if grep -q "iface $INTERFACE" "$INTERFACES_FILE" 2>/dev/null; then
        # Modify the main interfaces file
        # Remove existing configuration for the interface
        sed -i "/auto $INTERFACE/,/^$/d" "$INTERFACES_FILE"
        sed -i "/iface $INTERFACE/,/^$/d" "$INTERFACES_FILE"
    fi

    # Remove any interface-specific file in interfaces.d
    rm -f "$INTERFACES_D/$INTERFACE" 2>/dev/null

    # Create new static configuration
    cat >> "$INTERFACES_FILE" << EOF

# Static IP configuration applied by apply-static-ip service
auto $INTERFACE
iface $INTERFACE inet static
    address $STATIC_IP/$NETMASK
    gateway $GATEWAY
    dns-nameservers $DNS1 $DNS2
EOF

    log "Updated $INTERFACES_FILE with static configuration"

    # Apply the changes
    ip addr flush dev "$INTERFACE" 2>/dev/null || true
    ifdown "$INTERFACE" 2>/dev/null || true
    ifup "$INTERFACE" 2>/dev/null || true

elif command -v nmcli &> /dev/null; then
    # NetworkManager style
    log "Detected NetworkManager configuration"

    nmcli con mod "$INTERFACE" ipv4.addresses "$STATIC_IP/$NETMASK"
    nmcli con mod "$INTERFACE" ipv4.gateway "$GATEWAY"
    nmcli con mod "$INTERFACE" ipv4.dns "$DNS1 $DNS2"
    nmcli con mod "$INTERFACE" ipv4.method manual
    nmcli con down "$INTERFACE" 2>/dev/null || true
    nmcli con up "$INTERFACE"

    log "Applied NetworkManager static IP configuration"

elif [[ -d /etc/netplan ]]; then
    # Netplan style (Ubuntu)
    log "Detected Netplan configuration"

    NETPLAN_FILE="/etc/netplan/99-static-ip.yaml"
    cat > "$NETPLAN_FILE" << EOF
network:
  version: 2
  ethernets:
    $INTERFACE:
      addresses:
        - $STATIC_IP/$NETMASK
      gateway4: $GATEWAY
      nameservers:
        addresses:
          - $DNS1
          - $DNS2
EOF

    netplan apply
    log "Applied Netplan static IP configuration"

else
    log "ERROR: Could not detect network configuration method"
    exit 1
fi

# Verify the IP was applied
sleep 2
CURRENT_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [[ "$CURRENT_IP" == "$STATIC_IP" ]]; then
    log "SUCCESS: Static IP $STATIC_IP applied successfully"
    # Clean up - remove config and disable service after successful application
    rm -f "$CONFIG_FILE"
    systemctl disable apply-static-ip.service 2>/dev/null || true
    log "Static IP service completed and disabled"
else
    log "WARNING: IP verification failed. Current IP: $CURRENT_IP, Expected: $STATIC_IP"
    log "Configuration preserved for retry on next boot"
fi
SCRIPT_EOF

    chmod +x "$STATIC_IP_SCRIPT"
    log_info "Created static IP application script at $STATIC_IP_SCRIPT"

    # Create the systemd service
    cat > "$STATIC_IP_SERVICE" << 'SERVICE_EOF'
[Unit]
Description=Apply Static IP Configuration on Boot
After=network-pre.target
Before=network.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/apply-static-ip.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    log_info "Created systemd service at $STATIC_IP_SERVICE"
    systemctl daemon-reload
}

configure_static_ip() {
    local static_ip="$1"
    local gateway="$2"
    local interface="${3:-eth0}"
    local netmask="${4:-24}"
    local dns1="${5:-8.8.8.8}"
    local dns2="${6:-8.8.4.4}"

    # Ensure the service infrastructure is in place
    if [[ ! -f "$STATIC_IP_SCRIPT" ]]; then
        setup_static_ip_service
    fi

    # Write the configuration file
    cat > "$STATIC_IP_CONFIG" << EOF
# Static IP configuration - will be applied on next boot
# Generated on: $(date)
INTERFACE="$interface"
STATIC_IP="$static_ip"
NETMASK="$netmask"
GATEWAY="$gateway"
DNS1="$dns1"
DNS2="$dns2"
EOF

    log_info "Static IP configuration written to $STATIC_IP_CONFIG"
    log_info "  Interface: $interface"
    log_info "  IP: $static_ip/$netmask"
    log_info "  Gateway: $gateway"
    log_info "  DNS: $dns1, $dns2"

    # Enable the service
    systemctl enable apply-static-ip.service
    log_info "Static IP service enabled - will apply configuration on next boot"
}

cancel_static_ip() {
    if [[ -f "$STATIC_IP_CONFIG" ]]; then
        rm -f "$STATIC_IP_CONFIG"
        log_info "Static IP configuration cancelled"
    else
        log_info "No pending static IP configuration found"
    fi

    systemctl disable apply-static-ip.service 2>/dev/null || true
}

show_static_ip_status() {
    if [[ -f "$STATIC_IP_CONFIG" ]]; then
        log_info "Pending static IP configuration:"
        cat "$STATIC_IP_CONFIG"
    else
        log_info "No pending static IP configuration"
    fi
}

# ============================================
# Main execution
# ============================================

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  (no options)           Run full NAT/Masquerade setup"
    echo "  --set-static-ip        Configure static IP for next boot"
    echo "      -i, --ip IP        Static IP address (required)"
    echo "      -g, --gateway GW   Gateway address (required)"
    echo "      -n, --netmask NM   Netmask in CIDR (default: 24)"
    echo "      -d, --interface IF Network interface (default: eth0)"
    echo "      --dns1 DNS         Primary DNS (default: 8.8.8.8)"
    echo "      --dns2 DNS         Secondary DNS (default: 8.8.4.4)"
    echo "  --cancel-static-ip     Cancel pending static IP configuration"
    echo "  --static-ip-status     Show pending static IP configuration"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run NAT setup"
    echo "  $0 --set-static-ip -i 192.168.1.30 -g 192.168.1.1"
    echo "  $0 --set-static-ip -i 192.168.1.30 -g 192.168.1.1 -n 24 -d eth0"
    echo "  $0 --cancel-static-ip"
    echo "  $0 --static-ip-status"
}

# ============================================
# Watchdog & Boot Stability (Parent-Proofing)
# ============================================

WATCHDOG_SCRIPT="/usr/local/bin/tailscale-watchdog.sh"
WATCHDOG_LOG="/var/log/tailscale-watchdog.log"
BOOT_TIMER_FILE="/etc/systemd/system/tailscaled-delay.timer"

setup_watchdog() {
    log_info "Configuring Tailscale Watchdog..."

    # Create the watchdog script
    cat > "$WATCHDOG_SCRIPT" << EOF
#!/bin/bash
# Tailscale connection watchdog for $TAILSCALE_EXIT_NODE
EXIT_NODE="$TAILSCALE_EXIT_NODE"

# Try to ping the exit node (3 packets, 5 sec timeout)
if ! ping -c 3 -W 5 \$EXIT_NODE > /dev/null 2>&1; then
    echo "\$(date): Exit node \$EXIT_NODE unreachable. Restarting Tailscale..." >> $WATCHDOG_LOG
    systemctl restart tailscaled
    sleep 10
    tailscale up --exit-node=\$EXIT_NODE --accept-routes --exit-node-allow-lan-access=true
else
    # Optional: uncomment for verbose logging
    # echo "\$(date): Connection to \$EXIT_NODE healthy." >> $WATCHDOG_LOG
    exit 0
fi
EOF

    chmod +x "$WATCHDOG_SCRIPT"
    
    # Add to crontab idempotently (runs every 5 minutes)
    (crontab -l 2>/dev/null | grep -v "$WATCHDOG_SCRIPT"; echo "*/5 * * * * $WATCHDOG_SCRIPT") | crontab -
    
    log_info "Watchdog script installed at $WATCHDOG_SCRIPT"
    log_info "Cron job scheduled for every 5 minutes"
}

setup_boot_delay() {
    log_info "Configuring 45-second boot delay to prevent 'Startup Storm'..."

    cat > "$BOOT_TIMER_FILE" << EOF
[Unit]
Description=Delay Tailscale start after boot to let network settle

[Timer]
OnBootSec=45s
Unit=tailscaled.service

[Install]
WantedBy=timers.target
EOF

    # Re-configure service to wait for timer
    systemctl disable tailscaled.service > /dev/null 2>&1
    systemctl enable tailscaled-delay.timer > /dev/null 2>&1
    systemctl daemon-reload

    log_info "Boot delay timer enabled (tailscaled will now start 45s after power-on)"
}

main() {
    # Parse command line arguments
    local cmd=""
    local static_ip=""
    local gateway=""
    local interface="eth0"
    local netmask="24"
    local dns1="8.8.8.8"
    local dns2="8.8.4.4"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --set-static-ip)
                cmd="set-static-ip"
                shift
                ;;
            --cancel-static-ip)
                cmd="cancel-static-ip"
                shift
                ;;
            --static-ip-status)
                cmd="static-ip-status"
                shift
                ;;
            -i|--ip)
                static_ip="$2"
                shift 2
                ;;
            -g|--gateway)
                gateway="$2"
                shift 2
                ;;
            -n|--netmask)
                netmask="$2"
                shift 2
                ;;
            -d|--interface)
                interface="$2"
                shift 2
                ;;
            --dns1)
                dns1="$2"
                shift 2
                ;;
            --dns2)
                dns2="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Handle static IP commands (don't require Tailscale checks)
    case $cmd in
        set-static-ip)
            if [[ -z "$static_ip" ]] || [[ -z "$gateway" ]]; then
                log_error "Static IP and gateway are required"
                echo ""
                show_usage
                exit 1
            fi
            setup_static_ip_service
            configure_static_ip "$static_ip" "$gateway" "$interface" "$netmask" "$dns1" "$dns2"
            echo ""
            log_info "============================================"
            log_info "Static IP configured for next boot!"
            log_info "============================================"
            log_warn "Reboot the device to apply the new IP configuration"
            exit 0
            ;;
        cancel-static-ip)
            cancel_static_ip
            exit 0
            ;;
        static-ip-status)
            show_static_ip_status
            exit 0
            ;;
    esac

    # Default: run full NAT setup
    # Check Tailscale status only for NAT setup (not for static IP commands)
    check_tailscale
    echo ""

    log_info "Starting Tailscale NAT/Masquerade setup..."
    echo ""

    enable_ip_forwarding
    echo ""

    setup_nat_masquerade
    echo ""

    persist_iptables
    echo ""

    configure_tailscale_exit_node
    echo ""

    setup_watchdog
    echo ""
    
    setup_boot_delay
    echo ""

    log_info "============================================"
    log_info "Setup complete!"
    log_info "============================================"
    echo ""
    log_info "Summary:"
    log_info "  - IP forwarding: enabled and persisted"
    log_info "  - NAT/Masquerade: configured for Tailscale"
    log_info "  - iptables rules: persisted"
    log_info "  - Tailscale exit node: $TAILSCALE_EXIT_NODE (LAN access enabled)"
    echo ""
    log_info "Current iptables NAT rules:"
    iptables -t nat -L POSTROUTING -v --line-numbers
}

main "$@"
