#!/bin/bash
#
# Single-node deployment script for ECDSA Scanner
# Installs PostgreSQL, Go, and the scanner on a single machine
# Secures with Tailscale and UFW - no public interfaces exposed
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/fegge/ecdsa-scanner/main/deploy/single-node/setup.sh | sudo bash -s -- --tailscale-key tskey-xxx
#
# Or interactively:
#   sudo ./setup.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

# Default values
TAILSCALE_AUTH_KEY=""
HOSTNAME="ecdsa-scanner"
POSTGRES_PASSWORD=""
ANKR_API_KEY=""
PORT=8000
SKIP_TAILSCALE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --tailscale-key)
            TAILSCALE_AUTH_KEY="$2"
            shift 2
            ;;
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --postgres-password)
            POSTGRES_PASSWORD="$2"
            shift 2
            ;;
        --ankr-key)
            ANKR_API_KEY="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --skip-tailscale)
            SKIP_TAILSCALE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --tailscale-key KEY    Tailscale auth key (required unless --skip-tailscale)"
            echo "  --hostname NAME        Tailscale hostname (default: ecdsa-scanner)"
            echo "  --postgres-password PW PostgreSQL password (auto-generated if not provided)"
            echo "  --ankr-key KEY         Ankr API key for RPC access (optional)"
            echo "  --port PORT            Web UI port (default: 8000)"
            echo "  --skip-tailscale       Skip Tailscale setup (for testing only)"
            echo "  --help                 Show this help message"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Check root
[[ $EUID -eq 0 ]] || error "This script must be run as root"

# Prompt for Tailscale key if not provided
if [[ -z "$TAILSCALE_AUTH_KEY" ]] && [[ "$SKIP_TAILSCALE" == false ]]; then
    echo ""
    echo "Tailscale auth key required for secure access."
    echo "Get one from: https://login.tailscale.com/admin/settings/keys"
    echo "Create a reusable, ephemeral key."
    echo ""
    read -rp "Enter Tailscale auth key: " TAILSCALE_AUTH_KEY
    [[ -n "$TAILSCALE_AUTH_KEY" ]] || error "Tailscale auth key is required"
fi

# Generate PostgreSQL password if not provided
if [[ -z "$POSTGRES_PASSWORD" ]]; then
    POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
    log "Generated PostgreSQL password"
fi

log "Starting single-node ECDSA Scanner deployment"

# Update system
log "Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

# Install dependencies
log "Installing dependencies..."
apt-get install -y -qq \
    curl \
    ufw \
    git \
    mosh \
    postgresql \
    postgresql-contrib

# Install Tailscale
if [[ "$SKIP_TAILSCALE" == false ]]; then
    if ! command -v tailscale &> /dev/null; then
        log "Installing Tailscale..."
        curl -fsSL https://tailscale.com/install.sh | sh
    fi
    
    log "Connecting to Tailscale..."
    tailscale up --authkey="$TAILSCALE_AUTH_KEY" --hostname="$HOSTNAME" --ssh
    
    # Wait for Tailscale IP
    sleep 5
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
    [[ -n "$TAILSCALE_IP" ]] || error "Failed to get Tailscale IP"
    log "Tailscale IP: $TAILSCALE_IP"
else
    warn "Skipping Tailscale setup - services will be exposed locally only"
    TAILSCALE_IP="127.0.0.1"
fi

# Configure UFW
log "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

if [[ "$SKIP_TAILSCALE" == false ]]; then
    # Only allow traffic on Tailscale interface
    ufw allow in on tailscale0
    # Allow Tailscale UDP for NAT traversal
    ufw allow 41641/udp
else
    # For testing: allow localhost only
    ufw allow from 127.0.0.1
fi

# Note: mosh uses UDP ports 60000-61000, but since we allow all traffic
# on tailscale0, mosh will work over Tailscale automatically

ufw --force enable
log "Firewall configured - only Tailscale traffic allowed"

# Configure PostgreSQL
log "Configuring PostgreSQL..."

# Wait for PostgreSQL to be ready
until pg_isready -q; do
    sleep 2
done

# Get PostgreSQL version directory
PG_VERSION=$(ls /etc/postgresql/ | head -1)
PG_CONF_DIR="/etc/postgresql/$PG_VERSION/main"

# Create database and user
sudo -u postgres psql -c "SELECT 1 FROM pg_user WHERE usename = 'ecdsa_scanner'" | grep -q 1 || \
    sudo -u postgres psql <<EOF
CREATE USER ecdsa_scanner WITH PASSWORD '$POSTGRES_PASSWORD';
CREATE DATABASE ecdsa_scanner OWNER ecdsa_scanner;
GRANT ALL PRIVILEGES ON DATABASE ecdsa_scanner TO ecdsa_scanner;
EOF

# Configure PostgreSQL to listen on localhost only
sed -i "s/^#*listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF_DIR/postgresql.conf"

# Configure pg_hba.conf for localhost-only access
cat > "$PG_CONF_DIR/pg_hba.conf" <<EOF
# PostgreSQL Client Authentication Configuration
# Local connections
local   all             postgres                                peer
local   all             all                                     peer

# Localhost only
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256

# Reject everything else
host    all             all             0.0.0.0/0               reject
host    all             all             ::/0                    reject
EOF

systemctl restart postgresql
log "PostgreSQL configured"

# Install Go
if ! command -v go &> /dev/null || [[ $(go version | grep -oP '\d+\.\d+' | head -1) < "1.21" ]]; then
    log "Installing Go..."
    curl -fsSL https://go.dev/dl/go1.24.4.linux-amd64.tar.gz | tar -C /usr/local -xzf -
fi
export PATH=$PATH:/usr/local/go/bin

# Create ecdsa user
id -u ecdsa &>/dev/null || useradd -r -s /bin/false ecdsa

# Create directories
mkdir -p /opt/ecdsa-scanner
mkdir -p /opt/ecdsa-scanner-src

# Clone and build
log "Building ECDSA Scanner..."
if [[ -d /opt/ecdsa-scanner-src/.git ]]; then
    cd /opt/ecdsa-scanner-src
    git pull -q
else
    rm -rf /opt/ecdsa-scanner-src
    git clone -q https://github.com/fegge/ecdsa-scanner.git /opt/ecdsa-scanner-src
    cd /opt/ecdsa-scanner-src
fi

/usr/local/go/bin/go build -o /opt/ecdsa-scanner/ecdsa-scanner ./cmd/scanner/
cp -r static /opt/ecdsa-scanner/

# Create environment file
cat > /opt/ecdsa-scanner/.env <<EOF
DATABASE_URL=postgres://ecdsa_scanner:$POSTGRES_PASSWORD@localhost:5432/ecdsa_scanner
ANKR_API_KEY=$ANKR_API_KEY
PORT=$PORT
BIND_ADDRS=0.0.0.0
EOF
chmod 600 /opt/ecdsa-scanner/.env

# Create systemd service
cat > /etc/systemd/system/ecdsa-scanner.service <<EOF
[Unit]
Description=Multi-Chain ECDSA R-Value Scanner
After=network.target postgresql.service tailscaled.service
Wants=postgresql.service

[Service]
Type=simple
User=ecdsa
Group=ecdsa
WorkingDirectory=/opt/ecdsa-scanner
ExecStart=/opt/ecdsa-scanner/ecdsa-scanner
Restart=always
RestartSec=5
EnvironmentFile=/opt/ecdsa-scanner/.env

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
chown -R ecdsa:ecdsa /opt/ecdsa-scanner

# Enable and start service
systemctl daemon-reload
systemctl enable ecdsa-scanner
systemctl start ecdsa-scanner

# Configure SSH to only listen on Tailscale (if not skipped)
if [[ "$SKIP_TAILSCALE" == false ]]; then
    log "Configuring SSH for Tailscale-only access..."
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/tailscale-only.conf <<EOF
ListenAddress $TAILSCALE_IP
EOF
    systemctl restart sshd
fi

# Print summary
echo ""
echo "========================================"
echo -e "${GREEN}ECDSA Scanner deployed successfully!${NC}"
echo "========================================"
echo ""
if [[ "$SKIP_TAILSCALE" == false ]]; then
    TAILNET=$(tailscale status --json | grep -oP '"MagicDNSSuffix":"\K[^"]+' || echo "your-tailnet")
    echo "Access the scanner at:"
    echo "  http://$HOSTNAME.$TAILNET:$PORT"
    echo "  http://$TAILSCALE_IP:$PORT"
    echo ""
    echo "SSH access (via Tailscale):"
    echo "  ssh root@$HOSTNAME"
    echo ""
    echo "Database connection (SSH to host first, then):"
    echo "  psql postgres://ecdsa_scanner:$POSTGRES_PASSWORD@localhost:5432/ecdsa_scanner"
else
    echo "Access the scanner at:"
    echo "  http://localhost:$PORT"
    echo ""
    echo "Database connection:"
    echo "  psql postgres://ecdsa_scanner:$POSTGRES_PASSWORD@localhost:5432/ecdsa_scanner"
fi
echo ""
echo "View logs:"
echo "  journalctl -u ecdsa-scanner -f"
echo ""
echo "PostgreSQL password: $POSTGRES_PASSWORD"
echo "(Save this password securely!)"
echo ""
