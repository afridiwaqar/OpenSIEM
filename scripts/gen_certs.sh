#!/bin/bash
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.
#
# Generates a self-signed TLS certificate for the OpenSIEM server.
# Run once on the OpenSIEM server. Then copy server.crt to each watcher.
#
# Usage:
#   chmod +x gen_certs.sh
#   sudo ./gen_certs.sh
#
# Output:
#   /etc/opensiem/certs/server.crt   <- copy this to each watcher machine
#   /etc/opensiem/certs/server.key   <- keep this on the server only, never distribute

set -e

CERT_DIR="/etc/opensiem/certs"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"
DAYS=825   # ~2.25 years — browsers cap at 825 days, matches industry norm

GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${YLW}OpenSIEM TLS Certificate Generator${NC}"
echo "────────────────────────────────────"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./gen_certs.sh)${NC}"
    exit 1
fi

ARCHIVE_KEY_FILE="$CERT_DIR/archive.key"

mkdir -p "$CERT_DIR"
chown root:www-data "$CERT_DIR"
chmod 750 "$CERT_DIR"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo -e "${YLW}Existing certificates found.${NC}"
    EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
    echo "  Current cert expires: $EXPIRY"
    read -rp "Regenerate? This will invalidate existing watcher certs. [y/N]: " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Detect server IP/hostname for the certificate Subject Alternative Name
SERVER_IP=$(hostname -I | awk '{print $1}')
SERVER_HOST=$(hostname -f 2>/dev/null || hostname)

echo ""
echo "Generating certificate for:"
echo "  Hostname : $SERVER_HOST"
echo "  IP       : $SERVER_IP"
echo "  Valid for: $DAYS days"
echo ""

openssl req -x509 -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days "$DAYS" \
    -nodes \
    -subj "/CN=opensiem-server/O=OpenSIEM/C=XX" \
    -addext "subjectAltName=IP:$SERVER_IP,DNS:$SERVER_HOST,DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

# Restrict key permissions — only root and opensiem user should read it
chmod 640 "$KEY_FILE"
chmod 644 "$CERT_FILE"
chown root:opensiem "$KEY_FILE" "$CERT_FILE" 2>/dev/null || chown root:root "$KEY_FILE" "$CERT_FILE"

echo -e "${GRN}✓ Certificate generated successfully${NC}"
echo ""
echo "  Certificate : $CERT_FILE"
echo "  Private key : $KEY_FILE"
echo ""

# ── Archive credentials encryption key ──────────────────────────────────
# Used by storage.php / archive_storage.py to encrypt/decrypt SFTP & S3
# credentials at rest in the database. Unrelated to the TLS cert above —
# provisioned here only because it lives in the same directory and needs
# the same "run once, as root, before the app touches it" treatment.
if [ -f "$ARCHIVE_KEY_FILE" ]; then
    echo -e "${YLW}Archive encryption key already exists — leaving it in place.${NC}"
    echo "  (Regenerating it would make any already-encrypted stored credentials unreadable.)"
else
    echo "Generating archive credentials encryption key..."
    if ! python3 -c "from cryptography.fernet import Fernet" 2>/dev/null; then
        echo -e "${RED}✗ Python 'cryptography' package not found.${NC}"
        echo "  Install it first:  pip install cryptography --break-system-packages"
        echo "  Then re-run this script to generate archive.key."
    else
        python3 -c "
from cryptography.fernet import Fernet
with open('$ARCHIVE_KEY_FILE', 'wb') as f:
    f.write(Fernet.generate_key())
"
        chown www-data:www-data "$ARCHIVE_KEY_FILE" 2>/dev/null || true
        chmod 600 "$ARCHIVE_KEY_FILE"
        echo -e "${GRN}✓ Archive encryption key generated: $ARCHIVE_KEY_FILE${NC}"
    fi
fi
echo ""
echo -e "${YLW}Next steps:${NC}"
echo ""
echo "1. Add to /etc/opensiem/opensiem.conf:"
echo ""
echo "   [tls]"
echo "   enabled  = true"
echo "   certfile = $CERT_FILE"
echo "   keyfile  = $KEY_FILE"
echo ""
echo "2. Copy the certificate to each watcher machine:"
echo ""
echo "   Linux watcher:"
echo "     scp $CERT_FILE user@watcher-host:/etc/opensiem/certs/server.crt"
echo "     # Then set TLS_ENABLED = True and TLS_SERVER_CERT in watcher.py"
echo ""
echo "   Windows watcher:"
echo "     Copy server.crt to C:\\ProgramData\\OpenSIEM\\server.crt"
echo "     # Then set TLS_ENABLED = True in watcher_windows.py"
echo ""
echo "3. Restart OpenSIEM:"
echo "     sudo systemctl restart opensiem-server"
echo ""

EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
echo -e "${YLW}⚠ Certificate expires: $EXPIRY_DATE${NC}"
echo "  Add a reminder to regenerate before this date and redistribute server.crt"
