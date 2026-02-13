#!/bin/bash

# Collabora Online Standalone - Setup Script
# This script sets up the initial environment for deployment
# Supports: Ubuntu/Debian (apt), RHEL/CentOS/Fedora (yum/dnf), SUSE (zypper)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect OS and package manager
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
        OS_PRETTY=$PRETTY_NAME
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="rhel"
        OS_PRETTY=$(cat /etc/redhat-release)
    elif [ -f /etc/debian_version ]; then
        OS_NAME="debian"
        OS_PRETTY="Debian $(cat /etc/debian_version)"
    else
        OS_NAME="unknown"
        OS_PRETTY="Unknown Linux"
    fi

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf check-update || true"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum check-update || true"
    elif command -v zypper &> /dev/null; then
        PKG_MANAGER="zypper"
        PKG_INSTALL="zypper install -y"
        PKG_UPDATE="zypper refresh"
    else
        PKG_MANAGER="unknown"
    fi

    export OS_NAME OS_VERSION OS_PRETTY PKG_MANAGER PKG_INSTALL PKG_UPDATE
}

# Install package based on detected package manager
install_package() {
    local pkg_apt=$1
    local pkg_yum=$2
    local pkg_zypper=${3:-$2}

    if [ "$PKG_MANAGER" = "apt" ]; then
        sudo $PKG_INSTALL $pkg_apt
    elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        sudo $PKG_INSTALL $pkg_yum
    elif [ "$PKG_MANAGER" = "zypper" ]; then
        sudo $PKG_INSTALL $pkg_zypper
    else
        echo -e "${RED}Unknown package manager. Please install manually: $pkg_apt (Debian) or $pkg_yum (RHEL)${NC}"
        return 1
    fi
}

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Collabora Online Standalone Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Detect OS
detect_os
echo -e "${BLUE}Detected OS: ${OS_PRETTY}${NC}"
echo -e "${BLUE}Package Manager: ${PKG_MANAGER}${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Note: Some operations may require sudo privileges${NC}"
fi

# Check prerequisites
echo -e "${GREEN}Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed.${NC}"
    echo ""
    echo "Install Docker using one of these methods:"
    echo ""
    if [ "$PKG_MANAGER" = "apt" ]; then
        echo "  # Ubuntu/Debian:"
        echo "  curl -fsSL https://get.docker.com -o get-docker.sh"
        echo "  sudo sh get-docker.sh"
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        echo "  # Fedora:"
        echo "  sudo dnf install -y dnf-plugins-core"
        echo "  sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo"
        echo "  sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin"
        echo "  sudo systemctl enable --now docker"
    elif [ "$PKG_MANAGER" = "yum" ]; then
        echo "  # RHEL/CentOS:"
        echo "  sudo yum install -y yum-utils"
        echo "  sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo"
        echo "  sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin"
        echo "  sudo systemctl enable --now docker"
    else
        echo "  Visit: https://docs.docker.com/engine/install/"
    fi
    exit 1
fi
echo -e "  ✓ Docker installed"

# Check Docker Compose
if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Docker Compose is not installed.${NC}"
    echo ""
    if [ "$PKG_MANAGER" = "apt" ]; then
        echo "  sudo apt-get install -y docker-compose-plugin"
    elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        echo "  sudo $PKG_INSTALL docker-compose-plugin"
        echo "  # Or standalone: https://docs.docker.com/compose/install/standalone/"
    fi
    exit 1
fi
echo -e "  ✓ Docker Compose installed"

# Check OpenSSL
if ! command -v openssl &> /dev/null; then
    echo -e "${YELLOW}OpenSSL not found. Attempting to install...${NC}"
    install_package "openssl" "openssl"
fi
echo -e "  ✓ OpenSSL installed"

echo ""

# Get domain name
read -p "Enter your domain name (e.g., collabora.example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Domain name is required${NC}"
    exit 1
fi

# Create .env file from template
echo -e "${GREEN}Creating environment configuration...${NC}"

if [ -f .env ]; then
    read -p ".env file already exists. Overwrite? (y/N): " OVERWRITE
    if [ "$OVERWRITE" != "y" ] && [ "$OVERWRITE" != "Y" ]; then
        echo "Keeping existing .env file"
    else
        cp .env.example .env
    fi
else
    cp .env.example .env
fi

# Generate secure secrets (using hex to avoid special characters in sed)
JWT_SECRET=$(openssl rand -hex 32)
WOPI_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
# Use hex for admin password too, then take first 16 chars for readability
COLLABORA_ADMIN_PASSWORD=$(openssl rand -hex 8)

# Function to safely update .env values (handles special characters)
update_env_value() {
    local key=$1
    local value=$2
    local file=$3
    
    # Escape special characters for sed
    local escaped_value=$(printf '%s\n' "$value" | sed 's/[&/\]/\\&/g')
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|^${key}=.*|${key}=${escaped_value}|" "$file"
    else
        sed -i "s|^${key}=.*|${key}=${escaped_value}|" "$file"
    fi
}

# Update .env file using pipe delimiter to avoid conflicts with paths/special chars
update_env_value "DOMAIN" "$DOMAIN" ".env"
update_env_value "JWT_SECRET" "$JWT_SECRET" ".env"
update_env_value "WOPI_SECRET" "$WOPI_SECRET" ".env"
update_env_value "POSTGRES_PASSWORD" "$POSTGRES_PASSWORD" ".env"
update_env_value "COLLABORA_ADMIN_PASSWORD" "$COLLABORA_ADMIN_PASSWORD" ".env"

echo -e "  ✓ Environment file configured"

# Create SSL directory
echo -e "${GREEN}Setting up SSL certificates...${NC}"
mkdir -p ssl

# Check for existing certificates
if [ -f ssl/fullchain.pem ] && [ -f ssl/privkey.pem ]; then
    echo -e "  ✓ SSL certificates already exist"
else
    echo ""
    echo "SSL Certificate Options:"
    echo "  1) Generate self-signed certificates (for testing)"
    echo "  2) Import existing certificates"
    echo "  3) Skip (configure later)"
    echo ""
    read -p "Select option [1-3]: " SSL_OPTION
    
    case $SSL_OPTION in
        1)
            # Generate self-signed certificate
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout ssl/privkey.pem \
                -out ssl/fullchain.pem \
                -subj "/CN=${DOMAIN}" \
                -addext "subjectAltName=DNS:${DOMAIN}"
            echo -e "  ✓ Self-signed certificates generated"
            echo -e "${YELLOW}  Note: For production, use Let's Encrypt or your own certificates${NC}"
            ;;
        2)
            echo ""
            echo -e "${BLUE}Import Existing SSL Certificates${NC}"
            echo "You can provide paths to your existing certificate files."
            echo ""
            read -p "Path to certificate file (fullchain/cert.pem): " CERT_PATH
            read -p "Path to private key file (privkey.pem): " KEY_PATH
            
            if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
                cp "$CERT_PATH" ssl/fullchain.pem
                cp "$KEY_PATH" ssl/privkey.pem
                chmod 600 ssl/privkey.pem
                echo -e "  ✓ SSL certificates imported"
            else
                echo -e "${RED}  Error: Certificate files not found${NC}"
                echo -e "${YELLOW}  Please manually copy your certificates to:${NC}"
                echo "    - ssl/fullchain.pem"
                echo "    - ssl/privkey.pem"
            fi
            ;;
        3)
            echo -e "${YELLOW}  Please add your SSL certificates to the ssl/ directory:${NC}"
            echo "    - ssl/fullchain.pem (certificate chain)"
            echo "    - ssl/privkey.pem (private key)"
            ;;
        *)
            echo -e "${YELLOW}  Skipping SSL setup. Add certificates manually.${NC}"
            ;;
    esac
fi

# LDAP/LTPA Authentication Configuration
echo ""
echo -e "${GREEN}Authentication Configuration...${NC}"
echo ""
echo "Authentication Mode Options:"
echo "  1) Local (database users only)"
echo "  2) LDAP (Active Directory / OpenLDAP)"
echo "  3) LTPA (IBM WebSphere SSO)"
echo "  4) Hybrid (LDAP + Local fallback)"
echo "  5) LDAP + LTPA Combined (SSO with LDAP user validation)"
echo ""
read -p "Select authentication mode [1-5] (default: 1): " AUTH_OPTION

case $AUTH_OPTION in
    2)
        AUTH_MODE="ldap"
        echo ""
        echo -e "${BLUE}LDAP Configuration${NC}"
        read -p "LDAP Server URL (e.g., ldap://ldap.example.com:389): " LDAP_URL
        read -p "LDAP Base DN (e.g., dc=example,dc=com): " LDAP_BASE_DN
        read -p "LDAP Bind DN (service account, leave empty for anonymous): " LDAP_BIND_DN
        if [ -n "$LDAP_BIND_DN" ]; then
            read -sp "LDAP Bind Password: " LDAP_BIND_PASSWORD
            echo ""
        fi
        read -p "LDAP User Search Base (e.g., ou=users): " LDAP_USER_SEARCH_BASE
        read -p "LDAP User Search Filter (default: (uid={{username}})): " LDAP_USER_SEARCH_FILTER
        LDAP_USER_SEARCH_FILTER=${LDAP_USER_SEARCH_FILTER:-"(uid={{username}})"}
        
        # Update .env with LDAP settings (quote values that may contain spaces)
        cat >> .env << EOF

# LDAP Authentication
AUTH_MODE=ldap
LDAP_URL="${LDAP_URL}"
LDAP_BASE_DN="${LDAP_BASE_DN}"
LDAP_BIND_DN="${LDAP_BIND_DN}"
LDAP_BIND_PASSWORD="${LDAP_BIND_PASSWORD}"
LDAP_USER_SEARCH_BASE="${LDAP_USER_SEARCH_BASE:-ou=users}"
LDAP_USER_SEARCH_FILTER="${LDAP_USER_SEARCH_FILTER}"
LDAP_USERNAME_ATTR=uid
LDAP_EMAIL_ATTR=mail
LDAP_DISPLAY_NAME_ATTR=cn
LDAP_ADMIN_GROUP=cn=admins
EOF
        echo -e "  ✓ LDAP configuration added to .env"
        ;;
    3)
        AUTH_MODE="ltpa"
        echo ""
        echo -e "${BLUE}LTPA2 SSO Configuration${NC}"
        echo "You need the LTPA keys from your WebSphere/Liberty server."
        read -p "Path to LTPA keys file (ltpa.keys): " LTPA_KEYS_PATH
        
        if [ -f "$LTPA_KEYS_PATH" ]; then
            # Extract LTPA secret from keys file
            LTPA_SECRET=$(grep -E "^com.ibm.websphere.ltpa.3DESKey=" "$LTPA_KEYS_PATH" | cut -d'=' -f2)
            if [ -n "$LTPA_SECRET" ]; then
                cat >> .env << EOF

# LTPA2 SSO Authentication
AUTH_MODE=ltpa
LTPA_SECRET_KEY=${LTPA_SECRET}
LTPA_COOKIE_NAME=LtpaToken2
LTPA_REALM=defaultRealm
LTPA_TOKEN_EXPIRATION=7200
EOF
                echo -e "  ✓ LTPA configuration added to .env"
            else
                echo -e "${YELLOW}  Could not extract LTPA key. Please configure manually in .env${NC}"
            fi
        else
            read -p "LTPA Secret Key (base64): " LTPA_SECRET_KEY
            read -p "LTPA Cookie Name (default: LtpaToken2): " LTPA_COOKIE_NAME
            read -p "LTPA Realm: " LTPA_REALM
            
            cat >> .env << EOF

# LTPA2 SSO Authentication
AUTH_MODE=ltpa
LTPA_SECRET_KEY=${LTPA_SECRET_KEY}
LTPA_COOKIE_NAME=${LTPA_COOKIE_NAME:-LtpaToken2}
LTPA_REALM=${LTPA_REALM:-defaultRealm}
LTPA_TOKEN_EXPIRATION=7200
EOF
            echo -e "  ✓ LTPA configuration added to .env"
        fi
        ;;
    4)
        AUTH_MODE="hybrid"
        echo ""
        echo -e "${BLUE}Hybrid Authentication (LDAP + Local)${NC}"
        read -p "LDAP Server URL (e.g., ldap://ldap.example.com:389): " LDAP_URL
        read -p "LDAP Base DN (e.g., dc=example,dc=com): " LDAP_BASE_DN
        read -p "LDAP Bind DN (service account): " LDAP_BIND_DN
        if [ -n "$LDAP_BIND_DN" ]; then
            read -sp "LDAP Bind Password: " LDAP_BIND_PASSWORD
            echo ""
        fi
        
        cat >> .env << EOF

# Hybrid Authentication (LDAP + Local)
AUTH_MODE=hybrid
LDAP_URL="${LDAP_URL}"
LDAP_BASE_DN="${LDAP_BASE_DN}"
LDAP_BIND_DN="${LDAP_BIND_DN}"
LDAP_BIND_PASSWORD="${LDAP_BIND_PASSWORD}"
LDAP_USER_SEARCH_BASE="ou=users"
LDAP_USER_SEARCH_FILTER="(uid={{username}})"
LDAP_USERNAME_ATTR=uid
LDAP_EMAIL_ATTR=mail
LDAP_DISPLAY_NAME_ATTR=cn
EOF
        echo -e "  ✓ Hybrid authentication configuration added to .env"
        ;;
    5)
        AUTH_MODE="ldap_ltpa"
        echo ""
        echo -e "${BLUE}LDAP + LTPA Combined Configuration${NC}"
        echo "This mode uses LTPA tokens for SSO and validates users against LDAP."
        echo ""
        
        # LDAP Configuration
        echo -e "${BLUE}Step 1: LDAP Configuration${NC}"
        read -p "LDAP Server URL (e.g., ldap://ldap.example.com:389): " LDAP_URL
        read -p "LDAP Base DN (e.g., dc=example,dc=com): " LDAP_BASE_DN
        read -p "LDAP Bind DN (service account): " LDAP_BIND_DN
        if [ -n "$LDAP_BIND_DN" ]; then
            read -sp "LDAP Bind Password: " LDAP_BIND_PASSWORD
            echo ""
        fi
        read -p "LDAP User Search Base (e.g., ou=users): " LDAP_USER_SEARCH_BASE
        
        # LTPA Configuration
        echo ""
        echo -e "${BLUE}Step 2: LTPA Keys Configuration${NC}"
        echo "You need the LTPA keys file from your WebSphere/Liberty server."
        echo ""
        read -p "Path to LTPA keys file (ltpa.keys): " LTPA_KEYS_PATH
        
        LTPA_SECRET=""
        if [ -f "$LTPA_KEYS_PATH" ]; then
            read -sp "LTPA Keys Password: " LTPA_KEYS_PASSWORD
            echo ""
            
            # Copy keys file to config directory
            mkdir -p config/ltpa
            cp "$LTPA_KEYS_PATH" config/ltpa/ltpa.keys
            chmod 600 config/ltpa/ltpa.keys
            
            # Extract LTPA secret from keys file
            LTPA_SECRET=$(grep -E "^com.ibm.websphere.ltpa.3DESKey=" "$LTPA_KEYS_PATH" | cut -d'=' -f2)
            LTPA_REALM=$(grep -E "^com.ibm.websphere.ltpa.Realm=" "$LTPA_KEYS_PATH" | cut -d'=' -f2)
            LTPA_REALM=${LTPA_REALM:-defaultRealm}
            
            echo -e "  ✓ LTPA keys file copied to config/ltpa/"
        else
            echo -e "${YELLOW}LTPA keys file not found. You can upload it later via admin UI.${NC}"
            read -p "LTPA Secret Key (base64, or leave empty): " LTPA_SECRET
            read -p "LTPA Realm (default: defaultRealm): " LTPA_REALM
            LTPA_REALM=${LTPA_REALM:-defaultRealm}
        fi
        
        read -p "LTPA Cookie Name (default: LtpaToken2): " LTPA_COOKIE_NAME
        LTPA_COOKIE_NAME=${LTPA_COOKIE_NAME:-LtpaToken2}
        
        # Write configuration (quote values that may contain spaces)
        cat >> .env << EOF

# LDAP + LTPA Combined Authentication
AUTH_MODE=ldap_ltpa

# LDAP Settings
LDAP_URL="${LDAP_URL}"
LDAP_BASE_DN="${LDAP_BASE_DN}"
LDAP_BIND_DN="${LDAP_BIND_DN}"
LDAP_BIND_PASSWORD="${LDAP_BIND_PASSWORD}"
LDAP_USER_SEARCH_BASE="${LDAP_USER_SEARCH_BASE:-ou=users}"
LDAP_USER_SEARCH_FILTER="(uid={{username}})"
LDAP_USERNAME_ATTR=uid
LDAP_EMAIL_ATTR=mail
LDAP_DISPLAY_NAME_ATTR=cn

# LTPA Settings
LTPA_SECRET_KEY="${LTPA_SECRET}"
LTPA_COOKIE_NAME="${LTPA_COOKIE_NAME}"
LTPA_REALM="${LTPA_REALM}"
LTPA_TOKEN_EXPIRATION=7200
EOF
        echo -e "  ✓ LDAP + LTPA configuration added to .env"
        
        if [ -z "$LTPA_SECRET" ]; then
            echo ""
            echo -e "${YELLOW}Note: LTPA keys not fully configured.${NC}"
            echo "After deployment, upload your ltpa.keys file via:"
            echo "  - Admin UI: Settings > Authentication > Upload LTPA Keys"
            echo "  - API: POST /api/admin/ltpa/upload"
        fi
        ;;
    *)
        AUTH_MODE="local"
        echo -e "  ✓ Using local authentication (default)"
        ;;
esac

# Create necessary directories
echo -e "${GREEN}Creating directories...${NC}"
mkdir -p nginx/logs
mkdir -p wopi-server/templates
echo -e "  ✓ Directories created"

# Create empty document templates
echo -e "${GREEN}Creating document templates...${NC}"
touch wopi-server/templates/empty.odt
touch wopi-server/templates/empty.ods
touch wopi-server/templates/empty.odp
echo -e "  ✓ Templates created"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Configuration summary:"
echo -e "  Domain: ${YELLOW}${DOMAIN}${NC}"
echo -e "  Collabora Admin Password: ${YELLOW}${COLLABORA_ADMIN_PASSWORD}${NC}"
echo ""
echo "Next steps:"
echo "  1. Review and update .env file if needed"
echo "  2. For production: Replace self-signed SSL certificates"
echo "  3. Run: ./scripts/deploy.sh"
echo ""
echo -e "${YELLOW}Important: Save the Collabora admin password shown above!${NC}"
