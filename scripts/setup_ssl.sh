#!/bin/bash

# OmicsOracle SSL Certificate Setup Script
# Supports Let's Encrypt, self-signed certificates, and custom certificates

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$PROJECT_ROOT/config/ssl"
NGINX_CONF_DIR="$PROJECT_ROOT/config"
DOMAIN=""
EMAIL=""
SSL_TYPE="letsencrypt"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

SSL Certificate Setup for OmicsOracle

OPTIONS:
    --domain DOMAIN        Domain name for the certificate (required)
    --email EMAIL          Email for Let's Encrypt registration
    --type TYPE            Certificate type: letsencrypt, self-signed, custom (default: letsencrypt)
    --staging              Use Let's Encrypt staging environment for testing
    --custom-cert PATH     Path to custom certificate file
    --custom-key PATH      Path to custom private key file
    --custom-chain PATH    Path to custom certificate chain file
    --help                 Show this help message

CERTIFICATE TYPES:
    letsencrypt    Automatic SSL certificate from Let's Encrypt (recommended for production)
    self-signed    Generate self-signed certificate (for development/testing)
    custom         Use your own certificate files

EXAMPLES:
    $0 --domain example.com --email admin@example.com
    $0 --domain localhost --type self-signed
    $0 --domain example.com --type custom --custom-cert /path/to/cert.pem --custom-key /path/to/key.pem

EOF
}

# Create SSL directory structure
setup_ssl_directory() {
    log_info "Setting up SSL directory structure..."

    mkdir -p "$SSL_DIR"
    mkdir -p "$SSL_DIR/live"
    mkdir -p "$SSL_DIR/certs"
    mkdir -p "$SSL_DIR/private"
    mkdir -p "$SSL_DIR/csr"

    # Set proper permissions
    chmod 755 "$SSL_DIR"
    chmod 700 "$SSL_DIR/private"
    chmod 755 "$SSL_DIR/certs"

    log_success "SSL directory structure created"
}

# Generate self-signed certificate
generate_self_signed() {
    local domain=$1

    log_info "Generating self-signed certificate for $domain..."

    local cert_file="$SSL_DIR/certs/${domain}.crt"
    local key_file="$SSL_DIR/private/${domain}.key"
    local config_file="$SSL_DIR/${domain}.conf"

    # Create OpenSSL configuration
    cat > "$config_file" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=State
L=City
O=Organization
OU=OmicsOracle
CN=$domain

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
DNS.2 = www.$domain
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

    # Generate private key
    openssl genrsa -out "$key_file" 2048
    chmod 600 "$key_file"

    # Generate certificate
    openssl req -new -x509 -key "$key_file" -out "$cert_file" -days 365 -config "$config_file" -extensions v3_req
    chmod 644 "$cert_file"

    # Create symbolic links for Nginx
    ln -sf "$cert_file" "$SSL_DIR/omics_oracle.crt"
    ln -sf "$key_file" "$SSL_DIR/omics_oracle.key"

    log_success "Self-signed certificate generated for $domain"
    log_warning "Self-signed certificates are not trusted by browsers and should only be used for development"
}

# Setup Let's Encrypt certificate
setup_letsencrypt() {
    local domain=$1
    local email=$2
    local staging=${3:-false}

    log_info "Setting up Let's Encrypt certificate for $domain..."

    # Check if certbot is installed
    if ! command -v certbot &> /dev/null; then
        log_error "Certbot is not installed. Please install it first:"
        echo "  - Ubuntu/Debian: sudo apt-get install certbot python3-certbot-nginx"
        echo "  - CentOS/RHEL: sudo yum install certbot python3-certbot-nginx"
        echo "  - macOS: brew install certbot"
        exit 1
    fi

    # Prepare certbot command
    local certbot_cmd="certbot certonly --webroot -w /var/www/certbot"

    if [[ "$staging" == "true" ]]; then
        certbot_cmd="$certbot_cmd --staging"
        log_warning "Using Let's Encrypt staging environment"
    fi

    # Add domain and email
    certbot_cmd="$certbot_cmd -d $domain"
    if [[ "$domain" != "localhost" ]] && [[ "$domain" != *.localhost ]]; then
        certbot_cmd="$certbot_cmd -d www.$domain"
    fi

    if [[ -n "$email" ]]; then
        certbot_cmd="$certbot_cmd --email $email --agree-tos --no-eff-email"
    else
        certbot_cmd="$certbot_cmd --register-unsafely-without-email --agree-tos"
    fi

    log_info "Running: $certbot_cmd"

    # Create webroot directory for challenge
    mkdir -p /var/www/certbot

    # Run certbot
    if eval "$certbot_cmd"; then
        # Create symbolic links for Nginx
        local cert_path="/etc/letsencrypt/live/$domain"
        ln -sf "$cert_path/fullchain.pem" "$SSL_DIR/omics_oracle.crt"
        ln -sf "$cert_path/privkey.pem" "$SSL_DIR/omics_oracle.key"
        ln -sf "$cert_path/chain.pem" "$SSL_DIR/omics_oracle_chain.crt"

        log_success "Let's Encrypt certificate obtained for $domain"

        # Setup auto-renewal
        setup_auto_renewal
    else
        log_error "Failed to obtain Let's Encrypt certificate"
        log_info "Falling back to self-signed certificate..."
        generate_self_signed "$domain"
    fi
}

# Setup custom certificate
setup_custom_certificate() {
    local cert_file=$1
    local key_file=$2
    local chain_file=$3

    log_info "Setting up custom certificate..."

    # Validate certificate files
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        exit 1
    fi

    if [[ ! -f "$key_file" ]]; then
        log_error "Private key file not found: $key_file"
        exit 1
    fi

    # Validate certificate
    if ! openssl x509 -in "$cert_file" -text -noout > /dev/null 2>&1; then
        log_error "Invalid certificate file: $cert_file"
        exit 1
    fi

    # Validate private key
    if ! openssl rsa -in "$key_file" -check > /dev/null 2>&1; then
        log_error "Invalid private key file: $key_file"
        exit 1
    fi

    # Copy certificate files
    cp "$cert_file" "$SSL_DIR/omics_oracle.crt"
    cp "$key_file" "$SSL_DIR/omics_oracle.key"

    if [[ -n "$chain_file" ]] && [[ -f "$chain_file" ]]; then
        cp "$chain_file" "$SSL_DIR/omics_oracle_chain.crt"
    fi

    # Set proper permissions
    chmod 644 "$SSL_DIR/omics_oracle.crt"
    chmod 600 "$SSL_DIR/omics_oracle.key"

    if [[ -f "$SSL_DIR/omics_oracle_chain.crt" ]]; then
        chmod 644 "$SSL_DIR/omics_oracle_chain.crt"
    fi

    log_success "Custom certificate installed"
}

# Setup automatic renewal for Let's Encrypt
setup_auto_renewal() {
    log_info "Setting up automatic certificate renewal..."

    # Create renewal script
    local renewal_script="$PROJECT_ROOT/scripts/ssl_renewal.sh"

    cat > "$renewal_script" << 'EOF'
#!/bin/bash

# OmicsOracle SSL Certificate Renewal Script

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "[$(date)] [INFO] $1"
}

log_success() {
    echo -e "[$(date)] ${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "[$(date)] ${RED}[ERROR]${NC} $1"
}

# Renew certificates
if certbot renew --quiet; then
    log_success "Certificate renewal successful"

    # Reload Nginx if running
    if docker ps | grep -q nginx; then
        docker exec nginx nginx -s reload && log_success "Nginx reloaded"
    fi

    # Restart OmicsOracle containers if needed
    if docker ps | grep -q omics-oracle; then
        docker-compose restart omics-oracle && log_success "OmicsOracle restarted"
    fi
else
    log_error "Certificate renewal failed"
    exit 1
fi
EOF

    chmod +x "$renewal_script"

    # Add to crontab (runs twice daily)
    local cron_entry="0 12,0 * * * $renewal_script >> $PROJECT_ROOT/logs/ssl_renewal.log 2>&1"

    # Check if cron entry already exists
    if ! crontab -l 2>/dev/null | grep -q "$renewal_script"; then
        (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
        log_success "Auto-renewal cron job added"
    else
        log_info "Auto-renewal cron job already exists"
    fi
}

# Update Nginx configuration for SSL
update_nginx_config() {
    local domain=$1

    log_info "Updating Nginx configuration for SSL..."

    # Update domain name in SSL config
    local ssl_config="$NGINX_CONF_DIR/nginx.ssl.conf"

    if [[ -f "$ssl_config" ]]; then
        # Create backup
        cp "$ssl_config" "$ssl_config.backup.$(date +%Y%m%d_%H%M%S)"

        # Replace domain placeholders
        sed -i.tmp "s/your-domain\.com/$domain/g" "$ssl_config"
        rm -f "$ssl_config.tmp"

        # Copy as main nginx config for production
        cp "$ssl_config" "$NGINX_CONF_DIR/nginx.conf"

        log_success "Nginx configuration updated for $domain"
    else
        log_warning "SSL Nginx configuration not found, using default"
    fi
}

# Main execution
main() {
    DOMAIN=""
    EMAIL=""
    SSL_TYPE="letsencrypt"
    STAGING=false
    CUSTOM_CERT=""
    CUSTOM_KEY=""
    CUSTOM_CHAIN=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --email)
                EMAIL="$2"
                shift 2
                ;;
            --type)
                SSL_TYPE="$2"
                shift 2
                ;;
            --staging)
                STAGING=true
                shift
                ;;
            --custom-cert)
                CUSTOM_CERT="$2"
                shift 2
                ;;
            --custom-key)
                CUSTOM_KEY="$2"
                shift 2
                ;;
            --custom-chain)
                CUSTOM_CHAIN="$2"
                shift 2
                ;;
            --help)
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

    # Validate required parameters
    if [[ -z "$DOMAIN" ]]; then
        log_error "Domain name is required (--domain)"
        show_usage
        exit 1
    fi

    if [[ "$SSL_TYPE" == "letsencrypt" ]] && [[ -z "$EMAIL" ]] && [[ "$DOMAIN" != "localhost" ]]; then
        log_warning "Email is recommended for Let's Encrypt certificates"
    fi

    if [[ "$SSL_TYPE" == "custom" ]]; then
        if [[ -z "$CUSTOM_CERT" ]] || [[ -z "$CUSTOM_KEY" ]]; then
            log_error "Custom certificate requires --custom-cert and --custom-key"
            exit 1
        fi
    fi

    log_info "🔒 Setting up SSL certificate for OmicsOracle"
    log_info "Domain: $DOMAIN"
    log_info "Type: $SSL_TYPE"

    # Setup SSL directory
    setup_ssl_directory

    # Generate/obtain certificate based on type
    case $SSL_TYPE in
        letsencrypt)
            setup_letsencrypt "$DOMAIN" "$EMAIL" "$STAGING"
            ;;
        self-signed)
            generate_self_signed "$DOMAIN"
            ;;
        custom)
            setup_custom_certificate "$CUSTOM_CERT" "$CUSTOM_KEY" "$CUSTOM_CHAIN"
            ;;
        *)
            log_error "Invalid SSL type: $SSL_TYPE"
            show_usage
            exit 1
            ;;
    esac

    # Update Nginx configuration
    update_nginx_config "$DOMAIN"

    log_success "🎉 SSL setup completed!"
    log_info "Certificate files:"
    log_info "  - Certificate: $SSL_DIR/omics_oracle.crt"
    log_info "  - Private Key: $SSL_DIR/omics_oracle.key"
    if [[ -f "$SSL_DIR/omics_oracle_chain.crt" ]]; then
        log_info "  - Certificate Chain: $SSL_DIR/omics_oracle_chain.crt"
    fi

    log_info "Next steps:"
    log_info "  1. Review the Nginx configuration: $NGINX_CONF_DIR/nginx.conf"
    log_info "  2. Deploy with SSL: ./scripts/deploy.sh production"
    log_info "  3. Test your SSL setup: https://$DOMAIN"

    if [[ "$SSL_TYPE" == "self-signed" ]]; then
        log_warning "Remember: Self-signed certificates will show security warnings in browsers"
    fi
}

# Run main function
main "$@"
