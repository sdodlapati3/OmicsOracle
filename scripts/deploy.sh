#!/bin/bash

# OmicsOracle Production-Hardened Deployment Script
# Supports development, staging, and production deployments with comprehensive checks
# Features: Health monitoring, automatic rollback, security checks, performance monitoring

set -e  # Exit on any error
set -u  # Exit on undefined variables
set -o pipefail  # Exit on pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEFAULT_ENV="development"
DEPLOYMENT_LOG="$PROJECT_ROOT/logs/deployment_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="$PROJECT_ROOT/backups"
MAX_HEALTH_RETRIES=30
HEALTH_CHECK_INTERVAL=10

# Ensure logs directory exists
mkdir -p "$(dirname "$DEPLOYMENT_LOG")"
mkdir -p "$BACKUP_DIR"

# Logging functions
log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "$msg" >> "$DEPLOYMENT_LOG"
}

log_success() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1"
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$msg" >> "$DEPLOYMENT_LOG"
}

log_warning() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1"
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "$msg" >> "$DEPLOYMENT_LOG"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$msg" >> "$DEPLOYMENT_LOG"
}

log_debug() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $1"
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1"
    fi
    echo "$msg" >> "$DEPLOYMENT_LOG"
}

show_usage() {
    cat << EOF
Usage: $0 [ENVIRONMENT] [OPTIONS]

ENVIRONMENT:
    development Deploy for local development (default)
    staging     Deploy to staging environment
    production  Deploy to production environment

OPTIONS:
    --skip-tests        Skip running tests before deployment
    --skip-backup       Skip database backup (production only)
    --force            Force deployment without confirmations
    --legacy           Include legacy interface
    --rollback         Rollback to previous deployment
    --debug            Enable debug logging
    --dry-run          Show what would be deployed without executing
    --help             Show this help message

EXAMPLES:
    $0                          # Development deployment
    $0 staging                  # Staging deployment
    $0 production --legacy      # Production with legacy interface
    $0 development --force      # Skip confirmations
    $0 production --rollback    # Rollback production deployment

EOF
}

# Trap function for cleanup on script exit
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Deployment failed with exit code $exit_code"
        if [[ "${ENVIRONMENT:-}" == "production" ]] && [[ "${AUTO_ROLLBACK:-true}" == "true" ]]; then
            log_warning "Initiating automatic rollback..."
            rollback_deployment
        fi
    fi
    exit $exit_code
}

trap cleanup EXIT

# Security validation
validate_environment_security() {
    local env=$1
    log_info "Validating security configuration for $env..."

    # Check for secure passwords in production
    if [[ "$env" == "production" ]]; then
        if [[ -f ".env.production" ]]; then
            # Check for weak passwords
            if grep -q "password.*=.*123\|password.*=.*password\|password.*=.*admin" ".env.production" 2>/dev/null; then
                log_error "Weak passwords detected in production configuration!"
                return 1
            fi

            # Check for missing required secrets
            local required_vars=("POSTGRES_PASSWORD" "JWT_SECRET_KEY" "REDIS_PASSWORD")
            for var in "${required_vars[@]}"; do
                if ! grep -q "^$var=" ".env.production" 2>/dev/null; then
                    log_error "Required security variable $var is missing from .env.production"
                    return 1
                fi
            done
        fi
    fi

    log_success "Security validation passed"
    return 0
}

# Performance and resource checks
check_system_resources() {
    log_info "Checking system resources..."

    # Check available disk space (require at least 2GB)
    local available_space=$(df "$PROJECT_ROOT" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 2097152 ]]; then  # 2GB in KB
        log_warning "Low disk space: $(($available_space / 1024))MB available"
    fi

    # Check available memory
    if command -v free >/dev/null 2>&1; then
        local available_mem=$(free -m | awk 'NR==2{print $7}')
        if [[ $available_mem -lt 1024 ]]; then
            log_warning "Low memory: ${available_mem}MB available"
        fi
    fi

    # Check if ports are available
    local ports_to_check=("8001" "6379")
    if [[ "$INCLUDE_LEGACY" == "true" ]]; then
        ports_to_check+=("8000")
    fi

    for port in "${ports_to_check[@]}"; do
        if netstat -ln 2>/dev/null | grep -q ":$port "; then
            log_warning "Port $port is already in use"
        fi
    done

    log_success "System resource check completed"
}

# Backup functions
create_backup() {
    local env=$1
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        log_warning "Skipping backup as requested"
        return 0
    fi

    log_info "Creating backup for $env environment..."

    local backup_name="backup_${env}_$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"

    mkdir -p "$backup_path"

    # Backup environment configuration
    if [[ -f ".env.$env" ]]; then
        cp ".env.$env" "$backup_path/"
        log_debug "Backed up .env.$env"
    fi

    # Backup docker volumes (if any data exists)
    if docker volume ls -q | grep -q omics; then
        log_info "Backing up Docker volumes..."
        docker run --rm -v omics_oracle_data:/data -v "$backup_path":/backup alpine tar czf /backup/volumes.tar.gz -C /data . 2>/dev/null || log_warning "Volume backup failed or no data to backup"
    fi

    # Store backup metadata
    cat > "$backup_path/metadata.json" << EOF
{
    "environment": "$env",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "deployment_version": "$(date +%Y%m%d_%H%M%S)"
}
EOF

    echo "$backup_name" > "$BACKUP_DIR/latest_backup"
    log_success "Backup created: $backup_name"
    return 0
}

rollback_deployment() {
    log_warning "Rolling back deployment..."

    if [[ ! -f "$BACKUP_DIR/latest_backup" ]]; then
        log_error "No backup found for rollback"
        return 1
    fi

    local backup_name=$(cat "$BACKUP_DIR/latest_backup")
    local backup_path="$BACKUP_DIR/$backup_name"

    if [[ ! -d "$backup_path" ]]; then
        log_error "Backup directory not found: $backup_path"
        return 1
    fi

    log_info "Restoring from backup: $backup_name"

    # Stop current services
    docker-compose down || true

    # Restore configuration
    if [[ -f "$backup_path/.env.$ENVIRONMENT" ]]; then
        cp "$backup_path/.env.$ENVIRONMENT" ".env.$ENVIRONMENT"
        log_debug "Restored .env.$ENVIRONMENT"
    fi

    # Restore volumes if backup exists
    if [[ -f "$backup_path/volumes.tar.gz" ]]; then
        docker run --rm -v omics_oracle_data:/data -v "$backup_path":/backup alpine tar xzf /backup/volumes.tar.gz -C /data
        log_debug "Restored Docker volumes"
    fi

    log_success "Rollback completed"
}

# Enhanced prerequisite checks
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi

    # Check Docker version compatibility
    local docker_version=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
    local min_version="20.10"
    if [[ "$(printf '%s\n' "$min_version" "$docker_version" | sort -V | head -n1)" != "$min_version" ]]; then
        log_warning "Docker version $docker_version is older than recommended $min_version"
    fi

    # Check if docker-compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available. Please install Docker Compose."
        exit 1
    fi

    # Determine compose command
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    export COMPOSE_CMD

    # Check for required files
    local required_files=("docker-compose.yml" "Dockerfile")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$PROJECT_ROOT/$file" ]]; then
            log_error "Required file not found: $file"
            exit 1
        fi
    done

    log_success "Prerequisites check passed"
}

# Enhanced testing with coverage and security
run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        log_warning "Skipping tests as requested"
        return 0
    fi

    log_info "Running comprehensive test suite..."
    cd "$PROJECT_ROOT"

    # Create test results directory
    mkdir -p test_results

    # Run security tests
    log_info "Running security scans..."
    if command -v bandit &> /dev/null; then
        bandit -r src/ -f json -o test_results/security_scan.json || log_warning "Security scan found issues"
    fi

    # Run unit tests with coverage
    log_info "Running unit tests..."
    if ! python -m pytest tests/unit/ -v --cov=src --cov-report=html:test_results/coverage --cov-report=json:test_results/coverage.json; then
        log_error "Unit tests failed. Aborting deployment."
        exit 1
    fi

    # Run integration tests
    log_info "Running integration tests..."
    if ! python -m pytest tests/integration/ -v --maxfail=3; then
        log_error "Integration tests failed. Aborting deployment."
        exit 1
    fi

    # Validate interfaces
    log_info "Validating interfaces..."
    if [[ -f "interfaces/futuristic/validate_interface.py" ]]; then
        if ! (cd interfaces/futuristic && python validate_interface.py); then
            log_error "Futuristic interface validation failed. Aborting deployment."
            exit 1
        fi
    fi

    # Performance baseline tests for production
    if [[ "$ENVIRONMENT" == "production" ]]; then
        log_info "Running performance baseline tests..."
        if [[ -f "tests/performance/baseline_test.py" ]]; then
            python tests/performance/baseline_test.py || log_warning "Performance tests completed with warnings"
        fi
    fi

    log_success "All tests passed"
}

# Enhanced deployment with monitoring
deploy_environment() {
    local env=$1
    log_info "Deploying to $env environment..."

    cd "$PROJECT_ROOT"

    # Use environment-specific .env file
    if [[ -f ".env.$env" ]]; then
        log_info "Using environment file: .env.$env"
        cp ".env.$env" ".env"
    else
        log_warning "No .env.$env file found, using existing .env or defaults"
    fi

    # Set compose profiles based on environment and options
    local profiles="default"
    case $env in
        development)
            profiles="default,dev,frontend"
            if command -v jupyter &> /dev/null; then
                profiles="$profiles,jupyter"
            fi
            ;;
        staging)
            profiles="default,legacy"
            ;;
        production)
            profiles="production"
            if [[ "$INCLUDE_LEGACY" == "true" ]]; then
                profiles="$profiles,legacy"
            fi
            ;;
    esac

    export COMPOSE_PROFILES="$profiles"
    log_info "Using profiles: $profiles"

    # Stop existing services gracefully
    log_info "Stopping existing services..."
    $COMPOSE_CMD down --remove-orphans || true

    # Pull latest images for production
    if [[ "$env" == "production" ]]; then
        log_info "Pulling latest images..."
        $COMPOSE_CMD pull || log_warning "Some images couldn't be pulled"
    fi

    # Build and start services
    log_info "Building and starting services..."
    $COMPOSE_CMD build --parallel
    $COMPOSE_CMD up -d --remove-orphans

    # Enhanced health checking with retry logic
    perform_health_checks

    # Performance monitoring setup
    setup_monitoring "$env"

    log_success "Deployment completed for $env environment"
}

# Comprehensive health checks
perform_health_checks() {
    log_info "Performing comprehensive health checks..."

    local main_port=${MAIN_PORT:-8001}
    local legacy_port=${LEGACY_PORT:-8000}
    local retry_count=0

    # Wait for containers to start
    log_info "Waiting for containers to initialize..."
    sleep 15

    # Check main interface
    log_info "Checking futuristic interface health..."
    while [[ $retry_count -lt $MAX_HEALTH_RETRIES ]]; do
        if curl -f -s "http://localhost:$main_port/api/v2/health" > /dev/null 2>&1; then
            log_success "✅ Futuristic interface is healthy (http://localhost:$main_port)"
            break
        fi

        ((retry_count++))
        log_debug "Health check attempt $retry_count/$MAX_HEALTH_RETRIES for futuristic interface"
        sleep $HEALTH_CHECK_INTERVAL
    done

    if [[ $retry_count -eq $MAX_HEALTH_RETRIES ]]; then
        log_error "❌ Futuristic interface health check failed after $MAX_HEALTH_RETRIES attempts"
        return 1
    fi

    # Check legacy interface if enabled
    if [[ "$INCLUDE_LEGACY" == "true" ]]; then
        retry_count=0
        log_info "Checking legacy interface health..."
        while [[ $retry_count -lt $MAX_HEALTH_RETRIES ]]; do
            if curl -f -s "http://localhost:$legacy_port/health" > /dev/null 2>&1; then
                log_success "✅ Legacy interface is healthy (http://localhost:$legacy_port)"
                break
            fi

            ((retry_count++))
            log_debug "Health check attempt $retry_count/$MAX_HEALTH_RETRIES for legacy interface"
            sleep $HEALTH_CHECK_INTERVAL
        done

        if [[ $retry_count -eq $MAX_HEALTH_RETRIES ]]; then
            log_warning "⚠️  Legacy interface health check failed"
        fi
    fi

    # Check database connectivity
    if $COMPOSE_CMD ps | grep -q postgres; then
        log_info "Checking PostgreSQL connectivity..."
        if $COMPOSE_CMD exec -T postgres pg_isready > /dev/null 2>&1; then
            log_success "✅ PostgreSQL is ready"
        else
            log_warning "⚠️  PostgreSQL connectivity check failed"
        fi
    fi

    # Check Redis connectivity
    if $COMPOSE_CMD ps | grep -q redis; then
        log_info "Checking Redis connectivity..."
        if $COMPOSE_CMD exec -T redis redis-cli ping > /dev/null 2>&1; then
            log_success "✅ Redis is ready"
        else
            log_warning "⚠️  Redis connectivity check failed"
        fi
    fi

    log_success "Health checks completed"
}

# Monitoring setup
setup_monitoring() {
    local env=$1

    if [[ "$env" == "production" ]]; then
        log_info "Setting up production monitoring..."

        # Create monitoring dashboard
        cat > "$PROJECT_ROOT/monitoring_dashboard.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OmicsOracle Monitoring Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status { padding: 5px 10px; border-radius: 4px; color: white; font-weight: bold; }
        .healthy { background: #28a745; }
        .warning { background: #ffc107; color: #212529; }
        .error { background: #dc3545; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        h1 { color: #333; text-align: center; }
        h2 { color: #555; margin-top: 0; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; }
        .refresh-btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧬 OmicsOracle Monitoring Dashboard</h1>
        <div style="text-align: center; margin: 20px 0;">
            <button class="refresh-btn" onclick="window.location.reload()">Refresh Status</button>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Service Status</h2>
                <div id="service-status">
                    <div class="metric">
                        <span>Futuristic Interface:</span>
                        <span class="status healthy" id="main-status">Checking...</span>
                    </div>
                    <div class="metric">
                        <span>Legacy Interface:</span>
                        <span class="status healthy" id="legacy-status">Checking...</span>
                    </div>
                    <div class="metric">
                        <span>Database:</span>
                        <span class="status healthy" id="db-status">Checking...</span>
                    </div>
                    <div class="metric">
                        <span>Redis Cache:</span>
                        <span class="status healthy" id="redis-status">Checking...</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Quick Links</h2>
                <div>
                    <p><a href="http://localhost:8001" target="_blank">🚀 Futuristic Interface</a></p>
                    <p><a href="http://localhost:8000" target="_blank">📊 Legacy Interface</a></p>
                    <p><a href="http://localhost:8001/docs" target="_blank">📖 API Documentation</a></p>
                    <p><a href="http://localhost:8001/api/v2/health" target="_blank">🔍 Health Check</a></p>
                </div>
            </div>

            <div class="card">
                <h2>Deployment Info</h2>
                <div class="metric">
                    <span>Environment:</span>
                    <span>Production</span>
                </div>
                <div class="metric">
                    <span>Deployed:</span>
                    <span id="deploy-time">%DEPLOY_TIME%</span>
                </div>
                <div class="metric">
                    <span>Version:</span>
                    <span id="version">%VERSION%</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => window.location.reload(), 30000);

        // Check service status
        async function checkStatus(url, elementId) {
            try {
                const response = await fetch(url);
                const element = document.getElementById(elementId);
                if (response.ok) {
                    element.textContent = 'Healthy';
                    element.className = 'status healthy';
                } else {
                    element.textContent = 'Error';
                    element.className = 'status error';
                }
            } catch (error) {
                const element = document.getElementById(elementId);
                element.textContent = 'Offline';
                element.className = 'status error';
            }
        }

        // Check all services
        checkStatus('http://localhost:8001/api/v2/health', 'main-status');
        checkStatus('http://localhost:8000/health', 'legacy-status');
    </script>
</body>
</html>
EOF

        # Replace placeholders
        sed -i.bak "s/%DEPLOY_TIME%/$(date)/g" "$PROJECT_ROOT/monitoring_dashboard.html"
        sed -i.bak "s/%VERSION%/$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')/g" "$PROJECT_ROOT/monitoring_dashboard.html"
        rm -f "$PROJECT_ROOT/monitoring_dashboard.html.bak"

        log_success "Monitoring dashboard created: monitoring_dashboard.html"
    fi
}

# Deployment summary and reporting
show_deployment_summary() {
    local env=$1

    log_info "=== DEPLOYMENT SUMMARY ==="
    echo ""
    log_info "Environment: $env"
    log_info "Timestamp: $(date)"
    log_info "Deployed by: $(whoami)"
    log_info "Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    echo ""

    log_info "Services Status:"
    $COMPOSE_CMD ps
    echo ""

    log_info "Access Points:"
    echo "  🚀 Futuristic Interface: http://localhost:${MAIN_PORT:-8001}"
    if [[ "$INCLUDE_LEGACY" == "true" ]]; then
        echo "  📊 Legacy Interface: http://localhost:${LEGACY_PORT:-8000}"
    fi
    echo "  📖 API Documentation: http://localhost:${MAIN_PORT:-8001}/docs"
    echo "  🔍 Health Check: http://localhost:${MAIN_PORT:-8001}/api/v2/health"

    if [[ "$env" == "production" ]]; then
        echo "  📊 Monitoring Dashboard: file://$PROJECT_ROOT/monitoring_dashboard.html"
    fi
    echo ""

    log_info "Logs Location: $DEPLOYMENT_LOG"

    if [[ "$env" == "production" ]]; then
        log_info "🔥 Production deployment completed successfully!"
        log_warning "Remember to:"
        echo "  - Monitor application performance"
        echo "  - Check error logs regularly"
        echo "  - Ensure backups are working"
        echo "  - Monitor resource usage"
    fi
}

# Parse command line arguments
parse_arguments() {
    ENVIRONMENT="$DEFAULT_ENV"
    SKIP_TESTS=false
    SKIP_BACKUP=false
    FORCE=false
    INCLUDE_LEGACY=false
    DRY_RUN=false
    ROLLBACK=false
    DEBUG=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            development|staging|production)
                ENVIRONMENT="$1"
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --legacy)
                INCLUDE_LEGACY=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --debug)
                DEBUG=true
                shift
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

    # Export variables for use in other functions
    export ENVIRONMENT SKIP_TESTS SKIP_BACKUP FORCE INCLUDE_LEGACY DRY_RUN ROLLBACK DEBUG
}

# Main execution function
main() {
    # Parse arguments first
    parse_arguments "$@"

    log_info "🚀 Starting OmicsOracle Production-Hardened Deployment"
    log_info "Environment: $ENVIRONMENT"
    log_info "Log file: $DEPLOYMENT_LOG"

    if [[ "$DEBUG" == "true" ]]; then
        log_info "Debug mode enabled"
        set -x  # Enable command tracing
    fi

    # Handle rollback
    if [[ "$ROLLBACK" == "true" ]]; then
        if [[ "$ENVIRONMENT" == "production" ]] && [[ "$FORCE" != "true" ]]; then
            log_warning "⚠️  You are about to ROLLBACK PRODUCTION"
            read -p "Are you sure? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Rollback cancelled"
                exit 0
            fi
        fi
        rollback_deployment
        exit 0
    fi

    # Dry run mode
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "🔍 DRY RUN MODE - No changes will be made"
        log_info "Would deploy to: $ENVIRONMENT"
        log_info "Would include legacy: $INCLUDE_LEGACY"
        log_info "Would skip tests: $SKIP_TESTS"
        log_info "Would skip backup: $SKIP_BACKUP"
        exit 0
    fi

    # Load environment variables
    if [[ -f ".env.$ENVIRONMENT" ]]; then
        source ".env.$ENVIRONMENT"
    fi

    # Confirmation for production
    if [[ "$ENVIRONMENT" == "production" ]] && [[ "$FORCE" != "true" ]]; then
        log_warning "⚠️  You are about to deploy to PRODUCTION"
        log_warning "This will affect live users and services"
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deployment cancelled"
            exit 0
        fi
    fi

    # Execute deployment pipeline
    check_prerequisites
    validate_environment_security "$ENVIRONMENT"
    check_system_resources
    create_backup "$ENVIRONMENT"
    run_tests
    deploy_environment "$ENVIRONMENT"
    show_deployment_summary "$ENVIRONMENT"

    log_success "🎉 Deployment pipeline completed successfully!"
}

# Run main function with all arguments
main "$@"
