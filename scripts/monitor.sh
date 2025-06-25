#!/bin/bash

# OmicsOracle Production Monitoring Script
# Provides real-time monitoring, alerting, and performance metrics

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MONITOR_LOG="$PROJECT_ROOT/logs/monitor_$(date +%Y%m%d_%H%M%S).log"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=85
ALERT_THRESHOLD_DISK=90
HEALTH_CHECK_INTERVAL=30
ALERT_EMAIL=""  # Set this for email alerts

# Ensure logs directory exists
mkdir -p "$(dirname "$MONITOR_LOG")"

# Logging functions
log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "$msg" >> "$MONITOR_LOG"
}

log_success() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1"
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$msg" >> "$MONITOR_LOG"
}

log_warning() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1"
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "$msg" >> "$MONITOR_LOG"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$msg" >> "$MONITOR_LOG"
}

log_metric() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [METRIC] $1"
    echo -e "${CYAN}[METRIC]${NC} $1"
    echo "$msg" >> "$MONITOR_LOG"
}

show_usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    status      Show current system status (default)
    watch       Continuous monitoring with auto-refresh
    health      Perform health checks
    metrics     Show detailed performance metrics
    alerts      Check for active alerts
    cleanup     Clean up old logs and data
    dashboard   Start web dashboard (if available)

OPTIONS:
    --interval SECONDS    Monitoring interval for watch mode (default: 30)
    --threshold-cpu NUM   CPU alert threshold percentage (default: 80)
    --threshold-mem NUM   Memory alert threshold percentage (default: 85)
    --threshold-disk NUM  Disk alert threshold percentage (default: 90)
    --email EMAIL         Email address for alerts
    --help               Show this help message

EXAMPLES:
    $0                    # Show current status
    $0 watch              # Continuous monitoring
    $0 metrics            # Detailed metrics
    $0 watch --interval 60 # Monitor every 60 seconds

EOF
}

# System metrics collection
get_system_metrics() {
    local metrics=()

    # CPU usage
    if command -v top >/dev/null 2>&1; then
        local cpu_usage=$(top -l 1 -n 0 | grep "CPU usage" | awk '{print $3}' | sed 's/%//' 2>/dev/null || echo "0")
        metrics+=("CPU:${cpu_usage}%")
    fi

    # Memory usage
    if command -v vm_stat >/dev/null 2>&1; then
        local memory_info=$(vm_stat | grep -E "(free|active|inactive|wired)" | awk '{print $3}' | sed 's/\.//' | paste -sd+ | bc 2>/dev/null || echo "0")
        local memory_usage=$(echo "scale=1; 100 - ($(vm_stat | grep "Pages free" | awk '{print $3}' | sed 's/\.//' || echo "0") * 100 / $memory_info)" | bc 2>/dev/null || echo "0")
        metrics+=("Memory:${memory_usage}%")
    elif command -v free >/dev/null 2>&1; then
        local memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
        metrics+=("Memory:${memory_usage}%")
    fi

    # Disk usage
    local disk_usage=$(df "$PROJECT_ROOT" | awk 'NR==2 {print $5}' | sed 's/%//')
    metrics+=("Disk:${disk_usage}%")

    # Load average
    if command -v uptime >/dev/null 2>&1; then
        local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
        metrics+=("Load:${load_avg}")
    fi

    printf "%s " "${metrics[@]}"
}

# Container health checks
check_container_health() {
    local container_name=$1
    local health_endpoint=$2

    if docker ps --format "table {{.Names}}" | grep -q "^$container_name$"; then
        local status=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "unknown")

        if [[ "$status" == "healthy" ]]; then
            echo "✅ $container_name"
        elif [[ "$status" == "unhealthy" ]]; then
            echo "❌ $container_name"
        else
            # Manual health check via HTTP
            if [[ -n "$health_endpoint" ]] && curl -f -s "$health_endpoint" > /dev/null 2>&1; then
                echo "✅ $container_name"
            else
                echo "⚠️  $container_name"
            fi
        fi
    else
        echo "🔴 $container_name (not running)"
    fi
}

# Service monitoring
monitor_services() {
    log_info "Checking service health..."

    # Check main services
    check_container_health "omics-oracle" "http://localhost:8001/api/v2/health"
    check_container_health "omics-oracle-legacy" "http://localhost:8000/health"
    check_container_health "redis" ""
    check_container_health "postgres" ""
    check_container_health "nginx" "http://localhost:80/health"

    # Check service-specific metrics
    if docker ps | grep -q omics-oracle; then
        local container_stats=$(docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" | grep omics-oracle || echo "N/A")
        log_metric "Container Stats: $container_stats"
    fi
}

# Alert system
check_alerts() {
    local alerts=()
    local metrics=$(get_system_metrics)

    # Parse metrics and check thresholds
    for metric in $metrics; do
        local name=$(echo "$metric" | cut -d: -f1)
        local value=$(echo "$metric" | cut -d: -f2 | sed 's/%//')

        case $name in
            CPU)
                if (( $(echo "$value > $ALERT_THRESHOLD_CPU" | bc -l) )); then
                    alerts+=("High CPU usage: ${value}%")
                fi
                ;;
            Memory)
                if (( $(echo "$value > $ALERT_THRESHOLD_MEMORY" | bc -l) )); then
                    alerts+=("High memory usage: ${value}%")
                fi
                ;;
            Disk)
                if (( value > ALERT_THRESHOLD_DISK )); then
                    alerts+=("High disk usage: ${value}%")
                fi
                ;;
        esac
    done

    # Check for failed services
    if ! curl -f -s "http://localhost:8001/api/v2/health" > /dev/null 2>&1; then
        alerts+=("Futuristic interface is not responding")
    fi

    if docker ps | grep -q omics-oracle-legacy && ! curl -f -s "http://localhost:8000/health" > /dev/null 2>&1; then
        alerts+=("Legacy interface is not responding")
    fi

    # Display alerts
    if [[ ${#alerts[@]} -gt 0 ]]; then
        log_error "🚨 ACTIVE ALERTS:"
        for alert in "${alerts[@]}"; do
            log_error "  - $alert"
        done

        # Send email alert if configured
        if [[ -n "$ALERT_EMAIL" ]]; then
            send_alert_email "${alerts[@]}"
        fi

        return 1
    else
        log_success "✅ No active alerts"
        return 0
    fi
}

# Email alerting (requires mailx or similar)
send_alert_email() {
    local alerts=("$@")

    if command -v mail >/dev/null 2>&1; then
        local subject="OmicsOracle Alert - $(date)"
        local body="The following alerts have been triggered:\n\n"

        for alert in "${alerts[@]}"; do
            body="${body}- $alert\n"
        done

        body="${body}\nPlease check the system immediately.\n\nGenerated at: $(date)"

        echo -e "$body" | mail -s "$subject" "$ALERT_EMAIL"
        log_info "Alert email sent to $ALERT_EMAIL"
    else
        log_warning "Mail command not available, email alert not sent"
    fi
}

# Performance metrics
show_detailed_metrics() {
    log_info "=== DETAILED PERFORMANCE METRICS ==="
    echo ""

    # System metrics
    log_metric "System Metrics: $(get_system_metrics)"

    # Docker stats
    if docker ps --quiet | wc -l | grep -q -v "^0$"; then
        log_info "Docker Container Statistics:"
        docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"
    fi

    # Network connections
    log_info "Active Network Connections:"
    netstat -an | grep -E ":(8001|8000|5432|6379)" | head -10 || echo "None found"

    # Recent errors in logs
    if [[ -f "$PROJECT_ROOT/logs/omics_oracle_web_errors.log" ]]; then
        local error_count=$(tail -100 "$PROJECT_ROOT/logs/omics_oracle_web_errors.log" 2>/dev/null | wc -l)
        log_metric "Recent errors in application log: $error_count"
    fi

    # Database connections (if PostgreSQL is running)
    if docker ps | grep -q postgres; then
        local db_connections=$(docker exec -it $(docker ps --filter "name=postgres" --format "{{.Names}}" | head -1) psql -U postgres -t -c "SELECT count(*) FROM pg_stat_activity;" 2>/dev/null | tr -d ' \n' || echo "N/A")
        log_metric "Database connections: $db_connections"
    fi

    echo ""
}

# Cleanup operations
cleanup_logs() {
    log_info "Cleaning up old logs and temporary files..."

    # Clean logs older than 30 days
    find "$PROJECT_ROOT/logs" -name "*.log" -mtime +30 -delete 2>/dev/null || true

    # Clean old deployment logs
    find "$PROJECT_ROOT/logs" -name "deployment_*.log" -mtime +7 -delete 2>/dev/null || true

    # Clean old monitoring logs
    find "$PROJECT_ROOT/logs" -name "monitor_*.log" -mtime +7 -delete 2>/dev/null || true

    # Clean Docker images and containers
    log_info "Cleaning up Docker resources..."
    docker system prune -f --filter "until=24h" || true

    # Clean old backups (keep last 10)
    if [[ -d "$PROJECT_ROOT/backups" ]]; then
        ls -t "$PROJECT_ROOT/backups" | tail -n +11 | xargs -I {} rm -rf "$PROJECT_ROOT/backups/{}" 2>/dev/null || true
    fi

    log_success "Cleanup completed"
}

# Watch mode for continuous monitoring
watch_mode() {
    local interval=${HEALTH_CHECK_INTERVAL}

    log_info "Starting continuous monitoring (interval: ${interval}s)"
    log_info "Press Ctrl+C to stop"

    while true; do
        clear
        echo -e "${PURPLE}🧬 OmicsOracle Production Monitor${NC}"
        echo -e "${BLUE}Last updated: $(date)${NC}"
        echo ""

        # System metrics
        echo -e "${CYAN}System Metrics:${NC} $(get_system_metrics)"
        echo ""

        # Service status
        echo -e "${CYAN}Service Status:${NC}"
        monitor_services
        echo ""

        # Alert check
        if ! check_alerts; then
            echo ""
        fi

        sleep "$interval"
    done
}

# Parse command line arguments
parse_arguments() {
    COMMAND="status"

    while [[ $# -gt 0 ]]; do
        case $1 in
            status|watch|health|metrics|alerts|cleanup|dashboard)
                COMMAND="$1"
                shift
                ;;
            --interval)
                HEALTH_CHECK_INTERVAL="$2"
                shift 2
                ;;
            --threshold-cpu)
                ALERT_THRESHOLD_CPU="$2"
                shift 2
                ;;
            --threshold-mem)
                ALERT_THRESHOLD_MEMORY="$2"
                shift 2
                ;;
            --threshold-disk)
                ALERT_THRESHOLD_DISK="$2"
                shift 2
                ;;
            --email)
                ALERT_EMAIL="$2"
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
}

# Main execution
main() {
    parse_arguments "$@"

    log_info "🔍 OmicsOracle Production Monitor"
    log_info "Command: $COMMAND"
    log_info "Log file: $MONITOR_LOG"

    case $COMMAND in
        status)
            log_info "=== CURRENT STATUS ==="
            echo "System Metrics: $(get_system_metrics)"
            echo ""
            monitor_services
            echo ""
            check_alerts
            ;;
        watch)
            watch_mode
            ;;
        health)
            log_info "=== HEALTH CHECK ==="
            monitor_services
            ;;
        metrics)
            show_detailed_metrics
            ;;
        alerts)
            log_info "=== ALERT CHECK ==="
            check_alerts
            ;;
        cleanup)
            cleanup_logs
            ;;
        dashboard)
            if [[ -f "$PROJECT_ROOT/monitoring_dashboard.html" ]]; then
                log_info "Opening monitoring dashboard..."
                if command -v open >/dev/null 2>&1; then
                    open "file://$PROJECT_ROOT/monitoring_dashboard.html"
                else
                    log_info "Dashboard available at: file://$PROJECT_ROOT/monitoring_dashboard.html"
                fi
            else
                log_error "Monitoring dashboard not found. Run a production deployment first."
            fi
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
