# 🚀 OmicsOracle Production-Hardened Deployment Guide

## Quick Start

### Development
```bash
# Start development environment
./scripts/deploy.sh development

# Or manually:
docker-compose --env-file .env.development up -d
```

### Staging
```bash
# Deploy to staging
./scripts/deploy.sh staging

# With legacy interface
./scripts/deploy.sh staging --legacy
```

### Production
```bash
# Setup SSL certificates first (recommended)
./scripts/setup_ssl.sh --domain your-domain.com --email admin@your-domain.com

# Deploy to production (with confirmation)
./scripts/deploy.sh production --legacy

# Force deploy without confirmation
./scripts/deploy.sh production --force

# Monitor production deployment
./scripts/monitor.sh watch
```

## Production Features

### 🔒 Security Hardening

- **SSL/TLS encryption** with automatic Let's Encrypt certificates
- **Security headers** (HSTS, CSP, X-Frame-Options, etc.)
- **Rate limiting** on API endpoints and search functionality
- **Input validation** and sanitization
- **Secure session management** with encrypted cookies
- **Database connection security** with encrypted connections

### 📊 Monitoring & Alerting

- **Real-time health monitoring** with automatic checks
- **Performance metrics** collection and display
- **Resource usage monitoring** (CPU, memory, disk)
- **Automated alerting** via email for critical issues
- **Comprehensive logging** with rotation and retention
- **Interactive monitoring dashboard** for production

### 🚀 Performance Optimization

- **Nginx reverse proxy** with caching and compression
- **Connection pooling** for database connections
- **Redis caching** for improved response times
- **Static file optimization** with aggressive caching
- **Load balancing** ready for multi-instance deployment

### 🔄 Deployment Automation

- **Zero-downtime deployments** with health checks
- **Automatic rollback** on deployment failures
- **Environment-specific configurations** with validation
- **Pre-deployment testing** with comprehensive test suite
- **Backup automation** before production deployments

## Environment Configurations

| Environment | Database | Profiles | Purpose | Features |
|-------------|----------|----------|---------|----------|
| `development` | MongoDB | `default,dev,frontend,jupyter` | Local development | Hot reload, debug tools |
| `staging` | PostgreSQL | `default,legacy` | Testing deployment | Production-like testing |
| `production` | PostgreSQL | `production,legacy` | Live deployment | SSL, monitoring, backups |

## Available Services

### Core Services (Always Available)

- **Main Interface** (Port 8001): Futuristic interface
- **Redis**: Caching and session storage

### Profile-Based Services

- **Legacy Interface** (Port 8000): `legacy` profile
- **MongoDB** (Port 27017): `dev` profile
- **PostgreSQL** (Port 5432): `production` profile
- **Frontend** (Port 3000): `frontend` profile
- **Jupyter** (Port 8888): `jupyter` profile
- **Nginx** (Port 80/443): `production` profile

## SSL Certificate Setup

### Automatic Let's Encrypt Certificate (Recommended)

```bash
# Setup SSL with Let's Encrypt
./scripts/setup_ssl.sh --domain your-domain.com --email admin@your-domain.com

# For testing with staging certificates
./scripts/setup_ssl.sh --domain your-domain.com --email admin@your-domain.com --staging
```

### Self-Signed Certificate (Development)

```bash
# Generate self-signed certificate for localhost
./scripts/setup_ssl.sh --domain localhost --type self-signed
```

### Custom Certificate

```bash
# Use your own SSL certificate
./scripts/setup_ssl.sh --domain your-domain.com --type custom \
  --custom-cert /path/to/cert.pem \
  --custom-key /path/to/key.pem \
  --custom-chain /path/to/chain.pem
```

## Production Monitoring

### Real-time Monitoring

```bash
# Continuous monitoring with auto-refresh
./scripts/monitor.sh watch

# Check current status
./scripts/monitor.sh status

# Detailed performance metrics
./scripts/monitor.sh metrics

# Check for alerts
./scripts/monitor.sh alerts
```

### Monitoring Dashboard

```bash
# Open web-based monitoring dashboard
./scripts/monitor.sh dashboard
```

### Alert Configuration

```bash
# Monitor with custom thresholds and email alerts
./scripts/monitor.sh watch \
  --threshold-cpu 85 \
  --threshold-mem 90 \
  --email admin@your-domain.com
```

## Configuration Files

- `.env.development` - Development settings
- `.env.staging` - Staging settings
- `.env.production` - Production settings
- `.env.production.template` - Production configuration template
- `docker-compose.yml` - Unified compose file
- `config/nginx.conf` - Basic Nginx configuration
- `config/nginx.ssl.conf` - Production SSL Nginx configuration

## Manual Commands

### Start specific profiles

```bash
# Development with all optional services
COMPOSE_PROFILES=default,dev,frontend,jupyter docker-compose up -d

# Production setup with SSL
COMPOSE_PROFILES=production,legacy docker-compose --env-file .env.production up -d

# Minimal setup (just main interface + redis)
docker-compose --env-file .env.development up -d omics-oracle redis
```

### Health checks

```bash
# Check futuristic interface
curl http://localhost:8001/api/v2/health

# Check legacy interface
curl http://localhost:8000/health

# Check with SSL
curl https://your-domain.com/api/v2/health
```

### View logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f omics-oracle

# Nginx access logs
docker-compose exec nginx tail -f /var/log/nginx/access.log
```

### Backup and Maintenance

```bash
# Create manual backup
./scripts/deploy.sh production --skip-tests

# Clean up old logs and resources
./scripts/monitor.sh cleanup

# Rollback to previous deployment
./scripts/deploy.sh production --rollback
```

## Environment Variables

### Required for Production

```bash
POSTGRES_PASSWORD=secure_password
JWT_SECRET_KEY=secure_jwt_secret
OPENAI_API_KEY=your_openai_key
NCBI_API_KEY=your_ncbi_key
NCBI_EMAIL=your_email@example.com
```

### Optional Customization

```bash
MAIN_PORT=8001          # Futuristic interface port
LEGACY_PORT=8000        # Legacy interface port
REDIS_PORT=6379         # Redis port
POSTGRES_PORT=5432      # PostgreSQL port
HTTP_PORT=80            # Nginx HTTP port
HTTPS_PORT=443          # Nginx HTTPS port
```

### Security Configuration

```bash
# SSL/TLS Settings
SSL_CERT_PATH=/app/config/ssl/cert.pem
SSL_KEY_PATH=/app/config/ssl/key.pem

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_BURST=20

# CORS Settings
CORS_ORIGINS=https://your-domain.com
ALLOWED_HOSTS=your-domain.com,www.your-domain.com
```

## Production Deployment Checklist

### Pre-Deployment

- [ ] Configure production environment variables (`.env.production`)
- [ ] Setup SSL certificates (`./scripts/setup_ssl.sh`)
- [ ] Review security settings and passwords
- [ ] Test staging deployment
- [ ] Backup existing production data

### Deployment

- [ ] Deploy to production (`./scripts/deploy.sh production`)
- [ ] Verify all services are healthy
- [ ] Test SSL certificate and HTTPS access
- [ ] Check monitoring dashboard
- [ ] Verify API endpoints are working

### Post-Deployment

- [ ] Monitor application performance
- [ ] Check error logs for issues
- [ ] Test user-facing functionality
- [ ] Verify backup systems are working
- [ ] Document any issues or changes

## Troubleshooting

### Common Issues

**SSL Certificate Issues:**
```bash
# Check certificate status
openssl x509 -in config/ssl/omics_oracle.crt -text -noout

# Verify certificate chain
openssl verify -CAfile config/ssl/omics_oracle_chain.crt config/ssl/omics_oracle.crt
```

**Service Health Issues:**
```bash
# Check container logs
docker-compose logs omics-oracle

# Check resource usage
./scripts/monitor.sh metrics

# Restart specific service
docker-compose restart omics-oracle
```

**Performance Issues:**
```bash
# Monitor resource usage
./scripts/monitor.sh watch

# Check database connections
docker-compose exec postgres psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;"

# Clear Redis cache
docker-compose exec redis redis-cli FLUSHALL
```

### Emergency Procedures

**Rollback Deployment:**
```bash
./scripts/deploy.sh production --rollback --force
```

**Emergency Maintenance Mode:**
```bash
# Stop all services except Nginx (shows maintenance page)
docker-compose stop omics-oracle omics-oracle-legacy
```

**Quick Recovery:**
```bash
# Restart all services
docker-compose restart

# Force rebuild and restart
docker-compose down && ./scripts/deploy.sh production --force
```

## Removed Redundancy

### Consolidated Files

- ✅ **Single docker-compose.yml** (was: docker-compose.yml + docker-compose.production.yml)
- ✅ **Enhanced Dockerfile** (was: Dockerfile + Dockerfile.production)
- ✅ **Unified deploy.sh** (was: deploy.sh + deploy_to_all_remotes.sh)
- ✅ **Environment-specific configs** (.env.development, .env.staging, .env.production)

### Benefits

- 🎯 **Single source of truth** for deployment configuration
- 🔧 **Environment-specific customization** without duplication
- 📦 **Profile-based services** (optional components)
- 🚀 **Simplified deployment** with one script for all environments
- 🧹 **Reduced maintenance** overhead
- 🔒 **Production hardening** with security, monitoring, and performance optimization
- 📊 **Comprehensive monitoring** with real-time dashboards and alerting
- 🔄 **Automated deployment** with rollback capabilities
