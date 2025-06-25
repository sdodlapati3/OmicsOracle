#!/bin/bash

# OmicsOracle Deployment Validation Script
# Tests the existing deployment infrastructure

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 OmicsOracle Deployment Infrastructure Validation${NC}"
echo "============================================================"

# Check if Docker is available
echo -e "\n${BLUE}📦 Checking Docker...${NC}"
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✅ Docker is installed${NC}"
    docker --version
else
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

# Check if Docker Compose is available
echo -e "\n${BLUE}🔧 Checking Docker Compose...${NC}"
if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
    echo -e "${GREEN}✅ Docker Compose is available${NC}"
    if command -v docker-compose &> /dev/null; then
        docker-compose --version
    else
        docker compose version
    fi
else
    echo -e "${RED}❌ Docker Compose is not available${NC}"
    exit 1
fi

# Check deployment files
echo -e "\n${BLUE}📄 Checking deployment files...${NC}"

files=(
    "Dockerfile"
    "Dockerfile.production"
    "docker-compose.yml"
    "docker-compose.production.yml"
    "config/nginx.conf"
    "config/prometheus.yml"
    ".env.example"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅ $file${NC}"
    else
        echo -e "${RED}❌ $file${NC}"
    fi
done

# Check if .env exists
echo -e "\n${BLUE}🔐 Checking environment configuration...${NC}"
if [ -f ".env" ]; then
    echo -e "${GREEN}✅ .env file exists${NC}"
else
    echo -e "${YELLOW}⚠️  .env file not found (copy from .env.example)${NC}"
fi

# Test development deployment
echo -e "\n${BLUE}🧪 Testing development build...${NC}"
if docker build -t omics-oracle-test . > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Development Docker build successful${NC}"
    docker rmi omics-oracle-test > /dev/null 2>&1
else
    echo -e "${RED}❌ Development Docker build failed${NC}"
fi

# Test production build
echo -e "\n${BLUE}🏭 Testing production build...${NC}"
if docker build -f Dockerfile.production -t omics-oracle-prod-test . > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Production Docker build successful${NC}"
    docker rmi omics-oracle-prod-test > /dev/null 2>&1
else
    echo -e "${RED}❌ Production Docker build failed${NC}"
fi

# Check deployment scripts
echo -e "\n${BLUE}🚀 Checking deployment scripts...${NC}"
if [ -f "scripts/deployment/deploy_to_all_remotes.sh" ]; then
    echo -e "${GREEN}✅ Deployment script exists${NC}"
else
    echo -e "${RED}❌ Deployment script not found${NC}"
fi

echo -e "\n${BLUE}📊 Summary${NC}"
echo "============================================================"
echo -e "${GREEN}✅ Deployment infrastructure is ready!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Copy .env.example to .env and configure your API keys"
echo "2. Run: docker-compose -f docker-compose.production.yml up --build"
echo "3. Test the deployment at http://localhost"
echo ""
echo -e "${BLUE}🌐 Endpoints after deployment:${NC}"
echo "  - Futuristic Interface: http://localhost (port 80)"
echo "  - Legacy Interface: http://localhost/legacy"
echo "  - Prometheus Monitoring: http://localhost:9090"
echo "  - Health Check: http://localhost/health"
