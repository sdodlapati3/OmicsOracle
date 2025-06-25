# OmicsOracle Backend API

**Pure REST API Backend for OmicsOracle**

## Overview
The Backend API provides programmatic access to OmicsOracle functionality through RESTful endpoints. This is a pure API service without any frontend interface - it's designed for developers and applications that need to integrate with OmicsOracle programmatically.

## Features
- 🔌 RESTful API endpoints
- 📊 Structured JSON responses
- 🔐 API authentication support
- 📈 Rate limiting and monitoring
- 🧪 Comprehensive API testing suite

## Quick Start

### Start the API Server
```bash
./start.sh
```

The API will be available at: **http://localhost:8000**

### API Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI Schema: http://localhost:8000/openapi.json

## Key Endpoints

### Health Check
```bash
GET /health
```

### Search Biological Data
```bash
POST /search
Content-Type: application/json

{
  "query": "breast cancer",
  "max_results": 10,
  "include_sra": false
}
```

### Query Processing
```bash
POST /process-query
Content-Type: application/json

{
  "query": "RNA-seq data for breast cancer",
  "result_format": "json"
}
```

## Configuration
- **Port**: 8000
- **Host**: 0.0.0.0 (all interfaces)
- **Environment**: Production-ready
- **Dependencies**: See requirements.txt

## Usage Examples

### Python
```python
import requests

# Search for datasets
response = requests.post(
    "http://localhost:8000/search",
    json={"query": "breast cancer", "max_results": 5}
)
data = response.json()
```

### cURL
```bash
curl -X POST "http://localhost:8000/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "breast cancer", "max_results": 5}'
```

## Architecture
- **Framework**: FastAPI
- **Database**: SQLite (development), PostgreSQL (production)
- **Authentication**: JWT tokens
- **Monitoring**: Built-in metrics and logging
