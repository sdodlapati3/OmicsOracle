# Futuristic Interface Enhanced - Development Guide

## Quick Start

### Prerequisites
- **Node.js** 18+ and npm 8+
- **Python** 3.8+ with virtual environment
- **Git** for version control

### Setup Development Environment

1. **Navigate to the enhanced interface directory:**
   ```bash
   cd interfaces/futuristic_enhanced/
   ```

2. **Install Node.js dependencies:**
   ```bash
   npm install
   ```

3. **Start development server:**
   ```bash
   # Option 1: Full development mode (recommended)
   npm run dev
   
   # Option 2: Backend only
   npm run serve
   
   # Option 3: Frontend build watch mode
   npm run build:watch
   ```

4. **Access the interface:**
   - **Main Interface**: http://localhost:8001
   - **API Documentation**: http://localhost:8001/docs
   - **WebSocket**: ws://localhost:8001/ws/{client_id}

## Development Commands

### Building and Serving
```bash
# Development with hot reload
npm run dev

# Production build
npm run build

# Serve backend only
npm run serve

# Watch mode for assets
npm run build:watch
```

### Code Quality
```bash
# Lint JavaScript/TypeScript
npm run lint
npm run lint:fix

# Format code
npm run format
npm run format:check

# Type checking
npm run type-check
```

### Testing
```bash
# Run all tests
npm test

# Watch mode testing
npm run test:watch

# Run with coverage
npm test -- --coverage
```

### Maintenance
```bash
# Clean build artifacts
npm run clean

# Prepare for deployment
npm run prepare
```

## Project Structure

```
interfaces/futuristic_enhanced/
├── package.json           # Node.js dependencies and scripts
├── webpack.config.js      # Build configuration
├── tsconfig.json         # TypeScript configuration
├── .eslintrc.js          # Linting rules
├── .prettierrc           # Code formatting rules
├── main.py               # FastAPI backend entry point
├── agents/               # AI agent system
├── ui/                   # Backend UI routes
├── static/               # Frontend source code
│   ├── js/              # JavaScript/TypeScript files
│   ├── css/             # Stylesheets
│   └── assets/          # Images, fonts, etc.
├── dist/                # Built frontend assets (generated)
├── tests/               # Test files
└── docs/                # Documentation
```

## Backend Integration

### Clean Architecture API Integration

The enhanced interface integrates with the Clean Architecture backend:

```python
# Example API integration
import requests

# v2 API endpoints
base_url = "http://localhost:8000/api/v2"

# Search datasets
response = requests.post(f"{base_url}/search", json={
    "query": "cancer genomics",
    "filters": {"organism": "human"}
})

# Enhanced search with metadata
response = requests.post(f"{base_url}/search/enhanced", json={
    "query": "BRCA1 mutations",
    "include_metadata": True
})
```

### WebSocket Integration

Real-time features use WebSocket connections:

```javascript
// Connect to WebSocket
const ws = new WebSocket(`ws://localhost:8001/ws/${clientId}`);

// Handle real-time updates
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    handleRealtimeUpdate(data);
};
```

## Configuration

### Environment Variables

Create `.env` file in the interface directory:

```bash
# Backend configuration
BACKEND_URL=http://localhost:8000
NCBI_EMAIL=your-email@example.com

# Interface configuration
INTERFACE_PORT=8001
DEBUG_MODE=true
LOG_LEVEL=INFO

# Feature flags
ENABLE_REAL_TIME=true
ENABLE_ADVANCED_CHARTS=true
```

### API Configuration

The interface automatically detects and connects to:
- **Clean Architecture Backend**: http://localhost:8000
- **Legacy Backend**: Fallback mode available

## Development Workflow

### 1. Feature Development
```bash
# Create feature branch
git checkout -b feature/new-visualization

# Start development server
npm run dev

# Make changes to static/js/ or static/css/
# Hot reload will update automatically

# Test changes
npm test

# Lint and format
npm run lint:fix
npm run format
```

### 2. Backend Integration
```bash
# Ensure Clean Architecture backend is running
cd ../../  # Back to project root
./start_server.sh

# In another terminal, start interface
cd interfaces/futuristic_enhanced/
npm run dev
```

### 3. Testing Strategy
```bash
# Unit tests for JavaScript/TypeScript
npm test

# Integration tests (Python backend)
cd ../../
python -m pytest tests/integration/

# End-to-end tests
python test_endpoints_comprehensive.py
```

## Advanced Features

### Real-time Data Streaming

The interface supports real-time data updates via WebSockets:

```javascript
class RealtimeDataManager {
    constructor(websocket) {
        this.ws = websocket;
        this.subscribers = new Map();
    }
    
    subscribe(eventType, callback) {
        if (!this.subscribers.has(eventType)) {
            this.subscribers.set(eventType, []);
        }
        this.subscribers.get(eventType).push(callback);
    }
    
    handleMessage(data) {
        const { type, payload } = data;
        const callbacks = this.subscribers.get(type) || [];
        callbacks.forEach(callback => callback(payload));
    }
}
```

### Multi-Agent Coordination

The agent system provides modular AI capabilities:

```python
# Example agent usage
from agents.orchestrator import AgentOrchestrator
from agents.search_agent import SearchAgent
from agents.visualization_agent import VisualizationAgent

orchestrator = AgentOrchestrator()
orchestrator.register_agent(SearchAgent())
orchestrator.register_agent(VisualizationAgent())

result = await orchestrator.process_request({
    "type": "search_and_visualize",
    "query": "cancer genomics",
    "visualization_type": "scatter_plot"
})
```

## Performance Optimization

### Frontend Performance
- **Code Splitting**: Webpack automatically splits vendor and app code
- **Hot Module Replacement**: Fast development updates
- **Source Maps**: Debugging support in development
- **Asset Optimization**: Minification and compression in production

### Backend Performance
- **Async Operations**: FastAPI with async/await
- **Caching**: Integration with Redis cache hierarchy
- **Connection Pooling**: Efficient database connections
- **Load Balancing**: Ready for horizontal scaling

## Deployment

### Development Deployment
```bash
# Build production assets
npm run build

# Start production server
python main.py
```

### Production Deployment
```bash
# Install dependencies
npm ci --production

# Build optimized bundle
npm run build

# Start with process manager
pm2 start main.py --name futuristic-interface
```

## Troubleshooting

### Common Issues

1. **Port conflicts:**
   ```bash
   # Check what's using port 8001
   lsof -i :8001
   
   # Kill process if needed
   kill -9 <PID>
   ```

2. **Node.js version issues:**
   ```bash
   # Check version
   node --version
   
   # Use nvm to manage versions
   nvm use 18
   ```

3. **Python import errors:**
   ```bash
   # Ensure you're in the right directory
   cd interfaces/futuristic_enhanced/
   
   # Check Python path
   python -c "import sys; print(sys.path)"
   ```

4. **WebSocket connection issues:**
   - Ensure backend is running on correct port
   - Check CORS configuration
   - Verify client ID generation

### Debug Mode

Enable debug mode for detailed logging:

```bash
# Set environment variable
export DEBUG_MODE=true

# Or in .env file
DEBUG_MODE=true

# Start with debug logging
npm run dev
```

## Contributing

### Code Style
- Follow ESLint and Prettier configurations
- Use TypeScript for new JavaScript files
- Write tests for new features
- Update documentation for API changes

### Pull Request Process
1. Create feature branch from main
2. Implement changes with tests
3. Run full test suite
4. Update documentation
5. Submit pull request with clear description

---

**For additional help, check the main project documentation or create an issue in the GitHub repository.**
