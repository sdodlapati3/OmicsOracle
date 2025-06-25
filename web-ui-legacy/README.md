# OmicsOracle - Original Web Interface

This is the **very first web interface** created for OmicsOracle. It has been preserved and restored as a standalone application that can run independently alongside the modern React interface.

## 🏛️ Historical Significance

This interface represents the original implementation of OmicsOracle's web capabilities:
- **Technology**: FastAPI backend serving static HTML with embedded JavaScript
- **Architecture**: Monolithic single-file HTML with all CSS/JS embedded
- **Features**: Basic search, real-time updates via WebSockets, results visualization
- **Era**: Created as the initial proof-of-concept web interface

## 🚀 Quick Start

### Option 1: Using the startup script (Recommended)
```bash
cd web-interface-original
./start.sh
```

### Option 2: Manual startup
```bash
cd web-interface-original
pip3 install -r requirements.txt
python3 main.py
```

The interface will be available at: **http://localhost:8001**

## 🔧 Features

- **Simple Search Interface**: Clean, straightforward search functionality
- **Real-time Updates**: WebSocket-based live query status updates
- **Results Visualization**: Basic charts and data display
- **Export Capabilities**: Download results in multiple formats
- **Responsive Design**: Works on desktop and mobile devices

## 🏗️ Architecture

### Backend (`main.py`)
- FastAPI application running on port 8001
- WebSocket support for real-time communication
- Compatible with full OmicsOracle pipeline
- Falls back to demo mode if OmicsOracle modules unavailable

### Frontend (`index.html`)
- Single HTML file with embedded CSS and JavaScript
- No build process required
- Direct API communication with backend
- Real-time updates via WebSocket connection

## 🔄 Comparison with Modern Interface

| Feature | Original Interface | Modern Interface |
|---------|-------------------|------------------|
| **Technology** | FastAPI + Static HTML | FastAPI + React/Vite |
| **Port** | 8001 | Backend: 8000, Frontend: 5173 |
| **Architecture** | Monolithic | Modular/Microservices |
| **Build Process** | None | npm build required |
| **Styling** | Embedded CSS | Tailwind CSS + Components |
| **State Management** | Vanilla JavaScript | React hooks |
| **Real-time** | WebSockets | WebSockets + React |

## 🎯 Use Cases

- **Historical Reference**: Understanding the evolution of OmicsOracle
- **Lightweight Deployment**: Minimal resource requirements
- **Educational Purposes**: Learning web interface development
- **Backup Interface**: Alternative when modern interface has issues
- **Testing**: Comparing functionality between interfaces

## 📋 API Endpoints

- `GET /` - Main interface
- `GET /health` - Health check
- `POST /api/search` - Search datasets
- `GET /api/query/{query_id}/status` - Query status
- `WebSocket /ws` - Real-time updates

## 🛠️ Dependencies

- `fastapi>=0.68.0` - Web framework
- `uvicorn>=0.15.0` - ASGI server
- `websockets>=10.0` - WebSocket support

## 🔍 Demo Mode

If OmicsOracle modules are not available, the interface runs in demo mode:
- Mock search results
- All functionality preserved
- Useful for testing and development

## 📝 Notes

- This interface runs completely independently of the modern React interface
- Both interfaces can run simultaneously on different ports
- The original HTML file is preserved exactly as it was in the first implementation
- No modifications were made to the core functionality

## 🎉 Running Both Interfaces

You can run both the original and modern interfaces simultaneously:

```bash
# Terminal 1: Start original interface
cd web-interface-original
./start.sh

# Terminal 2: Start modern interface
cd web-interface
npm run dev

# Terminal 3: Start backend (if not already running)
python3 -m omics_oracle.web.main
```

- Original Interface: http://localhost:8001
- Modern Interface: http://localhost:5173
- Backend API: http://localhost:8000
