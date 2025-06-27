# 🚀 OmicsOracle Startup Guide

**Last Updated:** June 27, 2025

This repository has been optimized to have only **3 essential startup scripts** for maximum clarity and ease of use.

---

## 📋 Available Startup Scripts

### 1. **`./start_server.sh`** - Backend API Only
**Purpose:** Start only the FastAPI backend server
**Port:** 8000
**Best for:** API development, backend testing, microservice architecture

```bash
./start_server.sh
```

**Features:**
- ✅ Comprehensive environment setup
- ✅ Virtual environment activation
- ✅ Dependency installation
- ✅ Health checks and error handling
- ✅ Clean Architecture FastAPI server

---

### 2. **`./start-futuristic-enhanced.sh`** - Full Stack (Recommended)
**Purpose:** Unified launcher for both backend and frontend
**Ports:** 8000 (backend), 8001 (frontend)
**Best for:** Full application testing, demos, production-like environment

```bash
# Start both backend and frontend (recommended)
./start-futuristic-enhanced.sh

# Start only backend
./start-futuristic-enhanced.sh --backend-only

# Start only frontend (if backend already running)
./start-futuristic-enhanced.sh --frontend-only

# Custom ports
./start-futuristic-enhanced.sh --backend-port 9000 --frontend-port 9001

# Get help
./start-futuristic-enhanced.sh --help
```

**Features:**
- ✅ Colorized output with status indicators
- ✅ Flexible backend/frontend options
- ✅ Port conflict detection and resolution
- ✅ Automatic npm build integration
- ✅ Background process management
- ✅ Clean shutdown handling

---

### 3. **`interfaces/futuristic_enhanced/start_enhanced.sh`** - Frontend Development
**Purpose:** Frontend-only with hot reload and development tools
**Port:** 8001
**Best for:** Frontend development, UI/UX work, component testing

```bash
cd interfaces/futuristic_enhanced
./start_enhanced.sh
```

**Features:**
- ✅ Webpack build watching (`npm run build:watch`)
- ✅ Hot reload for development
- ✅ Node.js dependency management
- ✅ Virtual environment auto-detection
- ✅ Enhanced development mode
- ✅ Frontend asset optimization

---

## 🎯 Quick Decision Guide

**What do you want to do?**

| Use Case | Command | Description |
|----------|---------|-------------|
| **Test APIs** | `./start_server.sh` | Backend only |
| **Full Demo** | `./start-futuristic-enhanced.sh` | Complete application |
| **Frontend Work** | `cd interfaces/futuristic_enhanced && ./start_enhanced.sh` | UI development |
| **Backend + existing frontend** | `./start-futuristic-enhanced.sh --backend-only` | API with external frontend |

---

## 🌟 Recommended Workflow

### **New Users / Quick Start**
```bash
# One command to get everything running
./start-futuristic-enhanced.sh
```

### **API Development**
```bash
# Backend only for API work
./start_server.sh
```

### **Frontend Development**
```bash
# Terminal 1: Start backend
./start_server.sh

# Terminal 2: Start frontend with hot reload
cd interfaces/futuristic_enhanced
./start_enhanced.sh
```

---

## 📖 What Was Cleaned Up

**Before:** 13 confusing startup scripts
**After:** 3 purpose-built scripts

**Removed files:**
- `start_server_simple.sh` (redundant)
- `scripts/startup/` directory (8 legacy scripts)
- `src/omics_oracle/web/start.sh` (outdated)
- `scripts/start_web_server.py` (Python duplicate)

**Benefits:**
- ✅ No more confusion about which script to use
- ✅ Each script has a clear, specific purpose
- ✅ Better maintenance and updates
- ✅ Improved user experience

---

## 🆘 Need Help?

**All scripts include built-in help:**
```bash
./start-futuristic-enhanced.sh --help
```

**Common Issues:**
- **Port conflicts:** Scripts automatically detect and resolve
- **Missing dependencies:** Scripts install what's needed
- **Virtual environment:** Scripts activate automatically
- **Wrong directory:** Scripts provide clear error messages

**Logs:** Check `backend.log` for backend issues, terminal output for frontend issues.

---

**Happy coding! 🎉**
