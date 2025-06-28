# OmicsOracle Web Interfaces

This directory contains the different web interface implementations for OmicsOracle.

## Structure

- **`current/`** - Current stable FastAPI-based web interface (formerly web-ui-stable)
- **`react/`** - React TypeScript interface with modern architecture
- **`modern/`** - Vite-based modern UI implementation

## Usage

### Current Interface (Production)
```bash
cd current && ./start.sh
```

### React Interface (Development)
```bash
cd react && npm install && npm start
```

### Modern Interface (Experimental)
```bash
cd modern && npm install && npm run dev
```

## Architecture

Each interface has its own README with specific setup and development instructions.
