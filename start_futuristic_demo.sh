#!/bin/bash

# OmicsOracle Futuristic Interface Quick Start Script
# This script helps start the interface for testing with proper fallbacks

echo "🚀 OmicsOracle Futuristic Interface - Quick Start"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "interfaces/futuristic/main.py" ]; then
    echo "❌ Error: Please run this script from the OmicsOracle root directory"
    exit 1
fi

echo "📁 Setting up environment..."

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "🐍 Python version: $python_version"

# Install required packages if needed
echo "📦 Checking dependencies..."
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo "Installing FastAPI..."
    pip3 install fastapi uvicorn
fi

# Start the interface with proper error handling
echo "🌟 Starting Futuristic Interface..."
echo "   URL: http://localhost:8001"
echo "   Press Ctrl+C to stop"
echo ""

cd interfaces/futuristic

# Create a simple fallback server if the main one fails
if ! python3 main.py 2>/dev/null; then
    echo "⚠️  Main server failed to start. Creating fallback HTML server..."
    
    # Create a simple Python HTTP server serving the test page
    cat > simple_server.py << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            # Serve our test HTML with color schemes
            html_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmicsOracle - Futuristic Interface (Demo)</title>
    <link rel="stylesheet" href="/static/css/main.css">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="gradient-bg min-h-screen">
    <!-- Color Scheme Selector -->
    <div class="color-scheme-selector">
        <h4>🎨 Color Themes</h4>
        <div class="theme-options">
            <div class="theme-option active" data-theme="default" title="Milky White"></div>
            <div class="theme-option" data-theme="dark-ocean" title="Dark Ocean"></div>
            <div class="theme-option" data-theme="forest-green" title="Forest Green"></div>
            <div class="theme-option" data-theme="sunset-purple" title="Sunset Purple"></div>
            <div class="theme-option" data-theme="warm-amber" title="Warm Amber"></div>
            <div class="theme-option" data-theme="modern-gray" title="Modern Gray"></div>
        </div>
    </div>

    <div id="app" class="container mx-auto px-4 py-8">
        <!-- Header -->
        <header class="text-center mb-12">
            <h1 class="text-6xl font-bold text-white mb-4">
                🧬 OmicsOracle
            </h1>
            <p class="text-xl text-gray-200 mb-6">
                Futuristic Research Platform - Demo Mode
            </p>
            <div class="glass-effect rounded-lg p-4 inline-block">
                <div class="flex items-center space-x-4">
                    <div class="flex items-center">
                        <div class="w-3 h-3 rounded-full bg-yellow-400 mr-2"></div>
                        <span class="text-white">Demo Mode - Color Schemes Active</span>
                    </div>
                </div>
            </div>
        </header>

        <!-- Main Interface -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <!-- Test Panel 1 -->
            <div class="glass-effect rounded-xl p-6">
                <h2 class="text-2xl font-bold text-white mb-4">🎨 Color Scheme Testing</h2>
                <p class="text-gray-200 mb-4">
                    Click the colored circles in the top-left to test different themes. 
                    Your selection will be saved automatically.
                </p>
                
                <div class="space-y-4">
                    <div class="result-item dataset-item">
                        <div class="dataset-header">
                            <h5 class="dataset-title">
                                <a href="#" class="geo-link">📊 Sample Dataset Display</a>
                            </h5>
                            <div class="dataset-metadata-compact">
                                <span class="meta-badge geo-badge">
                                    <span class="meta-icon">🆔</span>
                                    <a href="#" class="geo-link">GSE123456</a>
                                </span>
                                <span class="meta-badge organism-badge">
                                    <span class="meta-icon">🧬</span>
                                    Homo sapiens
                                </span>
                                <span class="meta-badge samples-badge">
                                    <span class="meta-icon">🧪</span>
                                    <a href="#" class="samples-link">150 samples</a>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Test Panel 2 -->
            <div class="glass-effect rounded-xl p-6">
                <h2 class="text-2xl font-bold text-white mb-4">ℹ️ Theme Information</h2>
                <div class="space-y-3">
                    <div class="flex justify-between text-white">
                        <span>Current Theme:</span>
                        <span id="current-theme-name">Default</span>
                    </div>
                    <div class="flex justify-between text-white">
                        <span>Status:</span>
                        <span class="text-green-300">✅ Functional</span>
                    </div>
                    <div class="flex justify-between text-white">
                        <span>Features:</span>
                        <span class="text-blue-300">6 Themes Ready</span>
                    </div>
                </div>
                
                <div class="mt-6">
                    <h6 class="text-white font-semibold mb-2">Available Themes:</h6>
                    <div class="text-sm text-gray-300 space-y-1">
                        <div>🤍 Default - Clean milky white</div>
                        <div>🌊 Dark Ocean - Deep blue theme</div>
                        <div>🌿 Forest Green - Natural theme</div>
                        <div>🌅 Sunset Purple - Elegant theme</div>
                        <div>🌕 Warm Amber - Cozy theme</div>
                        <div>⚫ Modern Gray - Sleek theme</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="/static/js/main.js"></script>
    <script>
        // Simple theme functionality for demo
        document.addEventListener('DOMContentLoaded', () => {
            const themeOptions = document.querySelectorAll('.theme-option');
            const themeNameEl = document.getElementById('current-theme-name');
            
            // Load saved theme
            const savedTheme = localStorage.getItem('omics-oracle-theme') || 'default';
            applyTheme(savedTheme);
            updateActiveThem(savedTheme);
            updateThemeName(savedTheme);
            
            // Setup click handlers
            themeOptions.forEach(option => {
                option.addEventListener('click', () => {
                    const theme = option.dataset.theme;
                    applyTheme(theme);
                    updateActiveThem(theme);
                    updateThemeName(theme);
                    localStorage.setItem('omics-oracle-theme', theme);
                });
            });
            
            function applyTheme(themeName) {
                document.body.removeAttribute('data-theme');
                if (themeName && themeName !== 'default') {
                    document.body.setAttribute('data-theme', themeName);
                }
            }
            
            function updateActiveThem(themeName) {
                themeOptions.forEach(opt => opt.classList.remove('active'));
                const activeOption = document.querySelector(`[data-theme="${themeName}"]`);
                if (activeOption) activeOption.classList.add('active');
            }
            
            function updateThemeName(themeName) {
                if (themeNameEl) {
                    const displayNames = {
                        'default': 'Default (Milky White)',
                        'dark-ocean': 'Dark Ocean',
                        'forest-green': 'Forest Green',
                        'sunset-purple': 'Sunset Purple',
                        'warm-amber': 'Warm Amber',
                        'modern-gray': 'Modern Gray'
                    };
                    themeNameEl.textContent = displayNames[themeName] || themeName;
                }
            }
        });
    </script>
</body>
</html>
            '''
            
            self.wfile.write(html_content.encode())
            return
        else:
            # Serve static files normally
            super().do_GET()

PORT = 8001
Handler = CustomHandler

print(f"🌟 Serving OmicsOracle Demo at http://localhost:{PORT}")
print("   📁 Serving static files from current directory")
print("   🎨 Color scheme functionality active")
print("   ⌨️  Press Ctrl+C to stop")

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Server stopped.")
EOF
    
    python3 simple_server.py
fi
