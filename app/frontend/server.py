#!/usr/bin/env python3
"""
Simple HTTP server to serve the frontend on a different port.
Run this script to serve the frontend on port 8080.
"""

import http.server
import socketserver
import os
import sys
from pathlib import Path

# Get the directory where this script is located
FRONTEND_DIR = Path(__file__).parent.absolute()
PORT = 8083

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)
    
    def do_GET(self):
        # Serve index.html for root path
        if self.path == '/':
            self.path = '/index.html'
        return super().do_GET()
    
    def end_headers(self):
        # Add CORS headers to allow requests from the FastAPI backend
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

def main():
    os.chdir(FRONTEND_DIR)
    
    with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
        print(f"🚀 Frontend server running on http://localhost:{PORT}")
        print(f"📁 Serving files from: {FRONTEND_DIR}")
        print(f"🔗 Open http://localhost:{PORT} in your browser")
        print(f"\n⚠️  Make sure your FastAPI backend is running on port 8000")
        print(f"Press Ctrl+C to stop the server\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n🛑 Server stopped")
            sys.exit(0)

if __name__ == "__main__":
    main()

