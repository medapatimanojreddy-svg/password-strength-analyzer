import http.server
import socketserver
import webbrowser
import os
import sys

DEFAULT_PORT = 8000

def find_available_port(start_port):
    import socket
    port = start_port
    while port < start_port + 50:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:
                return port
        port += 1
    return start_port

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    port = find_available_port(DEFAULT_PORT)
    handler = http.server.SimpleHTTPRequestHandler
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    
    with socketserver.ThreadingTCPServer(("", port), handler) as httpd:
        url = f"http://localhost:{port}"
        print("=" * 60)
        print("  CipherGuard - Password Strength Analyzer Live Server")
        print("=" * 60)
        print(f"  --> Running locally at: {url}")
        print("  --> Press Ctrl+C in terminal to stop server.")
        print("=" * 60)
        
        # Open in default web browser
        try:
            webbrowser.open(url)
        except Exception:
            pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
            httpd.server_close()
            sys.exit(0)

if __name__ == "__main__":
    main()
