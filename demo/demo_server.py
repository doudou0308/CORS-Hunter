#!/usr/bin/env python3
"""Loopback-only CORS fixtures. Never use with production data."""
import argparse
import json
from pathlib import Path
import threading
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from functools import partial


class API(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.respond(True)

    def do_GET(self):
        self.respond(False)

    def do_HEAD(self):
        self.respond(False)

    def respond(self, preflight):
        path = self.path.split('?', 1)[0]
        origin = self.headers.get('Origin', '')
        if preflight and path == '/api/preflight-denied':
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(204 if preflight else 200)
        if path == '/api/reflect' or path == '/api/preflight-denied':
            if origin:
                self.send_header('Access-Control-Allow-Origin', origin)
        elif path == '/api/strict':
            self.send_header('Access-Control-Allow-Origin', 'http://127.0.0.1:%d' % self.server.server_port)
        elif path == '/api/null' and origin == 'null':
            self.send_header('Access-Control-Allow-Origin', 'null')
        elif path == '/api/wildcard':
            self.send_header('Access-Control-Allow-Origin', '*')
        elif path == '/api/invalid':
            self.send_header('Access-Control-Allow-Origin', origin + '.wrong.invalid')
        elif path == '/api/duplicate':
            self.send_header('Access-Control-Allow-Origin', origin or 'null')
            self.send_header('Access-Control-Allow-Origin', origin or 'null')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Vary', 'Origin')
        if preflight:
            self.send_header('Access-Control-Allow-Methods', 'GET, HEAD')
            self.send_header('Access-Control-Allow-Headers', 'X-Demo, Content-Type')
            self.end_headers()
            return
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Set-Cookie', 'cors_hunter_demo=1; SameSite=Lax; Path=/')
        data = json.dumps({'fixture': 'local fake data only', 'path': path,
                           'cookie_received': 'cors_hunter_demo=1' in self.headers.get('Cookie', '')}).encode()
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        print('API:', self.command, self.path.split('?', 1)[0])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-port', type=int, default=8000)
    parser.add_argument('--page-port', type=int, default=8001)
    args = parser.parse_args()
    pages = Path(__file__).resolve().parent / 'pages'
    api = ThreadingHTTPServer(('127.0.0.1', args.api_port), API)
    try:
        web = ThreadingHTTPServer(('127.0.0.1', args.page_port), partial(SimpleHTTPRequestHandler, directory=str(pages)))
    except Exception:
        api.server_close()
        raise
    threading.Thread(target=api.serve_forever, daemon=True).start()
    print('API: http://127.0.0.1:%d/api/reflect' % args.api_port)
    print('Pages: http://127.0.0.1:%d/' % args.page_port)
    print('Save browser-check HTML exported by the plugin into demo/pages. Ctrl+C to stop.')
    try:
        web.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        web.server_close()
        api.shutdown()
        api.server_close()


if __name__ == '__main__':
    main()
