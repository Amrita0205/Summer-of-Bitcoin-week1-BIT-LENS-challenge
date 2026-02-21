#!/usr/bin/env python3
"""Web server for Chain Lens Bitcoin visualizer."""
import sys, json, os, subprocess, tempfile, cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR   = os.path.dirname(SCRIPT_DIR)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, content):
        body = content.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/api/health':
            self.send_json({'ok': True}); return
        if path in ('/', '/index.html'):
            html_path = os.path.join(SCRIPT_DIR, 'index.html')
            with open(html_path, encoding="utf-8") as f:
                self.send_html(f.read()); return
        self.send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path

        # ── Transaction analyze ────────────────────────────────────────────
        if path == '/api/analyze':
            length = int(self.headers.get('Content-Length', 0))
            body   = self.rfile.read(length)
            try:
                payload = json.loads(body)
            except Exception:
                self.send_json({'ok': False, 'error': {'code': 'INVALID_JSON', 'message': 'Invalid JSON body'}}, 400)
                return
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                json.dump(payload, tmp)
                tmp_path = tmp.name
            try:
                r = subprocess.run(
                    ['python3', os.path.join(REPO_DIR, 'analyzer.py'), tmp_path],
                    capture_output=True, text=True, timeout=30, cwd=REPO_DIR
                )
                if r.returncode == 0:
                    self.send_json(json.loads(r.stdout))
                else:
                    self.send_json({'ok': False, 'error': {'code': 'PARSE_ERROR', 'message': r.stderr or 'Parse error'}}, 500)
            except subprocess.TimeoutExpired:
                self.send_json({'ok': False, 'error': {'code': 'TIMEOUT', 'message': 'Analyzer timed out'}}, 504)
            except Exception as e:
                self.send_json({'ok': False, 'error': {'code': 'SERVER_ERROR', 'message': str(e)}}, 500)
            finally:
                try: os.unlink(tmp_path)
                except: pass
            return

        # ── Block analyze ──────────────────────────────────────────────────
        if path == '/api/analyze-block':
            ct = self.headers.get('Content-Type', '')
            length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(length)

            # Parse multipart form
            tmpdir = tempfile.mkdtemp()
            blk_path = rev_path = xor_path = None
            try:
                import email
                from email import policy as ep
                # Build a fake email message to parse multipart
                full = b'Content-Type: ' + ct.encode() + b'\r\n\r\n' + raw
                msg = email.message_from_bytes(full)
                for part in msg.walk():
                    cd = part.get('Content-Disposition', '')
                    if not cd: continue
                    fname = None
                    for p in cd.split(';'):
                        p = p.strip()
                        if p.startswith('filename='):
                            fname = p.split('=',1)[1].strip('"\'')
                    if not fname: continue
                    data = part.get_payload(decode=True)
                    fpath = os.path.join(tmpdir, fname)
                    with open(fpath, 'wb') as f:
                        f.write(data)
                    n = fname.lower()
                    if 'blk' in n:   blk_path = fpath
                    elif 'rev' in n: rev_path = fpath
                    elif 'xor' in n: xor_path = fpath

                if not all([blk_path, rev_path, xor_path]):
                    self.send_json({'ok': False, 'error': {'code': 'MISSING_FILES', 'message': 'Need blk*.dat, rev*.dat, xor.dat'}}, 400)
                    return

                r = subprocess.run(
                    ['python3', os.path.join(REPO_DIR, 'block_analyzer.py'), blk_path, rev_path, xor_path],
                    capture_output=True, text=True, timeout=120, cwd=REPO_DIR
                )
                if r.returncode == 0:
                    self.send_json(json.loads(r.stdout))
                else:
                    self.send_json({'ok': False, 'error': {'code': 'BLOCK_ERROR', 'message': r.stderr or 'Block parse error'}}, 500)
            except subprocess.TimeoutExpired:
                self.send_json({'ok': False, 'error': {'code': 'TIMEOUT', 'message': 'Block analysis timed out'}}, 504)
            except Exception as e:
                self.send_json({'ok': False, 'error': {'code': 'SERVER_ERROR', 'message': str(e)}}, 500)
            finally:
                import shutil
                try: shutil.rmtree(tmpdir)
                except: pass
            return

        self.send_json({'error': 'Not found'}, 404)


def main():
    port = int(os.environ.get('PORT', sys.argv[1] if len(sys.argv) > 1 else 3000))
    server = HTTPServer(('127.0.0.1', port), Handler)
    url = 'http://127.0.0.1:' + str(port)
    print(url, flush=True)
    server.serve_forever()

if __name__ == '__main__':
    main()