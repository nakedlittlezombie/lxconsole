"""
WebSocket Proxy for LXConsole

This module provides server-side WebSocket proxying to allow browser clients
to connect to LXD/Incus servers that require mTLS (mutual TLS) authentication.
"""

import ssl
import json
import threading
from flask import request
from flask_sock import Sock
from flask_login import login_required, current_user


# Set to True to enable verbose debug logging
DEBUG_LOGGING = False


def get_client_crt():
    return 'certs/client.crt'


def get_client_key():
    return 'certs/client.key'


def get_server_by_id(server_id):
    from lxconsole.models import Server
    return Server.query.filter_by(id=server_id).first()


def check_privilege(endpoint, server_id=None):
    from lxconsole.api.access_controls import privilege_check
    return privilege_check(endpoint, server_id)


def create_ssl_opt(server):
    ssl_opt = {
        'certfile': get_client_crt(),
        'keyfile': get_client_key(),
    }
    
    if not server.ssl_verify:
        ssl_opt['cert_reqs'] = ssl.CERT_NONE
        ssl_opt['check_hostname'] = False
    
    return ssl_opt


class WebSocketProxy:
    def __init__(self, client_ws, lxd_url, ssl_opt, debug_name=""):
        self.client_ws = client_ws
        self.lxd_url = lxd_url
        self.ssl_opt = ssl_opt
        self.lxd_ws = None
        self.running = True
        self.lock = threading.Lock()
        self.debug_name = debug_name
        
    def log(self, msg):
        if DEBUG_LOGGING:
            print(f"[WS-PROXY {self.debug_name}] {msg}")
        
    def run(self):
        try:
            import websocket
        except ImportError:
            self._send_error("websocket-client library not installed")
            return
        
        try:
            self.log(f"Connecting to LXD...")
            
            self.lxd_ws = websocket.create_connection(
                self.lxd_url,
                sslopt=self.ssl_opt,
                timeout=60,
                skip_utf8_validation=True
            )
            
            self.log(f"Connected to LXD")
            
            # Start LXD -> Client thread
            lxd_thread = threading.Thread(target=self._lxd_to_client, daemon=True)
            lxd_thread.start()
            
            # Run Client -> LXD in main thread
            self._client_to_lxd()
            
            self.running = False
            lxd_thread.join(timeout=3)
            
        except Exception as e:
            self.log(f"ERROR: {type(e).__name__}: {e}")
            self._send_error(str(e))
        finally:
            self.running = False
            self._cleanup()

    def _client_to_lxd(self):
        import websocket

        while self.running:
            try:
                data = self.client_ws.receive()

                if data is None:
                    self.log("Client disconnected")
                    break

                with self.lock:
                    if self.lxd_ws and self.lxd_ws.connected:
                        if isinstance(data, bytes):
                            self.lxd_ws.send_binary(data)
                        else:
                            self.lxd_ws.send_binary(
                                data.encode("utf-8") if isinstance(data, str) else data
                            )
                    else:
                        break

            except Exception as e:
                self.log(f"Client->LXD error: {e}")
                break

        self.running = False

    def _lxd_to_client(self):
        import websocket
        
        while self.running:
            try:
                with self.lock:
                    if not self.lxd_ws or not self.lxd_ws.connected:
                        break
                    ws = self.lxd_ws
                
                ws.settimeout(1.0)
                
                try:
                    opcode, data = ws.recv_data()
                except websocket.WebSocketTimeoutException:
                    continue
                except websocket.WebSocketConnectionClosedException:
                    break
                
                if data:
                    try:
                        self.client_ws.send(data)
                    except Exception as e:
                        self.log(f"LXD->Client error: {e}")
                        break
                        
            except websocket.WebSocketConnectionClosedException:
                break
            except Exception as e:
                if self.running:
                    self.log(f"LXD->Client error: {e}")
                break
        
        self.running = False
    
    def _send_error(self, message):
        try:
            self.client_ws.send(json.dumps({'type': 'error', 'message': message}))
        except:
            pass
    
    def _cleanup(self):
        with self.lock:
            try:
                if self.lxd_ws:
                    self.lxd_ws.close()
                    self.lxd_ws = None
            except:
                pass


sock = Sock()


def init_websocket_proxy(flask_app):
    sock.init_app(flask_app)


@sock.route('/ws/exec/<int:server_id>/<project>/<instance>')
@login_required
def proxy_exec_websocket(ws, server_id, project, instance):
    if not check_privilege('establish_instance_exec_websocket', server_id):
        ws.send(json.dumps({'type': 'error', 'message': 'Not authorized'}))
        return
    
    operation = request.args.get('operation')
    secret = request.args.get('secret')
    
    if not operation or not secret:
        ws.send(json.dumps({'type': 'error', 'message': 'Missing operation or secret'}))
        return
    
    server = get_server_by_id(server_id)
    if not server:
        ws.send(json.dumps({'type': 'error', 'message': 'Server not found'}))
        return
    
    ws_type = request.args.get('type', 'data')
    lxd_url = f"wss://{server.addr}:{server.port}{operation}/websocket?secret={secret}"
    ssl_opt = create_ssl_opt(server)
    
    proxy = WebSocketProxy(ws, lxd_url, ssl_opt, f"exec-{ws_type}")
    proxy.run()


@sock.route('/ws/console/<int:server_id>/<project>/<instance>')
@login_required
def proxy_console_websocket(ws, server_id, project, instance):
    if not check_privilege('establish_instance_console_websocket', server_id):
        ws.send(json.dumps({'type': 'error', 'message': 'Not authorized'}))
        return
    
    operation = request.args.get('operation')
    secret = request.args.get('secret')
    
    if not operation or not secret:
        ws.send(json.dumps({'type': 'error', 'message': 'Missing operation or secret'}))
        return
    
    server = get_server_by_id(server_id)
    if not server:
        ws.send(json.dumps({'type': 'error', 'message': 'Server not found'}))
        return
    
    ws_type = request.args.get('type', 'data')
    lxd_url = f"wss://{server.addr}:{server.port}{operation}/websocket?secret={secret}"
    ssl_opt = create_ssl_opt(server)
    
    proxy = WebSocketProxy(ws, lxd_url, ssl_opt, f"console-{ws_type}")
    proxy.run()


@sock.route('/ws/vga/<int:server_id>/<project>/<instance>')
@login_required
def proxy_vga_websocket(ws, server_id, project, instance):
    if not check_privilege('establish_instance_console_websocket', server_id):
        ws.send(json.dumps({'type': 'error', 'message': 'Not authorized'}))
        return
    
    operation = request.args.get('operation')
    secret = request.args.get('secret')
    
    if not operation or not secret:
        ws.send(json.dumps({'type': 'error', 'message': 'Missing operation or secret'}))
        return
    
    server = get_server_by_id(server_id)
    if not server:
        ws.send(json.dumps({'type': 'error', 'message': 'Server not found'}))
        return
    
    ws_type = request.args.get('type', 'data')
    lxd_url = f"wss://{server.addr}:{server.port}{operation}/websocket?secret={secret}"
    ssl_opt = create_ssl_opt(server)
    
    proxy = WebSocketProxy(ws, lxd_url, ssl_opt, f"vga-{ws_type}")
    proxy.run()